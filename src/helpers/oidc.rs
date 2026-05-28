//! eBPF helper wrappers for the OIDC Authorization-Code + PKCE login flow.
//!
//! These are thin bindings over [`crate::oidc`]: they read the config from a
//! JSON object handle plus string arguments out of script memory, run the flow,
//! and write the terminal HTTP response (redirect + cookies) back into the
//! execution context.

use async_ebpf::program::HelperScope;

use crate::json::JsonRef;
use crate::oidc::{
    self, DEFAULT_SCOPE, DEFAULT_SESSION_TTL_SECS, OidcConfig, SESSION_COOKIE, STATE_COOKIE,
    STATE_TTL_SECS, SessionData, StateData,
};
use crate::script::{ScriptResponse, read_utf8, with_ectx};

fn opt_string(scope: &HelperScope, ptr: u64, len: u64) -> Result<Option<String>, ()> {
    if len == 0 {
        Ok(None)
    } else {
        Ok(Some(read_utf8(scope, ptr, len)?.to_string()))
    }
}

/// Read the OIDC config from a JSON object handle (built by the script with
/// `zs_json_parse` or `zs_json_new_object`/`zs_json_set_string`). Recognised
/// keys: `issuer`, `authorization_endpoint`, `token_endpoint`, `client_id`,
/// `client_secret`, `redirect_uri`, `scope`, `cookie_secret`,
/// `session_ttl_secs`.
///
/// Returns `Ok(None)` when the handle does not resolve to a JSON object —
/// callers should surface that as a configuration error (`-1`) rather than a
/// hard script abort.
fn read_config(scope: &HelperScope, cfg_handle: u64) -> Result<Option<OidcConfig>, ()> {
    with_ectx(scope, |ctx| {
        let json = ctx.extobj::<JsonRef>(cfg_handle)?;
        json.view(|v| {
            let obj = v.as_object()?;
            let s = |k: &str| obj.get(k).and_then(|x| x.as_str()).map(str::to_string);
            Some(OidcConfig {
                issuer: s("issuer"),
                authorization_endpoint: s("authorization_endpoint"),
                token_endpoint: s("token_endpoint"),
                client_id: s("client_id").unwrap_or_default(),
                client_secret: s("client_secret").unwrap_or_default(),
                redirect_uri: s("redirect_uri").unwrap_or_default(),
                scope: s("scope").unwrap_or_else(|| DEFAULT_SCOPE.to_string()),
                cookie_secret: s("cookie_secret").unwrap_or_default().into_bytes(),
                session_ttl_secs: obj
                    .get("session_ttl_secs")
                    .and_then(|x| x.as_u64())
                    .filter(|n| *n > 0)
                    .unwrap_or(DEFAULT_SESSION_TTL_SECS),
            })
        })
        .map_err(|_| ())
    })
}

/// Log an OIDC configuration error and return `-1` to the script. The script
/// can decide how to react (respond 500 itself, fall through to other
/// middleware, etc.) instead of the runtime hard-aborting the request.
/// `ctx.error` is intentionally NOT touched — that channel is reserved for
/// fatal helper failures (the `Err(())` path).
fn config_error_code(_scope: &HelperScope, msg: impl AsRef<str>) -> Result<u64, ()> {
    eprintln!("[oidc] {}", msg.as_ref());
    Ok(-1i64 as u64)
}

/// Set a terminal response on the execution context.
fn respond(
    ctx: &mut crate::script::ScriptExecutionContext,
    status: u16,
    body: &str,
    headers: Vec<(String, String)>,
) {
    ctx.response = Some(ScriptResponse {
        status,
        body: body.as_bytes().to_vec(),
        headers,
    });
}

/// `zs_oidc_begin_login(cfg, return_to, return_to_len)`
///
/// Generate PKCE/state, set the sealed state cookie, and 302-redirect the user
/// to the IdP authorization endpoint. Terminal.
pub fn h_oidc_begin_login(
    scope: &HelperScope,
    cfg_handle: u64,
    return_to_ptr: u64,
    return_to_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(cfg) = read_config(scope, cfg_handle)? else {
        return config_error_code(
            scope,
            "zs_oidc_begin_login: cfg handle is not a JSON object",
        );
    };
    if cfg.client_id.is_empty() || cfg.redirect_uri.is_empty() || cfg.cookie_secret.len() < 16 {
        return config_error_code(
            scope,
            "zs_oidc_begin_login: missing client_id/redirect_uri or weak cookie_secret",
        );
    }
    let return_to = opt_string(scope, return_to_ptr, return_to_len)?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    let secure = with_ectx(scope, |ctx| Ok(ctx.request.scheme == "https"))?;

    scope.post_task(async move {
        let result = async {
            let endpoints = oidc::resolve_endpoints(&cfg).await?;
            let params = oidc::generate_login_params();
            let authorize_url =
                oidc::build_authorize_url(&endpoints.authorization_endpoint, &cfg, &params)?;
            let state = StateData {
                state: params.state.clone(),
                nonce: params.nonce.clone(),
                code_verifier: params.code_verifier.clone(),
                return_to,
                exp: chrono::Utc::now().timestamp() + STATE_TTL_SECS as i64,
            };
            let sealed = oidc::seal_state(&cfg.cookie_secret, &state)?;
            anyhow::Ok((authorize_url, sealed))
        }
        .await;

        move |scope: &HelperScope| match result {
            Ok((authorize_url, sealed)) => with_ectx(scope, |ctx| {
                respond(
                    ctx,
                    302,
                    "",
                    vec![
                        ("location".into(), authorize_url),
                        (
                            "set-cookie".into(),
                            oidc::set_cookie(STATE_COOKIE, &sealed, Some(STATE_TTL_SECS), secure),
                        ),
                    ],
                );
                Ok(0)
            }),
            Err(err) => with_ectx(scope, |ctx| {
                ctx.error = format!("zs_oidc_begin_login: {err}");
                Err(())
            }),
        }
    });
    Ok(0)
}

/// `zs_oidc_handle_callback(cfg)`
///
/// Validate the returned `state` against the sealed state cookie, exchange the
/// authorization code for tokens, validate id_token claims, issue the sealed
/// session cookie, and 302-redirect back to the originally requested URL.
pub fn h_oidc_handle_callback(
    scope: &HelperScope,
    cfg_handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(cfg) = read_config(scope, cfg_handle)? else {
        return config_error_code(
            scope,
            "zs_oidc_handle_callback: cfg handle is not a JSON object",
        );
    };
    if cfg.client_id.is_empty() || cfg.redirect_uri.is_empty() || cfg.cookie_secret.len() < 16 {
        return config_error_code(
            scope,
            "zs_oidc_handle_callback: missing client_id/redirect_uri or weak cookie_secret",
        );
    }

    // Pull request-scoped inputs synchronously.
    let (code, query_state, cookie_header, secure) = with_ectx(scope, |ctx| {
        let code = ctx.request.query_param("code").map(str::to_string);
        let state = ctx.request.query_param("state").map(str::to_string);
        let cookie = ctx.request.header("cookie").map(str::to_string);
        Ok((code, state, cookie, ctx.request.scheme == "https"))
    })?;

    // Validate the CSRF state and recover the PKCE verifier from the state cookie.
    let bad_request = |scope: &HelperScope, msg: &str| -> Result<u64, ()> {
        with_ectx(scope, |ctx| {
            respond(ctx, 400, msg, vec![]);
            Ok(())
        })?;
        Ok(0)
    };
    let (Some(code), Some(query_state)) = (code, query_state) else {
        return bad_request(scope, "missing code or state");
    };
    let Some(cookie_header) = cookie_header else {
        return bad_request(scope, "missing login state");
    };
    let Some(sealed_state) = oidc::cookie_value(&cookie_header, STATE_COOKIE) else {
        return bad_request(scope, "missing login state");
    };
    let Some(state_data) = oidc::open_state(&cfg.cookie_secret, sealed_state) else {
        return bad_request(scope, "invalid or expired login state");
    };
    if state_data.state != query_state {
        return bad_request(scope, "state mismatch");
    }

    let ttl = cfg.session_ttl_secs;
    let code_verifier = state_data.code_verifier;
    let nonce = state_data.nonce;
    let return_to = state_data.return_to;

    scope.post_task(async move {
        let result = async {
            let endpoints = oidc::resolve_endpoints(&cfg).await?;
            let claims = oidc::exchange_code(
                &cfg,
                &endpoints.token_endpoint,
                &code,
                &code_verifier,
                &nonce,
            )
            .await?;
            let session = SessionData {
                exp: chrono::Utc::now().timestamp() + ttl as i64,
                claims,
            };
            let sealed = oidc::seal_session(&cfg.cookie_secret, &session)?;
            anyhow::Ok(sealed)
        }
        .await;

        move |scope: &HelperScope| match result {
            Ok(sealed) => with_ectx(scope, |ctx| {
                respond(
                    ctx,
                    302,
                    "",
                    vec![
                        ("location".into(), return_to),
                        (
                            "set-cookie".into(),
                            oidc::set_cookie(SESSION_COOKIE, &sealed, Some(ttl), secure),
                        ),
                        (
                            "set-cookie".into(),
                            oidc::clear_cookie(STATE_COOKIE, secure),
                        ),
                    ],
                );
                Ok(0)
            }),
            Err(err) => with_ectx(scope, |ctx| {
                ctx.error = format!("zs_oidc_handle_callback: {err}");
                respond(ctx, 502, "authentication failed", vec![]);
                Ok(0)
            }),
        }
    });
    Ok(0)
}

/// `zs_oidc_session_verify(cfg)`
///
/// Returns a JSON object handle of the session claims if a valid session cookie
/// is present, `0` if absent/invalid/expired, `<0` on internal error. Not terminal.
pub fn h_oidc_session_verify(
    scope: &HelperScope,
    cfg_handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(cfg) = read_config(scope, cfg_handle)? else {
        return config_error_code(
            scope,
            "zs_oidc_session_verify: cfg handle is not a JSON object",
        );
    };
    if cfg.cookie_secret.len() < 16 {
        return config_error_code(scope, "zs_oidc_session_verify: weak cookie_secret");
    }

    with_ectx(scope, |ctx| {
        let Some(cookie_header) = ctx.request.header("cookie").map(str::to_string) else {
            return Ok(0);
        };
        let Some(sealed) = oidc::cookie_value(&cookie_header, SESSION_COOKIE) else {
            return Ok(0);
        };
        let Some(session) = oidc::open_session(&cfg.cookie_secret, sealed) else {
            return Ok(0);
        };
        ctx.alloc_extobj(JsonRef::new(session.claims))
    })
}

/// `zs_oidc_logout(cfg, end_session_url, end_session_url_len)`
///
/// Clear the session cookie. Redirects to `end_session_url` when non-empty,
/// otherwise returns 200. Terminal.
pub fn h_oidc_logout(
    scope: &HelperScope,
    cfg_handle: u64,
    end_session_ptr: u64,
    end_session_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // Validate the config struct shape even though logout only clears the cookie.
    if read_config(scope, cfg_handle)?.is_none() {
        return config_error_code(scope, "zs_oidc_logout: cfg handle is not a JSON object");
    }
    let end_session_url =
        opt_string(scope, end_session_ptr, end_session_len)?.filter(|s| !s.is_empty());

    with_ectx(scope, |ctx| {
        let secure = ctx.request.scheme == "https";
        let clear = oidc::clear_cookie(SESSION_COOKIE, secure);
        match end_session_url {
            Some(url) => respond(
                ctx,
                302,
                "",
                vec![("location".into(), url), ("set-cookie".into(), clear)],
            ),
            None => respond(ctx, 200, "logged out", vec![("set-cookie".into(), clear)]),
        }
        Ok(0)
    })
}
