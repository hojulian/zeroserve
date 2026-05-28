//! OAuth2 / OIDC Authorization-Code + PKCE client (Relying Party) logic.
//!
//! `zeroserve` acts as the OAuth2 client: it redirects an unauthenticated user
//! to the configured identity provider, handles the redirect callback, exchanges
//! the authorization code for tokens at the token endpoint, and issues a sealed
//! session cookie. Transient login state (PKCE verifier, CSRF state, nonce) and
//! the session itself are carried entirely in encrypted+authenticated cookies, so
//! there is no server-side session store.
//!
//! ## id_token signature verification
//!
//! The id_token is obtained directly from the token endpoint over a server-
//! validated TLS connection. Per OpenID Connect Core 1.0 §3.1.3.7 (note 2), in
//! the Authorization Code flow the TLS channel MAY be relied upon in place of
//! verifying the id_token signature. We therefore validate the id_token *claims*
//! (`iss`, `aud`, `exp`, `nonce`) but do not perform JWKS/RSA signature
//! verification. A future enhancement may add optional `jwks_uri` verification.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};

use crate::http::h1::{self, H1Connection, RequestHead};
use crate::pool::PooledConnection;
use crate::server::{BackendScheme, BackendTarget, connect_backend, parse_backend_target};

/// Default OAuth scope when the script does not specify one.
pub const DEFAULT_SCOPE: &str = "openid profile email";
/// Default session lifetime (seconds) when the script passes 0.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600;
/// How long the transient login-state cookie is valid (seconds).
pub const STATE_TTL_SECS: u64 = 600;

/// Cookie name carrying the transient login state during the redirect dance.
pub const STATE_COOKIE: &str = "__zs_oidc_state";
/// Cookie name carrying the authenticated session.
pub const SESSION_COOKIE: &str = "__zs_oidc_session";

const AAD_STATE: &[u8] = b"zeroserve.oidc.state.v1";
const AAD_SESSION: &[u8] = b"zeroserve.oidc.session.v1";
const XNONCE_LEN: usize = 24;
const MAX_HTTP_RESPONSE: usize = 256 * 1024;

/// Resolved OIDC configuration for one request, built from the C `zs_oidc_config`.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
    pub cookie_secret: Vec<u8>,
    pub session_ttl_secs: u64,
}

/// IdP endpoints, either supplied explicitly or via discovery.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Sealed payload of the transient login-state cookie.
#[derive(Serialize, Deserialize)]
pub struct StateData {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub return_to: String,
    pub exp: i64,
}

/// Sealed payload of the session cookie: the validated id_token claims plus our
/// own expiry.
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    pub exp: i64,
    pub claims: serde_json::Value,
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Cookie sealing (XChaCha20-Poly1305, key = SHA256(cookie_secret))
// ---------------------------------------------------------------------------

fn cipher(secret: &[u8]) -> Result<XChaCha20Poly1305> {
    let key = Sha256::digest(secret);
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid cookie key"))
}

/// Encrypt+authenticate `plaintext` and return a base64url(nonce || ciphertext)
/// string suitable for a cookie value.
pub fn seal(secret: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<String> {
    let cipher = cipher(secret)?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("seal failed"))?;
    let mut combined = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(Base64UrlUnpadded::encode_string(&combined))
}

/// Inverse of [`seal`]; returns `None` on any tamper / decode / auth failure.
pub fn open(secret: &[u8], aad: &[u8], token: &str) -> Option<Vec<u8>> {
    let combined = Base64UrlUnpadded::decode_vec(token.trim()).ok()?;
    if combined.len() < XNONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = combined.split_at(XNONCE_LEN);
    let cipher = cipher(secret).ok()?;
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

pub fn seal_state(secret: &[u8], data: &StateData) -> Result<String> {
    seal(secret, AAD_STATE, &serde_json::to_vec(data)?)
}

pub fn open_state(secret: &[u8], token: &str) -> Option<StateData> {
    let bytes = open(secret, AAD_STATE, token)?;
    let data: StateData = serde_json::from_slice(&bytes).ok()?;
    if data.exp < now_secs() {
        return None;
    }
    Some(data)
}

pub fn seal_session(secret: &[u8], data: &SessionData) -> Result<String> {
    seal(secret, AAD_SESSION, &serde_json::to_vec(data)?)
}

pub fn open_session(secret: &[u8], token: &str) -> Option<SessionData> {
    let bytes = open(secret, AAD_SESSION, token)?;
    let data: SessionData = serde_json::from_slice(&bytes).ok()?;
    if data.exp < now_secs() {
        return None;
    }
    Some(data)
}

// ---------------------------------------------------------------------------
// Cookie header formatting / parsing
// ---------------------------------------------------------------------------

/// Build a `Set-Cookie` header value. `secure` adds the `Secure` attribute
/// (only safe over HTTPS). `max_age` of `None` produces a session cookie.
pub fn set_cookie(name: &str, value: &str, max_age: Option<u64>, secure: bool) -> String {
    let mut s = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
    if let Some(age) = max_age {
        s.push_str(&format!("; Max-Age={age}"));
    }
    if secure {
        s.push_str("; Secure");
    }
    s
}

/// Build a `Set-Cookie` header value that immediately expires `name`.
pub fn clear_cookie(name: &str, secure: bool) -> String {
    let mut s = format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        s.push_str("; Secure");
    }
    s
}

/// Extract a single cookie value from a request `Cookie` header.
pub fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// PKCE, state, authorize URL
// ---------------------------------------------------------------------------

fn random_b64url(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    Base64UrlUnpadded::encode_string(&bytes)
}

/// One-time login parameters generated at the start of a login.
pub struct LoginParams {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

pub fn generate_login_params() -> LoginParams {
    let code_verifier = random_b64url(32);
    let challenge = Sha256::digest(code_verifier.as_bytes());
    LoginParams {
        state: random_b64url(16),
        nonce: random_b64url(16),
        code_challenge: Base64UrlUnpadded::encode_string(&challenge),
        code_verifier,
    }
}

/// Build the IdP authorization URL for the Authorization-Code + PKCE flow.
pub fn build_authorize_url(
    authorization_endpoint: &str,
    cfg: &OidcConfig,
    p: &LoginParams,
) -> Result<String> {
    let mut url = Url::parse(authorization_endpoint)
        .map_err(|e| anyhow!("invalid authorize endpoint: {e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_uri)
        .append_pair("scope", &cfg.scope)
        .append_pair("state", &p.state)
        .append_pair("nonce", &p.nonce)
        .append_pair("code_challenge", &p.code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

// ---------------------------------------------------------------------------
// id_token claims
// ---------------------------------------------------------------------------

/// Parse (without signature verification) the claims set from a JWT id_token.
pub fn parse_id_token_claims(id_token: &str) -> Option<serde_json::Value> {
    let mut parts = id_token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _sig = parts.next()?;
    let bytes = Base64UrlUnpadded::decode_vec(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Validate id_token claims for the Authorization-Code flow (signature is
/// trusted via the direct TLS connection to the token endpoint — see module
/// docs).
pub fn validate_claims(
    claims: &serde_json::Value,
    expected_issuer: Option<&str>,
    client_id: &str,
    expected_nonce: &str,
) -> Result<()> {
    if let Some(expected) = expected_issuer {
        let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if iss != expected {
            bail!("id_token issuer mismatch");
        }
    }

    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        bail!("id_token audience mismatch");
    }

    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if exp != 0 && exp < now_secs() {
        bail!("id_token expired");
    }

    if let Some(nonce) = claims.get("nonce").and_then(|v| v.as_str()) {
        if nonce != expected_nonce {
            bail!("id_token nonce mismatch");
        }
    } else {
        bail!("id_token missing nonce");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Outbound HTTP (reuses the server's connect_backend / h1 client codec)
// ---------------------------------------------------------------------------

fn host_header(t: &BackendTarget) -> String {
    let default_port = matches!(t.scheme, BackendScheme::Https) && t.port == 443
        || matches!(t.scheme, BackendScheme::Http) && t.port == 80;
    let host = if t.is_ipv6 {
        format!("[{}]", t.host)
    } else {
        t.host.clone()
    };
    if default_port {
        host
    } else {
        format!("{host}:{}", t.port)
    }
}

fn origin_form_uri(t: &BackendTarget) -> Result<http::Uri> {
    let path = if t.base_path.is_empty() {
        "/"
    } else {
        t.base_path.as_str()
    };
    let raw = match &t.base_query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    };
    raw.parse()
        .map_err(|e| anyhow!("invalid endpoint path: {e}"))
}

async fn run_over<IO: AsyncReadRent + AsyncWriteRent>(
    conn: &mut H1Connection<IO>,
    head: RequestHead,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>)> {
    {
        let io = conn.io_mut()?;
        h1::write_request_head(io, &head)
            .await
            .map_err(|e| anyhow!("write request head: {e}"))?;
        if !body.is_empty() {
            let (res, _) = io.write_all(body).await;
            res.map_err(|e| anyhow!("write request body: {e}"))?;
        }
        let _ = io.flush().await;
    }

    let response = conn
        .next_response()
        .await
        .map_err(|e| anyhow!("read response: {e}"))?
        .ok_or_else(|| anyhow!("endpoint closed without response"))?;
    let (resp_head, mut resp_body) = response.into_parts();
    let status = resp_head.status.as_u16();

    let mut out = Vec::new();
    while let Some(chunk) = resp_body.next_data(conn).await {
        let chunk = chunk.map_err(|e| anyhow!("read response body: {e}"))?;
        if out.len() + chunk.len() > MAX_HTTP_RESPONSE {
            bail!("endpoint response too large");
        }
        out.extend_from_slice(&chunk);
    }
    Ok((status, out))
}

/// Perform a request to `url` (fresh connection, not pooled) and collect the
/// full response body. `form` non-empty implies a `POST`.
async fn request(
    url: &str,
    form: &[(&str, &str)],
    basic_auth: Option<(&str, &str)>,
) -> Result<(u16, Vec<u8>)> {
    let target = parse_backend_target(url)?;
    let uri = origin_form_uri(&target)?;

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_str(&host_header(&target))?,
    );
    headers.insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );
    if let Some((user, pass)) = basic_auth {
        let raw = format!("{user}:{pass}");
        let encoded = base64ct::Base64::encode_string(raw.as_bytes());
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Basic {encoded}"))?,
        );
    }

    let (method, body) = if form.is_empty() {
        (http::Method::GET, Vec::new())
    } else {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in form {
            ser.append_pair(k, v);
        }
        let body = ser.finish().into_bytes();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body.len().to_string())?,
        );
        (http::Method::POST, body)
    };

    let head = RequestHead {
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
    };

    match connect_backend(&target).await? {
        PooledConnection::Http(mut conn) => run_over(&mut conn, head, body).await,
        PooledConnection::Https(mut conn) => run_over(&mut conn, head, body).await,
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Exchange an authorization code (with the PKCE verifier) at the token endpoint
/// and return the validated id_token claims.
pub async fn exchange_code(
    cfg: &OidcConfig,
    token_endpoint: &str,
    code: &str,
    code_verifier: &str,
    expected_nonce: &str,
) -> Result<serde_json::Value> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("code_verifier", code_verifier),
    ];
    let (status, body) = request(token_endpoint, &form, None).await?;
    let parsed: TokenResponse = serde_json::from_slice(&body)
        .map_err(|e| anyhow!("token endpoint returned non-JSON: {e}"))?;
    if status >= 400 || parsed.error.is_some() {
        bail!(
            "token endpoint error (status {status}): {} {}",
            parsed.error.unwrap_or_default(),
            parsed.error_description.unwrap_or_default()
        );
    }
    let id_token = parsed
        .id_token
        .ok_or_else(|| anyhow!("token response missing id_token"))?;
    let claims = parse_id_token_claims(&id_token).ok_or_else(|| anyhow!("malformed id_token"))?;
    validate_claims(
        &claims,
        cfg.issuer.as_deref(),
        &cfg.client_id,
        expected_nonce,
    )?;
    Ok(claims)
}

// ---------------------------------------------------------------------------
// OIDC discovery (cached per worker thread)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
}

thread_local! {
    static DISCOVERY_CACHE: RefCell<HashMap<String, (Instant, Endpoints)>> =
        RefCell::new(HashMap::new());
}

const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

/// Resolve the IdP endpoints, preferring explicit config and falling back to
/// OIDC discovery against `{issuer}/.well-known/openid-configuration`.
pub async fn resolve_endpoints(cfg: &OidcConfig) -> Result<Endpoints> {
    if let (Some(auth), Some(token)) = (&cfg.authorization_endpoint, &cfg.token_endpoint) {
        return Ok(Endpoints {
            authorization_endpoint: auth.clone(),
            token_endpoint: token.clone(),
        });
    }

    let issuer = cfg
        .issuer
        .as_deref()
        .ok_or_else(|| anyhow!("oidc config needs either explicit endpoints or an issuer"))?;

    if let Some(found) = DISCOVERY_CACHE.with(|c| {
        c.borrow()
            .get(issuer)
            .and_then(|(at, ep)| (at.elapsed() < DISCOVERY_TTL).then(|| ep.clone()))
    }) {
        return Ok(found);
    }

    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let (status, body) = request(&url, &[], None).await?;
    if status >= 400 {
        bail!("discovery failed (status {status})");
    }
    let doc: DiscoveryDoc =
        serde_json::from_slice(&body).map_err(|e| anyhow!("invalid discovery document: {e}"))?;
    let endpoints = Endpoints {
        authorization_endpoint: doc.authorization_endpoint,
        token_endpoint: doc.token_endpoint,
    };
    DISCOVERY_CACHE.with(|c| {
        c.borrow_mut()
            .insert(issuer.to_string(), (Instant::now(), endpoints.clone()));
    });
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-very-stable-cookie-secret-0123";

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: Some("https://idp.example".into()),
            authorization_endpoint: Some("https://idp.example/authorize".into()),
            token_endpoint: Some("https://idp.example/token".into()),
            client_id: "client-123".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app.example/callback".into(),
            scope: DEFAULT_SCOPE.into(),
            cookie_secret: SECRET.to_vec(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let sealed = seal(SECRET, AAD_SESSION, b"hello world").unwrap();
        assert_eq!(open(SECRET, AAD_SESSION, &sealed).unwrap(), b"hello world");
    }

    #[test]
    fn open_rejects_tamper() {
        let mut sealed = seal(SECRET, AAD_SESSION, b"payload").unwrap();
        // Flip a character in the ciphertext.
        let last = sealed.pop().unwrap();
        sealed.push(if last == 'A' { 'B' } else { 'A' });
        assert!(open(SECRET, AAD_SESSION, &sealed).is_none());
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let sealed = seal(SECRET, AAD_STATE, b"payload").unwrap();
        assert!(open(SECRET, AAD_SESSION, &sealed).is_none());
        assert!(open(SECRET, AAD_STATE, &sealed).is_some());
    }

    #[test]
    fn open_rejects_wrong_key() {
        let sealed = seal(SECRET, AAD_SESSION, b"payload").unwrap();
        assert!(open(b"different-secret-xxxxxxxxxxxxxxxx", AAD_SESSION, &sealed).is_none());
    }

    #[test]
    fn state_cookie_expiry() {
        let expired = StateData {
            state: "s".into(),
            nonce: "n".into(),
            code_verifier: "v".into(),
            return_to: "/".into(),
            exp: now_secs() - 10,
        };
        let sealed = seal_state(SECRET, &expired).unwrap();
        assert!(open_state(SECRET, &sealed).is_none());

        let valid = StateData {
            exp: now_secs() + 100,
            ..expired
        };
        let sealed = seal_state(SECRET, &valid).unwrap();
        assert_eq!(open_state(SECRET, &sealed).unwrap().state, "s");
    }

    #[test]
    fn pkce_challenge_matches_known_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn authorize_url_has_pkce_params() {
        let p = LoginParams {
            state: "STATE".into(),
            nonce: "NONCE".into(),
            code_verifier: "VERIFIER".into(),
            code_challenge: "CHALLENGE".into(),
        };
        let url = build_authorize_url("https://idp.example/authorize", &cfg(), &p).unwrap();
        assert!(url.starts_with("https://idp.example/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=CHALLENGE"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=STATE"));
        assert!(url.contains("client_id=client-123"));
    }

    fn make_id_token(claims: serde_json::Value) -> String {
        let payload = Base64UrlUnpadded::encode_string(claims.to_string().as_bytes());
        format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig")
    }

    #[test]
    fn claims_validation_good() {
        let token = make_id_token(serde_json::json!({
            "iss": "https://idp.example",
            "aud": "client-123",
            "exp": now_secs() + 100,
            "nonce": "NONCE",
            "sub": "user1",
        }));
        let claims = parse_id_token_claims(&token).unwrap();
        assert!(
            validate_claims(&claims, Some("https://idp.example"), "client-123", "NONCE").is_ok()
        );
    }

    #[test]
    fn claims_validation_rejects_bad() {
        let base = serde_json::json!({
            "iss": "https://idp.example",
            "aud": "client-123",
            "exp": now_secs() + 100,
            "nonce": "NONCE",
        });

        let wrong_aud = parse_id_token_claims(&make_id_token({
            let mut c = base.clone();
            c["aud"] = serde_json::json!("other-client");
            c
        }))
        .unwrap();
        assert!(
            validate_claims(
                &wrong_aud,
                Some("https://idp.example"),
                "client-123",
                "NONCE"
            )
            .is_err()
        );

        let expired = parse_id_token_claims(&make_id_token({
            let mut c = base.clone();
            c["exp"] = serde_json::json!(now_secs() - 5);
            c
        }))
        .unwrap();
        assert!(
            validate_claims(&expired, Some("https://idp.example"), "client-123", "NONCE").is_err()
        );

        let bad_nonce = parse_id_token_claims(&make_id_token(base.clone())).unwrap();
        assert!(
            validate_claims(
                &bad_nonce,
                Some("https://idp.example"),
                "client-123",
                "OTHER"
            )
            .is_err()
        );

        let wrong_iss = parse_id_token_claims(&make_id_token(base)).unwrap();
        assert!(
            validate_claims(
                &wrong_iss,
                Some("https://evil.example"),
                "client-123",
                "NONCE"
            )
            .is_err()
        );
    }

    #[test]
    fn aud_array_accepted() {
        let token = make_id_token(serde_json::json!({
            "aud": ["other", "client-123"],
            "exp": now_secs() + 100,
            "nonce": "NONCE",
        }));
        let claims = parse_id_token_claims(&token).unwrap();
        assert!(validate_claims(&claims, None, "client-123", "NONCE").is_ok());
    }

    #[test]
    fn cookie_value_parsing() {
        let header = "foo=bar; __zs_oidc_session=abc.def; baz=qux";
        assert_eq!(cookie_value(header, "__zs_oidc_session"), Some("abc.def"));
        assert_eq!(cookie_value(header, "foo"), Some("bar"));
        assert_eq!(cookie_value(header, "missing"), None);
    }
}
