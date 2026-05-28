use std::{
    any::Any, cell::RefCell, collections::HashMap, pin::Pin, rc::Rc, sync::Arc, time::Duration,
};

use ::http::{
    Uri,
    header::{HeaderName, HeaderValue},
};
use anyhow::Context;
use async_ebpf::{
    helpers::{Helper, write_cstr},
    program::{
        GlobalEnv, HelperScope, PreemptionEnabled, Program, ProgramEventListener, ProgramLoader,
        ThreadEnv, TimesliceConfig, Timeslicer, UnboundProgram,
    },
};
use futures::{FutureExt, channel::oneshot};
use monoio::fs::File;
use ulid::Ulid;
use url::form_urlencoded;

use crate::helpers;
use crate::{logging::async_log, site::Site, thread_pool::CPU_TP};

const SCRIPT_ENTRYPOINT: &str = "zeroserve.request";
const MAX_EXTERNAL_OBJECTS: usize = 32;

type BodyReaderFuture = Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, BodyReadError>>>>;

pub enum BodyReadError {
    TooLarge,
    ReadError,
}

enum BodySourceState {
    Pending(BodyReaderFuture),
    Ready(Vec<u8>),
    TooLarge,
    Empty,
}

#[derive(Clone)]
pub struct BodySource {
    inner: Rc<RefCell<BodySourceState>>,
}

impl BodySource {
    pub fn new(reader: BodyReaderFuture) -> Self {
        Self {
            inner: Rc::new(RefCell::new(BodySourceState::Pending(reader))),
        }
    }

    pub async fn read(&self) -> Result<Vec<u8>, ()> {
        {
            let state = self.inner.borrow();
            match &*state {
                BodySourceState::Ready(bytes) => return Ok(bytes.clone()),
                BodySourceState::TooLarge | BodySourceState::Empty => return Err(()),
                BodySourceState::Pending(_) => {}
            }
        }

        let future = {
            let mut state = self.inner.borrow_mut();
            match std::mem::replace(&mut *state, BodySourceState::Empty) {
                BodySourceState::Pending(f) => f,
                other => {
                    *state = other;
                    return Err(());
                }
            }
        };

        let result = future.await;

        let mut state = self.inner.borrow_mut();
        match result {
            Ok(bytes) => {
                *state = BodySourceState::Ready(bytes.clone());
                Ok(bytes)
            }
            Err(BodyReadError::TooLarge) => {
                *state = BodySourceState::TooLarge;
                Err(())
            }
            Err(BodyReadError::ReadError) => {
                *state = BodySourceState::Empty;
                Err(())
            }
        }
    }
}

static SCRIPT_HELPERS: &[(&str, Helper)] = &[
    ("zs_log", helpers::h_log),
    ("zs_now_ms", helpers::h_now_ms),
    ("zs_env_get", helpers::h_env_get),
    ("zs_getrandom", helpers::h_getrandom),
    ("zs_sha256", helpers::h_sha256),
    ("zs_hmac_sha256", helpers::h_hmac_sha256),
    ("zs_base64_encode", helpers::h_base64_encode),
    (
        "zs_base64_decode_in_place",
        helpers::h_base64_decode_in_place,
    ),
    ("zs_hex_encode", helpers::h_hex_encode),
    ("zs_hex_decode_in_place", helpers::h_hex_decode_in_place),
    ("zs_memcpy", helpers::h_memcpy),
    ("zs_memcmp", helpers::h_memcmp),
    ("zs_memset", helpers::h_memset),
    ("zs_json_parse", helpers::h_json_parse),
    ("zs_load_static_json", helpers::h_load_static_json),
    ("zs_load_file_metadata", helpers::h_load_file_metadata),
    ("zs_json_reset", helpers::h_json_reset),
    ("zs_json_get", helpers::h_json_get),
    ("zs_json_array_get", helpers::h_json_array_get),
    ("zs_json_read_string", helpers::h_json_read_string),
    ("zs_json_read_i64", helpers::h_json_read_i64),
    ("zs_json_read_bool", helpers::h_json_read_bool),
    ("zs_json_new_object", helpers::h_json_new_object),
    ("zs_json_new_array", helpers::h_json_new_array),
    ("zs_json_clone", helpers::h_json_clone),
    ("zs_json_type", helpers::h_json_type),
    ("zs_json_len", helpers::h_json_len),
    ("zs_json_set", helpers::h_json_set),
    ("zs_json_remove", helpers::h_json_remove),
    ("zs_json_array_push", helpers::h_json_array_push),
    ("zs_json_array_set", helpers::h_json_array_set),
    ("zs_json_set_string", helpers::h_json_set_string),
    ("zs_json_set_i64", helpers::h_json_set_i64),
    ("zs_json_set_bool", helpers::h_json_set_bool),
    ("zs_json_set_null", helpers::h_json_set_null),
    ("zs_json_respond", helpers::h_json_respond),
    ("zs_object_free", helpers::h_object_free),
    ("zs_req_method", helpers::h_req_method),
    ("zs_req_path", helpers::h_req_path),
    ("zs_req_uri", helpers::h_req_uri),
    ("zs_req_set_uri", helpers::h_req_set_uri),
    ("zs_req_query", helpers::h_req_query),
    ("zs_req_scheme", helpers::h_req_scheme),
    ("zs_req_peer", helpers::h_req_peer),
    ("zs_connection_info", helpers::h_connection_info),
    ("zs_req_header", helpers::h_req_header),
    ("zs_req_set_header", helpers::h_req_set_header),
    ("zs_req_query_param", helpers::h_req_query_param),
    ("zs_req_body_json", helpers::h_req_body_json),
    ("zs_meta_get", helpers::h_meta_get),
    ("zs_meta_set", helpers::h_meta_set),
    ("zs_respond", helpers::h_respond),
    ("zs_reverse_proxy", helpers::h_reverse_proxy),
    (
        "zs_aws_v4_authorization_header",
        helpers::h_aws_v4_authorization_header,
    ),
    ("zs_aws_v4_presigned_url", helpers::h_aws_v4_presigned_url),
    ("zs_rate_limit", helpers::h_rate_limit),
    ("zs_oidc_begin_login", helpers::h_oidc_begin_login),
    ("zs_oidc_handle_callback", helpers::h_oidc_handle_callback),
    ("zs_oidc_session_verify", helpers::h_oidc_session_verify),
    ("zs_oidc_logout", helpers::h_oidc_logout),
];

static HELPER_TABLES: &[&[(&str, Helper)]] = &[SCRIPT_HELPERS];

/// Observed state of the underlying connection at the moment the request
/// arrived. Exposed to scripts via `zs_connection_info` so they can react to
/// TLS / ECH posture without re-parsing transport-layer details.
#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
    /// True when the request was received over TLS.
    pub tls: bool,
    /// Negotiated ALPN protocol (e.g. "h2", "http/1.1"). `None` when ALPN
    /// was not used or the connection is plaintext.
    pub alpn: Option<String>,
    /// The server name BoringSSL is serving: the inner (real, protected) SNI
    /// when ECH was accepted, otherwise the cleartext SNI. `None` if the
    /// client sent no SNI or the connection is plaintext.
    pub inner_sni: Option<String>,
    /// The cleartext outer SNI — the ECH public name — when ECH was accepted
    /// on this connection. `None` for plain TLS, rejected ECH, or when the
    /// configured public name is ambiguous.
    pub outer_sni: Option<String>,
    /// `None` when the server has no ECH keys loaded; otherwise whether
    /// BoringSSL accepted ECH on this connection (decrypted the inner
    /// ClientHello). `Some(false)` covers both "client offered a stale/no
    /// config" and "client did not offer ECH".
    pub ech_accepted: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ScriptRequest {
    pub request_id: Ulid,
    pub method: String,
    pub path: String,
    pub uri: String,
    pub query: String,
    pub scheme: String,
    pub peer: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub connection: ConnectionInfo,
    pub(crate) uri_changed: bool,
    pub(crate) header_changes: HashMap<String, Option<String>>,
}

impl ScriptRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.get(&name).map(String::as_str)
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query_params.get(name).map(String::as_str)
    }

    pub fn set_uri(&mut self, uri: &str) -> Result<(), ()> {
        let uri = uri.trim();
        if uri.is_empty() {
            return Err(());
        }
        let parsed: Uri = uri.parse().map_err(|_| ())?;
        let path = parsed.path().to_string();
        let query = parsed.query().unwrap_or("").to_string();
        self.uri = uri.to_string();
        self.path = path;
        self.query = query.clone();
        self.query_params = parse_query_params(&query);
        self.uri_changed = true;
        Ok(())
    }

    pub fn set_header(&mut self, name: &str, value: Option<&str>) -> Result<(), ()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(());
        }
        match value {
            Some(value) => {
                if HeaderValue::from_str(value).is_err() {
                    return Err(());
                }
                let value = value.to_string();
                self.headers.insert(name.clone(), value.clone());
                self.header_changes.insert(name, Some(value));
            }
            None => {
                self.headers.remove(&name);
                self.header_changes.insert(name, None);
            }
        }
        Ok(())
    }

    pub(crate) fn uri_changed(&self) -> bool {
        self.uri_changed
    }

    pub(crate) fn header_changes(&self) -> &HashMap<String, Option<String>> {
        &self.header_changes
    }
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    let mut query_params = HashMap::new();
    if !query.is_empty() {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            query_params
                .entry(key.into_owned())
                .or_insert(value.into_owned());
        }
    }
    query_params
}

#[derive(Clone, Debug)]
pub struct ScriptResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Extra response headers set by a helper (e.g. `Location`, `Set-Cookie`).
    /// Emitted in order with `HeaderMap::append`, so repeated names (multiple
    /// `Set-Cookie`) are preserved.
    pub headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct ScriptOutcome {
    pub request: ScriptRequest,
    pub metadata: HashMap<String, String>,
    pub response: Option<ScriptResponse>,
    pub reverse_proxy: Option<String>,
}

impl ScriptOutcome {
    pub(crate) fn from_request(request: ScriptRequest) -> Self {
        ScriptOutcome {
            request,
            metadata: HashMap::new(),
            response: None,
            reverse_proxy: None,
        }
    }
}

pub struct ScriptExecutionContext {
    pub request: ScriptRequest,
    pub body_source: BodySource,
    pub metadata: HashMap<String, String>,
    pub response: Option<ScriptResponse>,
    pub reverse_proxy: Option<String>,
    pub script_name: String,
    pub log_buffer: Vec<u8>,
    pub external_objects: ObjectRegistry,
    pub error: String,
    pub memory_footprint_bytes: u64,
    pub max_memory_footprint: u64,
    pub site: Arc<Site>,
}

impl ScriptExecutionContext {
    pub fn extobj<T: Any>(&mut self, idx: u64) -> Result<&mut T, ()> {
        self.external_objects
            .objects
            .get_mut(&idx)
            .ok_or(())
            .and_then(|x| x.downcast_mut().ok_or(()))
            .inspect_err(|()| self.error = format!("invalid external object index {}", idx))
    }

    pub fn alloc_extobj(&mut self, x: impl Any) -> Result<u64, ()> {
        if self.external_objects.objects.len() >= MAX_EXTERNAL_OBJECTS {
            self.error = format!("external object limit exceeded ({})", MAX_EXTERNAL_OBJECTS);
            return Err(());
        }

        let idx = self.external_objects.next_idx;
        self.external_objects.next_idx += 1;
        self.external_objects.objects.insert(idx, Box::new(x));
        Ok(idx as u64)
    }

    pub fn alloc_memory_footprint(&mut self, n: u64) -> Result<(), ()> {
        if self.memory_footprint_bytes.saturating_add(n) > self.max_memory_footprint {
            self.error = format!(
                "memory footprint limit exceeded ({} bytes) while allocating {} bytes",
                self.max_memory_footprint, n,
            );
            return Err(());
        }
        self.memory_footprint_bytes += n;
        Ok(())
    }
}

pub struct ObjectRegistry {
    next_idx: u64,
    objects: HashMap<u64, Box<dyn Any>>,
}

impl ObjectRegistry {
    pub fn insert(&mut self, idx: u64, obj: Box<dyn Any>) {
        self.objects.insert(idx, obj);
    }

    pub fn remove(&mut self, idx: u64) -> bool {
        self.objects.remove(&idx).is_some()
    }
}

pub struct ScriptRuntime {
    t: ThreadEnv,
    scripts: RefCell<Rc<Vec<(String, Program)>>>,
    max_memory_footprint: u64,
}

#[derive(Clone, Debug)]
pub struct ScriptRuntimeConfig {
    pub preempt_timer_interval: Duration,
    pub max_memory_footprint: u64,
}

impl ScriptRuntime {
    pub unsafe fn new(config: ScriptRuntimeConfig) -> Self {
        let g = unsafe { GlobalEnv::new() };
        let t = g.init_thread(config.preempt_timer_interval);
        let scripts = RefCell::new(Rc::new(Vec::new()));
        ScriptRuntime {
            t,
            scripts,
            max_memory_footprint: config.max_memory_footprint,
        }
    }

    pub async fn reload(&self, site: Arc<Site>) -> anyhow::Result<()> {
        let pl = Arc::new(ProgramLoader::new(
            &mut rand::thread_rng(),
            Arc::new(EventListener),
            HELPER_TABLES,
        ));
        let file = site
            .tar_file
            .try_clone()
            .and_then(File::from_std)
            .with_context(|| "failed to prepare tar file")?;
        let scripts: RefCell<HashMap<String, UnboundProgram>> = RefCell::new(HashMap::new());
        futures::future::join_all(site.entries.iter().map(|(path, entry)| {
            let scripts = &scripts;
            let file = &file;
            let pl = pl.clone();
            async move {
                let Some(name) = path.strip_prefix(".zeroserve/scripts/") else {
                    return;
                };
                if !name.ends_with(".o") {
                    return;
                }
                let (Ok(()), buf) = file
                    .read_exact_at(vec![0u8; entry.size as usize], entry.offset)
                    .await
                else {
                    return;
                };
                let prog_len = buf.len();
                let (tx, rx) = oneshot::channel();
                CPU_TP.with(|tp| {
                    tp.spawn(move || {
                        let _ = tx.send(pl.load(&mut rand::thread_rng(), &buf));
                    });
                });
                let prog = rx.await.unwrap();
                let prog = match prog {
                    Ok(x) => x,
                    Err(err) => {
                        async_log(
                            format!(
                                "failed to load script '{}' ({} bytes): {:?}\n",
                                name, prog_len, err
                            )
                            .into_bytes(),
                        )
                        .await;
                        return;
                    }
                };
                async_log(
                    format!("compiled script '{}' ({} bytes)\n", name, prog_len).into_bytes(),
                )
                .await;
                scripts.borrow_mut().insert(name.to_string(), prog);
            }
        }))
        .await;
        let scripts = scripts.into_inner();
        let mut scripts: Vec<(String, Program)> = scripts
            .into_iter()
            .map(|(k, v)| (k, v.pin_to_current_thread(self.t)))
            .collect();
        scripts.sort_by(|a, b| a.0.cmp(&b.0));
        *self.scripts.borrow_mut() = Rc::new(scripts);
        Ok(())
    }

    pub async fn run_request(
        &self,
        site: Arc<Site>,
        request: ScriptRequest,
        body_source: BodySource,
    ) -> anyhow::Result<ScriptOutcome> {
        let timeslice = TimesliceConfig {
            max_run_time_before_throttle: Duration::from_millis(20),
            max_run_time_before_yield: Duration::from_millis(1),
            throttle_duration: Duration::from_millis(100),
        };
        let scripts = (*self.scripts.borrow()).clone();
        let outcome = run_request_scripts(
            self.t,
            &scripts,
            site,
            request,
            body_source,
            &timeslice,
            &MonoioTimeslicer,
            self.max_memory_footprint,
        )
        .await;
        Ok(outcome)
    }
}

async fn run_request_scripts(
    t: ThreadEnv,
    scripts: &[(String, Program)],
    site: Arc<Site>,
    request: ScriptRequest,
    body_source: BodySource,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    max_memory_footprint: u64,
) -> ScriptOutcome {
    if scripts.is_empty() {
        return ScriptOutcome::from_request(request);
    }

    let mut request = request;
    let mut metadata: HashMap<String, String> = HashMap::new();
    let mut response: Option<ScriptResponse> = None;
    let mut reverse_proxy: Option<String> = None;
    let preemption = PreemptionEnabled::new(t);

    for (name, program) in scripts {
        if !program.has_section(SCRIPT_ENTRYPOINT) {
            continue;
        }

        let mut ctx = ScriptExecutionContext {
            request,
            body_source: body_source.clone(),
            metadata,
            response: None,
            reverse_proxy: None,
            script_name: name.clone(),
            log_buffer: vec![],
            external_objects: ObjectRegistry {
                next_idx: 1,
                objects: HashMap::new(),
            },
            error: String::new(),
            memory_footprint_bytes: 0,
            max_memory_footprint,
            site: site.clone(),
        };
        let mut resources: [&mut dyn Any; 1] = [&mut ctx];
        let run = program
            .run(
                timeslice,
                timeslicer,
                SCRIPT_ENTRYPOINT,
                &mut resources,
                &[],
                &preemption,
            )
            .await;

        metadata = ctx.metadata;
        request = ctx.request;
        if let Err(err) = run {
            async_log(
                format!(
                    "[script_runtime] script '{}' failed: {:?} ({})\n",
                    name,
                    err,
                    if ctx.error.is_empty() {
                        "no details"
                    } else {
                        ctx.error.as_str()
                    }
                )
                .into_bytes(),
            )
            .await;
            return ScriptOutcome {
                request,
                metadata,
                response: Some(ScriptResponse {
                    status: 500,
                    body: vec![],
                    headers: Vec::new(),
                }),
                reverse_proxy: None,
            };
        }
        if let Some(script_response) = ctx.response {
            response = Some(script_response);
            break;
        }
        if let Some(proxy_url) = ctx.reverse_proxy {
            reverse_proxy = Some(proxy_url);
            break;
        }
    }

    ScriptOutcome {
        request,
        metadata,
        response,
        reverse_proxy,
    }
}

pub fn with_ectx<R>(
    scope: &async_ebpf::program::HelperScope,
    f: impl FnOnce(&mut ScriptExecutionContext) -> Result<R, ()>,
) -> Result<R, ()> {
    scope.with_resource_mut(|res: Result<&mut ScriptExecutionContext, ()>| match res {
        Ok(ctx) => f(ctx),
        Err(_) => Err(()),
    })
}

pub fn read_utf8<'a>(
    scope: &'a async_ebpf::program::HelperScope,
    ptr: u64,
    len: u64,
) -> Result<&'a str, ()> {
    let data = scope.user_memory(ptr, len)?;
    std::str::from_utf8(&data).map_err(|_| ())
}

pub fn deref_and_write_cstr(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    value: &str,
) -> Result<u64, ()> {
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    Ok(write_cstr(&[value.as_bytes()], &mut out))
}

struct MonoioTimeslicer;

impl Timeslicer for MonoioTimeslicer {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        monoio::time::sleep(duration)
    }

    fn yield_now(&self) -> impl Future<Output = ()> {
        monoio::time::sleep(Duration::from_millis(0))
    }
}

struct EventListener;

impl ProgramEventListener for EventListener {
    fn did_throttle(&self, scope: &HelperScope) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
        with_ectx(scope, |ctx| {
            let msg = format!(
                "[script_runtime] {}: {}: throttling\n",
                ctx.request.request_id, ctx.script_name
            );
            Ok(Some(async_log(msg.into_bytes()).boxed_local()))
        })
        .unwrap()
    }
}
