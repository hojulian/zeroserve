use std::{
    any::Any,
    cell::RefCell,
    collections::HashMap,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_ebpf::{
    helpers::{Helper, write_cstr},
    program::{
        GlobalEnv, HelperScope, PreemptionEnabled, Program, ProgramEventListener, ProgramLoader,
        ThreadEnv, TimesliceConfig, Timeslicer, UnboundProgram,
    },
};
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use futures::{FutureExt, channel::oneshot};
use hmac::{Hmac, Mac};
use http::{
    Uri,
    header::{HeaderName, HeaderValue},
};
use monoio::fs::File;
use rand::RngCore;
use sha2::Sha256;
use ulid::Ulid;
use url::form_urlencoded;

use crate::{
    json::JsonRef, logging::async_log, shared::read_tar_entry, site::Site, thread_pool::CPU_TP,
};

const SCRIPT_ENTRYPOINT: &str = "zeroserve.request";
const HMAC_SHA256_LEN: usize = 32;
const BASE64_ENCODING_STANDARD: u64 = 0;
const BASE64_ENCODING_STANDARD_NO_PAD: u64 = 1;
const BASE64_ENCODING_URL: u64 = 2;
const BASE64_ENCODING_URL_NO_PAD: u64 = 3;
const MAX_EXTERNAL_OBJECTS: usize = 32;
const MAX_MEMORY_FOOTPRINT: u64 = 256 * 1024;

type HmacSha256 = Hmac<Sha256>;

static SCRIPT_HELPERS: &[(&str, Helper)] = &[
    ("zs_log", h_log),
    ("zs_now_ms", h_now_ms),
    ("zs_getrandom", h_getrandom),
    ("zs_hmac_sha256", h_hmac_sha256),
    ("zs_base64_encode", h_base64_encode),
    ("zs_base64_decode_in_place", h_base64_decode_in_place),
    ("zs_memcpy", h_memcpy),
    ("zs_memcmp", h_memcmp),
    ("zs_memset", h_memset),
    ("zs_json_parse", h_json_parse),
    ("zs_load_static_json", h_load_static_json),
    ("zs_json_reset", h_json_reset),
    ("zs_json_get", h_json_get),
    ("zs_json_array_get", h_json_array_get),
    ("zs_json_read_string", h_json_read_string),
    ("zs_json_read_i64", h_json_read_i64),
    ("zs_json_read_bool", h_json_read_bool),
    ("zs_object_free", h_object_free),
    ("zs_req_method", h_req_method),
    ("zs_req_path", h_req_path),
    ("zs_req_uri", h_req_uri),
    ("zs_req_set_uri", h_req_set_uri),
    ("zs_req_query", h_req_query),
    ("zs_req_scheme", h_req_scheme),
    ("zs_req_peer", h_req_peer),
    ("zs_req_header", h_req_header),
    ("zs_req_set_header", h_req_set_header),
    ("zs_req_query_param", h_req_query_param),
    ("zs_meta_get", h_meta_get),
    ("zs_meta_set", h_meta_set),
    ("zs_respond", h_respond),
    ("zs_reverse_proxy", h_reverse_proxy),
];

static HELPER_TABLES: &[&[(&str, Helper)]] = &[SCRIPT_HELPERS];

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
    pub(crate) uri_changed: bool,
    pub(crate) header_changes: HashMap<String, Option<String>>,
}

impl ScriptRequest {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.get(&name).map(String::as_str)
    }

    fn query_param(&self, name: &str) -> Option<&str> {
        self.query_params.get(name).map(String::as_str)
    }

    fn set_uri(&mut self, uri: &str) -> Result<(), ()> {
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

    fn set_header(&mut self, name: &str, value: Option<&str>) -> Result<(), ()> {
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

struct ScriptExecutionContext {
    request: ScriptRequest,
    metadata: HashMap<String, String>,
    response: Option<ScriptResponse>,
    reverse_proxy: Option<String>,
    script_name: String,
    log_buffer: Vec<u8>,
    external_objects: ObjectRegistry,
    error: String,
    memory_footprint_bytes: u64,
    site: Arc<Site>,
}

impl ScriptExecutionContext {
    fn extobj<T: Any>(&mut self, idx: u64) -> Result<&T, ()> {
        self.external_objects
            .objects
            .get(&idx)
            .ok_or(())
            .and_then(|x| x.downcast_ref().ok_or(()))
            .inspect_err(|()| self.error = format!("invalid external object index {}", idx))
    }

    fn alloc_extobj(&mut self, x: impl Any) -> Result<u64, ()> {
        if self.external_objects.objects.len() >= MAX_EXTERNAL_OBJECTS {
            self.error = format!("external object limit exceeded ({})", MAX_EXTERNAL_OBJECTS);
            return Err(());
        }

        let idx = self.external_objects.next_idx;
        self.external_objects.next_idx += 1;
        self.external_objects.objects.insert(idx, Box::new(x));
        Ok(idx as u64)
    }

    fn alloc_memory_footprint(&mut self, n: u64) -> Result<(), ()> {
        if self.memory_footprint_bytes.saturating_add(n) > MAX_MEMORY_FOOTPRINT {
            self.error = format!(
                "memory footprint limit exceeded ({} bytes) while allocating {} bytes",
                MAX_MEMORY_FOOTPRINT, n,
            );
            return Err(());
        }
        self.memory_footprint_bytes += n;
        Ok(())
    }
}

struct ObjectRegistry {
    next_idx: u64,
    objects: HashMap<u64, Box<dyn Any>>,
}

pub struct ScriptRuntime {
    t: ThreadEnv,
    scripts: RefCell<Rc<Vec<(String, Program)>>>,
}

#[derive(Clone, Debug)]
pub struct ScriptRuntimeConfig {
    pub preempt_timer_interval: Duration,
}

impl ScriptRuntime {
    pub unsafe fn new(config: ScriptRuntimeConfig) -> Self {
        let g = unsafe { GlobalEnv::new() };
        let t = g.init_thread(config.preempt_timer_interval);
        let scripts = RefCell::new(Rc::new(Vec::new()));
        ScriptRuntime { t, scripts }
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
            &timeslice,
            &MonoioTimeslicer,
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
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
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

fn with_ectx<R>(
    scope: &async_ebpf::program::HelperScope,
    f: impl FnOnce(&mut ScriptExecutionContext) -> Result<R, ()>,
) -> Result<R, ()> {
    scope.with_resource_mut(|res: Result<&mut ScriptExecutionContext, ()>| match res {
        Ok(ctx) => f(ctx),
        Err(_) => Err(()),
    })
}

fn read_utf8<'a>(
    scope: &'a async_ebpf::program::HelperScope,
    ptr: u64,
    len: u64,
) -> Result<&'a str, ()> {
    let data = scope.user_memory(ptr, len)?;
    std::str::from_utf8(&data).map_err(|_| ())
}

fn deref_and_write_cstr(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    value: &str,
) -> Result<u64, ()> {
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    Ok(write_cstr(&[value.as_bytes()], &mut out))
}

fn h_log(
    scope: &async_ebpf::program::HelperScope,
    msg_ptr: u64,
    msg_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let mut msg = scope.user_memory(msg_ptr, msg_len)?;
    let newline_index = msg.iter().enumerate().find(|x| *x.1 == b'\n').map(|x| x.0);
    with_ectx(scope, |ctx| {
        let buf = &mut ctx.log_buffer;
        if newline_index.is_none() && buf.len() < 512 {
            buf.extend_from_slice(msg);
            return Ok(());
        }
        if let Some(i) = newline_index {
            buf.extend_from_slice(&msg[..i]);
            msg = &msg[i + 1..];
        }
        for b in &mut *buf {
            if !b.is_ascii() || (b.is_ascii_control() && *b != b'\t') {
                *b = b'?';
            }
        }
        let output = format!(
            "[user_log] {}: {}: {}\n",
            ctx.request.request_id,
            ctx.script_name,
            std::str::from_utf8(&buf).unwrap_or("(invalid)")
        );
        buf.clear();
        buf.extend_from_slice(msg);
        scope.post_task(async move {
            async_log(output.into_bytes()).await;
            |_: &HelperScope| Ok(0)
        });
        Ok(())
    })?;
    Ok(0)
}

fn h_now_ms(
    _: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(now.as_millis() as u64)
}

fn h_getrandom(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if out_len == 0 {
        return Ok(0);
    }
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    rand::thread_rng().fill_bytes(&mut out[..]);
    Ok(out_len)
}

fn h_hmac_sha256(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    msg_ptr: u64,
    msg_len: u64,
    out_ptr: u64,
) -> Result<u64, ()> {
    let key = scope.user_memory(key_ptr, key_len)?;
    let msg = scope.user_memory(msg_ptr, msg_len)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| ())?;
    mac.update(&msg);
    let digest = mac.finalize().into_bytes();
    let mut out = scope.user_memory_mut(out_ptr, HMAC_SHA256_LEN as u64)?;
    out[..digest.len()].copy_from_slice(&digest);
    Ok(digest.len() as u64)
}

fn h_base64_encode(
    scope: &async_ebpf::program::HelperScope,
    data_ptr: u64,
    data_len: u64,
    out_ptr: u64,
    out_len: u64,
    encoding: u64,
) -> Result<u64, ()> {
    let data = scope.user_memory(data_ptr, data_len)?;
    let required_len = base64_encoded_len(encoding, &data)?;
    if data_len != 0 && required_len == 0 {
        return Err(());
    }
    if out_len == 0 {
        return Ok(required_len as u64);
    }
    if required_len as u64 > out_len {
        return Err(());
    }
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    base64_encode_into(encoding, &data, &mut out[..required_len])?;
    Ok(required_len as u64)
}

fn h_base64_decode_in_place(
    scope: &async_ebpf::program::HelperScope,
    buf_ptr: u64,
    buf_len: u64,
    encoding: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if buf_len == 0 {
        return Ok(0);
    }
    let mut buf = scope.user_memory_mut(buf_ptr, buf_len)?;
    match base64_decode_in_place(encoding, &mut buf) {
        Ok(x) => Ok(x),
        Err(_) => Ok(-1i64 as u64),
    }
}

fn h_memcpy(
    scope: &async_ebpf::program::HelperScope,
    dst_ptr: u64,
    src_ptr: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst_ptr);
    }
    let src = scope.user_memory(src_ptr, n)?;
    let mut dst = scope.user_memory_mut(dst_ptr, n)?;
    dst.copy_from_slice(&src);
    Ok(dst_ptr)
}

fn h_memcmp(
    scope: &async_ebpf::program::HelperScope,
    a_ptr: u64,
    b_ptr: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(0);
    }
    let a = scope.user_memory(a_ptr, n)?;
    let b = scope.user_memory(b_ptr, n)?;
    for (left, right) in a.iter().zip(b.iter()) {
        if left != right {
            let diff = i64::from(*left) - i64::from(*right);
            return Ok(diff as u64);
        }
    }
    Ok(0)
}

fn h_memset(
    scope: &async_ebpf::program::HelperScope,
    dst_ptr: u64,
    c: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst_ptr);
    }
    let mut dst = scope.user_memory_mut(dst_ptr, n)?;
    dst.fill(c as u8);
    Ok(dst_ptr)
}

fn h_json_parse(
    scope: &async_ebpf::program::HelperScope,
    data_ptr: u64,
    data_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let data = scope.user_memory(data_ptr, data_len)?;
    with_ectx(scope, |ctx| {
        let data: serde_json::Value = match serde_json::from_slice(data) {
            Ok(x) => x,
            Err(_) => return Ok(-1i64 as u64),
        };
        ctx.alloc_memory_footprint(estimate_json_memory_usage(&data) as u64)?;
        let r = JsonRef::new(data);
        ctx.alloc_extobj(r)
    })
}

fn h_load_static_json(
    scope: &async_ebpf::program::HelperScope,
    path_ptr: u64,
    path_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let path = match read_utf8(scope, path_ptr, path_len) {
        Ok(path) if !path.is_empty() => path.to_string(),
        _ => return Ok(-1i64 as u64),
    };
    let site = with_ectx(scope, |ctx| Ok(ctx.site.clone()))?;
    scope.post_task(async move {
        let result = async {
            let entry = site.entries.get(&path).cloned().ok_or(())?;
            let buf = read_tar_entry(entry, &site).await.map_err(|_| ())?;
            serde_json::from_slice::<serde_json::Value>(&buf).map_err(|_| ())
        }
        .await;
        move |scope: &HelperScope| match result {
            Ok(json) => with_ectx(scope, |ctx| {
                ctx.alloc_memory_footprint(estimate_json_memory_usage(&json) as u64)?;
                let r = JsonRef::new(json);
                ctx.alloc_extobj(r)
            }),
            Err(()) => Ok(-1i64 as u64),
        }
    });
    Ok(0)
}

fn h_json_reset(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let root = ctx.extobj::<JsonRef>(idx)?.root();
        ctx.external_objects.objects.insert(idx, Box::new(root));
        Ok(0)
    })
}

const INVALID_JSON_REF_ERROR: &str = "json reference is no longer valid";

fn h_json_get(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    key_ptr: u64,
    key_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = scope.user_memory(key_ptr, key_len)?;
    let Ok(key) = std::str::from_utf8(key) else {
        return Ok(-1i64 as u64);
    };
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let r = r
            .get(|x| match x {
                serde_json::Value::Object(x) => x.get(key),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(r) = r else {
            return Ok(-1i64 as u64);
        };
        ctx.alloc_extobj(r)
    })
}

fn h_json_array_get(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    array_index: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let r = r
            .get(|x| match x {
                serde_json::Value::Array(x) => x.get(array_index as usize),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(r) = r else {
            return Ok(-1i64 as u64);
        };
        ctx.alloc_extobj(r)
    })
}

fn h_json_read_string(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        r.view(|x| match x {
            serde_json::Value::String(value) => {
                deref_and_write_cstr(scope, out_ptr, out_len, value)
            }
            _ => Ok(-1i64 as u64),
        })
        .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?
    })
}

fn h_json_read_i64(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let value = r
            .view(|x| match x {
                serde_json::Value::Number(value) => value.as_i64(),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(value) = value else {
            return Ok(-1i64 as u64);
        };
        const VALUE_LEN: u64 = std::mem::size_of::<i64>() as u64;
        if out_len != VALUE_LEN {
            return Err(());
        }
        scope
            .user_memory_mut(out_ptr, out_len)?
            .copy_from_slice(&value.to_ne_bytes());
        Ok(VALUE_LEN)
    })
}

fn h_json_read_bool(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let r = ctx.extobj::<JsonRef>(idx)?;
        let value = r
            .view(|x| match x {
                serde_json::Value::Bool(value) => Some(*value),
                _ => None,
            })
            .inspect_err(|()| ctx.error = INVALID_JSON_REF_ERROR.into())?;
        let Some(value) = value else {
            return Ok(-1i64 as u64);
        };
        const VALUE_LEN: u64 = 1;
        if out_len != VALUE_LEN {
            return Err(());
        }
        scope.user_memory_mut(out_ptr, out_len)?[0] = u8::from(value);
        Ok(VALUE_LEN)
    })
}

fn h_object_free(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        ctx.external_objects
            .objects
            .remove(&idx)
            .map(|_| 0)
            .ok_or(())
            .inspect_err(|()| ctx.error = format!("invalid object index {}", idx))
    })
}

fn base64_encoded_len(encoding: u64, data: &[u8]) -> Result<usize, ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Ok(Base64::encoded_len(data)),
        BASE64_ENCODING_STANDARD_NO_PAD => Ok(Base64Unpadded::encoded_len(data)),
        BASE64_ENCODING_URL => Ok(Base64Url::encoded_len(data)),
        BASE64_ENCODING_URL_NO_PAD => Ok(Base64UrlUnpadded::encoded_len(data)),
        _ => Err(()),
    }
}

fn base64_encode_into(encoding: u64, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Base64::encode(data, out).map(|_| ()).map_err(|_| ()),
        BASE64_ENCODING_STANDARD_NO_PAD => Base64Unpadded::encode(data, out)
            .map(|_| ())
            .map_err(|_| ()),
        BASE64_ENCODING_URL => Base64Url::encode(data, out).map(|_| ()).map_err(|_| ()),
        BASE64_ENCODING_URL_NO_PAD => Base64UrlUnpadded::encode(data, out)
            .map(|_| ())
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn base64_decode_in_place(encoding: u64, buf: &mut [u8]) -> Result<u64, ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Base64::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_STANDARD_NO_PAD => Base64Unpadded::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_URL => Base64Url::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_URL_NO_PAD => Base64UrlUnpadded::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn h_req_method(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.method)
    })
}

fn h_req_path(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.path)
    })
}

fn h_req_uri(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.uri)
    })
}

fn h_req_set_uri(
    scope: &async_ebpf::program::HelperScope,
    uri_ptr: u64,
    uri_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let uri = read_utf8(scope, uri_ptr, uri_len)?;
    with_ectx(scope, |ctx| {
        ctx.request.set_uri(uri)?;
        Ok(0)
    })
}

fn h_req_query(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.query)
    })
}

fn h_req_scheme(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.scheme)
    })
}

fn h_req_peer(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.peer)
    })
}

fn h_req_header(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.header(name.trim()).unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

fn h_req_set_header(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let value = if value_len == 0 {
        None
    } else {
        Some(read_utf8(scope, value_ptr, value_len)?)
    };
    with_ectx(scope, |ctx| {
        ctx.request.set_header(name, value)?;
        Ok(0)
    })
}

fn h_req_query_param(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.query_param(name.trim()).unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

fn h_meta_get(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx
            .metadata
            .get(key.trim())
            .map(String::as_str)
            .unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

fn h_meta_set(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err(());
    }
    let value = read_utf8(scope, val_ptr, val_len)?.to_string();
    with_ectx(scope, |ctx| {
        ctx.metadata.insert(key, value);
        Ok(0)
    })
}

fn h_respond(
    scope: &async_ebpf::program::HelperScope,
    status: u64,
    body_ptr: u64,
    body_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let status = u16::try_from(status).map_err(|_| ())?;
    let body = if body_len == 0 {
        Vec::new()
    } else {
        scope.user_memory(body_ptr, body_len)?.to_vec()
    };
    with_ectx(scope, |ctx| {
        ctx.response = Some(ScriptResponse { status, body });
        Ok(0)
    })
}

fn h_reverse_proxy(
    scope: &async_ebpf::program::HelperScope,
    url_ptr: u64,
    url_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let url = read_utf8(scope, url_ptr, url_len)?;
    let url = url.trim();
    if url.is_empty() {
        return Err(());
    }
    with_ectx(scope, |ctx| {
        if ctx.response.is_some() || ctx.reverse_proxy.is_some() {
            return Err(());
        }
        ctx.reverse_proxy = Some(url.to_string());
        Ok(0)
    })
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

fn estimate_json_memory_usage(root: &serde_json::Value) -> usize {
    use serde_json::Value;

    let mut total: usize = 0;
    let mut stack: Vec<&Value> = Vec::new();
    stack.push(root);

    while let Some(v) = stack.pop() {
        total += size_of::<Value>();

        match v {
            Value::Null | Value::Bool(_) | Value::Number(_) => {}

            Value::String(s) => {
                total += s.len();
            }

            Value::Array(a) => {
                for child in a.iter() {
                    stack.push(child);
                }
            }

            Value::Object(map) => {
                for (k, child) in map {
                    total += size_of::<String>() + k.len();
                    stack.push(child);
                }
            }
        }
    }

    total
}
