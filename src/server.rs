use std::{
    cell::RefCell,
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    rc::Rc,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::channel::oneshot;
use http::{
    Method, StatusCode, Uri,
    header::{HeaderName, HeaderValue},
};
use monoio::{
    buf::SliceMut,
    fs::File,
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Split, Splitable,
        sink::SinkExt, stream::Stream,
    },
    net::{TcpListener, TcpStream},
};
use monoio_http::{
    common::{
        body::{Body, StreamHint},
        error::HttpError,
        request::{Request, RequestHead},
        response::Response,
    },
    h1::{
        BorrowFramedRead,
        codec::{
            ClientCodec,
            decoder::{ChunkedBodyDecoder, FixedBodyDecoder, PayloadDecoder, RequestDecoder},
            encoder::GenericEncoder,
        },
        payload::{FixedPayload, Payload},
    },
};
use monoio_rustls::{ClientTlsStream, TlsConnector, TlsError};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use ulid::Ulid;
use url::Url;

use crate::{
    config::StaticConfig,
    logging::async_log,
    pool::{self, PoolKey, PooledConnection},
    script::{ScriptOutcome, ScriptRequest, ScriptResponse, ScriptRuntime},
    shared::{SharedState, read_tar_entry},
    site::{Site, TarEntry, guess_mime, normalize_request_path},
    thread_pool::DNS_TP,
};

type HttpBody = Payload<Bytes, HttpError>;

pub async fn amain(shared: Arc<SharedState>, script_runtime: Rc<ScriptRuntime>) -> Result<()> {
    if shared.config.tls_addr.is_some() {
        let tls_state = shared.clone();
        let script_runtime = script_runtime.clone();
        monoio::spawn(async move {
            if let Err(err) = run_tls_listener(tls_state, script_runtime).await {
                eprintln!("TLS listener stopped: {err:?}");
            }
        });
    }

    run_http_listener(shared, script_runtime).await
}

async fn run_http_listener(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
) -> Result<()> {
    let listener = shared
        .http_listener
        .lock()
        .unwrap()
        .take()
        .expect("http_listener");
    let listener = TcpListener::from_std(listener)?;
    eprintln!("listening on http://{}", shared.config.http_addr);
    loop {
        let (stream, addr) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let hup = shared.hup.wait(stream.as_raw_fd())?;
        let state = shared.clone();
        let script_runtime = script_runtime.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, addr, &state.config).await {
                    Ok(peer) => peer,
                    Err(err) => {
                        eprintln!(
                            "dropping http connection {addr} due to invalid PROXY header: {err}"
                        );
                        return;
                    }
                }
            } else {
                addr
            };
            if let Err(err) =
                handle_connection(hup, stream, peer, state, Scheme::Http, script_runtime).await
            {
                eprintln!("connection {} over http closed with error: {err:?}", peer);
            }
        });
    }
}

async fn run_tls_listener(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
) -> Result<()> {
    let addr = shared
        .config
        .tls_addr
        .ok_or_else(|| anyhow!("TLS listener requested without address"))?;
    let listener = shared
        .tls_listener
        .lock()
        .unwrap()
        .take()
        .expect("tls_listener");
    let listener = TcpListener::from_std(listener)?;
    eprintln!("listening on https://{}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let hup = shared.hup.wait(stream.as_raw_fd())?;
        let state = shared.clone();
        let script_runtime = script_runtime.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let reported_peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, peer, &state.config).await {
                    Ok(addr) => addr,
                    Err(err) => {
                        eprintln!(
                            "dropping TLS connection {peer} due to invalid PROXY header: {err}"
                        );
                        return;
                    }
                }
            } else {
                peer
            };
            let tls_state = match state.tls.load_full() {
                Some(runtime) => runtime,
                None => {
                    eprintln!("dropping TLS connection {reported_peer} due to missing TLS config");
                    return;
                }
            };
            match tls_state.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) = handle_connection(
                        hup,
                        tls_stream,
                        reported_peer,
                        state,
                        Scheme::Https,
                        script_runtime,
                    )
                    .await
                    {
                        eprintln!("TLS conn {reported_peer} closed with error: {err:?}");
                    }
                }
                Err(err) => log_tls_error(reported_peer, err),
            }
        });
    }
}

fn log_tls_error(peer: std::net::SocketAddr, error: TlsError) {
    if let TlsError::Io(x) = &error {
        if x.kind() == ErrorKind::ConnectionReset || x.kind() == ErrorKind::UnexpectedEof {
            return;
        }
    }
    eprintln!("TLS handshake with {peer} failed: {error:?}");
}

async fn handle_connection<IO>(
    mut hup: impl Future<Output = ()> + Unpin + 'static,
    io: IO,
    peer: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
    script_runtime: Rc<ScriptRuntime>,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent + Split + 'static,
{
    let (r, mut w) = io.into_split();
    let mut decoder = RequestDecoder::new(r);
    while let Some(result) = decoder.next().await {
        match result {
            Ok(request) => {
                let can_continue = handle_request(
                    request,
                    &shared,
                    &script_runtime,
                    peer,
                    scheme,
                    &mut w,
                    &mut hup,
                )
                .await;
                if !can_continue {
                    break;
                }
            }
            Err(err) => {
                if let HttpError::IOError(x) = &err {
                    if x.kind() == ErrorKind::ConnectionReset
                        || x.kind() == ErrorKind::UnexpectedEof
                    {
                        break;
                    }
                }

                eprintln!(
                    "{} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn handle_request(
    req: Request,
    shared: &Arc<SharedState>,
    script_runtime: &Rc<ScriptRuntime>,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    w: &mut impl AsyncWriteRent,
    interrupt: &mut (impl Future<Output = ()> + Unpin),
) -> bool {
    let request_id = Ulid::new();
    if !shared.config.disable_request_logging {
        log_request(request_id, peer, scheme, req.method(), req.uri()).await;
    }

    let (mut head, body) = req.into_parts();
    let head_only = head.method == Method::HEAD;

    let script_request = build_script_request(request_id, &head, peer, scheme);
    let script_request_fallback = script_request.clone();
    let script_outcome = monoio::select! {
        x = script_runtime.run_request(shared.site.load_full(), script_request) => x,
        _ = interrupt => {
          async_log(format!("[handle] {}: interrupted\n", request_id).into_bytes()).await;
          return false;
        }
    };
    let script_outcome = match script_outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            async_log(format!("[handle] {}: script runtime: {:?}\n", request_id, err).into_bytes())
                .await;
            ScriptOutcome::from_request(script_request_fallback)
        }
    };

    if let Err(err) = apply_script_request(&mut head, &script_outcome.request) {
        async_log(
            format!(
                "[handle] {}: script request update: {:?}\n",
                request_id, err
            )
            .into_bytes(),
        )
        .await;
    }

    if let Some(proxy_url) = script_outcome.reverse_proxy {
        if let Err(err) = reverse_proxy_request(
            &proxy_url,
            head,
            body,
            w,
            head_only,
            &script_outcome.metadata,
        )
        .await
        {
            async_log(format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes())
                .await;
            send_fixed(w, bad_gateway(), &script_outcome.metadata).await;
        }
        return true;
    }

    if let Some(response) = script_outcome.response {
        drain_payload(body).await;
        send_script_response(w, response, head_only, &script_outcome.metadata).await;
        return true;
    }

    drain_payload(body).await;

    match head.method {
        Method::GET | Method::HEAD => {
            if serve_static(&head, shared, head_only, peer, w, &script_outcome.metadata)
                .await
                .is_none()
            {
                send_fixed(w, not_found(), &script_outcome.metadata).await
            }
        }
        _ => send_fixed(w, method_not_allowed(), &script_outcome.metadata).await,
    }

    true
}

async fn send_fixed(
    w: &mut impl AsyncWriteRent,
    mut res: Response<Bytes>,
    metadata: &HashMap<String, String>,
) {
    apply_metadata_response_headers(res.headers_mut(), metadata);
    let _ = GenericEncoder::new(w)
        .send_and_flush(res.map(|x| Payload::Fixed(FixedPayload::<_, HttpError>::new(x))))
        .await;
}

async fn drain_payload<B>(mut payload: B)
where
    B: Body<Data = Bytes, Error = HttpError>,
{
    loop {
        match payload.next_data().await {
            Some(Ok(_)) => continue,
            Some(Err(_)) => continue,
            None => break,
        }
    }
}

async fn serve_static(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
    metadata: &HashMap<String, String>,
) -> Option<()> {
    let path = normalize_request_path(head.uri.path())?;
    let site = shared.site.load_full();
    let entry = site.lookup(&path, &shared.config.index_file, shared.config.try_html)?;
    let mime = guess_mime(&entry.path);

    if should_template_replace(mime, metadata) {
        match read_tar_entry(entry.clone(), &site).await {
            Ok(body) => {
                let rendered = match std::str::from_utf8(&body) {
                    Ok(text) => apply_template(text, metadata).into_bytes(),
                    Err(_) => body,
                };
                send_bytes_response(w, StatusCode::OK, mime, rendered, head_only, metadata).await;
            }
            Err(err) => {
                eprintln!("failed to render {}: {:?}", entry.path, err);
                send_bytes_response(
                    w,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    b"Internal Server Error".to_vec(),
                    head_only,
                    metadata,
                )
                .await;
            }
        }
        return Some(());
    }

    let mut headers = build_base_headers(entry.size, mime);
    headers.insert(
        http::header::ACCEPT_RANGES,
        http::HeaderValue::from_static("bytes"),
    );
    apply_metadata_response_headers(&mut headers, metadata);
    let _ = write_response_head(w, StatusCode::OK, &headers).await;

    if head_only {
        let _ = w.flush().await;
        return Some(());
    }

    match stream_tar_entry(entry.clone(), &site, shared.config.chunk_size, w).await {
        Ok(()) => {
            let _ = w.flush().await;
        }
        Err(e) => {
            if e.kind() != ErrorKind::ConnectionReset && e.kind() != ErrorKind::BrokenPipe {
                eprintln!("aborting stream with {} due to io error: {:?}", peer, e);
                let _ = w.shutdown().await;
            }
        }
    };
    Some(())
}

async fn stream_tar_entry(
    entry: Arc<TarEntry>,
    site: &Arc<Site>,
    chunk_size: usize,
    w: &mut impl AsyncWriteRent,
) -> std::io::Result<()> {
    thread_local! {
        static TAR_FILE_CACHE: RefCell<Vec<(Weak<Site>, Rc<File>)>> = RefCell::new(Vec::new());
    }

    let file = TAR_FILE_CACHE.with(|x| {
        let mut x = x.borrow_mut();
        x.retain(|x| x.0.strong_count() != 0);
        let site_weak = Arc::downgrade(site);
        if let Some(x) = x.iter().find(|x| x.0.ptr_eq(&site_weak)) {
            return Ok(x.1.clone());
        }
        let file = match site.tar_file.try_clone() {
            Ok(x) => Rc::new(File::from_std(x).unwrap()),
            Err(e) => {
                eprintln!("failed to create tar handle: {}", e);
                return Err(e);
            }
        };
        x.push((Arc::downgrade(&site), file.clone()));
        Ok(file)
    })?;

    let mut remaining = entry.size;
    let mut offset = entry.offset;
    let mut buffer = vec![0u8; chunk_size];
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
        let (res, view) = file.read_at(view, offset).await;
        buffer = view.into_inner();
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let view = monoio::buf::Slice::new(buffer, 0, n);
        let (res, view) = w.write_all(view).await;
        buffer = view.into_inner();
        res?;
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

fn should_template_replace(content_type: &str, metadata: &HashMap<String, String>) -> bool {
    !metadata.is_empty()
        && (content_type == "text/html"
            || content_type.starts_with("text/html;")
            || content_type == "application/xml")
}

fn apply_template(body: &str, metadata: &HashMap<String, String>) -> String {
    const START_TAG: &str = "<zs-meta>";
    const END_TAG: &str = "</zs-meta>";
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(START_TAG) {
        let (before, after_start) = rest.split_at(start);
        out.push_str(before);
        let after_start = &after_start[START_TAG.len()..];
        if let Some(end) = after_start.find(END_TAG) {
            let raw_key = &after_start[..end];
            let key = raw_key.trim();
            if let Some(value) = metadata.get(key) {
                out.push_str(value);
            }
            rest = &after_start[end + END_TAG.len()..];
        } else {
            out.push_str(START_TAG);
            out.push_str(after_start);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

const RESPONSE_HEADER_PREFIX: &str = "zs.response.header.";

fn build_base_headers(content_length: u64, content_type: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    let length = HeaderValue::from_str(&content_length.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(http::header::CONTENT_LENGTH, length);
    headers.insert(
        http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(http::header::CONTENT_TYPE, content_type);
    headers
}

fn apply_metadata_response_headers(
    headers: &mut http::HeaderMap,
    metadata: &HashMap<String, String>,
) {
    for (key, value) in metadata {
        let Some(header_name) = key.strip_prefix(RESPONSE_HEADER_PREFIX) else {
            continue;
        };
        let header_name = header_name.trim();
        if header_name.is_empty() {
            continue;
        }
        let Ok(header_name) = HeaderName::from_bytes(header_name.as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_str(value) else {
            continue;
        };
        headers.insert(header_name, header_value);
    }
}

async fn send_bytes_response(
    w: &mut impl AsyncWriteRent,
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    head_only: bool,
    metadata: &HashMap<String, String>,
) {
    let mut headers = build_base_headers(body.len() as u64, content_type);
    apply_metadata_response_headers(&mut headers, metadata);
    let _ = write_response_head(w, status, &headers).await;
    if !head_only {
        let _ = w.write_all(body).await;
    }
    let _ = w.flush().await;
}

fn build_script_request(
    request_id: Ulid,
    head: &RequestHead,
    peer: std::net::SocketAddr,
    scheme: Scheme,
) -> ScriptRequest {
    let mut headers = HashMap::new();
    for (name, value) in head.headers.iter() {
        if let Ok(value) = value.to_str() {
            headers.insert(name.as_str().to_ascii_lowercase(), value.to_string());
        }
    }

    let query = head.uri.query().unwrap_or("").to_string();
    let mut query_params = HashMap::new();
    if !query.is_empty() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            query_params
                .entry(key.into_owned())
                .or_insert(value.into_owned());
        }
    }

    ScriptRequest {
        request_id,
        method: head.method.as_str().to_string(),
        path: head.uri.path().to_string(),
        uri: head.uri.to_string(),
        query,
        scheme: scheme.as_str().to_string(),
        peer: peer.to_string(),
        headers,
        query_params,
        uri_changed: false,
        header_changes: HashMap::new(),
    }
}

fn apply_script_request(head: &mut RequestHead, request: &ScriptRequest) -> Result<()> {
    if request.uri_changed() {
        let uri: Uri = request
            .uri
            .parse()
            .map_err(|err| anyhow!("invalid script uri: {err}"))?;
        head.uri = uri;
    }

    if request.header_changes().is_empty() {
        return Ok(());
    }

    for (name, value) in request.header_changes() {
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        match value {
            Some(value) => {
                let Ok(header_value) = HeaderValue::from_str(value) else {
                    continue;
                };
                head.headers.insert(header_name, header_value);
            }
            None => {
                head.headers.remove(&header_name);
            }
        }
    }
    Ok(())
}

async fn send_script_response(
    w: &mut impl AsyncWriteRent,
    response: ScriptResponse,
    head_only: bool,
    metadata: &HashMap<String, String>,
) {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    send_bytes_response(
        w,
        status,
        "text/plain; charset=utf-8",
        response.body,
        head_only,
        metadata,
    )
    .await;
}

async fn reverse_proxy_request(
    backend_url: &str,
    mut head: RequestHead,
    body: HttpBody,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    metadata: &HashMap<String, String>,
) -> Result<()> {
    let target = match parse_backend_target(backend_url) {
        Ok(target) => target,
        Err(err) => {
            drain_payload(body).await;
            return Err(err);
        }
    };
    let uri = match build_backend_uri(&target, &head.uri) {
        Ok(uri) => uri,
        Err(err) => {
            drain_payload(body).await;
            return Err(err);
        }
    };

    let mut headers = head.headers;
    strip_hop_headers(&mut headers);
    let host_header = target.host_header();
    let host_header_value = match http::HeaderValue::from_str(&host_header) {
        Ok(value) => value,
        Err(_) => {
            drain_payload(body).await;
            return Err(anyhow!("invalid backend host header"));
        }
    };
    headers.insert(http::header::HOST, host_header_value);

    head.uri = uri;
    head.headers = headers;
    head.version = http::Version::HTTP_11;

    let pool_key = PoolKey::new(
        target.host.clone(),
        target.port,
        matches!(target.scheme, BackendScheme::Https),
    );
    let mut conn = match pool::take_connection(&pool_key) {
        Some(conn) => conn,
        None => match connect_backend(&target).await {
            Ok(conn) => conn,
            Err(err) => {
                drain_payload(body).await;
                return Err(err);
            }
        },
    };

    let reuse = match &mut conn {
        PooledConnection::Http(codec) => {
            proxy_over_codec(codec, head, body, w, head_only, metadata).await?
        }
        PooledConnection::Https(codec) => {
            proxy_over_codec(codec, head, body, w, head_only, metadata).await?
        }
    };

    if reuse {
        pool::return_connection(pool_key, conn);
    }

    Ok(())
}

async fn connect_backend(target: &BackendTarget) -> Result<PooledConnection> {
    thread_local! {
        static DNS_CACHE: RefCell<mini_moka::unsync::Cache<String, Arc<Vec<SocketAddr>>>> =
            RefCell::new(mini_moka::unsync::CacheBuilder::new(128)
                .time_to_live(Duration::from_secs(60))
                .build());
    }
    let addr = target.authority();
    let addr = match DNS_CACHE.with(|x| x.borrow_mut().get(&addr).cloned()) {
        Some(x) => x,
        None => {
            let (tx, rx) = oneshot::channel();
            DNS_TP.with(|tp| {
                tp.spawn(move || {
                    let resolved = addr.to_socket_addrs();
                    let _ = tx.send((addr, resolved));
                });
            });
            let (k, v) = rx.await?;
            let v = v
                .with_context(|| "failed to resolve dns name")?
                .into_iter()
                .collect::<Vec<_>>();
            let v = Arc::new(v);
            DNS_CACHE.with(|x| x.borrow_mut().insert(k, v.clone()));
            v
        }
    };
    let stream = TcpStream::connect(&addr[..]).await.and_then(|x| {
        x.set_nodelay(true)?;
        Ok(x)
    });
    let stream = match stream {
        Ok(stream) => stream,
        Err(err) => return Err(anyhow!("failed to connect to backend: {err}")),
    };

    match target.scheme {
        BackendScheme::Http => Ok(PooledConnection::Http(ClientCodec::new(stream))),
        BackendScheme::Https => {
            let tls_stream = connect_tls(stream, &target.host).await?;
            Ok(PooledConnection::Https(ClientCodec::new(tls_stream)))
        }
    }
}

async fn connect_tls(stream: TcpStream, host: &str) -> Result<ClientTlsStream<TcpStream>> {
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid TLS server name"))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|err| anyhow!("TLS handshake failed: {err}"))
}

async fn proxy_over_codec<IO>(
    codec: &mut ClientCodec<IO>,
    head: RequestHead,
    body: HttpBody,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    metadata: &HashMap<String, String>,
) -> Result<bool>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let request = Request::from_parts(head, body);
    codec
        .send_and_flush(request)
        .await
        .map_err(|err| anyhow!("failed to send proxy request: {err}"))?;

    let response = match codec.next().await {
        Some(Ok(resp)) => resp,
        Some(Err(err)) => return Err(anyhow!("failed to read proxy response: {err}")),
        None => return Err(anyhow!("proxy backend closed without response")),
    };

    let (resp_head, mut resp_body) = response.into_parts();
    let status = resp_head.status;
    let can_reuse = should_reuse_proxy_connection(resp_head.version, &resp_head.headers);
    let mut headers = resp_head.headers;
    strip_hop_headers(&mut headers);

    let body_hint = resp_body.hint();
    let send_body = should_send_proxy_body(status, body_hint, head_only);
    apply_proxy_response_headers(&mut headers, body_hint, send_body);
    apply_metadata_response_headers(&mut headers, metadata);
    write_response_head(w, status, &headers).await?;

    if !send_body {
        drain_proxy_payload(codec, &mut resp_body).await?;
        let _ = w.flush().await;
        return Ok(can_reuse);
    }

    match &mut resp_body {
        PayloadDecoder::None => {}
        PayloadDecoder::Fixed(decoder) => forward_fixed_body(w, codec, decoder).await?,
        PayloadDecoder::Streamed(decoder) => forward_chunked_body(w, codec, decoder).await?,
    }

    let _ = w.flush().await;
    Ok(can_reuse)
}

fn should_reuse_proxy_connection(version: http::Version, headers: &http::HeaderMap) -> bool {
    if version != http::Version::HTTP_11 {
        return false;
    }
    !connection_has_close(headers)
}

fn connection_has_close(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
        .unwrap_or(false)
}

fn should_send_proxy_body(status: StatusCode, body_hint: StreamHint, head_only: bool) -> bool {
    if head_only {
        return false;
    }
    if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED)
        || status.is_informational()
    {
        return false;
    }
    !matches!(body_hint, StreamHint::None)
}

fn apply_proxy_response_headers(
    headers: &mut http::HeaderMap,
    body_hint: StreamHint,
    send_body: bool,
) {
    if !send_body {
        headers.remove(http::header::TRANSFER_ENCODING);
        return;
    }

    match body_hint {
        StreamHint::None => {
            headers.remove(http::header::CONTENT_LENGTH);
            headers.remove(http::header::TRANSFER_ENCODING);
        }
        StreamHint::Fixed => {
            headers.remove(http::header::TRANSFER_ENCODING);
        }
        StreamHint::Stream => {
            headers.remove(http::header::CONTENT_LENGTH);
            headers.insert(
                http::header::TRANSFER_ENCODING,
                http::HeaderValue::from_static("chunked"),
            );
        }
    }
}

async fn write_response_head(
    w: &mut impl AsyncWriteRent,
    status: StatusCode,
    headers: &http::HeaderMap,
) -> Result<()> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut buf = Vec::new();
    buf.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());
    for (name, value) in headers.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    let (res, _) = w.write_all(buf).await;
    res.map_err(|err| anyhow!("failed to write proxy response head: {err}"))?;
    Ok(())
}

async fn drain_proxy_payload<IO>(
    codec: &mut ClientCodec<IO>,
    body: &mut PayloadDecoder<FixedBodyDecoder, ChunkedBodyDecoder>,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    match body {
        PayloadDecoder::None => Ok(()),
        PayloadDecoder::Fixed(decoder) => {
            read_fixed_chunk(codec, decoder).await?;
            Ok(())
        }
        PayloadDecoder::Streamed(decoder) => loop {
            match codec.framed_mut().next_with(decoder).await {
                None => return Err(anyhow!("proxy body read failed: unexpected eof")),
                Some(Ok(Some(_))) => continue,
                Some(Ok(None)) => return Ok(()),
                Some(Err(err)) => return Err(anyhow!("proxy body read failed: {err}")),
            }
        },
    }
}

async fn read_fixed_chunk<IO>(
    codec: &mut ClientCodec<IO>,
    decoder: &mut FixedBodyDecoder,
) -> Result<Bytes>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    match codec.framed_mut().next_with(decoder).await {
        None => Err(anyhow!("proxy body read failed: unexpected eof")),
        Some(Ok(chunk)) => Ok(chunk),
        Some(Err(err)) => Err(anyhow!("proxy body read failed: {err}")),
    }
}

async fn forward_fixed_body<IO>(
    w: &mut impl AsyncWriteRent,
    codec: &mut ClientCodec<IO>,
    decoder: &mut FixedBodyDecoder,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let data = read_fixed_chunk(codec, decoder).await?;
    let (res, _) = w.write_all(data).await;
    res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
    Ok(())
}

async fn forward_chunked_body<IO>(
    w: &mut impl AsyncWriteRent,
    codec: &mut ClientCodec<IO>,
    decoder: &mut ChunkedBodyDecoder,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    loop {
        match codec.framed_mut().next_with(decoder).await {
            None => return Err(anyhow!("proxy body read failed: unexpected eof")),
            Some(Ok(Some(data))) => {
                if data.is_empty() {
                    continue;
                }
                let header = format!("{:X}\r\n", data.len());
                let (res, _) = w.write_all(header.into_bytes()).await;
                res.map_err(|err| anyhow!("failed to write proxy body header: {err}"))?;
                let (res, _) = w.write_all(data).await;
                res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
                let (res, _) = w.write_all(b"\r\n".to_vec()).await;
                res.map_err(|err| anyhow!("failed to write proxy body trailer: {err}"))?;
            }
            Some(Ok(None)) => break,
            Some(Err(err)) => return Err(anyhow!("proxy body read failed: {err}")),
        }
    }
    let (res, _) = w.write_all(b"0\r\n\r\n".to_vec()).await;
    res.map_err(|err| anyhow!("failed to write proxy body end: {err}"))?;
    Ok(())
}

fn strip_hop_headers(headers: &mut http::HeaderMap) {
    let connection_values = headers
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    if let Some(value) = connection_values {
        for name in value.split(',').map(|name| name.trim()) {
            if !name.is_empty() {
                let name = name.to_ascii_lowercase();
                headers.remove(name.as_str());
            }
        }
    }

    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[derive(Clone, Copy)]
enum BackendScheme {
    Http,
    Https,
}

impl BackendScheme {
    fn default_port(self) -> u16 {
        match self {
            BackendScheme::Http => 80,
            BackendScheme::Https => 443,
        }
    }
}

struct BackendTarget {
    scheme: BackendScheme,
    host: String,
    is_ipv6: bool,
    port: u16,
    base_path: String,
    base_query: Option<String>,
}

impl BackendTarget {
    fn authority(&self) -> String {
        format_host_port(&self.host, self.port, self.is_ipv6)
    }

    fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            if self.is_ipv6 {
                format!("[{}]", self.host)
            } else {
                self.host.clone()
            }
        } else {
            self.authority()
        }
    }
}

fn parse_backend_target(raw: &str) -> Result<BackendTarget> {
    let url = Url::parse(raw).map_err(|err| anyhow!("invalid backend url: {err}"))?;
    let scheme = match url.scheme() {
        "http" => BackendScheme::Http,
        "https" => BackendScheme::Https,
        other => return Err(anyhow!("unsupported backend scheme: {other}")),
    };
    let host = url
        .host()
        .ok_or_else(|| anyhow!("backend url missing host"))?;
    let (host, is_ipv6) = match host {
        url::Host::Domain(name) => (name.to_string(), false),
        url::Host::Ipv4(addr) => (addr.to_string(), false),
        url::Host::Ipv6(addr) => (addr.to_string(), true),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("backend url missing port"))?;
    let base_path = url.path().to_string();
    let base_query = url.query().map(|q| q.to_string());

    Ok(BackendTarget {
        scheme,
        host,
        is_ipv6,
        port,
        base_path,
        base_query,
    })
}

fn build_backend_uri(target: &BackendTarget, req_uri: &Uri) -> Result<Uri> {
    let req_path = req_uri.path();
    let base_path = &target.base_path;
    let path = join_paths(base_path, req_path);
    let query = merge_queries(target.base_query.as_deref(), req_uri.query());
    let mut out = path;
    if let Some(query) = query {
        out.push('?');
        out.push_str(&query);
    }
    out.parse()
        .map_err(|err| anyhow!("invalid proxy path: {err}"))
}

fn join_paths(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    if base.is_empty() || base == "/" {
        path.to_string()
    } else {
        format!("{}/{}", base, path.trim_start_matches('/'))
    }
}

fn merge_queries(base: Option<&str>, extra: Option<&str>) -> Option<String> {
    match (base, extra) {
        (Some(base), Some(extra)) if !base.is_empty() && !extra.is_empty() => {
            Some(format!("{base}&{extra}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(extra)) if !extra.is_empty() => Some(extra.to_string()),
        _ => None,
    }
}

fn format_host_port(host: &str, port: u16, is_ipv6: bool) -> String {
    if is_ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn not_found() -> Response<Bytes> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
}

fn bad_gateway() -> Response<Bytes> {
    text_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
}

fn method_not_allowed() -> Response<Bytes> {
    text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn text_response(status: StatusCode, body: &str) -> Response<Bytes> {
    http::Response::builder()
        .status(status)
        .header(http::header::SERVER, crate::SERVER_HEADER)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::copy_from_slice(body.as_bytes()))
        .unwrap()
}

async fn log_request(
    request_id: Ulid,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    method: &Method,
    uri: &Uri,
) {
    async_log(
        format!(
            "[request] {}: {} {} {} {}\n",
            request_id,
            scheme.as_str(),
            peer,
            method,
            uri
        )
        .into_bytes(),
    )
    .await
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

const MAX_PROXY_LINE_LEN: usize = 108;

async fn read_proxy_protocol_peer(
    stream: &mut TcpStream,
    fallback: std::net::SocketAddr,
    config: &StaticConfig,
) -> Result<std::net::SocketAddr> {
    let mut line: Vec<u8> = Vec::with_capacity(MAX_PROXY_LINE_LEN);

    if !config.debug_proxy_protocol_disable_fast_path {
        stream.readable(false).await?;

        // fast path: peek socket buffer
        unsafe {
            let n = libc::recv(
                stream.as_raw_fd(),
                line.as_mut_ptr().cast(),
                line.capacity(),
                libc::MSG_PEEK,
            );
            if n > 0 {
                let n = n as usize;
                assert!(n <= line.capacity());
                line.set_len(n);
            }
        }
        if !line.is_empty() {
            let len = line
                .windows(2)
                .enumerate()
                .find(|x| x.1 == b"\r\n")
                .map(|x| x.0);
            if let Some(len) = len {
                let output = parse_proxy_protocol_v1(&line[..len], fallback);
                // consume the buffer
                let (res, _) = stream.read_exact(SliceMut::new(line, 0, len + 2)).await;
                res?;
                return output;
            }
        }

        line.clear();
    }

    let mut buffer = Box::new([0u8; 1]);
    while line.len() < MAX_PROXY_LINE_LEN {
        let (res, buf) = stream.read_exact(buffer).await;
        buffer = buf;
        res.map_err(|e| anyhow!("failed to read PROXY header: {e}"))?;
        let byte = buffer[0];
        line.push(byte);
        let len = line.len();
        if len >= 2 && line[len - 2] == b'\r' && line[len - 1] == b'\n' {
            return parse_proxy_protocol_v1(&line, fallback);
        }
    }
    Err(anyhow!(
        "PROXY header exceeded {MAX_PROXY_LINE_LEN} bytes before newline"
    ))
}

fn parse_proxy_protocol_v1(
    header: &[u8],
    fallback: std::net::SocketAddr,
) -> Result<std::net::SocketAddr> {
    let header = std::str::from_utf8(header).context("PROXY header must be valid ASCII")?;
    let header = header.trim_end_matches("\r\n");
    let mut parts = header.split_whitespace();
    let prefix = parts
        .next()
        .ok_or_else(|| anyhow!("received empty PROXY header"))?;
    if prefix != "PROXY" {
        return Err(anyhow!("invalid PROXY header prefix: {prefix}"));
    }
    let family = parts
        .next()
        .ok_or_else(|| anyhow!("missing PROXY protocol family"))?;
    match family {
        "UNKNOWN" => Ok(fallback),
        "TCP4" | "TCP6" => {
            let src_ip = parts
                .next()
                .ok_or_else(|| anyhow!("missing source address in PROXY header"))?;
            let _dst_ip = parts
                .next()
                .ok_or_else(|| anyhow!("missing destination address in PROXY header"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| anyhow!("missing source port in PROXY header"))?;
            let _dst_port = parts
                .next()
                .ok_or_else(|| anyhow!("missing destination port in PROXY header"))?;
            let port: u16 = src_port
                .parse()
                .map_err(|e| anyhow!("invalid source port in PROXY header: {e}"))?;
            let addr = if family == "TCP4" {
                let ip: Ipv4Addr = src_ip
                    .parse()
                    .map_err(|e| anyhow!("invalid IPv4 in PROXY header: {e}"))?;
                std::net::SocketAddr::new(IpAddr::V4(ip), port)
            } else {
                let ip: Ipv6Addr = src_ip
                    .parse()
                    .map_err(|e| anyhow!("invalid IPv6 in PROXY header: {e}"))?;
                std::net::SocketAddr::new(IpAddr::V6(ip), port)
            };
            Ok(addr)
        }
        other => Err(anyhow!("unsupported PROXY protocol family: {other}")),
    }
}
