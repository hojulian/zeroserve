use std::{
    cell::RefCell,
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use ::http::{
    Method, StatusCode, Uri,
    header::{HeaderName, HeaderValue},
};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures::channel::oneshot;
use monoio::{
    buf::SliceMut,
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, BufReader, BufWriter,
        Split, Splitable,
    },
    net::{TcpListener, TcpStream},
};
use monoio_rustls::{ClientTlsStream, TlsConnector, TlsError};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use ulid::Ulid;
use url::Url;

use crate::{
    config::StaticConfig,
    http::h1::{self, HttpError, Request, RequestHead, StreamHint},
    logging::async_log,
    pool::{self, PoolKey, PooledConnection},
    script::{ScriptOutcome, ScriptRequest, ScriptResponse, ScriptRuntime},
    shared::{SharedState, read_tar_entry, stream_tar_entry},
    site::{guess_mime, normalize_request_path},
    thread_pool::DNS_TP,
};

type HttpBody = h1::Body;

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
                async_log(
                    format!(
                        "[listener] connection {} over http closed with error: {err:?}",
                        peer
                    )
                    .into_bytes(),
                )
                .await;
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
                        async_log(
                            format!(
                                "[listener] connection {} over tls closed with error: {err:?}",
                                reported_peer
                            )
                            .into_bytes(),
                        )
                        .await;
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
    let (r, w) = io.into_split();
    let r = BufReader::new(r);
    let mut w = BufWriter::new(w);
    let mut reader = h1::H1Connection::new(r);
    loop {
        let result = reader.next_request().await;
        let request = match result {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(err) => {
                if matches!(err, HttpError::Io(ref x) if x.kind() == ErrorKind::ConnectionReset
                    || x.kind() == ErrorKind::UnexpectedEof)
                    || matches!(err, HttpError::UnexpectedEof)
                {
                    break;
                }
                eprintln!(
                    "{} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        };

        let can_continue = handle_request(
            request,
            &mut reader,
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
    Ok(())
}

async fn handle_request<R: AsyncReadRent>(
    req: Request,
    reader: &mut h1::H1Connection<R>,
    shared: &Arc<SharedState>,
    script_runtime: &Rc<ScriptRuntime>,
    peer: std::net::SocketAddr,
    scheme: Scheme,
    w: &mut impl AsyncWriteRent,
    interrupt: &mut (impl Future<Output = ()> + Unpin),
) -> bool {
    let request_id = Ulid::new();
    let (mut head, mut body) = req.into_parts();
    if !shared.config.disable_request_logging {
        log_request(request_id, peer, scheme, &head.method, &head.uri).await;
    }
    let head_only = head.method == Method::HEAD;

    let script_request = build_script_request(request_id, &head, peer, scheme);
    let script_request_fallback = script_request.clone();
    let script_outcome = monoio::select! {
        x = script_runtime.run_request(shared.site.load_full(), script_request) => x,
        _ = &mut *interrupt => {
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
        let res = monoio::select! {
            x = reverse_proxy_request(
                &proxy_url,
                head,
                body,
                reader,
                w,
                head_only,
                &script_outcome.metadata,
            ) => x,
            _ = &mut *interrupt => Err(anyhow::anyhow!("interrupted")),
        };
        match res {
            Ok(continue_conn) => return continue_conn,
            Err(err) => {
                async_log(
                    format!("[handle] {}: reverse proxy: {:?}\n", request_id, err).into_bytes(),
                )
                .await;
                return false;
            }
        }
    }

    if let Some(response) = script_outcome.response {
        drain_payload(reader, &mut body).await;
        send_script_response(w, response, head_only, &script_outcome.metadata).await;
        return true;
    }

    drain_payload(reader, &mut body).await;

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
    mut res: ::http::Response<Bytes>,
    metadata: &HashMap<String, String>,
) {
    if !res.headers().contains_key(::http::header::CONTENT_LENGTH)
        && !res
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING)
    {
        let length = ::http::HeaderValue::from_str(&res.body().len().to_string())
            .unwrap_or_else(|_| ::http::HeaderValue::from_static("0"));
        res.headers_mut()
            .insert(::http::header::CONTENT_LENGTH, length);
    }
    apply_metadata_response_headers(res.headers_mut(), metadata);
    let (parts, body) = res.into_parts();
    let _ = write_response_head(w, parts.status, &parts.headers).await;
    if !body.is_empty() {
        let _ = w.write_all(body.to_vec()).await;
    }
    let _ = w.flush().await;
}

async fn drain_payload<R: AsyncReadRent>(reader: &mut h1::H1Connection<R>, body: &mut h1::Body) {
    loop {
        match body.next_data(reader).await {
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

    if if_none_match_matches(&head.headers, &entry.etag) {
        send_not_modified(w, &entry.etag, metadata).await;
        return Some(());
    }

    let mut headers = build_base_headers(entry.size, mime);
    headers.insert(::http::header::ETAG, etag_header_value(&entry.etag));
    headers.insert(
        ::http::header::ACCEPT_RANGES,
        ::http::HeaderValue::from_static("bytes"),
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

fn build_base_headers(content_length: u64, content_type: &str) -> ::http::HeaderMap {
    let mut headers = ::http::HeaderMap::new();
    let length = HeaderValue::from_str(&content_length.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(::http::header::CONTENT_LENGTH, length);
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(::http::header::CONTENT_TYPE, content_type);
    headers
}

fn apply_metadata_response_headers(
    headers: &mut ::http::HeaderMap,
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

fn if_none_match_matches(headers: &::http::HeaderMap, etag: &str) -> bool {
    let value = match headers.get(::http::header::IF_NONE_MATCH) {
        Some(value) => value,
        None => return false,
    };
    let value = match value.to_str() {
        Ok(value) => value,
        Err(_) => return false,
    };
    if value.trim() == "*" {
        return true;
    }
    let quoted = format!("\"{etag}\"");
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let part = part.strip_prefix("W/").unwrap_or(part).trim();
        if part == etag || part == quoted {
            return true;
        }
    }
    false
}

fn etag_header_value(etag: &str) -> HeaderValue {
    let mut value = String::with_capacity(etag.len() + 2);
    value.push('"');
    value.push_str(etag);
    value.push('"');
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("\"\""))
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

async fn send_not_modified(
    w: &mut impl AsyncWriteRent,
    etag: &str,
    metadata: &HashMap<String, String>,
) {
    let mut headers = ::http::HeaderMap::new();
    headers.insert(
        ::http::header::SERVER,
        HeaderValue::from_static(crate::SERVER_HEADER),
    );
    headers.insert(::http::header::ETAG, etag_header_value(etag));
    headers.insert(
        ::http::header::CONTENT_LENGTH,
        HeaderValue::from_static("0"),
    );
    apply_metadata_response_headers(&mut headers, metadata);
    let _ = write_response_head(w, StatusCode::NOT_MODIFIED, &headers).await;
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
    mut body: HttpBody,
    reader: &mut h1::H1Connection<impl AsyncReadRent>,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    metadata: &HashMap<String, String>,
) -> Result<bool> {
    let target = match parse_backend_target(backend_url) {
        Ok(target) => target,
        Err(err) => {
            drain_payload(reader, &mut body).await;
            return Err(err);
        }
    };
    let uri = match build_backend_uri(&target, &head.uri) {
        Ok(uri) => uri,
        Err(err) => {
            drain_payload(reader, &mut body).await;
            return Err(err);
        }
    };

    let is_ws_request = h1::is_websocket_upgrade_request(&head);

    let mut headers = head.headers;
    strip_hop_headers(&mut headers, is_ws_request);
    apply_proxy_request_headers(&mut headers, &body);
    let host_header = target.host_header();
    let host_header_value = match ::http::HeaderValue::from_str(&host_header) {
        Ok(value) => value,
        Err(_) => {
            drain_payload(reader, &mut body).await;
            return Err(anyhow!("invalid backend host header"));
        }
    };
    headers.insert(::http::header::HOST, host_header_value);

    head.uri = uri;
    head.headers = headers;
    head.version = ::http::Version::HTTP_11;

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
                drain_payload(reader, &mut body).await;
                return Err(err);
            }
        },
    };

    let outcome = match &mut conn {
        PooledConnection::Http(codec) => {
            proxy_over_connection(
                codec,
                head,
                body,
                reader,
                w,
                head_only,
                metadata,
                is_ws_request,
            )
            .await?
        }
        PooledConnection::Https(codec) => {
            proxy_over_connection(
                codec,
                head,
                body,
                reader,
                w,
                head_only,
                metadata,
                is_ws_request,
            )
            .await?
        }
    };

    if outcome.reuse_backend {
        pool::return_connection(pool_key, conn);
    }

    Ok(outcome.keep_client)
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
        BackendScheme::Http => Ok(PooledConnection::Http(h1::H1Connection::new(stream))),
        BackendScheme::Https => {
            let tls_stream = connect_tls(stream, &target.host).await?;
            Ok(PooledConnection::Https(h1::H1Connection::new(tls_stream)))
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

struct ProxyOutcome {
    reuse_backend: bool,
    keep_client: bool,
}

async fn proxy_over_connection<IO, R>(
    conn: &mut h1::H1Connection<IO>,
    head: RequestHead,
    mut body: HttpBody,
    reader: &mut h1::H1Connection<R>,
    w: &mut impl AsyncWriteRent,
    head_only: bool,
    metadata: &HashMap<String, String>,
    is_ws_request: bool,
) -> Result<ProxyOutcome>
where
    IO: AsyncReadRent + AsyncWriteRent + Split,
    R: AsyncReadRent,
{
    h1::write_request_head(conn.io_mut()?, &head)
        .await
        .map_err(|err| anyhow!("failed to send proxy request head: {err}"))?;
    forward_request_body(conn, reader, &mut body)
        .await
        .map_err(|err| anyhow!("failed to send proxy request body: {err}"))?;

    let response = match conn.next_response().await {
        Ok(Some(resp)) => resp,
        Ok(None) => return Err(anyhow!("proxy backend closed without response")),
        Err(err) => return Err(anyhow!("failed to read proxy response: {err}")),
    };

    let (resp_head, mut resp_body) = response.into_parts();
    let status = resp_head.status;
    let mut can_reuse = should_reuse_proxy_connection(resp_head.version, &resp_head.headers);
    let is_ws_response = is_ws_request && h1::is_websocket_upgrade_response(&resp_head);
    let mut headers = resp_head.headers;
    if is_ws_response {
        strip_hop_headers(&mut headers, true);
    } else {
        strip_hop_headers(&mut headers, false);
    }
    let body_hint = resp_body.hint();
    if resp_body.is_eof() {
        can_reuse = false;
    }

    if is_ws_response {
        apply_metadata_response_headers(&mut headers, metadata);
        write_response_head(w, status, &headers).await?;
        let _ = w.flush().await;

        let (backend_io, backend_leftover) = conn
            .take_io()
            .ok_or_else(|| anyhow!("proxy backend missing io"))?;
        let (client_io, client_leftover) = reader
            .take_io()
            .ok_or_else(|| anyhow!("client missing io for websocket"))?;
        tunnel_websocket(client_io, w, backend_io, client_leftover, backend_leftover).await?;
        return Ok(ProxyOutcome {
            reuse_backend: false,
            keep_client: false,
        });
    }

    let send_body = should_send_proxy_body(status, body_hint, head_only);
    apply_proxy_response_headers(&mut headers, body_hint, send_body);
    apply_metadata_response_headers(&mut headers, metadata);
    write_response_head(w, status, &headers).await?;

    if !send_body {
        drain_proxy_payload(conn, &mut resp_body).await?;
        let _ = w.flush().await;
        return Ok(ProxyOutcome {
            reuse_backend: can_reuse,
            keep_client: true,
        });
    }

    forward_proxy_body(w, conn, &mut resp_body).await?;
    let _ = w.flush().await;
    Ok(ProxyOutcome {
        reuse_backend: can_reuse,
        keep_client: true,
    })
}

fn should_reuse_proxy_connection(version: ::http::Version, headers: &::http::HeaderMap) -> bool {
    if version != ::http::Version::HTTP_11 {
        return false;
    }
    !connection_has_close(headers)
}

fn connection_has_close(headers: &::http::HeaderMap) -> bool {
    headers
        .get(::http::header::CONNECTION)
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
    headers: &mut ::http::HeaderMap,
    body_hint: StreamHint,
    send_body: bool,
) {
    if !send_body {
        headers.remove(::http::header::TRANSFER_ENCODING);
        return;
    }

    match body_hint {
        StreamHint::None => {
            headers.remove(::http::header::CONTENT_LENGTH);
            headers.remove(::http::header::TRANSFER_ENCODING);
        }
        StreamHint::Fixed => {
            headers.remove(::http::header::TRANSFER_ENCODING);
        }
        StreamHint::Stream => {
            headers.remove(::http::header::CONTENT_LENGTH);
            headers.insert(
                ::http::header::TRANSFER_ENCODING,
                ::http::HeaderValue::from_static("chunked"),
            );
        }
    }
}

fn apply_proxy_request_headers(headers: &mut ::http::HeaderMap, body: &h1::Body) {
    if body.is_chunked() {
        headers.remove(::http::header::CONTENT_LENGTH);
        headers.insert(
            ::http::header::TRANSFER_ENCODING,
            ::http::HeaderValue::from_static("chunked"),
        );
    } else {
        headers.remove(::http::header::TRANSFER_ENCODING);
    }
}

async fn write_response_head(
    w: &mut impl AsyncWriteRent,
    status: StatusCode,
    headers: &::http::HeaderMap,
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

async fn forward_request_body<IO, R>(
    conn: &mut h1::H1Connection<IO>,
    reader: &mut h1::H1Connection<R>,
    body: &mut h1::Body,
) -> Result<()>
where
    IO: AsyncWriteRent,
    R: AsyncReadRent,
{
    match body.hint() {
        StreamHint::None => return Ok(()),
        StreamHint::Stream if body.is_eof() => {
            return Err(anyhow!("proxy request body missing length"));
        }
        _ => {}
    }

    if body.is_chunked() {
        while let Some(chunk) = body.next_data(reader).await {
            let chunk = chunk.map_err(|err| anyhow!("proxy request body read failed: {err}"))?;
            h1::write_chunk(conn.io_mut()?, chunk.as_ref())
                .await
                .map_err(|err| anyhow!("failed to write proxy body chunk: {err}"))?;
        }
        h1::write_chunk_end(conn.io_mut()?)
            .await
            .map_err(|err| anyhow!("failed to write proxy body end: {err}"))?;
    } else {
        while let Some(chunk) = body.next_data(reader).await {
            let chunk = chunk.map_err(|err| anyhow!("proxy request body read failed: {err}"))?;
            let (res, _) = conn.io_mut()?.write_all(chunk.to_vec()).await;
            res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
        }
    }
    let _ = conn.io_mut()?.flush().await;
    Ok(())
}

async fn drain_proxy_payload<IO>(conn: &mut h1::H1Connection<IO>, body: &mut h1::Body) -> Result<()>
where
    IO: AsyncReadRent,
{
    while let Some(chunk) = body.next_data(conn).await {
        chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
    }
    Ok(())
}

async fn forward_proxy_body<IO>(
    w: &mut impl AsyncWriteRent,
    conn: &mut h1::H1Connection<IO>,
    body: &mut h1::Body,
) -> Result<()>
where
    IO: AsyncReadRent,
{
    match body.hint() {
        StreamHint::None => Ok(()),
        StreamHint::Fixed => {
            while let Some(chunk) = body.next_data(conn).await {
                let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
                let (res, _) = w.write_all(chunk.to_vec()).await;
                res.map_err(|err| anyhow!("failed to write proxy body: {err}"))?;
            }
            Ok(())
        }
        StreamHint::Stream => {
            while let Some(chunk) = body.next_data(conn).await {
                let chunk = chunk.map_err(|err| anyhow!("proxy body read failed: {err}"))?;
                h1::write_chunk(w, chunk.as_ref())
                    .await
                    .map_err(|err| anyhow!("failed to write proxy body chunk: {err}"))?;
            }
            h1::write_chunk_end(w)
                .await
                .map_err(|err| anyhow!("failed to write proxy body end: {err}"))?;
            Ok(())
        }
    }
}

async fn tunnel_websocket<R, IO>(
    client_read: R,
    client_write: impl AsyncWriteRent,
    backend_io: IO,
    client_leftover: Vec<u8>,
    backend_leftover: Vec<u8>,
) -> Result<()>
where
    R: AsyncReadRent,
    IO: AsyncReadRent + AsyncWriteRent + Split,
{
    let (backend_read, backend_write) = backend_io.into_split();
    let client_to_backend = copy_stream(client_read, backend_write, client_leftover);
    let backend_to_client = copy_stream(backend_read, client_write, backend_leftover);
    let (res_a, res_b) = futures::future::join(client_to_backend, backend_to_client).await;
    res_a?;
    res_b?;
    Ok(())
}

async fn copy_stream<R, W>(mut reader: R, mut writer: W, pending: Vec<u8>) -> Result<()>
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    if !pending.is_empty() {
        let (res, _) = writer.write_all(pending).await;
        res.map_err(|err| anyhow!("failed to write websocket buffer: {err}"))?;
    }

    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let (res, next_buf) = futures::future::join(reader.read(buf), writer.flush())
            .await
            .0;
        buf = next_buf;
        let n = res.map_err(|err| anyhow!("websocket read failed: {err}"))?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        let view = monoio::buf::Slice::new(buf, 0, n);
        let (res, view) = writer.write_all(view).await;
        buf = view.into_inner();
        res.map_err(|err| anyhow!("websocket write failed: {err}"))?;
    }
}

fn strip_hop_headers(headers: &mut ::http::HeaderMap, keep_upgrade: bool) {
    let connection_values = headers
        .get(::http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    if let Some(value) = connection_values {
        let mut saw_upgrade = false;
        for name in value.split(',').map(|name| name.trim()) {
            if name.is_empty() {
                continue;
            }
            if keep_upgrade && name.eq_ignore_ascii_case("upgrade") {
                saw_upgrade = true;
                continue;
            }
            let name = name.to_ascii_lowercase();
            headers.remove(name.as_str());
        }
        if keep_upgrade {
            if saw_upgrade {
                headers.insert(
                    ::http::header::CONNECTION,
                    ::http::HeaderValue::from_static("upgrade"),
                );
            } else {
                headers.remove(::http::header::CONNECTION);
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
        if keep_upgrade && (name == "connection" || name == "upgrade") {
            continue;
        }
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

fn not_found() -> ::http::Response<Bytes> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
}

fn method_not_allowed() -> ::http::Response<Bytes> {
    text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn text_response(status: StatusCode, body: &str) -> ::http::Response<Bytes> {
    ::http::Response::builder()
        .status(status)
        .header(::http::header::SERVER, crate::SERVER_HEADER)
        .header(::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
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
