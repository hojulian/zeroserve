use std::{
    cell::RefCell,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsFd,
    rc::Rc,
    sync::{Arc, Weak},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use monoio::{
    fs::File,
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Split, Splitable,
        sink::SinkExt, stream::Stream,
    },
    net::{TcpListener, TcpStream},
};
use monoio_http::{
    common::{
        body::Body,
        error::HttpError,
        request::{Request, RequestHead},
        response::Response,
    },
    h1::{
        codec::{decoder::RequestDecoder, encoder::GenericEncoder},
        payload::{FixedPayload, Payload},
    },
};
use monoio_rustls::TlsError;

use crate::{
    shared::SharedState,
    site::{Site, TarEntry, guess_mime, normalize_request_path},
};

type HttpBody = Payload<Bytes, HttpError>;

pub async fn amain(shared: Arc<SharedState>) -> Result<()> {
    if shared.config.tls_addr.is_some() {
        let tls_state = shared.clone();
        monoio::spawn(async move {
            if let Err(err) = run_tls_listener(tls_state).await {
                eprintln!("TLS listener stopped: {err:?}");
            }
        });
    }

    run_http_listener(shared).await
}

async fn run_http_listener(shared: Arc<SharedState>) -> Result<()> {
    let listener = TcpListener::bind(shared.config.http_addr)
        .with_context(|| format!("failed to bind {}", shared.config.http_addr))?;
    eprintln!("listening on http://{}", shared.config.http_addr);
    loop {
        let (stream, addr) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let state = shared.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, addr).await {
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
            if let Err(err) = handle_connection(stream, peer, state, Scheme::Http).await {
                eprintln!("connection {} over http closed with error: {err:?}", peer);
            }
        });
    }
}

async fn run_tls_listener(shared: Arc<SharedState>) -> Result<()> {
    let addr = shared
        .config
        .tls_addr
        .ok_or_else(|| anyhow!("TLS listener requested without address"))?;
    let listener = TcpListener::bind(addr)
        .with_context(|| format!("failed to bind TLS listener on {addr}"))?;
    eprintln!("listening on https://{}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = shared.clone();
        monoio::spawn(async move {
            let mut stream = stream;
            let reported_peer = if state.config.enable_proxy_protocol {
                match read_proxy_protocol_peer(&mut stream, peer).await {
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
                    if let Err(err) =
                        handle_connection(tls_stream, reported_peer, state, Scheme::Https).await
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
    io: IO,
    peer: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent + Split + 'static,
{
    let (r, mut w) = io.into_split();
    let mut decoder = RequestDecoder::new(r);
    while let Some(result) = decoder.next().await {
        match result {
            Ok(request) => {
                let method = request.method().clone();
                let uri = request.uri().clone();
                if !shared.config.disable_request_logging {
                    log_request(peer, scheme, &method, &uri).await;
                }
                handle_request(request, &shared, peer, &mut w).await;
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
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
) {
    let (head, body) = req.into_parts();
    drain_payload(body).await;

    match head.method {
        Method::GET | Method::HEAD => {
            if serve_static(&head, shared, head.method == Method::HEAD, peer, w)
                .await
                .is_none()
            {
                send_fixed(w, not_found()).await
            }
        }
        _ => send_fixed(w, method_not_allowed()).await,
    }
}

async fn send_fixed(w: &mut impl AsyncWriteRent, res: Response<Bytes>) {
    let _ = GenericEncoder::new(w)
        .send_and_flush(res.map(|x| Payload::Fixed(FixedPayload::<_, HttpError>::new(x))))
        .await;
}

async fn drain_payload(mut payload: HttpBody) {
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
) -> Option<()> {
    let path = normalize_request_path(head.uri.path())?;
    let site = shared.site.load_full();
    let entry = site.lookup(&path, &shared.config.index_file, shared.config.try_html)?;

    let header = format!(
        "HTTP/1.1 200 OK\r
content-length: {}\r
server: {}\r
accept-ranges: bytes\r
content-type: {}\r\n\r\n",
        entry.size,
        crate::SERVER_HEADER,
        guess_mime(&entry.path),
    );

    let _ = w.write_all(header.into_bytes()).await;

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

fn not_found() -> Response<Bytes> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
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

async fn log_request(peer: std::net::SocketAddr, scheme: Scheme, method: &Method, uri: &Uri) {
    thread_local! {
        static STDERR: Rc<File> = Rc::new(File::from_std(
            std::fs::File::from(
                std::io::stderr().as_fd().try_clone_to_owned()
                    .expect("failed to clone stderr")
            )).unwrap());
    }
    let msg = format!("{} {} {} {}\n", scheme.as_str(), peer, method, uri).into_bytes();
    let stderr = STDERR.with(|x| x.clone());
    let _ = stderr.write_all_at(msg, 0).await;
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
) -> Result<std::net::SocketAddr> {
    let mut line = Vec::with_capacity(MAX_PROXY_LINE_LEN);
    let mut buffer = Box::new([0u8; 1]);
    while line.len() < MAX_PROXY_LINE_LEN {
        let (res, buf) = stream.read_exact(buffer).await;
        buffer = buf;
        res.map_err(|e| anyhow!("failed to read PROXY header: {e}"))?;
        let byte = buffer[0];
        line.push(byte);
        let len = line.len();
        if len >= 2 && line[len - 2] == b'\r' && line[len - 1] == b'\n' {
            let header = std::str::from_utf8(&line).context("PROXY header must be valid ASCII")?;
            return parse_proxy_protocol_v1(header, fallback);
        }
    }
    Err(anyhow!(
        "PROXY header exceeded {MAX_PROXY_LINE_LEN} bytes before newline"
    ))
}

fn parse_proxy_protocol_v1(
    header: &str,
    fallback: std::net::SocketAddr,
) -> Result<std::net::SocketAddr> {
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
