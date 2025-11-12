use std::{
    cell::RefCell,
    io::ErrorKind,
    os::fd::AsFd,
    rc::Rc,
    sync::{Arc, Weak},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use monoio::{
    fs::File,
    io::{AsyncReadRent, AsyncWriteRent, Split, sink::Sink, stream::Stream},
    net::TcpListener,
};
use monoio_http::{
    common::{
        body::Body,
        error::HttpError,
        request::{Request, RequestHead},
        response::Response,
    },
    h1::{
        codec::ServerCodec,
        payload::{FixedPayload, Payload, stream_payload_pair},
    },
};
use monoio_rustls::TlsError;

use crate::{
    shared::SharedState,
    site::{Site, TarEntry, guess_mime, normalize_request_path},
};

type HttpBody = Payload<Bytes, HttpError>;
type HttpResponse = Response<HttpBody>;

pub async fn amain(shared: Arc<SharedState>) -> Result<()> {
    if shared.config.tls_addr.is_some() {
        let tls_state = shared.clone();
        monoio::spawn(async move {
            if let Err(err) = run_tls_listener(tls_state).await {
                eprintln!("[zeroserve] TLS listener stopped: {err:?}");
            }
        });
    }

    run_http_listener(shared).await
}

async fn run_http_listener(shared: Arc<SharedState>) -> Result<()> {
    let listener = TcpListener::bind(shared.config.http_addr)
        .with_context(|| format!("failed to bind {}", shared.config.http_addr))?;
    eprintln!(
        "[zeroserve] listening on http://{}",
        shared.config.http_addr
    );
    loop {
        let (stream, addr) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let state = shared.clone();
        monoio::spawn(async move {
            if let Err(err) = handle_connection(stream, addr, state, Scheme::Http).await {
                eprintln!(
                    "[zeroserve] connection {} over http closed with error: {err:?}",
                    addr
                );
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
    eprintln!("[zeroserve] listening on https://{}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = shared.clone();
        monoio::spawn(async move {
            let tls_state = match state.tls.load_full() {
                Some(runtime) => runtime,
                None => {
                    eprintln!(
                        "[zeroserve] dropping TLS connection {peer} due to missing TLS config"
                    );
                    return;
                }
            };
            match tls_state.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) =
                        handle_connection(tls_stream, peer, state, Scheme::Https).await
                    {
                        eprintln!("[zeroserve] TLS conn {peer} closed with error: {err:?}");
                    }
                }
                Err(err) => log_tls_error(peer, err),
            }
        });
    }
}

fn log_tls_error(peer: std::net::SocketAddr, error: TlsError) {
    eprintln!("[zeroserve] TLS handshake with {peer} failed: {error}");
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
    let mut codec = ServerCodec::new(io);
    while let Some(result) = codec.next().await {
        match result {
            Ok(request) => {
                let method = request.method().clone();
                let uri = request.uri().clone();
                if !shared.config.disable_request_logging {
                    log_request(peer, scheme, &method, &uri).await;
                }
                let response = handle_request(request, &shared).await;
                if let Err(err) = codec.send(response).await {
                    return Err(err.into());
                }
                if let Err(err) = <ServerCodec<IO> as Sink<HttpResponse>>::flush(&mut codec).await {
                    return Err(err.into());
                }
            }
            Err(err) => {
                if let HttpError::IOError(x) = &err {
                    if x.kind() == ErrorKind::ConnectionReset {
                        break;
                    }
                }

                eprintln!(
                    "[zeroserve] {} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn handle_request(req: Request, shared: &Arc<SharedState>) -> HttpResponse {
    let (head, body) = req.into_parts();
    drain_payload(body).await;

    match head.method {
        Method::GET | Method::HEAD => {
            if let Some(resp) = serve_static(&head, shared, head.method == Method::HEAD) {
                resp
            } else {
                not_found()
            }
        }
        _ => method_not_allowed(),
    }
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

fn serve_static(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
) -> Option<HttpResponse> {
    let path = normalize_request_path(head.uri.path())?;
    let site = shared.site.load_full();
    let entry = site.lookup(&path, &shared.config.index_file, shared.config.try_html)?;

    let mut builder = http::Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, crate::SERVER_HEADER)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::CONTENT_TYPE, guess_mime(&entry.path));

    if head_only {
        builder = builder.header(http::header::CONTENT_LENGTH, entry.size.to_string());
        return Some(
            builder
                .body(Payload::None)
                .unwrap_or_else(|_| server_error()),
        );
    }

    let payload = match stream_tar_entry(entry.clone(), &site, shared.config.chunk_size) {
        Ok(x) => x,
        Err(e) => return Some(e),
    };
    Some(builder.body(payload).unwrap_or_else(|_| server_error()))
}

fn stream_tar_entry(
    entry: Arc<TarEntry>,
    site: &Arc<Site>,
    chunk_size: usize,
) -> Result<HttpBody, Response<Payload<Bytes, HttpError>>> {
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
                eprintln!("[zeroserve] failed to create tar handle: {}", e);
                return Err(server_error());
            }
        };
        x.push((Arc::downgrade(&site), file.clone()));
        Ok(file)
    })?;

    let (payload, mut sender) = stream_payload_pair();
    monoio::spawn(async move {
        if let Err(err) = pump_tar_entry(file, entry, chunk_size.max(1024), &mut sender).await {
            sender.feed_error(HttpError::from(err));
        }
        sender.feed_data(None);
    });
    Ok(Payload::Stream(payload))
}

async fn pump_tar_entry(
    file: Rc<File>,
    entry: Arc<TarEntry>,
    chunk_size: usize,
    sender: &mut monoio_http::h1::payload::StreamPayloadSender<Bytes, HttpError>,
) -> std::io::Result<()> {
    let mut remaining = entry.size;
    let mut offset = entry.offset;
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let buffer = vec![0u8; read_len];
        let (res, mut buf) = file.read_at(buffer, offset).await;
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hit EOF while reading tar entry",
            ));
        }
        buf.truncate(n);
        sender.feed_data(Some(Bytes::from(buf)));
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

fn not_found() -> Response<Payload<Bytes, HttpError>> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
}

fn method_not_allowed() -> Response<Payload<Bytes, HttpError>> {
    text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn server_error() -> Response<Payload<Bytes, HttpError>> {
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
}

fn text_response(status: StatusCode, body: &str) -> Response<Payload<Bytes, HttpError>> {
    let payload = Payload::Fixed(FixedPayload::new(Bytes::copy_from_slice(body.as_bytes())));
    http::Response::builder()
        .status(status)
        .header(http::header::SERVER, crate::SERVER_HEADER)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(payload)
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
    let msg = format!(
        "[zeroserve] {} {} {} {}\n",
        scheme.as_str(),
        peer,
        method,
        uri
    )
    .into_bytes();
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
