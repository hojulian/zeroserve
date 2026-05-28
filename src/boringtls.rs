//! BoringSSL-backed TLS for the server listener, driven sans-IO over monoio.
//!
//! BoringSSL has native server-side ECH (inner-ClientHello decryption, the
//! ServerHello.random acceptance signal, and `retry_configs` on rejection),
//! which rustls 0.23 does not expose. We drive boring's synchronous
//! `SslStream` over an in-memory BIO (`MemBridge`) and pump ciphertext between
//! that buffer and a monoio `TcpStream`, exposing monoio's owned-buffer
//! `AsyncReadRent`/`AsyncWriteRent` so the result is a drop-in for the old
//! `monoio_rustls::TlsStream` (the h1/h2 handlers are unchanged).
//!
//! No tokio: `boring` (unlike `tokio-boring`) has no async-runtime dependency.

use std::io::{self, Read, Write};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use boring::ssl::{
    AlpnError, ErrorCode, HandshakeError, Ssl, SslConnector, SslContext, SslContextBuilder,
    SslFiletype, SslMethod, SslStream, SslStreamBuilder, select_next_proto,
};
use monoio::{
    BufResult,
    buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut},
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt},
};

const READ_CHUNK: usize = 16 * 1024;
// Wire-format ALPN list the server offers, in preference order: h2, http/1.1.
const ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";

/// In-memory bridge that boring's `SslStream<S>` reads/writes synchronously.
/// `inbound` holds ciphertext received from the peer that the SSL state machine
/// has not consumed yet; `outbound` collects ciphertext the SSL produced that
/// we must still send to the peer.
struct MemBridge {
    inbound: Vec<u8>,
    inbound_pos: usize,
    outbound: Vec<u8>,
}

impl MemBridge {
    fn new() -> Self {
        Self {
            inbound: Vec::new(),
            inbound_pos: 0,
            outbound: Vec::new(),
        }
    }
}

impl Read for MemBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = &self.inbound[self.inbound_pos..];
        if avail.is_empty() {
            // No buffered ciphertext: tell BoringSSL to come back (WANT_READ).
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.inbound_pos += n;
        Ok(n)
    }
}

impl Write for MemBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A built server TLS context. Cheap to clone (refcounted `SSL_CTX`).
#[derive(Clone)]
pub struct BoringAcceptor {
    ctx: SslContext,
}

impl BoringAcceptor {
    /// Build a server context from PEM cert + key files, offering h2/http1.1
    /// via ALPN. `configure` runs against the builder before it is finalized
    /// (used to install ECH keys).
    pub fn build(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        configure: impl FnOnce(&mut SslContextBuilder) -> Result<()>,
    ) -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())
            .context("creating BoringSSL server context")?;
        builder
            .set_certificate_chain_file(cert_path)
            .with_context(|| format!("loading cert chain {}", cert_path.display()))?;
        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .with_context(|| format!("loading private key {}", key_path.display()))?;
        builder
            .check_private_key()
            .context("certificate/key mismatch")?;
        builder.set_alpn_select_callback(|_ssl, client| {
            select_next_proto(ALPN_WIRE, client).ok_or(AlpnError::NOACK)
        });
        configure(&mut builder)?;
        Ok(Self {
            ctx: builder.build(),
        })
    }

    /// Perform the server-side TLS handshake over `io`, pumping records
    /// through the in-memory bridge.
    pub async fn accept<IO>(&self, io: IO) -> Result<BoringStream<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent,
    {
        let ssl = Ssl::new(&self.ctx).context("Ssl::new")?;
        let mid = SslStreamBuilder::new(ssl, MemBridge::new()).setup_accept();
        drive_handshake(mid, io).await
    }
}

/// Drive a mid-handshake `SslStream` to completion over `io`, pumping records
/// through the in-memory bridge. Shared by the server `accept` and client
/// `connect` paths.
async fn drive_handshake<IO>(
    mut mid: boring::ssl::MidHandshakeSslStream<MemBridge>,
    mut io: IO,
) -> Result<BoringStream<IO>>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let stream = loop {
        match mid.handshake() {
            Ok(mut s) => {
                // Flush the final handshake flight to the peer.
                flush_out(s.get_mut(), &mut io).await?;
                break s;
            }
            Err(HandshakeError::WouldBlock(mut m)) => {
                flush_out(m.get_mut(), &mut io).await?;
                if !fill_in(m.get_mut(), &mut io).await? {
                    return Err(anyhow!("peer closed during TLS handshake"));
                }
                mid = m;
            }
            Err(HandshakeError::Failure(m)) => {
                return Err(anyhow!("TLS handshake failed: {}", m.error()));
            }
            Err(HandshakeError::SetupFailure(e)) => {
                return Err(anyhow!("TLS setup failed: {e}"));
            }
        }
    };
    Ok(BoringStream {
        ssl: stream,
        io,
        scratch: vec![0u8; READ_CHUNK],
        shutdown_sent: false,
    })
}

/// Process-wide TLS client connector for the reverse proxy, built once at
/// startup (before namespace isolation wipes `/etc`).
static CLIENT: OnceLock<SslConnector> = OnceLock::new();

/// Common system CA bundle locations, in probe order.
const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // BSD/macOS/some musl
    "/etc/ssl/ca-bundle.pem",             // openSUSE
];

/// Build the reverse-proxy TLS client from the host's CA bundle. MUST be called
/// at startup *before* namespace isolation, because `set_ca_file` eagerly loads
/// the certificates into the context (a lazy CA *path* would later fail once
/// `/etc` is a tmpfs). Reverse-proxying to HTTPS upstreams fails if this wasn't
/// initialized.
pub fn init_client_from_system_roots() -> Result<()> {
    let bundle = CA_BUNDLE_PATHS
        .iter()
        .map(std::path::Path::new)
        .find(|p| p.exists())
        .ok_or_else(|| {
            anyhow!(
                "no system CA bundle found (looked in {:?}); HTTPS reverse-proxy upstreams will fail",
                CA_BUNDLE_PATHS
            )
        })?;
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("creating BoringSSL client context")?;
    builder
        .set_ca_file(bundle)
        .with_context(|| format!("loading CA bundle {}", bundle.display()))?;
    // Upstream proxy connections are HTTP/1.1.
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .context("setting client ALPN")?;
    CLIENT
        .set(builder.build())
        .map_err(|_| anyhow!("TLS client already initialized"))?;
    Ok(())
}

/// Connect to an upstream over TLS, verifying its certificate chain against the
/// startup-loaded CA bundle and checking the hostname against `sni`.
pub async fn client_connect<IO>(io: IO, sni: &str) -> Result<BoringStream<IO>>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    let connector = CLIENT
        .get()
        .ok_or_else(|| anyhow!("TLS client not initialized (no system CA bundle at startup)"))?;
    // `into_ssl` sets SNI and enables hostname verification against `sni`.
    let ssl = connector
        .configure()
        .context("configuring TLS client")?
        .into_ssl(sni)
        .with_context(|| format!("invalid TLS server name {sni:?}"))?;
    let mut builder = SslStreamBuilder::new(ssl, MemBridge::new());
    builder.set_connect_state();
    drive_handshake(builder.setup_connect(), io).await
}

/// Flush any ciphertext BoringSSL has queued in `bridge.outbound` to the socket.
async fn flush_out<IO: AsyncWriteRent>(bridge: &mut MemBridge, io: &mut IO) -> Result<()> {
    if bridge.outbound.is_empty() {
        return Ok(());
    }
    let out = std::mem::take(&mut bridge.outbound);
    let (res, _) = io.write_all(out).await;
    res.context("writing TLS records to socket")?;
    io.flush().await.context("flushing socket")?;
    Ok(())
}

/// Read one chunk of ciphertext from the socket into `bridge.inbound`.
/// Returns `Ok(false)` on EOF.
async fn fill_in<IO: AsyncReadRent>(bridge: &mut MemBridge, io: &mut IO) -> Result<bool> {
    let buf = vec![0u8; READ_CHUNK];
    let (res, buf) = io.read(buf).await;
    let n = res.context("reading TLS records from socket")?;
    if n == 0 {
        return Ok(false);
    }
    // Compact fully-consumed inbound before appending so it can't grow forever.
    if bridge.inbound_pos == bridge.inbound.len() {
        bridge.inbound.clear();
        bridge.inbound_pos = 0;
    }
    bridge.inbound.extend_from_slice(&buf[..n]);
    Ok(true)
}

/// A negotiated TLS stream. Implements monoio's owned-buffer I/O traits so it
/// slots into the existing h1/h2 handlers in place of `monoio_rustls::TlsStream`.
pub struct BoringStream<IO> {
    ssl: SslStream<MemBridge>,
    io: IO,
    scratch: Vec<u8>,
    shutdown_sent: bool,
}

impl<IO> BoringStream<IO> {
    /// Negotiated ALPN protocol, if any (e.g. `b"h2"`).
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.ssl.ssl().selected_alpn_protocol().map(<[u8]>::to_vec)
    }

    /// Whether the client offered ECH and BoringSSL accepted it (decrypted the
    /// inner ClientHello and signaled acceptance). False for plain TLS and for
    /// ECH that was rejected / not offered.
    pub fn ech_accepted(&self) -> bool {
        self.ssl.ssl().ech_accepted()
    }

    /// The SNI BoringSSL is serving. When ECH was accepted this is the inner
    /// (real, protected) server name; for plain TLS it is the cleartext SNI.
    pub fn server_name(&self) -> Option<String> {
        self.ssl
            .ssl()
            .servername(boring::ssl::NameType::HOST_NAME)
            .map(str::to_string)
    }
}

impl<IO: AsyncWriteRent> BoringStream<IO> {
    async fn flush_outbound(&mut self) -> io::Result<()> {
        if self.ssl.get_mut().outbound.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.ssl.get_mut().outbound);
        let (res, _) = self.io.write_all(out).await;
        res?;
        self.io.flush().await
    }
}

impl<IO: AsyncReadRent> BoringStream<IO> {
    async fn fill_inbound(&mut self) -> io::Result<bool> {
        let buf = std::mem::take(&mut self.scratch);
        let (res, buf) = self.io.read(buf).await;
        let n = match res {
            Ok(n) => n,
            Err(e) => {
                self.scratch = buf;
                return Err(e);
            }
        };
        if n == 0 {
            self.scratch = buf;
            return Ok(false);
        }
        let bridge = self.ssl.get_mut();
        if bridge.inbound_pos == bridge.inbound.len() {
            bridge.inbound.clear();
            bridge.inbound_pos = 0;
        }
        bridge.inbound.extend_from_slice(&buf[..n]);
        self.scratch = buf;
        Ok(true)
    }
}

fn ssl_io_error(e: &boring::ssl::Error) -> io::Error {
    io::Error::other(format!("boring ssl error: {e}"))
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncReadRent for BoringStream<IO> {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let cap = buf.bytes_total();
        if cap == 0 {
            return (Ok(0), buf);
        }
        let want = cap.min(self.scratch.len().max(READ_CHUNK));
        let mut plaintext = vec![0u8; want];
        loop {
            // Drain any records BoringSSL wants to send (e.g. session tickets,
            // key updates) before potentially blocking on a read.
            if let Err(e) = self.flush_outbound().await {
                return (Err(e), buf);
            }
            match self.ssl.ssl_read(&mut plaintext) {
                Ok(n) => {
                    unsafe {
                        let dst = buf.write_ptr();
                        dst.copy_from_nonoverlapping(plaintext.as_ptr(), n);
                        buf.set_init(n);
                    }
                    return (Ok(n), buf);
                }
                Err(e) => match e.code() {
                    ErrorCode::ZERO_RETURN => return (Ok(0), buf), // clean close_notify
                    ErrorCode::WANT_READ => match self.fill_inbound().await {
                        Ok(true) => continue,
                        Ok(false) => return (Ok(0), buf),
                        Err(err) => return (Err(err), buf),
                    },
                    ErrorCode::WANT_WRITE => {
                        if let Err(err) = self.flush_outbound().await {
                            return (Err(err), buf);
                        }
                        continue;
                    }
                    _ => return (Err(ssl_io_error(&e)), buf),
                },
            }
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        // Fill only the first iovec slot; the AsyncReadRent contract allows a
        // short read. This keeps the vectored path simple and correct.
        let (ptr, len) = {
            #[cfg(unix)]
            unsafe {
                let slots =
                    std::slice::from_raw_parts(buf.write_iovec_ptr(), buf.write_iovec_len());
                match slots.iter().find(|s| s.iov_len > 0) {
                    Some(s) => (s.iov_base.cast::<u8>(), s.iov_len),
                    None => (std::ptr::null_mut(), 0),
                }
            }
            #[cfg(not(unix))]
            {
                (std::ptr::null_mut::<u8>(), 0usize)
            }
        };
        if len == 0 {
            return (Ok(0), buf);
        }
        let tmp = vec![0u8; len];
        let (res, tmp) = self.read(tmp).await;
        match res {
            Ok(n) => {
                unsafe {
                    ptr.copy_from_nonoverlapping(tmp.as_ptr(), n);
                    buf.set_init(n);
                }
                (Ok(n), buf)
            }
            Err(e) => (Err(e), buf),
        }
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncWriteRent for BoringStream<IO> {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let data = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        if data.is_empty() {
            return (Ok(0), buf);
        }
        // ssl_write either consumes the whole buffer into the BIO or asks for
        // more I/O; loop until it accepts the bytes, pumping the socket.
        let data = data.to_vec();
        loop {
            match self.ssl.ssl_write(&data) {
                Ok(n) => {
                    if let Err(e) = self.flush_outbound().await {
                        return (Err(e), buf);
                    }
                    return (Ok(n), buf);
                }
                Err(e) => match e.code() {
                    ErrorCode::WANT_WRITE => {
                        if let Err(err) = self.flush_outbound().await {
                            return (Err(err), buf);
                        }
                        continue;
                    }
                    ErrorCode::WANT_READ => match self.fill_inbound().await {
                        Ok(true) => continue,
                        Ok(false) => {
                            return (Err(io::Error::from(io::ErrorKind::UnexpectedEof)), buf);
                        }
                        Err(err) => return (Err(err), buf),
                    },
                    _ => return (Err(ssl_io_error(&e)), buf),
                },
            }
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let data = unsafe {
            #[cfg(unix)]
            {
                let iovs = std::slice::from_raw_parts(buf.read_iovec_ptr(), buf.read_iovec_len());
                let mut v = Vec::new();
                for iov in iovs {
                    v.extend_from_slice(std::slice::from_raw_parts(
                        iov.iov_base.cast::<u8>(),
                        iov.iov_len,
                    ));
                }
                v
            }
            #[cfg(not(unix))]
            {
                Vec::new()
            }
        };
        if data.is_empty() {
            return (Ok(0), buf);
        }
        let (res, _) = self.write(data).await;
        (res, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.flush_outbound().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if !self.shutdown_sent {
            // Best-effort close_notify; ignore WANT_* and errors.
            let _ = self.ssl.shutdown();
            self.shutdown_sent = true;
            let _ = self.flush_outbound().await;
        }
        self.io.shutdown().await
    }
}

// SAFETY: read paths only touch `inbound`/`scratch` and write paths only touch
// `outbound`; the underlying `IO` is itself `Split`. The h1 handler uses the
// halves sequentially (read request, then write response), matching the prior
// `monoio_rustls::TlsStream` usage which made the same promise.
unsafe impl<IO: monoio::io::Split> monoio::io::Split for BoringStream<IO> {}

#[cfg(test)]
mod tests {
    use super::*;

    // A localhost client+server TLS handshake driven entirely over monoio,
    // proving the WANT_READ/WANT_WRITE pump and record framing are correct.
    // `#[monoio::test]` can't be used here: it cfg-gates the test on the
    // *destination crate's* `iouring` feature, which zeroserve doesn't define,
    // so the test silently vanishes. Build the runtime explicitly instead.
    #[test]
    fn loopback_handshake_and_echo() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(loopback_handshake_and_echo_inner());
    }

    async fn loopback_handshake_and_echo_inner() {
        use boring::ssl::{SslConnector, SslVerifyMode};
        use monoio::net::{TcpListener, TcpStream};

        // Self-signed cert/key generated for 127.0.0.1 (the repo test pair).
        let cert = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certificate.pem");
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = BoringAcceptor::build(&cert, &key, |_| Ok(())).unwrap();

        let server = async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            // Echo one message.
            let (r, buf) = tls.read(vec![0u8; 64]).await;
            let n = r.unwrap();
            let (w, _) = tls.write(buf[..n].to_vec()).await;
            w.unwrap();
            tls.flush().await.unwrap();
        };

        let client = async move {
            let sock = TcpStream::connect(addr).await.unwrap();
            let mut cfg = SslConnector::builder(SslMethod::tls()).unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let cfg = cfg.build().configure().unwrap();
            // Drive the client over the same sans-IO bridge for the test.
            let ssl = cfg.into_ssl("localhost").unwrap();
            let mut mid = SslStreamBuilder::new(ssl, MemBridge::new());
            mid.set_connect_state();
            let mut io = sock;
            let mut mid = {
                let mut m = mid.setup_connect();
                loop {
                    match m.handshake() {
                        Ok(s) => break s,
                        Err(HandshakeError::WouldBlock(mut mm)) => {
                            flush_out(mm.get_mut(), &mut io).await.unwrap();
                            if !fill_in(mm.get_mut(), &mut io).await.unwrap() {
                                panic!("server closed during handshake");
                            }
                            m = mm;
                        }
                        Err(e) => panic!("client handshake failed: {e}"),
                    }
                }
            };
            // Send "ping" and read the echo using the same pump primitives.
            mid.ssl_write(b"ping").unwrap();
            flush_out(mid.get_mut(), &mut io).await.unwrap();
            let mut out = [0u8; 4];
            loop {
                match mid.ssl_read(&mut out) {
                    Ok(_) => break,
                    Err(e) if e.code() == ErrorCode::WANT_READ => {
                        flush_out(mid.get_mut(), &mut io).await.unwrap();
                        assert!(fill_in(mid.get_mut(), &mut io).await.unwrap());
                    }
                    Err(e) => panic!("client read failed: {e}"),
                }
            }
            assert_eq!(&out, b"ping");
        };

        monoio::join!(server, client);
    }

    // End-to-end ECH: a boring client offering a real ECHConfigList against our
    // boring server with the matching key. Asserts BOTH sides report ECH
    // accepted — the thing rustls could not do (no ServerHello acceptance
    // signal). This is the regression guard for server-side ECH.
    #[test]
    fn ech_accepted_end_to_end() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(ech_accepted_end_to_end_inner());
    }

    async fn ech_accepted_end_to_end_inner() {
        use crate::ech::config::{
            CipherSuite, EchConfig, HPKE_AEAD_AES_128_GCM, HPKE_KDF_HKDF_SHA256,
            HPKE_KEM_DHKEM_X25519, encode_list,
        };
        use boring::pkey::{Id, PKey};
        use boring::ssl::{SslConnector, SslEchKeys, SslVerifyMode};
        use monoio::net::{TcpListener, TcpStream};

        let cert = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certificate.pem");
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("key.pem");
        if !cert.exists() || !key.exists() {
            eprintln!("skipping: test cert/key not present");
            return;
        }

        // Generate an X25519 HPKE keypair with boring and build a matching
        // ECHConfig (config_id 0x2a, the MTI suite).
        let pkey = PKey::generate(Id::X25519).unwrap();
        let priv_raw = {
            let mut b = vec![0u8; 32];
            let s = pkey.raw_private_key(&mut b).unwrap();
            s.to_vec()
        };
        let pub_raw = {
            let mut b = vec![0u8; 32];
            let s = pkey.raw_public_key(&mut b).unwrap();
            s.to_vec()
        };
        let config = EchConfig {
            config_id: 0x2a,
            kem_id: HPKE_KEM_DHKEM_X25519,
            public_key: pub_raw,
            cipher_suites: vec![CipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }],
            maximum_name_length: 0,
            public_name: "public.example.com".into(),
        };
        let config_bytes = config.encode();
        let config_list = encode_list(&[config]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = BoringAcceptor::build(&cert, &key, move |builder| {
            let mut keys = SslEchKeys::builder().unwrap();
            let hpke = boring::hpke::HpkeKey::dhkem_p256_sha256(&priv_raw).unwrap();
            keys.add_key(true, &config_bytes, hpke).unwrap();
            builder.set_ech_keys(&keys.build()).unwrap();
            Ok(())
        })
        .unwrap();

        let server = async move {
            let (sock, _) = listener.accept().await.unwrap();
            match acceptor.accept(sock).await {
                Ok(tls) => {
                    // With ECH accepted, servername() must be the INNER name the
                    // client protected, not the public/outer name.
                    assert_eq!(tls.server_name().as_deref(), Some("secret.internal"));
                    Some(tls.ech_accepted())
                }
                Err(e) => {
                    eprintln!("server accept error: {e:?}");
                    None
                }
            }
        };

        let client = async move {
            let mut io = TcpStream::connect(addr).await.unwrap();
            let mut cfg = SslConnector::builder(SslMethod::tls()).unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let conf = cfg.build().configure().unwrap();
            // Inner (real) SNI is the protected name; outer becomes public_name.
            let mut ssl = conf.into_ssl("secret.internal").unwrap();
            ssl.set_ech_config_list(&config_list).unwrap();
            let mut mid = SslStreamBuilder::new(ssl, MemBridge::new()).setup_connect();
            loop {
                match mid.handshake() {
                    Ok(mut s) => {
                        // Flush the client's final flight (Finished) so the
                        // server can complete its handshake.
                        let _ = flush_out(s.get_mut(), &mut io).await;
                        break Some(s.ssl().ech_accepted());
                    }
                    Err(HandshakeError::WouldBlock(mut m)) => {
                        if let Err(e) = flush_out(m.get_mut(), &mut io).await {
                            eprintln!("client flush error: {e:?}");
                            break None;
                        }
                        match fill_in(m.get_mut(), &mut io).await {
                            Ok(true) => {}
                            Ok(false) => {
                                eprintln!("client: server closed during ECH handshake");
                                break None;
                            }
                            Err(e) => {
                                eprintln!("client fill error: {e:?}");
                                break None;
                            }
                        }
                        mid = m;
                    }
                    Err(e) => {
                        eprintln!("client ECH handshake failed: {e}");
                        break None;
                    }
                }
            }
        };

        let (server_ech, client_ech) = monoio::join!(server, client);
        assert_eq!(client_ech, Some(true), "client: ECH should be accepted");
        assert_eq!(server_ech, Some(true), "server: ECH should be accepted");
    }
}
