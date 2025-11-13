use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

pub fn must_be_positive(value: &str) -> Result<usize, String> {
    let parsed: usize = value.parse().map_err(|e| format!("invalid number: {e}"))?;
    if parsed == 0 {
        Err("value must be greater than zero".into())
    } else {
        Ok(parsed)
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Address (ip:port) to bind the HTTP server to.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub addr: SocketAddr,

    /// Optional HTTPS address (ip:port). Requires --cert and --key.
    #[arg(long)]
    pub tls_addr: Option<SocketAddr>,

    /// TLS certificate (PEM).
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// TLS private key (PEM).
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Default document to serve from directories.
    #[arg(long, default_value_t = String::from(crate::DEFAULT_INDEX))]
    pub index: String,

    /// Maximum chunk size (bytes) for streaming tarball reads.
    #[arg(long, default_value_t = 64 * 1024, value_parser = must_be_positive)]
    pub chunk_size: usize,

    /// Try serving <path>.html when the requested path is missing.
    #[arg(long)]
    pub try_html: bool,

    /// Path to the site tarball.
    #[arg(value_name = "SITE_TAR")]
    pub tarball: PathBuf,

    /// Disable per-request logging.
    #[arg(long)]
    pub disable_request_logging: bool,

    /// Expect a PROXY protocol v1 header before the first request on each connection.
    #[arg(long)]
    pub enable_proxy_protocol: bool,
}
