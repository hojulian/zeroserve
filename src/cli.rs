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

    /// Pack a directory to stdout as a site tarball.
    #[arg(long, value_name = "DIR", conflicts_with = "tarball")]
    pub pack: Option<PathBuf>,

    /// Dump the embedded SDK header to stdout.
    #[arg(long, conflicts_with_all = ["pack", "tarball"])]
    pub dump_sdk: bool,

    /// Path to the site tarball.
    #[arg(
        value_name = "SITE_TAR",
        required_unless_present_any = ["pack", "dump_sdk"],
        conflicts_with = "pack"
    )]
    pub tarball: Option<PathBuf>,

    /// Path to a signal file; polled every second, reloads when content changes.
    #[arg(long, value_name = "FILE")]
    pub reload_signal_file: Option<PathBuf>,

    /// Disable per-request logging.
    #[arg(long)]
    pub disable_request_logging: bool,

    /// Expect a PROXY protocol v1 header before the first request on each connection.
    #[arg(long)]
    pub enable_proxy_protocol: bool,

    /// Disable Linux namespace isolation.
    #[arg(long)]
    pub disable_ns_isolation: bool,

    /// Enable Linux network namespace isolation.
    #[arg(long, conflicts_with = "disable_ns_isolation")]
    pub enable_netns_isolation: bool,

    /// eBPF async preemption timer interval.
    #[arg(long, default_value_t = 2, value_parser = must_be_positive)]
    pub preempt_timer_interval_ms: usize,

    /// Enable io_uring sqpoll with the provided idle timeout.
    #[arg(long)]
    pub sqpoll_idle_ms: Option<u32>,

    /// Disable proxy protocol decoding fast path for debugging.
    #[arg(long)]
    pub debug_proxy_protocol_disable_fast_path: bool,
}
