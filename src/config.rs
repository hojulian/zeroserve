use std::{path::PathBuf, time::Duration};

use anyhow::{Result, anyhow};

use crate::cli::{Cli, ListenAddr};

pub struct StaticConfig {
    pub http_addr: ListenAddr,
    pub tls_addr: Option<ListenAddr>,
    pub tar_path: PathBuf,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub reload_signal_file: Option<PathBuf>,
    pub index_file: String,
    pub chunk_size: usize,
    pub try_html: bool,
    pub disable_request_logging: bool,
    pub enable_proxy_protocol: bool,
    pub disable_ns_isolation: bool,
    pub enable_netns_isolation: bool,
    pub preempt_timer_interval: Duration,
    pub sqpoll_idle_ms: Option<u32>,
    pub debug_proxy_protocol_disable_fast_path: bool,
    pub max_buffered_body_size: usize,
    pub max_request_external_memory_footprint: u64,
    pub max_rate_limit_buckets: usize,
    pub validate_hostnames: Vec<String>,
}

impl TryFrom<Cli> for StaticConfig {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self> {
        let http_addr = cli.addr;
        let tls_requested = cli.tls_addr.is_some() || cli.cert.is_some() || cli.key.is_some();
        let (tls_addr, cert_path, key_path) = if tls_requested {
            let cert = cli
                .cert
                .clone()
                .ok_or_else(|| anyhow!("--cert is required when enabling TLS"))?;
            let key = cli
                .key
                .clone()
                .ok_or_else(|| anyhow!("--key is required when enabling TLS"))?;
            let tls_addr = cli
                .tls_addr
                .ok_or_else(|| anyhow!("--tls-addr is required when enabling TLS"))?;
            (Some(tls_addr), Some(cert), Some(key))
        } else {
            (None, None, None)
        };

        let index_file = if cli.index.is_empty() {
            crate::DEFAULT_INDEX.to_string()
        } else {
            cli.index
        };

        let tar_path = cli
            .tarball
            .ok_or_else(|| anyhow!("SITE_TAR is required unless --pack or --dump-sdk is used"))?;

        Ok(Self {
            http_addr,
            tls_addr,
            tar_path,
            cert_path,
            key_path,
            reload_signal_file: cli.reload_signal_file,
            index_file,
            chunk_size: cli.chunk_size.max(1024),
            try_html: cli.try_html,
            disable_request_logging: cli.disable_request_logging,
            enable_proxy_protocol: cli.enable_proxy_protocol,
            disable_ns_isolation: cli.disable_ns_isolation,
            preempt_timer_interval: Duration::from_millis(cli.preempt_timer_interval_ms as u64),
            sqpoll_idle_ms: cli.sqpoll_idle_ms,
            enable_netns_isolation: cli.enable_netns_isolation,
            debug_proxy_protocol_disable_fast_path: cli.debug_proxy_protocol_disable_fast_path,
            max_buffered_body_size: cli.max_buffered_body_size_kb * 1024,
            max_request_external_memory_footprint: (cli.max_request_external_memory_footprint_kb
                * 1024) as u64,
            max_rate_limit_buckets: cli.max_rate_limit_buckets,
            validate_hostnames: cli.validate_hostnames,
        })
    }
}
