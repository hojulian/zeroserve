use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Result, anyhow};

use crate::cli::Cli;

pub struct StaticConfig {
    pub http_addr: SocketAddr,
    pub tls_addr: Option<SocketAddr>,
    pub tar_path: PathBuf,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub index_file: String,
    pub chunk_size: usize,
    pub try_html: bool,
    pub disable_request_logging: bool,
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
            let addr = cli
                .tls_addr
                .ok_or_else(|| anyhow!("--tls-addr is required when enabling TLS"))?;
            (Some(addr), Some(cert), Some(key))
        } else {
            (None, None, None)
        };

        let index_file = if cli.index.is_empty() {
            crate::DEFAULT_INDEX.to_string()
        } else {
            cli.index
        };

        Ok(Self {
            http_addr,
            tls_addr,
            tar_path: cli.tarball,
            cert_path,
            key_path,
            index_file,
            chunk_size: cli.chunk_size.max(1024),
            try_html: cli.try_html,
            disable_request_logging: cli.disable_request_logging,
        })
    }
}
