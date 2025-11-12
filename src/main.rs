mod cli;
mod config;
mod reload;
mod server;
mod shared;
mod site;
mod tls;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use monoio::{IoUringDriver, RuntimeBuilder};
use rustls::crypto::aws_lc_rs;

use crate::{
    cli::Cli, config::StaticConfig, reload::start_reload_thread, server::amain,
    shared::SharedState, site::Site, tls::load_tls_if_configured,
};

pub const SERVER_HEADER: &str = "zeroserve";
pub const DEFAULT_INDEX: &str = "index.html";

fn main() -> Result<()> {
    aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc provider");

    let args = Cli::parse();
    let config = Arc::new(StaticConfig::try_from(args)?);

    let site = Site::load(&config.tar_path)?;
    eprintln!(
        "[zeroserve] loaded {} entries from {} ({} bytes)",
        site.total_entries,
        config.tar_path.display(),
        site.total_bytes
    );

    let tls_runtime = load_tls_if_configured(&config)?;
    if tls_runtime.is_some() {
        eprintln!("[zeroserve] TLS enabled");
    }

    let shared = Arc::new(SharedState::new(config.clone(), site, tls_runtime));
    start_reload_thread(shared.clone())?;

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("zeroserve: failed to build io_uring runtime")
        .block_on(async move { amain(shared).await })
}
