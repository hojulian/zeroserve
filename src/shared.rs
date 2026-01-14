use std::{
    io,
    sync::{Arc, Mutex},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use std::net::TcpListener;

use monoio::fs::File;

use crate::{
    config::StaticConfig,
    hupwatch::HupWatcher,
    site::{Site, TarEntry},
    tls::TlsRuntime,
};

pub struct SharedState {
    pub config: Arc<StaticConfig>,
    pub site: ArcSwap<Site>,
    pub tls: ArcSwapOption<TlsRuntime>,
    pub http_listener: Mutex<Option<TcpListener>>,
    pub tls_listener: Mutex<Option<TcpListener>>,
    pub hup: Arc<HupWatcher>,
}

impl SharedState {
    pub fn new(
        config: Arc<StaticConfig>,
        site: Arc<Site>,
        tls: Option<TlsRuntime>,
        http_listener: TcpListener,
        tls_listener: Option<TcpListener>,
    ) -> Self {
        Self {
            config,
            site: ArcSwap::new(site),
            tls: ArcSwapOption::from(tls.map(Arc::new)),
            http_listener: Mutex::new(Some(http_listener)),
            tls_listener: Mutex::new(tls_listener),
            hup: HupWatcher::new(),
        }
    }
}

pub async fn read_tar_entry(entry: Arc<TarEntry>, site: &Arc<Site>) -> io::Result<Vec<u8>> {
    let file = site.tar_file.try_clone().and_then(File::from_std)?;
    let size =
        usize::try_from(entry.size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let (res, buf) = file.read_exact_at(vec![0u8; size], entry.offset).await;
    res?;
    Ok(buf)
}
