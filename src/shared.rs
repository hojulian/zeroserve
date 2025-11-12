use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};

use crate::{config::StaticConfig, site::Site, tls::TlsRuntime};

pub struct SharedState {
    pub config: Arc<StaticConfig>,
    pub site: ArcSwap<Site>,
    pub tls: ArcSwapOption<TlsRuntime>,
}

impl SharedState {
    pub fn new(config: Arc<StaticConfig>, site: Site, tls: Option<TlsRuntime>) -> Self {
        Self {
            config,
            site: ArcSwap::from_pointee(site),
            tls: ArcSwapOption::from(tls.map(Arc::new)),
        }
    }
}
