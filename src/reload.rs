use std::{sync::Arc, thread};

use anyhow::{Context, Result};
use signal_hook::{consts::signal::SIGHUP, iterator::Signals};

use crate::{shared::SharedState, site::Site, tls::load_tls_if_configured};

pub fn start_reload_thread(shared: Arc<SharedState>) -> Result<()> {
    let mut signals = Signals::new([SIGHUP]).context("failed to register SIGHUP handler")?;
    thread::Builder::new()
        .name("zeroserve-reload".into())
        .spawn(move || {
            for _ in signals.forever() {
                if let Err(err) = reload_assets(&shared) {
                    eprintln!("[zeroserve] reload failed: {err:?}");
                }
            }
        })
        .context("failed to spawn reload thread")?;
    Ok(())
}

fn reload_assets(shared: &Arc<SharedState>) -> Result<()> {
    eprintln!("[zeroserve] reloading site and TLS assets");
    let site = Site::load(&shared.config.tar_path)?;
    shared.site.store(Arc::new(site));
    eprintln!(
        "[zeroserve] reloaded tarball {}",
        shared.config.tar_path.display()
    );

    match load_tls_if_configured(&shared.config) {
        Ok(runtime_opt) => {
            let tls_present = runtime_opt.is_some();
            shared
                .tls
                .store(runtime_opt.map(|runtime| Arc::new(runtime)));
            if tls_present {
                eprintln!("[zeroserve] reloaded TLS configuration");
            }
        }
        Err(err) => eprintln!("[zeroserve] TLS reload failed: {err:?}"),
    }
    Ok(())
}
