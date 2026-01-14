use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use futures::{
    StreamExt,
    channel::{mpsc, oneshot},
};
use signal_hook::{consts::signal::SIGHUP, iterator::Signals};

use crate::{
    script::ScriptRuntime, shared::SharedState, site::Site, thread_pool::CPU_TP,
    tls::load_tls_if_configured,
};

pub fn start_reload_thread(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
) -> Result<()> {
    let mut signals = Signals::new([SIGHUP]).context("failed to register SIGHUP handler")?;
    let reload_signal_file = shared.config.reload_signal_file.clone();
    let (mut signal_tx, signal_rx) = mpsc::channel(1);
    thread::Builder::new()
        .name("zs-sigwatch".into())
        .spawn(move || {
            for _ in signals.forever() {
                let _ = signal_tx.try_send(());
            }
        })
        .expect("start_reload_thread: failed to spawn signal watcher");
    monoio::spawn(reload_task(
        shared,
        script_runtime,
        reload_signal_file,
        signal_rx,
    ));
    Ok(())
}

async fn reload_task(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    path: Option<PathBuf>,
    mut signal_rx: mpsc::Receiver<()>,
) {
    let (mut file_tx, mut file_rx) = mpsc::channel(1);
    if let Some(path) = path {
        monoio::spawn(async move {
            let mut last_signal_contents = read_signal_file(path.as_path()).await;
            loop {
                monoio::time::sleep(Duration::from_secs(5)).await;
                if let Some(contents) = read_signal_file(path.as_path()).await {
                    if last_signal_contents.as_ref() != Some(&contents) {
                        last_signal_contents = Some(contents);
                        let _ = file_tx.try_send(());
                    }
                }
            }
        });
    } else {
        std::mem::forget(file_tx);
    }
    loop {
        let sig = monoio::select! {
            x = signal_rx.next() => x,
            x = file_rx.next() => x,
        };
        if sig.is_none() {
            panic!("signal watcher exited unexpectedly");
        }
        if let Err(err) = reload_assets(&shared, &script_runtime).await {
            eprintln!("reload failed: {err:?}");
        }
    }
}

async fn read_signal_file(path: &Path) -> Option<Vec<u8>> {
    monoio::fs::read(path).await.ok()
}

async fn reload_assets(
    shared: &Arc<SharedState>,
    script_runtime: &Rc<ScriptRuntime>,
) -> Result<()> {
    eprintln!("reloading site and TLS assets");
    let (tx, rx) = oneshot::channel();
    CPU_TP.with(|tp| {
        let shared = shared.clone();
        tp.spawn(move || {
            let _ = tx.send(Site::load(&shared.config.tar_path).map(Arc::new));
        });
    });
    let site = rx.await.unwrap()?;
    shared.site.store(site.clone());
    eprintln!("reloaded tarball {}", shared.config.tar_path.display());
    match script_runtime.reload(site).await {
        Ok(()) => eprintln!("reloaded scripts"),
        Err(err) => eprintln!("failed to reload scripts: {err:?}"),
    }

    match load_tls_if_configured(&shared.config) {
        Ok(runtime_opt) => {
            let tls_present = runtime_opt.is_some();
            shared
                .tls
                .store(runtime_opt.map(|runtime| Arc::new(runtime)));
            if tls_present {
                eprintln!("reloaded TLS configuration");
            }
        }
        Err(err) => eprintln!("TLS reload failed: {err:?}"),
    }
    Ok(())
}
