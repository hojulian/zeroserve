use std::{
    os::fd::FromRawFd,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures::{
    StreamExt,
    channel::{mpsc, oneshot},
};
use monoio::{fs::File, io::AsyncReadRentExt};

use crate::{
    script::ScriptRuntime, shared::SharedState, site::Site, thread_pool::CPU_TP,
    tls::load_tls_if_configured,
};

pub struct SighupBlocked {
    mask: libc::sigset_t,
}

impl SighupBlocked {
    pub fn new() -> Self {
        let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGHUP);
            libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut());
        }
        Self { mask }
    }
}
pub fn start_reload_thread(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    sighup_blocked: SighupBlocked,
) -> Result<()> {
    let reload_signal_file = shared.config.reload_signal_file.clone();

    // Create signalfd for SIGHUP
    let sfd = unsafe { libc::signalfd(-1, &sighup_blocked.mask, libc::SFD_CLOEXEC) };
    if sfd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create signalfd");
    }

    let sfile = unsafe {
        File::from_std(std::fs::File::from_raw_fd(sfd)).context("failed to wrap signalfd")?
    };

    monoio::spawn(reload_task(
        shared,
        script_runtime,
        reload_signal_file,
        sfile,
    ));
    Ok(())
}

async fn reload_task(
    shared: Arc<SharedState>,
    script_runtime: Rc<ScriptRuntime>,
    path: Option<PathBuf>,
    mut sfile: File,
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
        monoio::select! {
            _ = wait_for_signal(&mut sfile) => {},
            x = file_rx.next() => {
                if x.is_none() {
                    panic!("file watcher exited unexpectedly");
                }
            },
        }
        if let Err(err) = reload_assets(&shared, &script_runtime).await {
            eprintln!("reload failed: {err:?}");
        }
    }
}

async fn wait_for_signal(sfile: &mut File) {
    let (res, _) = sfile
        .read_exact(Vec::with_capacity(std::mem::size_of::<
            libc::signalfd_siginfo,
        >()))
        .await;
    res.expect("signalfd read");
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
