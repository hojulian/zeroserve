mod boringtls;
mod cli;
mod config;
mod ech;
mod helpers;
mod http;
mod hupwatch;
mod ja4;
mod json;
mod logging;
mod oidc;
mod pack;
mod pool;
mod ratelimit;
mod reload;
mod script;
mod server;
mod shared;
mod site;
mod thread_pool;
mod tls;
mod vmmap;

use std::io::Write;
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::rc::Rc;
use std::sync::{Arc, mpsc as std_mpsc};

use crate::cli::ListenAddr;

use anyhow::{Context, Result};
use clap::Parser;
use futures::channel::mpsc;
use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};
use monoio::{IoUringDriver, RuntimeBuilder};
use nix::mount::MsFlags;
use socket2::{Domain, Protocol, Socket, Type};

use crate::reload::SighupBlocked;
use crate::{
    cli::Cli,
    config::StaticConfig,
    hupwatch::HupWatcher,
    pack::ZEROSERVE_H,
    reload::{ReloadRequest, spawn_coordinator, worker_reload_loop},
    script::{ScriptRuntime, ScriptRuntimeConfig},
    server::amain,
    shared::SharedState,
    site::Site,
    tls::load_tls_if_configured,
};

pub const SERVER_HEADER: &str = "zeroserve";
pub const DEFAULT_INDEX: &str = "index.html";

fn main() -> Result<()> {
    let args = Cli::parse();
    if args.dump_sdk {
        let mut out = std::io::stdout().lock();
        out.write_all(ZEROSERVE_H)?;
        out.flush()?;
        return Ok(());
    }
    if args.gen_ech_key {
        let public_name = args
            .ech_public_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--gen-ech-key requires --ech-public-name"))?;
        ech::keygen::run(public_name)?;
        return Ok(());
    }
    if let Some(pack_root) = args.pack.as_ref() {
        pack::pack_site(pack_root)?;
        return Ok(());
    }
    let config = Arc::new(StaticConfig::try_from(args)?);

    let fdlimit =
        rlimit::increase_nofile_limit(1048576).with_context(|| "failed to raise fd limit")?;
    eprintln!("fd limit {}", fdlimit);

    let threads = config.threads;

    // One listener per worker. This must happen before namespace isolation and
    // capability dropping so sockets bind in the caller's network namespace and
    // privileged ports remain possible.
    let http_listeners = create_worker_listeners(&config.http_addr, threads)
        .with_context(|| format!("failed to create HTTP listeners for {}", config.http_addr))?;
    let tls_listeners: Vec<Option<TcpListener>> = match &config.tls_addr {
        Some(addr) => create_worker_listeners(addr, threads)
            .with_context(|| format!("failed to create TLS listeners for {}", addr))?
            .into_iter()
            .map(Some)
            .collect(),
        None => (0..threads).map(|_| None).collect(),
    };

    // Build the reverse-proxy TLS client now, before namespace isolation turns
    // /etc into an empty tmpfs — the CA bundle must be read while it's still on
    // disk. Best-effort: HTTP proxying and serving still work without it; only
    // HTTPS upstreams would fail.
    match boringtls::init_client_from_system_roots() {
        Ok(()) => {}
        Err(err) => eprintln!("warning: {err}"),
    }

    if !config.disable_ns_isolation {
        setup_ns_isolation(&config).with_context(
            || "failed to set up namespace isolation (set --disable-ns-isolation to disable)",
        )?;

        let resolv_conf = std::fs::read("/etc/resolv.conf").ok();

        nix::mount::mount(
            None::<&str>,
            "/etc",
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| "failed to mount virtual /etc")?;

        if let Some(x) = &resolv_conf {
            std::fs::write("/etc/resolv.conf", x)
                .with_context(|| "failed to write /etc/resolv.conf in tmpfs")?;
        }

        drop_all_capabilities().with_context(|| "failed to drop capabilities")?;

        if let Err(err) = rlimit::Resource::NPROC.set(1024, 1024) {
            eprintln!("failed to restrict nproc: {:?}", err);
        }

        eprintln!(
            "isolation: ns_user=y, ns_net={}, ns_mount=y; caps, nproc",
            if config.enable_netns_isolation {
                "y"
            } else {
                "n"
            }
        );
    }

    setup_landlock(&config).with_context(|| "failed to setup landlock")?;
    eprintln!("enabled landlock");

    // Block SIGHUP early before spawning any threads
    let sighup_blocked = SighupBlocked::new();

    let plugin_sites = load_plugin_sites(&config)?;
    let site = Arc::new(Site::load(&config.tar_path, config.max_rate_limit_buckets)?);
    eprintln!(
        "loaded {} entries from {} ({} bytes)",
        site.total_entries,
        config.tar_path.display(),
        site.total_bytes
    );

    let tls_runtime = load_tls_if_configured(&config)?;
    if tls_runtime.is_some() {
        eprintln!("TLS enabled");
    }

    let vm_map = match &config.vm_map_file {
        Some(path) => {
            let map = vmmap::load_vm_map(path)?;
            eprintln!("loaded vm map from {} ({} entries)", path.display(), map.len());
            vmmap::spawn_vm_map_watcher(path.clone(), map.clone());
            Some(map)
        }
        None => None,
    };

    eprintln!(
        "async preemption timer interval: {:?}",
        config.preempt_timer_interval
    );

    let shared = Arc::new(SharedState::new(
        config.clone(),
        site,
        plugin_sites,
        tls_runtime,
        vm_map,
    ));

    // One reload channel per worker. The coordinator stages reloads on these:
    // the first worker acts as the canary, the rest are notified only after it
    // succeeds.
    #[allow(clippy::type_complexity)]
    let (reload_txs, reload_rxs): (
        Vec<mpsc::UnboundedSender<ReloadRequest>>,
        Vec<mpsc::UnboundedReceiver<ReloadRequest>>,
    ) = (0..threads).map(|_| mpsc::unbounded()).unzip();

    // The coordinator owns reload + rate-limit cleanup on its own thread.
    spawn_coordinator(shared.clone(), reload_txs, sighup_blocked)?;

    eprintln!(
        "listening on http://{} ({} worker thread(s))",
        config.http_addr, threads
    );
    if let Some(addr) = &config.tls_addr {
        eprintln!("listening on https://{}", addr);
    }

    let mut handles = Vec::with_capacity(threads);
    let (startup_tx, startup_rx) = std_mpsc::channel();
    for (i, ((http_listener, tls_listener), reload_rx)) in http_listeners
        .into_iter()
        .zip(tls_listeners)
        .zip(reload_rxs)
        .enumerate()
    {
        let shared = shared.clone();
        let config = config.clone();
        let startup_tx = startup_tx.clone();
        let handle = std::thread::Builder::new()
            .name(format!("worker-{i}"))
            .spawn(move || {
                if let Err(err) = run_worker(
                    i,
                    config,
                    shared,
                    http_listener,
                    tls_listener,
                    reload_rx,
                    startup_tx,
                ) {
                    eprintln!("worker {i} exited with error: {err:?}");
                }
            })
            .with_context(|| format!("failed to spawn worker thread {i}"))?;
        handles.push(handle);
    }
    drop(startup_tx);

    for _ in 0..threads {
        let (i, result) = startup_rx
            .recv()
            .with_context(|| "worker startup channel closed before all workers initialized")?;
        if let Err(err) = result {
            return Err(anyhow::anyhow!("worker {i} failed to start: {err}"));
        }
    }

    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/// Run a single worker: build a dedicated monoio runtime, create this thread's
/// own eBPF `ScriptRuntime`, compile its scripts, and serve its listeners. Each
/// worker is fully isolated — programs are pinned to this thread and never
/// shared.
fn run_worker(
    worker_id: usize,
    config: Arc<StaticConfig>,
    shared: Arc<SharedState>,
    http_listener: TcpListener,
    tls_listener: Option<TcpListener>,
    reload_rx: mpsc::UnboundedReceiver<ReloadRequest>,
    startup_tx: std_mpsc::Sender<(usize, Result<(), String>)>,
) -> Result<()> {
    let mut urb = io_uring::IoUring::builder();
    urb.setup_single_issuer();
    if let Some(ms) = config.sqpoll_idle_ms {
        urb.setup_sqpoll(ms);
    }

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .uring_builder(urb)
        .build()
        .expect("zeroserve: failed to build io_uring runtime")
        .block_on(async move {
            // SAFETY: GlobalEnv::new() is idempotent (Once-guarded) and
            // init_thread() sets up this thread's preemption watcher; both are
            // safe to call once per worker thread.
            let script_runtime = unsafe {
                ScriptRuntime::new(ScriptRuntimeConfig {
                    preempt_timer_interval: config.preempt_timer_interval,
                    max_memory_footprint: config.max_request_external_memory_footprint,
                })
            };
            let script_runtime = Rc::new(script_runtime);

            // Per-worker hangup watcher (spawns its task on this runtime).
            let hup = HupWatcher::new();

            let sites = shared.collect_sites();
            let scripts = match script_runtime.load_scripts_from_sites(&sites).await {
                Ok(scripts) => scripts,
                Err(err) => {
                    let err = err.context("failed to load scripts");
                    let _ = startup_tx.send((worker_id, Err(format!("{err:?}"))));
                    return Err(err);
                }
            };
            script_runtime.install_scripts(scripts);
            let _ = startup_tx.send((worker_id, Ok(())));

            monoio::spawn(worker_reload_loop(script_runtime.clone(), reload_rx));

            amain(shared, script_runtime, hup, http_listener, tls_listener).await
        })
}

fn load_plugin_sites(config: &StaticConfig) -> Result<Vec<Arc<Site>>> {
    let mut sites = Vec::with_capacity(config.plugin_paths.len());
    for plugin_path in &config.plugin_paths {
        let site = Arc::new(Site::load(plugin_path, config.max_rate_limit_buckets)?);
        eprintln!(
            "loaded {} entries from plugin {} ({} bytes)",
            site.total_entries,
            plugin_path.display(),
            site.total_bytes
        );
        sites.push(site);
    }
    Ok(sites)
}

fn setup_landlock(config: &StaticConfig) -> anyhow::Result<()> {
    let abi = landlock::ABI::V2;
    let access_read = AccessFs::ReadFile;
    let access_all = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default().handle_access(access_all)?.create()?;
    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/")?, access_read))?;

    // The broad rule above grants ReadFile everywhere but not ReadDir. Directory
    // based TLS and ECH configuration need enumeration on reload.
    if let Some(cert_dir) = &config.cert_dir_path {
        ruleset = ruleset.add_rule(PathBeneath::new(
            PathFd::new(cert_dir)?,
            AccessFs::ReadFile | AccessFs::ReadDir,
        ))?;
    }
    if let Some(ech_path) = &config.ech_key_path {
        let meta = std::fs::metadata(ech_path)
            .with_context(|| format!("stat ECH key path {}", ech_path.display()))?;
        if meta.is_dir() {
            ruleset = ruleset.add_rule(PathBeneath::new(
                PathFd::new(ech_path)?,
                AccessFs::ReadFile | AccessFs::ReadDir,
            ))?;
        }
    }

    ruleset.restrict_self()?;
    Ok(())
}

fn setup_ns_isolation(config: &StaticConfig) -> anyhow::Result<()> {
    unsafe {
        let uid = libc::getuid();
        let gid = libc::getgid();

        let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
        if config.enable_netns_isolation {
            flags |= libc::CLONE_NEWNET;
        }

        if libc::unshare(flags) != 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()).context("unshare"));
        }
        std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid))
            .with_context(|| "write uid_map")?;
        std::fs::write("/proc/self/setgroups", "deny\n").with_context(|| "write setgroups")?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid))
            .with_context(|| "write gid_map")?;
    }
    Ok(())
}

/// Create one listener per worker thread for the given address.
///
/// For a bound socket address, each worker gets its own `SO_REUSEPORT` socket so
/// the kernel hash-balances incoming connections across the workers. For an
/// inherited file descriptor (e.g. systemd socket activation) the single socket
/// cannot be re-bound, so each worker receives its own `dup`'d descriptor and
/// the kernel hands each accepted connection to exactly one worker.
fn create_worker_listeners(addr: &ListenAddr, count: usize) -> Result<Vec<TcpListener>> {
    match addr {
        ListenAddr::Socket(socket_addr) => {
            let mut listeners = Vec::with_capacity(count);
            for _ in 0..count {
                let socket = Socket::new(
                    Domain::for_address(*socket_addr),
                    Type::STREAM,
                    Some(Protocol::TCP),
                )?;
                socket.set_reuse_address(true)?;
                socket.set_reuse_port(true)?;
                socket.set_nonblocking(true)?;
                socket.bind(&(*socket_addr).into())?;
                socket.listen(1024)?;
                listeners.push(socket.into());
            }
            Ok(listeners)
        }
        ListenAddr::Fd(fd) => {
            let mut listeners = Vec::with_capacity(count);
            for _ in 0..count {
                // SAFETY: the caller guarantees `fd` is a valid listening socket
                // (socket activation). dup gives each worker an independent
                // descriptor referencing the same underlying socket.
                let duped = unsafe { libc::dup(*fd) };
                if duped < 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("failed to dup inherited fd {fd}"));
                }
                let listener = unsafe { TcpListener::from_raw_fd(duped) };
                listener.set_nonblocking(true)?;
                listeners.push(listener);
            }
            Ok(listeners)
        }
    }
}

pub fn drop_all_capabilities() -> Result<(), caps::errors::CapsError> {
    use caps::CapSet;

    // Order matters: clear Bounding/Ambient first while we may still have CAP_SETPCAP.
    caps::clear(None, CapSet::Bounding)?;
    caps::clear(None, CapSet::Ambient)?;

    // Then clear the traditional POSIX sets.
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Effective)?;

    Ok(())
}
