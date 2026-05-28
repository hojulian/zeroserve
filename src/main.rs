mod boringtls;
mod cli;
mod config;
mod ech;
mod helpers;
mod http;
mod hupwatch;
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

use std::io::Write;
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::rc::Rc;
use std::sync::Arc;

use crate::cli::ListenAddr;

use anyhow::{Context, Result};
use clap::Parser;
use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};
use monoio::{IoUringDriver, RuntimeBuilder};
use nix::mount::MsFlags;

use crate::reload::SighupBlocked;
use crate::{
    cli::Cli,
    config::StaticConfig,
    pack::ZEROSERVE_H,
    ratelimit::spawn_cleanup_task,
    reload::start_reload_thread,
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

    let http_listener = create_listener(&config.http_addr)
        .with_context(|| format!("failed to create HTTP listener for {}", config.http_addr))?;
    let tls_listener = if let Some(x) = &config.tls_addr {
        Some(
            create_listener(x)
                .with_context(|| format!("failed to create TLS listener for {}", x))?,
        )
    } else {
        None
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

    let mut urb = io_uring::IoUring::builder();
    urb.setup_single_issuer();
    if let Some(ms) = config.sqpoll_idle_ms {
        urb.setup_sqpoll(ms);
        eprintln!("io_uring sqpoll enabled with idle timeout {}ms", ms);
    }

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .uring_builder(urb)
        .build()
        .expect("zeroserve: failed to build io_uring runtime")
        .block_on(async move {
            // Spawn background task to clean up expired rate limit buckets
            spawn_cleanup_task(site.rate_limit_manager.clone());

            let script_runtime = unsafe {
                ScriptRuntime::new(ScriptRuntimeConfig {
                    preempt_timer_interval: config.preempt_timer_interval,
                    max_memory_footprint: config.max_request_external_memory_footprint,
                })
            };
            let script_runtime = Rc::new(script_runtime);
            eprintln!(
                "async preemption timer interval: {:?}",
                config.preempt_timer_interval
            );

            script_runtime
                .reload(site.clone())
                .await
                .with_context(|| "failed to load scripts")?;

            let shared = Arc::new(SharedState::new(
                config.clone(),
                site,
                tls_runtime,
                http_listener,
                tls_listener,
            ));
            start_reload_thread(shared.clone(), script_runtime.clone(), sighup_blocked)?;

            amain(shared, script_runtime).await
        })
}

fn setup_landlock(config: &StaticConfig) -> anyhow::Result<()> {
    let abi = landlock::ABI::V2;
    let access_read = AccessFs::ReadFile;
    let access_all = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default().handle_access(access_all)?.create()?;
    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/")?, access_read))?;

    // The broad rule above grants ReadFile everywhere but not ReadDir. When
    // --ech-key points at a directory we need to enumerate it (file-mode is
    // already covered by ReadFile).
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

fn create_listener(addr: &ListenAddr) -> std::io::Result<TcpListener> {
    match addr {
        ListenAddr::Socket(socket_addr) => TcpListener::bind(socket_addr),
        ListenAddr::Fd(fd) => {
            // SAFETY: The caller is responsible for ensuring the fd is a valid TCP listener socket.
            // This is typically used for socket activation (e.g., systemd) where the parent process
            // passes a pre-bound socket to the child.
            let listener = unsafe { TcpListener::from_raw_fd(*fd) };
            // Set non-blocking mode since we're using async I/O
            listener.set_nonblocking(true)?;
            Ok(listener)
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
