mod cli;
mod config;
mod hupwatch;
mod json;
mod logging;
mod pack;
mod pool;
mod reload;
mod script;
mod server;
mod shared;
mod site;
mod thread_pool;
mod tls;

use std::net::TcpListener;
use std::rc::Rc;
use std::sync::Arc;
use std::{collections::HashSet, io::Write};

use anyhow::{Context, Result};
use clap::Parser;
use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};
use monoio::{IoUringDriver, RuntimeBuilder};
use nix::mount::MsFlags;
use rustls::crypto::aws_lc_rs;

use crate::{
    cli::Cli,
    config::StaticConfig,
    pack::ZEROSERVE_H,
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
    aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc provider");

    let args = Cli::parse();
    if args.dump_sdk {
        let mut out = std::io::stdout().lock();
        out.write_all(ZEROSERVE_H)?;
        out.flush()?;
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

    let http_listener = TcpListener::bind(&config.http_addr)
        .with_context(|| format!("failed to bind HTTP listener on {}", config.http_addr))?;
    let tls_listener = if let Some(x) = &config.tls_addr {
        Some(
            TcpListener::bind(x)
                .with_context(|| format!("failed to bind TLS listener on {}", x))?,
        )
    } else {
        None
    };

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

    let site = Arc::new(Site::load(&config.tar_path)?);
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
            let script_runtime = unsafe {
                ScriptRuntime::new(ScriptRuntimeConfig {
                    preempt_timer_interval: config.preempt_timer_interval,
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
            start_reload_thread(shared.clone(), script_runtime.clone())?;

            amain(shared, script_runtime).await
        })
}

fn setup_landlock(config: &StaticConfig) -> anyhow::Result<()> {
    let abi = landlock::ABI::V2;
    let access_read = AccessFs::ReadFile;
    let access_all = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default().handle_access(access_all)?.create()?;
    if let Ok(x) = PathFd::new("/etc/resolv.conf") {
        ruleset = ruleset.add_rule(PathBeneath::new(x, access_read))?;
    }

    let mut ro_paths = HashSet::new();

    if let Some(x) = config.tar_path.parent() {
        ro_paths.insert(x);
    }

    if let Some(x) = &config.cert_path {
        if let Some(x) = x.parent() {
            ro_paths.insert(x);
        }
    }

    if let Some(x) = &config.key_path {
        if let Some(x) = x.parent() {
            ro_paths.insert(x);
        }
    }

    if let Some(x) = &config.reload_signal_file {
        if let Some(x) = x.parent() {
            ro_paths.insert(x);
        }
    }

    for x in ro_paths {
        ruleset = ruleset.add_rule(PathBeneath::new(
            PathFd::new(x)
                .with_context(|| format!("failed to open for landlock: {}", x.display()))?,
            access_read,
        ))?
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
