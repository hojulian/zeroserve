use std::{
    cell::RefCell,
    io,
    rc::Rc,
    sync::{Arc, Weak},
};

use arc_swap::{ArcSwap, ArcSwapOption};

use monoio::{
    fs::File,
    io::{AsyncWriteRent, AsyncWriteRentExt},
};

use crate::{
    config::StaticConfig,
    site::{Site, TarEntry},
    tls::TlsRuntime,
    kv_map::KvMap,
};

/// State shared across all worker event loops. Everything here is `Send + Sync`
/// and accessed concurrently from every worker thread. Per-thread state (the
/// monoio runtime, the eBPF `ScriptRuntime`, the TCP listeners, and the hangup
/// watcher) lives in the workers themselves, not here.
pub struct SharedState {
    pub config: Arc<StaticConfig>,
    pub site: ArcSwap<Site>,
    /// Plugin sites whose scripts run before the main site's scripts. Stored so
    /// each worker can recompile them on reload without re-reading the CLI.
    pub plugin_sites: ArcSwap<Vec<Arc<Site>>>,
    pub tls: ArcSwapOption<TlsRuntime>,
    /// Hot-reloadable string→string key-value map, populated from `--kv-map-file`.
    pub kv_map: ArcSwapOption<KvMap>,
}

impl SharedState {
    pub fn new(
        config: Arc<StaticConfig>,
        site: Arc<Site>,
        plugin_sites: Vec<Arc<Site>>,
        tls: Option<TlsRuntime>,
        kv_map: Option<Arc<KvMap>>,
    ) -> Self {
        Self {
            config,
            site: ArcSwap::new(site),
            plugin_sites: ArcSwap::new(Arc::new(plugin_sites)),
            tls: ArcSwapOption::from(tls.map(Arc::new)),
            kv_map: ArcSwapOption::from(kv_map),
        }
    }

    /// The ordered list of sites whose scripts a worker should compile and run:
    /// plugin sites first, then the main site. Matches the original startup
    /// ordering and is recomputed from the latest hot-reloaded assets.
    pub fn collect_sites(&self) -> Vec<Arc<Site>> {
        let plugins = self.plugin_sites.load_full();
        let site = self.site.load_full();
        plugins
            .iter()
            .cloned()
            .chain(std::iter::once(site))
            .collect()
    }
}

thread_local! {
    static TAR_FILE_CACHE: RefCell<Vec<(Weak<Site>, Rc<File>)>> = RefCell::new(Vec::new());
}

pub(crate) fn get_tar_file(site: &Arc<Site>) -> io::Result<Rc<File>> {
    TAR_FILE_CACHE.with(|x| {
        let mut x = x.borrow_mut();
        x.retain(|x| x.0.strong_count() != 0);
        let site_weak = Arc::downgrade(site);
        if let Some(x) = x.iter().find(|x| x.0.ptr_eq(&site_weak)) {
            return Ok(x.1.clone());
        }
        let file = match site.tar_file.try_clone() {
            Ok(x) => Rc::new(File::from_std(x).unwrap()),
            Err(e) => {
                eprintln!("failed to create tar handle: {}", e);
                return Err(e);
            }
        };
        x.push((Arc::downgrade(&site), file.clone()));
        Ok(file)
    })
}

pub async fn read_tar_entry(entry: Arc<TarEntry>, site: &Arc<Site>) -> io::Result<Vec<u8>> {
    let file = get_tar_file(site)?;
    let size =
        usize::try_from(entry.size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let (res, buf) = file.read_exact_at(vec![0u8; size], entry.offset).await;
    res?;
    Ok(buf)
}

pub async fn stream_tar_entry(
    entry: Arc<TarEntry>,
    site: &Arc<Site>,
    chunk_size: usize,
    w: &mut impl AsyncWriteRent,
) -> std::io::Result<()> {
    let file = get_tar_file(site)?;
    let mut remaining = entry.size;
    let mut offset = entry.offset;
    let mut buffer = vec![0u8; chunk_size];
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
        let (res, view) = file.read_at(view, offset).await;
        buffer = view.into_inner();
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let view = monoio::buf::Slice::new(buffer, 0, n);
        let (res, view) = w.write_all(view).await;
        buffer = view.into_inner();
        res?;
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}
