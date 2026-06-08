use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct VmMap {
    inner: ArcSwap<HashMap<String, String>>,
}

impl VmMap {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::new(Arc::new(HashMap::new())),
        })
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.inner.load().get(key).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    fn load_json(data: &[u8]) -> anyhow::Result<HashMap<String, String>> {
        let map: HashMap<String, String> = serde_json::from_slice(data)
            .map_err(|e| anyhow::anyhow!("failed to parse vm map JSON: {e}"))?;
        Ok(map)
    }

    pub fn reload_from_bytes(&self, data: &[u8]) -> anyhow::Result<()> {
        let map = Self::load_json(data)?;
        self.inner.store(Arc::new(map));
        Ok(())
    }
}

/// Load initial map from a file and return the populated `VmMap`.
pub fn load_vm_map(path: &PathBuf) -> anyhow::Result<Arc<VmMap>> {
    let vm_map = VmMap::new();
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read vm map file {}: {e}", path.display()))?;
    vm_map.reload_from_bytes(&data)?;
    Ok(vm_map)
}

/// Spawn a background thread that polls `path` every second. When the file
/// content changes, the new JSON is parsed and atomically swapped in.
pub fn spawn_vm_map_watcher(path: PathBuf, vm_map: Arc<VmMap>) {
    std::thread::Builder::new()
        .name("vm-map-watcher".into())
        .spawn(move || {
            let mut last_contents = std::fs::read(&path).ok();
            loop {
                std::thread::sleep(POLL_INTERVAL);
                if let Ok(contents) = std::fs::read(&path) {
                    if last_contents.as_deref() != Some(&contents) {
                        match vm_map.reload_from_bytes(&contents) {
                            Ok(()) => eprintln!(
                                "vm-map-watcher: reloaded {} entries from {}",
                                vm_map.inner.load().len(),
                                path.display()
                            ),
                            Err(err) => eprintln!(
                                "vm-map-watcher: failed to reload {}: {err}",
                                path.display()
                            ),
                        }
                        last_contents = Some(contents);
                    }
                }
            }
        })
        .expect("failed to spawn vm-map-watcher thread");
}
