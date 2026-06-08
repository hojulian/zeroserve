use std::{collections::HashMap, path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher, event::ModifyKind};

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

/// Spawn a background thread that watches `path` via inotify (Linux) and
/// hot-swaps the map whenever the file is written or replaced.
pub fn spawn_vm_map_watcher(path: PathBuf, vm_map: Arc<VmMap>) {
    std::thread::Builder::new()
        .name("vm-map-watcher".into())
        .spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("vm-map-watcher: failed to create watcher: {e}");
                    return;
                }
            };
            // Watch the parent directory so rename-over (atomic write) is also caught.
            let watch_path = path.parent().unwrap_or(&path);
            if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
                eprintln!("vm-map-watcher: failed to watch {}: {e}", watch_path.display());
                return;
            }

            for result in rx {
                let event = match result {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("vm-map-watcher: watch error: {e}");
                        continue;
                    }
                };

                // Only react to data writes and renames (atomic file replacement).
                let relevant = matches!(
                    event.kind,
                    EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Modify(ModifyKind::Name(_))
                        | EventKind::Create(_)
                );
                if !relevant {
                    continue;
                }

                // Confirm the event touches our specific file.
                let affects_our_file = event.paths.iter().any(|p| p == &path);
                if !affects_our_file {
                    continue;
                }

                match std::fs::read(&path) {
                    Ok(contents) => match vm_map.reload_from_bytes(&contents) {
                        Ok(()) => eprintln!(
                            "vm-map-watcher: reloaded {} entries from {}",
                            vm_map.len(),
                            path.display()
                        ),
                        Err(e) => eprintln!(
                            "vm-map-watcher: failed to reload {}: {e}",
                            path.display()
                        ),
                    },
                    Err(e) => eprintln!(
                        "vm-map-watcher: failed to read {}: {e}",
                        path.display()
                    ),
                }
            }
        })
        .expect("failed to spawn vm-map-watcher thread");
}
