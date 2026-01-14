use std::{
    collections::{HashMap, HashSet},
    fs::File as StdFile,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use tar::{Archive, EntryType};

pub struct Site {
    pub tar_file: StdFile,
    pub entries: HashMap<String, Arc<TarEntry>>,
    pub directories: HashSet<String>,
    pub total_bytes: u64,
    pub total_entries: usize,
}

#[derive(Debug)]
pub struct TarEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

impl Site {
    pub fn load(path: &Path) -> Result<Self> {
        let file = StdFile::open(path)
            .with_context(|| format!("failed to open tarball {}", path.display()))?;
        let meta = file
            .metadata()
            .with_context(|| format!("stat failed for {}", path.display()))?;
        let mut archive = Archive::new(file);
        let mut entries = HashMap::new();
        let mut directories = HashSet::new();

        let iter = archive
            .entries()
            .context("failed to iterate over tarball entries")?;
        for entry_res in iter {
            let entry = entry_res.context("unable to decode tar entry")?;
            let entry_type = entry.header().entry_type();
            let raw_path = entry.path().context("invalid tar entry path")?;
            let normalized = normalize_tar_path(raw_path.to_string_lossy().as_ref());
            if normalized.is_empty() {
                continue;
            }
            match entry_type {
                EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                    let arc_entry = Arc::new(TarEntry {
                        path: normalized.clone(),
                        offset: entry.raw_file_position(),
                        size: entry.size(),
                    });
                    entries.insert(normalized.clone(), arc_entry);
                    mark_parents(&normalized, &mut directories);
                }
                EntryType::Directory => {
                    directories.insert(normalized.clone());
                    mark_parents(&normalized, &mut directories);
                }
                _ => {}
            }
        }

        if entries.is_empty() {
            bail!(
                "tarball {} does not contain any regular files",
                path.display()
            );
        }

        let total_entries = entries.len();
        Ok(Self {
            tar_file: archive.into_inner(),
            entries,
            directories,
            total_bytes: meta.len(),
            total_entries,
        })
    }

    fn get_entry_safe<'a>(&'a self, key: &str) -> Option<&'a Arc<TarEntry>> {
        if key.starts_with(".zeroserve/") {
            return None;
        }
        self.entries.get(key)
    }

    pub fn lookup(
        &self,
        path: &NormalizedPath,
        default_index: &str,
        try_html: bool,
    ) -> Option<Arc<TarEntry>> {
        let rel = path.relative();
        if let Some(entry) = self.get_entry_safe(rel) {
            return Some(entry.clone());
        }

        if path.dir_hint() || rel.is_empty() || self.directories.contains(rel) {
            let index_key = path.append_index(default_index);
            if let Some(entry) = self.get_entry_safe(&index_key) {
                return Some(entry.clone());
            }
        }

        if !rel.is_empty() {
            let fallback = format!("{}/{}", rel, default_index);
            if let Some(entry) = self.get_entry_safe(&fallback) {
                return Some(entry.clone());
            }
        } else if let Some(entry) = self.get_entry_safe(default_index) {
            return Some(entry.clone());
        }

        if try_html && !rel.is_empty() && !rel.ends_with(".html") {
            let html_candidate = format!("{rel}.html");
            if let Some(entry) = self.get_entry_safe(&html_candidate) {
                return Some(entry.clone());
            }
        }

        None
    }
}

#[derive(Clone)]
pub struct NormalizedPath {
    relative: String,
    dir_hint: bool,
}

impl NormalizedPath {
    pub fn relative(&self) -> &str {
        &self.relative
    }

    pub fn dir_hint(&self) -> bool {
        self.dir_hint
    }

    pub fn append_index(&self, index: &str) -> String {
        if self.relative.is_empty() {
            index.to_string()
        } else {
            format!("{}/{}", self.relative, index)
        }
    }
}

pub fn normalize_request_path(raw: &str) -> Option<NormalizedPath> {
    let normalized_raw = if raw.is_empty() { "/" } else { raw };
    let dir_hint =
        normalized_raw == "/" || (normalized_raw.ends_with('/') && normalized_raw.len() > 1);
    let decoded = percent_decode(normalized_raw.as_bytes())?;
    let mut components = Vec::new();
    for part in decoded.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            components.pop()?;
            continue;
        }
        let segment = String::from_utf8(part.to_vec()).ok()?;
        components.push(segment);
    }
    let relative = components.join("/");
    Some(NormalizedPath { relative, dir_hint })
}

pub fn guess_mime(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                let hi = hex_val(input[i + 1])?;
                let lo = hex_val(input[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn mark_parents(path: &str, set: &mut HashSet<String>) {
    let mut current = trim_trailing_slash(path);
    if current.is_empty() {
        return;
    }
    while let Some(idx) = current.rfind('/') {
        current = &current[..idx];
        if current.is_empty() {
            break;
        }
        set.insert(current.to_string());
    }
}

fn trim_trailing_slash(path: &str) -> &str {
    path.trim_end_matches('/')
}

pub fn normalize_tar_path(path: &str) -> String {
    path.trim_start_matches("./").trim_matches('/').to_string()
}
