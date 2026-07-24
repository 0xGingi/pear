use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::FORMAT_VERSION;

/// Point-in-time state of a workspace: path -> content chunks + metadata.
/// Files only; directories are created on apply, empty dirs are not tracked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    pub workspace_id: String,
    /// When this manifest's scan started (unix seconds). The chunk cache in
    /// `sync` only trusts mtimes settled before this time, so coarse
    /// filesystem timestamps cannot hide a same-tick edit.
    #[serde(default)]
    pub scanned_at_secs: i64,
    /// Relative path (`/`-separated) -> file state.
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub size: u64,
    /// Unix permission bits.
    pub mode: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    /// Ordered BLAKE3 chunk hashes; concatenating the chunks yields the file.
    pub chunks: Vec<String>,
}

impl Manifest {
    pub fn new(workspace_id: String) -> Self {
        Self {
            version: FORMAT_VERSION,
            workspace_id,
            scanned_at_secs: 0,
            files: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManifestDiff {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
}

pub fn diff(old: &Manifest, new: &Manifest) -> ManifestDiff {
    let mut d = ManifestDiff::default();
    for path in new.files.keys() {
        match old.files.get(path) {
            None => d.added.push(path.clone()),
            Some(entry) if entry != &new.files[path] => d.changed.push(path.clone()),
            _ => {}
        }
    }
    for path in old.files.keys() {
        if !new.files.contains_key(path) {
            d.deleted.push(path.clone());
        }
    }
    d
}

pub fn load(path: &Path) -> Result<Option<Manifest>> {
    match fs::read(path) {
        Ok(data) => {
            let m = serde_json::from_slice(&data)
                .with_context(|| format!("parse manifest {}", path.display()))?;
            validate(&m).with_context(|| format!("invalid manifest {}", path.display()))?;
            Ok(Some(m))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read manifest {}", path.display())),
    }
}

/// Reject manifest paths that could escape the target tree when joined:
/// absolute paths, `.`/`..` components, empty keys. Manifests are data from
/// disk (and, from M2, the network) and are never trusted blindly. Chunk
/// references must be BLAKE3 hex digests: a malformed hash would wedge a
/// mirror in an infinite fetch-retry loop instead of failing the pull.
pub fn validate(m: &Manifest) -> Result<()> {
    for (rel, entry) in &m.files {
        validate_path(rel)?;
        for hash in &entry.chunks {
            if !is_chunk_hash(hash) {
                anyhow::bail!("invalid chunk hash {hash:?} for {rel:?} in manifest");
            }
        }
    }
    // A file and its own subdirectory cannot both exist (mirrored from
    // the relay's validation): applying such a manifest fails mid-batch.
    for path in m.files.keys() {
        let mut ancestor = path.as_str();
        while let Some(idx) = ancestor.rfind('/') {
            ancestor = &ancestor[..idx];
            if m.files.contains_key(ancestor) {
                anyhow::bail!(
                    "path {path:?} conflicts with {ancestor:?}: a file cannot also be a directory"
                );
            }
        }
    }
    Ok(())
}

fn validate_path(rel: &str) -> Result<()> {
    if rel.is_empty() {
        anyhow::bail!("empty path in manifest");
    }
    // `Path::components()` normalizes empty components away, so check the
    // raw key first: manifest keys must be canonical. "a//b" or "a/b/"
    // alias "a/b" — a hostile manifest could carry both as distinct
    // entries that map to one on-disk file (and a delete of one would
    // remove the file the other claims exists).
    if rel.split('/').any(|c| c.is_empty()) {
        anyhow::bail!("non-canonical path {rel:?} in manifest");
    }
    for component in Path::new(rel).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            anyhow::bail!("unsafe path {rel:?} in manifest");
        }
    }
    // Manifest operations must never touch pear's own metadata/store.
    // Compare the first component case-insensitively: case-insensitive
    // filesystems (APFS by default, Windows) resolve `.PEAR/...` into the
    // real `.pear` directory.
    if let Some(std::path::Component::Normal(first)) = Path::new(rel).components().next() {
        if first.to_string_lossy().eq_ignore_ascii_case(".pear") {
            anyhow::bail!("path {rel:?} targets pear metadata");
        }
    }
    Ok(())
}

/// A chunk reference is a BLAKE3 hex digest: 64 lowercase hex chars.
fn is_chunk_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn write_atomic(path: &Path, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)?;
    write_file_atomic(path, &bytes)
}

/// Write tmp file in the same directory, fsync, rename into place.
/// Owner-only: manifests carry file listings and chunk hashes (an unsalted
/// whole-file BLAKE3 for small files such as `.env`).
pub(crate) fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = crate::fsutil::create_private_file(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
    Ok(())
}

/// Best-effort directory fsync; errors are ignored by design.
pub(crate) fn sync_dir(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(size: u64, chunks: &[&str]) -> FileEntry {
        FileEntry {
            size,
            mode: 0o644,
            mtime_secs: 100,
            mtime_nanos: 0,
            chunks: chunks.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn diff_detects_add_change_delete() {
        let mut old = Manifest::new("ws".into());
        old.files.insert("keep".into(), entry(1, &["a"]));
        old.files.insert("change".into(), entry(2, &["b"]));
        old.files.insert("delete".into(), entry(3, &["c"]));

        let mut new = Manifest::new("ws".into());
        new.files.insert("keep".into(), entry(1, &["a"]));
        new.files.insert("change".into(), entry(4, &["d"]));
        new.files.insert("add".into(), entry(5, &["e"]));

        let d = diff(&old, &new);
        assert_eq!(d.added, vec!["add"]);
        assert_eq!(d.changed, vec!["change"]);
        assert_eq!(d.deleted, vec!["delete"]);
    }

    #[test]
    fn diff_detects_mode_only_change() {
        let mut old = Manifest::new("ws".into());
        old.files.insert("f".into(), entry(1, &["a"]));
        let mut new = old.clone();
        new.files.get_mut("f").unwrap().mode = 0o755;

        let d = diff(&old, &new);
        assert_eq!(d.changed, vec!["f"]);
        assert!(d.added.is_empty() && d.deleted.is_empty());
    }

    /// A valid 64-char lowercase hex chunk hash for fixtures.
    const H64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validate_rejects_unsafe_paths() {
        let mut m = Manifest::new("ws".into());
        for bad in [
            "",
            "/abs",
            "../x",
            "a/../../x",
            "./x",
            // Aliasing: `Path::components()` normalizes empty components
            // away, so each of these aliases "a/b" — two manifest keys
            // could map to one on-disk file.
            "a//b",
            "a/b/",
            "a///b",
            ".pear/manifest.json",
            ".pear/store/chunks/aa",
            ".PEAR/store/chunks/aa",
            ".Pear/manifest.json",
        ] {
            m.files.clear();
            m.files.insert(bad.to_string(), entry(1, &[H64]));
            assert!(validate(&m).is_err(), "must reject {bad:?}");
        }
        for good in ["a/b.txt", ".git/HEAD", ".env", ".env.local"] {
            m.files.clear();
            m.files.insert(good.to_string(), entry(1, &[H64]));
            assert!(validate(&m).is_ok(), "must accept {good:?}");
        }
    }

    #[test]
    fn validate_rejects_malformed_chunk_hashes() {
        let mut m = Manifest::new("ws".into());
        let short = "a".repeat(63);
        let upper = "A".repeat(64);
        let not_hex = "g".repeat(64);
        for bad in ["a", "xyz", &short, &upper, &not_hex] {
            m.files.clear();
            m.files.insert("f".to_string(), entry(1, &[bad]));
            assert!(validate(&m).is_err(), "must reject chunk hash {bad:?}");
        }
        m.files.clear();
        m.files.insert("f".to_string(), entry(1, &[H64, H64]));
        assert!(validate(&m).is_ok(), "real digests pass");
    }

    #[test]
    fn validate_rejects_file_dir_conflicts() {
        let mut m = Manifest::new("ws".into());
        m.files.insert("a".to_string(), entry(1, &[H64]));
        m.files.insert("a/b".to_string(), entry(1, &[H64]));
        assert!(
            validate(&m).is_err(),
            "a file and its own subdirectory cannot both exist"
        );

        // Non-adjacent in byte order: bytes below '/' sort between a
        // prefix and its subdirectory.
        let mut m = Manifest::new("ws".into());
        m.files.insert("a".to_string(), entry(1, &[H64]));
        m.files.insert("a-x".to_string(), entry(1, &[H64]));
        m.files.insert("a/b".to_string(), entry(1, &[H64]));
        assert!(validate(&m).is_err(), "non-adjacent conflict must reject");

        // A plain directory-like pair with no conflict is fine.
        let mut m = Manifest::new("ws".into());
        m.files.insert("a/b".to_string(), entry(1, &[H64]));
        m.files.insert("a/c".to_string(), entry(1, &[H64]));
        assert!(validate(&m).is_ok());
    }

    #[test]
    fn validate_rejects_aliasing_keys() {
        // "a/b" and "a//b" resolve to the same on-disk path: as distinct
        // manifest keys they would write the same file twice, and a later
        // delete of one would remove the file the other claims exists.
        let mut m = Manifest::new("ws".into());
        m.files.insert("a/b".to_string(), entry(1, &[H64]));
        m.files.insert("a//b".to_string(), entry(1, &[H64]));
        assert!(validate(&m).is_err(), "aliasing keys must reject");
    }
}
