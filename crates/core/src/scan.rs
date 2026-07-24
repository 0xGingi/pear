use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;

use anyhow::Result;
use ignore::{DirEntry, WalkBuilder};

/// Directories that never sync (reproducible build output). Pear's own
/// `.pear` metadata dir is excluded separately (root-only,
/// case-insensitive), not via this list.
const BUILTIN_EXCLUDES: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
];

/// One file found by the workspace walk, with the metadata the manifest tracks.
#[derive(Debug, Clone)]
pub struct ScannedFile {
    /// Relative path from the workspace root, `/`-separated.
    pub rel_path: String,
    pub size: u64,
    pub mode: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
}

/// The outcome of a workspace scan: the files found, plus the relative
/// prefixes that could not be read (so sync can retain last-good state
/// instead of treating their contents as deleted), plus paths that were
/// deliberately skipped (symlinks, non-UTF-8 names — strict captures use
/// this to fail rather than silently omit them), plus directories the
/// built-in name excludes or a `pear.toml` `exclude` entry pruned
/// (surfaced so preservation commands can report what is not captured).
pub struct ScanOutcome {
    pub files: Vec<ScannedFile>,
    pub unreadable: Vec<String>,
    /// Prefixes unreadable only in the ignore-rules-off `.env`/`.git`
    /// walk and outside `.git` — gitignored anyway; they can only hide
    /// `.env*` files, so they warn rather than fail a strict capture.
    pub unreadable_ignored: Vec<String>,
    pub skipped: Vec<String>,
    pub excluded: Vec<String>,
}

/// An optional `pear.toml` at the workspace root (§14). It syncs as a
/// normal worktree file, so all devices share it; it is re-read at the
/// start of every scan, so edits take effect on the next cycle.
#[derive(Debug, Default, serde::Deserialize)]
struct PearToml {
    #[serde(default)]
    sync: SyncConfig,
}

/// The `[sync]` table: per-workspace overrides of the exclusion rules.
/// Entries are root-relative path prefixes matched component-wise against
/// the normalized relative path — an entry matches the named path itself
/// and everything below it (`build` matches `build` and `build/x/y`, not
/// `rebuild` or `foo/build`), files and directories alike. Precedence:
/// `exclude` > `include` > built-in name excludes > gitignore.
#[derive(Debug, Default, Clone, serde::Deserialize)]
struct SyncConfig {
    /// Re-include paths the built-in name excludes would prune.
    #[serde(default)]
    include: Vec<String>,
    /// Exclude paths on top of everything else.
    #[serde(default)]
    exclude: Vec<String>,
}

impl SyncConfig {
    fn includes(&self, rel: &str) -> bool {
        self.include.iter().any(|p| matches_prefix(rel, p))
    }

    fn excludes(&self, rel: &str) -> bool {
        self.exclude.iter().any(|p| matches_prefix(rel, p))
    }

    /// True when an `include` entry targets something strictly below
    /// `rel` — the walk must descend into a built-in-excluded directory
    /// far enough to reach the re-included subtree instead of pruning
    /// the whole directory (a deep include must not silently no-op, §14).
    fn has_include_below(&self, rel: &str) -> bool {
        self.include.iter().any(|p| {
            p.strip_prefix(rel)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
        })
    }

    /// True when some ancestor of `rel` is pruned by the built-in name
    /// excludes without being re-included. The walk descends into such a
    /// directory only to reach a deeper `include`, so entries outside
    /// every `include` prefix stay unsynced (§14).
    fn shadowed(&self, rel: &str) -> bool {
        let mut ancestor = rel;
        while let Some(idx) = ancestor.rfind('/') {
            ancestor = &ancestor[..idx];
            if self.includes(ancestor) {
                return false;
            }
            let name = ancestor.rsplit('/').next().unwrap_or(ancestor);
            if BUILTIN_EXCLUDES.contains(&name) {
                return true;
            }
        }
        false
    }

    /// Strip surrounding slashes and drop empty entries so `["build/"]`
    /// behaves like `["build"]`.
    fn normalized(mut self) -> Self {
        for entry in self.include.iter_mut().chain(self.exclude.iter_mut()) {
            *entry = entry.trim_matches('/').to_string();
        }
        self.include.retain(|p| !p.is_empty());
        self.exclude.retain(|p| !p.is_empty());
        self
    }
}

/// Load the `[sync]` overrides from `pear.toml` at the workspace root. An
/// absent file means no overrides; an unparseable one warns once per scan
/// cycle and is treated as absent — a config typo must never wedge the
/// sync loop (§14).
fn load_sync_config(root: &Path) -> SyncConfig {
    let path = root.join("pear.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("pear: cannot read {}, ignoring it: {e}", path.display());
            }
            return SyncConfig::default();
        }
    };
    match toml::from_str::<PearToml>(&text) {
        Ok(parsed) => parsed.sync.normalized(),
        Err(e) => {
            eprintln!("pear: ignoring unparseable {}: {e}", path.display());
            SyncConfig::default()
        }
    }
}

/// Component-wise prefix match on a `/`-separated relative path:
/// `build` matches `build` and `build/x/y`, but not `rebuild` or
/// `foo/build`.
fn matches_prefix(rel: &str, prefix: &str) -> bool {
    rel == prefix
        || rel
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The `.env*` rule, THE single definition shared by the scanner and the
/// §28 kill switch (relay commit validation + the writer's watch refusal):
/// a path counts when its FINAL component starts with `.env` — exactly the
/// set pass 2 force-syncs even when gitignored. Case-sensitive (`.ENV` is
/// not `.env`), and a DIRECTORY named `.env*` does not make its contents
/// `.env*` (the walk's check is on each entry's own basename). The kill
/// switch must forbid precisely what the product promise syncs — no more,
/// no less — so all three enforcers call this, never a re-implementation.
pub fn is_dotenv(rel_path: &str) -> bool {
    rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .starts_with(".env")
}

/// Walk `root` respecting `.gitignore`, except `.env*` files which always sync.
/// Symlinks are skipped with a warning (known M1 limitation). `[sync]`
/// overrides from a root `pear.toml` apply per §14.
pub fn scan(root: &Path) -> Result<ScanOutcome> {
    let config = load_sync_config(root);
    let mut found: BTreeMap<String, ScannedFile> = BTreeMap::new();
    let mut unreadable = Vec::new();
    let mut unreadable_ignored = Vec::new();
    let mut skipped = Vec::new();

    // Pass 1: the gitignore-respecting walk. The root `.git` is pruned here;
    // pass 2 owns it so user gitignore rules never filter repo internals.
    let excluded_dirs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let excluded2 = excluded_dirs.clone();
    let root_owned = root.to_path_buf();
    let pass1_config = config.clone();
    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false) // dotfiles sync: `.env`, `.gitignore` itself
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            let rel = entry
                .path()
                .strip_prefix(&root_owned)
                .unwrap_or(entry.path());
            let rel = rel.to_string_lossy();
            let keep = is_scannable_pass1(entry, &rel, &pass1_config);
            // Record dirs pruned by the built-in name excludes (a
            // *tracked* dir named `build`/`dist`/`target` is not
            // captured unless `pear.toml` re-includes it) or by a user
            // `exclude` entry, so preservation commands can report the
            // omission.
            if !keep && entry.file_type().is_some_and(|ft| ft.is_dir()) {
                let name = entry.file_name();
                let pear_named = name.to_string_lossy().eq_ignore_ascii_case(".pear");
                let git_named = name == OsStr::new(".git");
                let pruned = pass1_config.excludes(&rel)
                    || pass1_config.shadowed(&rel)
                    || BUILTIN_EXCLUDES.iter().any(|n| OsStr::new(n) == name);
                if !pear_named && !git_named && pruned {
                    excluded2.lock().unwrap().push(rel.into_owned());
                }
            }
            keep
        });
    for result in walker.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                // An error at the workspace root means the whole scan is
                // garbage (mount hiccup, root perms): fail the cycle
                // rather than wipe the mirror with an empty file list.
                if error_path(&e).is_some_and(|p| p == root) {
                    return Err(anyhow::anyhow!("cannot read workspace root: {e}"));
                }
                // Unreadable directory etc.: skip it, do not fail the
                // scan — but record the prefix so sync can retain
                // last-good state instead of deleting it from the mirror.
                eprintln!("pear: skipping unreadable path: {e}");
                if let Some(rel) = error_path(&e).and_then(|p| rel_string(root, p, &mut skipped)) {
                    unreadable.push(rel);
                }
                continue;
            }
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            eprintln!("pear: skipping symlink {}", entry.path().display());
            if let Some(rel) = rel_string(root, entry.path(), &mut skipped) {
                skipped.push(rel);
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if let Some(f) = scanned_file(root, &entry, &mut unreadable, &mut skipped)? {
            found.insert(f.rel_path.clone(), f);
        }
    }

    // Pass 2: `.env*` files sync even when gitignored, and `.git/` syncs
    // completely — user gitignore patterns (e.g. `logs/`) must never filter
    // repo internals. The `ignore` crate's overrides can't express either
    // rule (any whitelist glob makes every unmatched file ignored), so this
    // pass walks with ignore rules off and keeps just these two kinds.
    let git_dir = root.join(".git");
    let git_dir2 = git_dir.clone();
    let root_owned2 = root.to_path_buf();
    let root_owned3 = root.to_path_buf();
    let pass2_config = config.clone();
    let pass2_config_loop = config.clone();
    let mut env_walker = WalkBuilder::new(root);
    env_walker
        .hidden(false)
        .ignore(false)
        .git_ignore(false)
        .git_exclude(false)
        .git_global(false)
        .parents(false)
        .follow_links(false)
        // Repo internals are never name-pruned: built-in excludes must
        // not drop `.git/refs/heads/build/` & co. A user `exclude` still
        // applies there — it outranks the `.env*`/`.git` exceptions (§14).
        .filter_entry(move |entry| {
            let rel = entry
                .path()
                .strip_prefix(&root_owned2)
                .unwrap_or(entry.path());
            let rel = rel.to_string_lossy();
            if entry.path().starts_with(&git_dir2) {
                return !pass2_config.excludes(&rel);
            }
            is_not_excluded_dir(entry, &rel, &pass2_config)
        });
    for result in env_walker.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                // An error at the workspace root means the whole scan is
                // garbage (mount hiccup, root perms): fail the cycle
                // rather than wipe the mirror with an empty file list.
                if error_path(&e).is_some_and(|p| p == root) {
                    return Err(anyhow::anyhow!("cannot read workspace root: {e}"));
                }
                // Unreadable directory etc.: skip it, do not fail the
                // scan — but record the prefix so sync can retain
                // last-good state instead of deleting it from the mirror.
                // Pass 2 with ignore rules off also walks gitignored
                // trees: an unreadable dir there can only hide `.env*`
                // files, so it warns rather than fails (strict mode,
                // sync.rs). Only `.git` unreadability is capture-fatal.
                eprintln!("pear: skipping unreadable path: {e}");
                if let Some(rel) = error_path(&e).and_then(|p| rel_string(root, p, &mut skipped)) {
                    if rel == ".git" || rel.starts_with(".git/") {
                        unreadable.push(rel);
                    } else {
                        unreadable_ignored.push(rel);
                    }
                }
                continue;
            }
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        // Cheap name checks first: only `.env*`, `.git/`, and
        // `include`-matched candidates get path processing at all —
        // `rel_string` records non-UTF-8 names in `skipped`, and a
        // gitignored non-candidate must never land there. The `.env*`
        // test is the shared `is_dotenv` (a bare basename has no '/', so
        // it reduces to the prefix check) — the §28 kill switch forbids
        // exactly the set this walk captures.
        let dotenv = is_dotenv(&entry.file_name().to_string_lossy());
        let git_candidate = entry.path().starts_with(&git_dir);
        // `include` outranks gitignore (§14 precedence): pass 1 runs with
        // gitignore on and never sees these files, so this ignore-rules-off
        // walk is the only place an include can reach them.
        let included = file_type.is_file() && {
            let rel = entry
                .path()
                .strip_prefix(&root_owned3)
                .unwrap_or(entry.path());
            pass2_config_loop.includes(&rel.to_string_lossy())
        };
        if !dotenv && !git_candidate && !included {
            continue;
        }
        let Some(rel) = rel_string(root, entry.path(), &mut skipped) else {
            continue;
        };
        let git_internal = rel == ".git" || rel.starts_with(".git/");
        if !dotenv && !git_internal && !included {
            continue;
        }
        if file_type.is_symlink() {
            eprintln!("pear: skipping symlink {}", entry.path().display());
            skipped.push(rel);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if let Some(f) = scanned_file(root, &entry, &mut unreadable, &mut skipped)? {
            found.entry(f.rel_path.clone()).or_insert(f);
        }
    }

    skipped.sort();
    skipped.dedup();
    unreadable_ignored.sort();
    unreadable_ignored.dedup();
    let mut excluded = excluded_dirs.lock().unwrap().clone();
    excluded.sort();
    excluded.dedup();
    Ok(ScanOutcome {
        files: found.into_values().collect(),
        unreadable,
        unreadable_ignored,
        skipped,
        excluded,
    })
}

/// Extract the filesystem path from an `ignore` walker error, unwrapping
/// the line-number/depth wrappers.
fn error_path(err: &ignore::Error) -> Option<&Path> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            error_path(err)
        }
        _ => None,
    }
}

/// Prune excluded entries from traversal (root excepted), applying the
/// per-workspace precedence (§14): user `exclude` > user `include` >
/// built-in name excludes. The ROOT `.pear` matches case-insensitively
/// and stays pruned regardless of overrides, so scan output always
/// passes manifest validation (which rejects first-component `.pear`
/// case-insensitively too) — including a root-level *file* named
/// `.PEAR`, possible on case-sensitive filesystems. A `.pear` directory
/// at any deeper level is ordinary content (a vendored fixture, a
/// nested workspace's metadata) and syncs like anything else.
fn is_not_excluded_dir(entry: &DirEntry, rel: &str, config: &SyncConfig) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let pear_named = entry
        .file_name()
        .to_string_lossy()
        .eq_ignore_ascii_case(".pear");
    if !entry.file_type().is_some_and(|ft| ft.is_dir()) {
        // Built-in excludes are dir-only, but a user `exclude` entry
        // matches any path at or below the named one, files included.
        if entry.depth() == 1 && pear_named {
            return false;
        }
        if config.excludes(rel) {
            return false;
        }
        if config.includes(rel) {
            return true;
        }
        // Under a built-in-excluded directory the walk only descended to
        // reach a deeper `include`: files outside it stay unsynced.
        return !config.shadowed(rel);
    }
    if pear_named {
        // Only the root `.pear` is our metadata (pruned); a nested one
        // is ordinary content — manifest validation rejects only
        // first-component `.pear`, and a silent prune here would omit
        // valid files without any report.
        return entry.depth() != 1;
    }
    if config.excludes(rel) {
        return false;
    }
    if config.includes(rel) {
        return true;
    }
    if config.shadowed(rel) {
        return false;
    }
    if BUILTIN_EXCLUDES
        .iter()
        .any(|name| OsStr::new(name) == entry.file_name())
    {
        // An `include` may target something below: descend far enough to
        // reach it (the rest of the tree is caught by `shadowed`).
        return config.has_include_below(rel);
    }
    true
}

/// Pass 1 traversal: the exclusion rules above plus the root `.git` (pass
/// 2 owns `.git` so user gitignore rules never filter repo internals).
/// Built-in excludes match by name at any depth, so a *tracked* directory
/// named `build`/`dist`/`target` does not sync unless `pear.toml`
/// re-includes it (§14).
fn is_scannable_pass1(entry: &DirEntry, rel: &str, config: &SyncConfig) -> bool {
    if !is_not_excluded_dir(entry, rel, config) {
        return false;
    }
    if entry.depth() == 1 && entry.file_type().is_some_and(|ft| ft.is_dir()) {
        return entry.file_name() != OsStr::new(".git");
    }
    true
}

fn scanned_file(
    root: &Path,
    entry: &DirEntry,
    unreadable: &mut Vec<String>,
    skipped: &mut Vec<String>,
) -> Result<Option<ScannedFile>> {
    let Some(rel_path) = rel_string(root, entry.path(), skipped) else {
        return Ok(None);
    };
    // A file vanishing between the directory listing and this stat
    // (temp-then-rename races) is skipped silently, not fatal. A stat that
    // fails for any other reason (e.g. EACCES: parent dir has read but no
    // execute permission) is reported like an unreadable directory, so
    // sync retains the mirror's last-good copy instead of deleting it.
    let md = match entry.metadata() {
        Ok(md) => md,
        Err(e) => {
            if e.io_error()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            {
                // Vanished between listing and stat (temp-then-rename race).
                return Ok(None);
            }
            eprintln!("pear: cannot stat {}: {e}", entry.path().display());
            unreadable.push(rel_path);
            return Ok(None);
        }
    };
    Ok(Some(ScannedFile {
        rel_path,
        size: md.len(),
        mode: unix_mode(&md),
        mtime_secs: mtime_secs(&md),
        mtime_nanos: mtime_nanos(&md),
    }))
}

fn rel_string(root: &Path, path: &Path, skipped: &mut Vec<String>) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    match rel.to_str() {
        Some(s) => Some(s.to_string()),
        // A lossy conversion would invent a name that does not exist on
        // disk; skip the file, like we skip symlinks.
        None => {
            eprintln!("pear: skipping non-UTF-8 path {}", path.display());
            skipped.push(path.display().to_string());
            None
        }
    }
}

#[cfg(unix)]
fn unix_mode(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    md.mode() & 0o7777
}

#[cfg(not(unix))]
fn unix_mode(_md: &std::fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn mtime_secs(md: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    md.mtime()
}

#[cfg(not(unix))]
fn mtime_secs(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn mtime_nanos(md: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    md.mtime_nsec()
}

#[cfg(not(unix))]
fn mtime_nanos(_md: &std::fs::Metadata) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::is_dotenv;

    /// The §28 boundary: `is_dotenv` is the scanner's own `.env*` rule, so
    /// these names pin exactly what the kill switch forbids — the final
    /// component's `.env` prefix, case-sensitive, nothing else.
    #[test]
    fn is_dotenv_matches_the_scanner_definition() {
        for yes in [
            ".env",
            ".env.local",
            ".env.production",
            // Prefix, not extension or glob: these all start with `.env`.
            ".envrc",
            ".environment",
            ".envx",
            "sub/.env",
            "sub/deep/.env.txt",
        ] {
            assert!(is_dotenv(yes), "{yes:?} must count as .env*");
        }
        for no in [
            // The prefix must be on the FINAL component...
            "env",
            ".en",
            "sub/env",
            ".ENV", // case-sensitive, like the walk
            // ...a directory named `.env*` does not taint its contents...
            ".env/config",
            ".env.d/local",
            // ...and the prefix is a prefix, not a substring.
            "foo.env",
            "sub/x.env",
        ] {
            assert!(!is_dotenv(no), "{no:?} must not count as .env*");
        }
    }
}
