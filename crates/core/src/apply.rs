use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::manifest::{self, diff, FileEntry, Manifest};
use crate::store::ChunkSource;

pub struct ApplyReport {
    pub written: Vec<String>,
    pub deleted: Vec<String>,
}

/// A deterministic refusal to apply a manifest (currently: case-colliding
/// keys). Retrying the same input fails identically, so mirror loops must
/// classify this as fatal rather than poll forever.
#[derive(Debug)]
pub struct ApplyRejection(pub String);

impl std::fmt::Display for ApplyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApplyRejection {}

/// Converge `target` from `old` to `new` in phases — worktree deletes,
/// worktree writes, `.git` deletes, `.git` writes (a stale-but-valid repo
/// beats a half-written one) — then the manifest pointer is swapped
/// atomically.
pub fn apply(
    target: &Path,
    old: &Manifest,
    new: &Manifest,
    chunks: &dyn ChunkSource,
) -> Result<ApplyReport> {
    // Manifests are disk and network data; never join unchecked paths, and
    // never resolve a destination through a symlinked ancestor inside the
    // target (checked per file in write_file/delete_file below).
    manifest::validate(old).context("invalid old manifest")?;
    manifest::validate(new).context("invalid new manifest")?;
    // Keys differing only in case are legal on case-sensitive filesystems
    // but resolve to ONE file on a case-insensitive mirror (default APFS,
    // Windows): writing both would silently diverge, and a later delete
    // of one would remove the file the other claims exists. Refuse the
    // whole pull loudly here rather than misapply it. The fold is Rust's
    // `to_lowercase` — deliberately documented as best-effort: Unicode
    // normalization aliases (NFC vs NFD, which APFS also resolves to one
    // file) and filesystem-specific fold tables (Kelvin sign, dotted I)
    // are out of scope without a normalization crate; a writer producing
    // such pairs is pathological and the failure mode is the same loud
    // refusal on most real trees.
    let mut folded: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for rel in new.files.keys() {
        let lower = rel.to_lowercase();
        if let Some(other) = folded.get(&lower) {
            return Err(ApplyRejection(format!(
                "manifest paths {other:?} and {rel:?} collide on case-insensitive filesystems"
            ))
            .into());
        }
        folded.insert(lower, rel.as_str());
    }

    let pear_dir = target.join(".pear");
    let staging = pear_dir.join("staging");
    fs::create_dir_all(&staging).with_context(|| format!("create {}", staging.display()))?;
    // Staging and manifests hold assembled plaintext and metadata
    // (possibly `.env`): owner-only.
    crate::fsutil::set_private_dir(&pear_dir)?;
    crate::fsutil::set_private_dir(&staging)?;
    clean_staging(&staging);

    let d = diff(old, new);
    let mut writes = d.added;
    writes.extend(d.changed);
    let (wt_del, git_del) = partition_git(d.deleted);
    let (wt_wr, git_wr) = partition_git(writes);

    let mut deleted = Vec::new();
    let mut written = Vec::new();
    // Recorded for the group flush below (§18): every written dest path
    // (reopen + fsync) and the parent dir of every written OR DELETED
    // file (deduped — deletes gain directory durability for the first
    // time).
    let mut written_paths: Vec<PathBuf> = Vec::new();
    let mut sync_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for rel in &wt_del {
        delete_file(target, rel, &mut sync_dirs)?;
        deleted.push(rel.clone());
    }
    for rel in &wt_wr {
        let entry = new
            .files
            .get(rel)
            .with_context(|| format!("manifest has no entry for {rel}"))?;
        write_file(target, &staging, rel, entry, chunks, &mut written_paths, &mut sync_dirs)?;
        written.push(rel.clone());
    }
    for rel in &git_del {
        delete_file(target, rel, &mut sync_dirs)?;
        deleted.push(rel.clone());
    }
    for rel in &git_wr {
        let entry = new
            .files
            .get(rel)
            .with_context(|| format!("manifest has no entry for {rel}"))?;
        write_file(target, &staging, rel, entry, chunks, &mut written_paths, &mut sync_dirs)?;
        written.push(rel.clone());
    }

    // Group flush (§18), landing BEFORE the commit point: fsync each
    // written file (reopened — a file that vanished between rename and
    // flush is moot: skip NotFound, propagate anything else), then fsync
    // each recorded parent dir.
    for path in &written_paths {
        match fs::OpenOptions::new().read(true).open(path) {
            Ok(f) => f
                .sync_all()
                .with_context(|| format!("fsync {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reopen {}", path.display())),
        }
    }
    for dir in &sync_dirs {
        // Best-effort already: a deleted file's parent may have been
        // pruned away by prune_empty_parents.
        manifest::sync_dir(dir);
    }

    // The apply batch is durable only once the manifest pointer moves.
    manifest::write_atomic(&pear_dir.join("manifest.json"), new)?;

    Ok(ApplyReport { written, deleted })
}

/// Split paths into (worktree, `.git`), preserving their sorted order.
/// The `.git` *file* (gitfile, used by worktrees/submodules) goes in the
/// `.git` partition too, so directory↔gitfile transitions keep
/// delete-before-write ordering.
fn partition_git(paths: Vec<String>) -> (Vec<String>, Vec<String>) {
    paths
        .into_iter()
        .partition(|p| !(p == ".git" || p.starts_with(".git/")))
}

fn delete_file(target: &Path, rel: &str, sync_dirs: &mut BTreeSet<PathBuf>) -> Result<()> {
    let path = target.join(rel);
    crate::fsutil::ensure_real_ancestors(target, &path)?;
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("delete {}", path.display())),
    }
    // A delete is durable only once its parent dir's fsync lands: record
    // it for the group flush (§18). prune_empty_parents may remove that
    // dir itself; manifest::sync_dir opens best-effort and skips it.
    if let Some(parent) = path.parent() {
        sync_dirs.insert(parent.to_path_buf());
    }
    prune_empty_parents(target, &path);
    Ok(())
}

/// Assemble the file from its chunks under `.pear/staging/`, rename into
/// place, restore the recorded mtime. NO fsync here (§18): staging temps
/// need none (a crash can only resurrect a tmp name — cleaned by
/// `clean_staging` — or lose a dest rename, rewritten next cycle from
/// the still-old manifest). `apply` group-flushes every written file
/// and parent dir before the manifest commit; this fn only records the
/// dest path and its parent dir for that flush.
fn write_file(
    target: &Path,
    staging: &Path,
    rel: &str,
    entry: &FileEntry,
    chunks: &dyn ChunkSource,
    written_paths: &mut Vec<PathBuf>,
    sync_dirs: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let tmp = staging.join(format!(
        "stage-{}-{:08x}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    {
        let mut f = crate::fsutil::create_private_file(&tmp)
            .with_context(|| format!("stage {}", tmp.display()))?;
        for hash in &entry.chunks {
            let data = chunks
                .get(hash)
                .with_context(|| format!("fetch chunk {hash} for {rel}"))?;
            f.write_all(&data)?;
        }
        set_mode(&f, entry.mode)?;
    }
    let dest = target.join(rel);
    // Manifests are network input: refuse to write through a symlinked
    // ancestor inside the target (DESIGN §10).
    crate::fsutil::ensure_real_ancestors(target, &dest)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::rename(&tmp, &dest).with_context(|| format!("rename into {}", dest.display()))?;
    // Restore the recorded mtime so the mirror is metadata-faithful to the
    // manifest (and a later role reversal is not a full-manifest miss).
    filetime::set_file_mtime(
        &dest,
        filetime::FileTime::from_unix_time(
            entry.mtime_secs,
            entry.mtime_nanos.clamp(0, 999_999_999) as u32,
        ),
    )
    .with_context(|| format!("restore mtime on {}", dest.display()))?;
    if let Some(parent) = dest.parent() {
        sync_dirs.insert(parent.to_path_buf());
    }
    written_paths.push(dest);
    Ok(())
}

#[cfg(unix)]
fn set_mode(f: &fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Manifests are network input: never materialize setuid/setgid/sticky
    // bits on a mirror — a writer (or the semi-trusted relay, §7) must not
    // get to plant a privilege-escalation vector on another host. The
    // writer's own manifest keeps the true bits; only applied modes mask.
    f.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_f: &fs::File, _mode: u32) -> Result<()> {
    Ok(())
}

fn clean_staging(staging: &Path) {
    if let Ok(entries) = fs::read_dir(staging) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Remove now-empty parent directories up to (not including) `root`, like git.
fn prune_empty_parents(root: &Path, path: &Path) {
    let mut dir: Option<PathBuf> = path.parent().map(Path::to_path_buf);
    while let Some(d) = dir {
        if d == root {
            break;
        }
        if fs::remove_dir(&d).is_err() {
            break; // not empty or not removable: stop climbing
        }
        dir = d.parent().map(Path::to_path_buf);
    }
}
