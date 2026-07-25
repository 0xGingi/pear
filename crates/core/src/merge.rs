//! Deterministic 3-way manifest merge (§32): the decision half of the
//! converge step. Pure — no clock, no filesystem, no network — so two
//! devices that see the same `(base, local, remote)` produce byte-identical
//! `merged` manifests, which is what lets the relay's head CAS be the only
//! concurrency control multi-writer needs.
//!
//! `base` is the last converged manifest (`.pear/manifest.json`), `local`
//! a fresh scan, `remote` the relay head. "Changed" throughout means
//! whole-`FileEntry` inequality against `base`, exactly as in
//! [`manifest::diff`].

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::SystemTime;

use crate::manifest::{self, FileEntry, Manifest, ManifestDiff};
use crate::FORMAT_VERSION;

/// The side that lost a last-writer-wins race for a path and is preserved
/// as a conflict copy (§32: a converge never loses a byte of user data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSide {
    Local,
    Remote,
}

/// Where a `.git` conflict copy is preserved instead of beside the file it
/// lost (§32 as-built): `.pear` never enters a manifest, so these copies
/// stay on the device that made them and never sync.
pub const LOCAL_CONFLICT_DIR: &str = ".pear/conflicts";

/// One conflict copy the converge step must materialize. A `Local` loser's
/// bytes are already on disk at `path`; a `Remote` loser's bytes exist only
/// as chunks and are assembled like any other apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictCopy {
    pub side: ConflictSide,
    /// The contested path — the winner's entry lives here in `merged`.
    pub path: String,
    /// Where the loser's content is preserved: beside the contested file,
    /// or — when `local_only` — under [`LOCAL_CONFLICT_DIR`].
    pub copy_path: String,
    /// A copy that must NOT enter the merged manifest: a file inside
    /// `.git`, whose conflict copy would be an invalid refname/object
    /// path and would make `git fsck --strict` fail on every device that
    /// synced it. Preserved locally under [`LOCAL_CONFLICT_DIR`] instead —
    /// each device keeps only its own losing side.
    pub local_only: bool,
    /// The loser's entry, verbatim: its chunks, mode, and mtime.
    pub entry: FileEntry,
}

/// The result of one 3-way merge.
#[derive(Debug, PartialEq, Eq)]
pub struct MergeOutcome {
    /// The manifest to publish and to record as the new converged base.
    pub merged: Manifest,
    /// What the local tree must change to reach `merged`: `diff(local,
    /// merged)` minus the `Local`-side conflict copies, whose bytes never
    /// come from the remote (they are copied from the file already on
    /// disk, before anything overwrites it). `Remote`-side conflict copies
    /// DO appear here, as adds — they are ordinary remote content.
    pub apply_from_remote: ManifestDiff,
    /// Conflict copies to create, in path order. The `local_only` ones
    /// are absent from `merged`: they land under [`LOCAL_CONFLICT_DIR`]
    /// on this device and never sync.
    pub conflicts: Vec<ConflictCopy>,
}

/// 3-way merge per §32's rule table. `local_device` names this device (it
/// labels conflict copies whose LOCAL side lost); `stamp` is the injected
/// `YYYY-MM-DD HHMMSS` timestamp — merge never reads the clock, so it
/// stays a pure function of its inputs. Use [`conflict_stamp`] to build it.
pub fn merge(
    base: &Manifest,
    local: &Manifest,
    remote: &Manifest,
    local_device: &str,
    stamp: &str,
) -> MergeOutcome {
    let device = sanitize_device(local_device);
    let mut names = NameSpace::new(local, remote);
    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut conflicts: Vec<ConflictCopy> = Vec::new();

    // Sorted union of every path any side knows: BTreeMap iteration order
    // makes conflict-copy numbering deterministic too.
    let paths: BTreeSet<&str> = base
        .files
        .keys()
        .chain(local.files.keys())
        .chain(remote.files.keys())
        .map(String::as_str)
        .collect();

    for path in paths {
        let b = base.files.get(path);
        let l = local.files.get(path);
        let r = remote.files.get(path);
        match decide(b, l, r) {
            Decision::Winner(Some(entry)) => {
                files.insert(path.to_string(), entry.clone());
            }
            Decision::Winner(None) => {}
            Decision::Conflict {
                winner,
                loser_side,
                loser,
            } => {
                files.insert(path.to_string(), winner.clone());
                let device = match loser_side {
                    ConflictSide::Local => device.as_str(),
                    // The relay carries no per-entry authorship, so the
                    // remote loser's device is unknowable: §32 pins the
                    // literal name `remote` for that side.
                    ConflictSide::Remote => "remote",
                };
                let name = names.claim(path, device, stamp);
                // A copy inside `.git` is not a valid ref/object path:
                // syncing it would break `git fsck --strict` everywhere.
                // It becomes a local-only copy under `.pear/conflicts/`,
                // keeping the same name and collision numbering.
                let local_only = is_git_path(path);
                let copy_path = if local_only {
                    format!("{LOCAL_CONFLICT_DIR}/{name}")
                } else {
                    files.insert(name.clone(), loser.clone());
                    name
                };
                conflicts.push(ConflictCopy {
                    side: loser_side,
                    path: path.to_string(),
                    copy_path,
                    local_only,
                    entry: loser.clone(),
                });
            }
        }
    }

    let merged = Manifest {
        version: FORMAT_VERSION,
        workspace_id: local.workspace_id.clone(),
        // The merged manifest doubles as this device's chunk cache, so it
        // carries THIS scan's timestamp, not the remote's.
        scanned_at_secs: local.scanned_at_secs,
        files,
    };

    // Local losers are copied from the file already on disk, so they are
    // never fetched; local-only copies are not in `merged` at all, so the
    // diff never mentions them.
    let local_copies: HashSet<&str> = conflicts
        .iter()
        .filter(|c| c.side == ConflictSide::Local && !c.local_only)
        .map(|c| c.copy_path.as_str())
        .collect();
    let mut apply_from_remote = manifest::diff(local, &merged);
    apply_from_remote
        .added
        .retain(|p| !local_copies.contains(p.as_str()));

    MergeOutcome {
        merged,
        apply_from_remote,
        conflicts,
    }
}

/// Per-path outcome. `Winner(None)` is "the path is deleted in `merged`".
enum Decision<'a> {
    Winner(Option<&'a FileEntry>),
    Conflict {
        winner: &'a FileEntry,
        loser_side: ConflictSide,
        loser: &'a FileEntry,
    },
}

/// §32's rule table, in table order.
fn decide<'a>(
    b: Option<&'a FileEntry>,
    l: Option<&'a FileEntry>,
    r: Option<&'a FileEntry>,
) -> Decision<'a> {
    // Both sides agree (neither changed, both changed identically, or both
    // deleted): nothing to decide.
    if l == r {
        return Decision::Winner(l);
    }
    if l == b {
        // Only the remote moved: adopt it (an add, a change, or a delete).
        return Decision::Winner(r);
    }
    if r == b {
        // Only we moved: our state stands and gets re-published.
        return Decision::Winner(l);
    }
    match (l, r) {
        // Edit beats delete, both ways: the edit survives and the file is
        // restored (remote edit) or re-pushed (local edit).
        (None, Some(_)) => Decision::Winner(r),
        (Some(_), None) => Decision::Winner(l),
        (Some(le), Some(re)) => {
            if le.chunks == re.chunks && le.mode == re.mode && le.size == re.size {
                // Same content and mode, different mtime: one entry has to
                // win so the two devices agree byte-for-byte. Newer mtime
                // wins; no conflict copy, nothing is lost. (Equal mtimes
                // would make the entries equal, handled above.)
                return Decision::Winner(Some(if mtime(re) >= mtime(le) { re } else { le }));
            }
            // LWW on (mtime_secs, mtime_nanos); a tie goes to the remote so
            // that both devices pick the same winner. The loser becomes a
            // conflict copy.
            if mtime(re) >= mtime(le) {
                Decision::Conflict {
                    winner: re,
                    loser_side: ConflictSide::Local,
                    loser: le,
                }
            } else {
                Decision::Conflict {
                    winner: le,
                    loser_side: ConflictSide::Remote,
                    loser: re,
                }
            }
        }
        // `l == r` above already returned for (None, None).
        (None, None) => unreachable!("equal sides are decided before this point"),
    }
}

fn mtime(e: &FileEntry) -> (i64, i64) {
    (e.mtime_secs, e.mtime_nanos)
}

/// Whether `path`'s first component is `.git` — the repository's own
/// state, including the `.git` gitfile itself, exactly as [`crate::apply`]
/// partitions it.
fn is_git_path(path: &str) -> bool {
    path == ".git" || path.starts_with(".git/")
}

/// Every name a conflict copy must not collide with: the keys of both
/// input manifests (a superset of `merged`'s), every directory prefix of
/// those keys (so a copy can never shadow a directory and break
/// [`manifest::validate`]'s file/dir rule), and the copies claimed so far.
struct NameSpace(HashSet<String>);

impl NameSpace {
    fn new(local: &Manifest, remote: &Manifest) -> Self {
        let mut taken = HashSet::new();
        for path in local.files.keys().chain(remote.files.keys()) {
            taken.insert(path.clone());
            let mut rest = path.as_str();
            while let Some(idx) = rest.rfind('/') {
                rest = &rest[..idx];
                taken.insert(rest.to_string());
            }
        }
        Self(taken)
    }

    /// `stem (conflict from <device> <stamp>)[.ext]` in `path`'s directory,
    /// with ` 2`, ` 3`, … appended before the extension on collision.
    fn claim(&mut self, path: &str, device: &str, stamp: &str) -> String {
        let (dir, name) = match path.rfind('/') {
            Some(idx) => (&path[..=idx], &path[idx + 1..]),
            None => ("", path),
        };
        // A leading dot is not an extension: `.env` keeps its whole name as
        // the stem, `archive.tar.gz` splits at the LAST dot.
        let (stem, ext) = match name.rfind('.') {
            Some(idx) if idx > 0 => (&name[..idx], &name[idx..]),
            _ => (name, ""),
        };
        let mut n = 1u32;
        loop {
            let ordinal = if n == 1 {
                String::new()
            } else {
                format!(" {n}")
            };
            let candidate = format!("{dir}{stem} (conflict from {device} {stamp}){ordinal}{ext}");
            if self.0.insert(candidate.clone()) {
                return candidate;
            }
            n += 1;
        }
    }
}

/// A device name goes into a manifest path, so it must not carry a
/// separator or a control character: `manifest::validate` would reject the
/// merged manifest, and a `/` would relocate the copy.
fn sanitize_device(device: &str) -> String {
    let cleaned: String = device
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() {
        "device".to_string()
    } else {
        cleaned
    }
}

/// Format a conflict-copy timestamp as `YYYY-MM-DD HHMMSS` in UTC (no
/// colons: the stamp lands in a filename). Kept out of [`merge`] itself so
/// the merge stays pure; the converge loop injects the result.
pub fn conflict_stamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02} {h:02}{mi:02}{s:02}")
}

/// Days-since-epoch -> (year, month, day), Howard Hinnant's `civil_from_days`
/// (public domain). std has no calendar, and §32 adds no dependencies.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAMP: &str = "2026-07-24 153000";
    const DEV: &str = "dev";

    fn h(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    /// A FileEntry whose content is `seed` and whose mtime is `mtime`.
    fn e(seed: u8, mtime: i64) -> FileEntry {
        FileEntry {
            size: seed as u64 + 1,
            mode: 0o644,
            mtime_secs: mtime,
            mtime_nanos: 0,
            chunks: vec![h(seed)],
        }
    }

    fn manifest(entries: &[(&str, FileEntry)]) -> Manifest {
        let mut m = Manifest::new("ws".into());
        for (path, entry) in entries {
            m.files.insert((*path).to_string(), entry.clone());
        }
        m
    }

    fn run(
        base: &[(&str, FileEntry)],
        local: &[(&str, FileEntry)],
        remote: &[(&str, FileEntry)],
    ) -> MergeOutcome {
        let out = merge(
            &manifest(base),
            &manifest(local),
            &manifest(remote),
            DEV,
            STAMP,
        );
        manifest::validate(&out.merged).expect("merged manifests always validate");
        out
    }

    // ---------- §32 merge-rule table, row by row ----------

    #[test]
    fn row_unchanged_unchanged_keeps() {
        let out = run(&[("f", e(1, 10))], &[("f", e(1, 10))], &[("f", e(1, 10))]);
        assert_eq!(out.merged.files["f"], e(1, 10));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_local_changed_remote_unchanged_keeps_local() {
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 20))], &[("f", e(1, 10))]);
        assert_eq!(out.merged.files["f"], e(2, 20));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_local_added_remote_absent_keeps_local() {
        let out = run(&[], &[("f", e(2, 20))], &[]);
        assert_eq!(out.merged.files["f"], e(2, 20));
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_remote_changed_local_unchanged_applies_remote() {
        let out = run(&[("f", e(1, 10))], &[("f", e(1, 10))], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote.changed, vec!["f"]);
    }

    #[test]
    fn row_remote_added_local_absent_applies_remote() {
        let out = run(&[], &[], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30));
        assert_eq!(out.apply_from_remote.added, vec!["f"]);
    }

    #[test]
    fn row_local_deleted_remote_unchanged_propagates_delete() {
        let out = run(&[("f", e(1, 10))], &[], &[("f", e(1, 10))]);
        assert!(out.merged.files.is_empty());
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_remote_deleted_local_unchanged_deletes_locally() {
        let out = run(&[("f", e(1, 10))], &[("f", e(1, 10))], &[]);
        assert!(out.merged.files.is_empty());
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote.deleted, vec!["f"]);
    }

    #[test]
    fn row_local_deleted_remote_changed_restores_remote() {
        // Edit beats delete: the file comes back.
        let out = run(&[("f", e(1, 10))], &[], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote.added, vec!["f"]);
    }

    #[test]
    fn row_local_changed_remote_deleted_keeps_local() {
        // Edit beats delete the other way: our edit is re-published.
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 20))], &[]);
        assert_eq!(out.merged.files["f"], e(2, 20));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_both_changed_equal_content_keeps_newer_mtime() {
        // Same chunks, same mode, same size — only the mtime differs.
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 20))], &[("f", e(2, 50))]);
        assert_eq!(out.merged.files["f"], e(2, 50), "newer mtime wins the entry");
        assert!(out.conflicts.is_empty(), "same bytes, no conflict copy");
        assert_eq!(out.apply_from_remote.changed, vec!["f"]);

        // The other direction: the local entry is the newer one.
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 60))], &[("f", e(2, 50))]);
        assert_eq!(out.merged.files["f"], e(2, 60));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_both_added_equal_is_a_keep() {
        // Absent from base, added identically on both sides.
        let out = run(&[], &[("f", e(2, 20))], &[("f", e(2, 20))]);
        assert_eq!(out.merged.files["f"], e(2, 20));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.apply_from_remote, ManifestDiff::default());
    }

    #[test]
    fn row_both_changed_differing_is_lww_remote_newer() {
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 20))], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30), "newer remote wins");
        assert_eq!(out.conflicts.len(), 1);
        let c = &out.conflicts[0];
        assert_eq!(c.side, ConflictSide::Local);
        assert_eq!(c.path, "f");
        assert_eq!(c.copy_path, format!("f (conflict from {DEV} {STAMP})"));
        assert_eq!(c.entry, e(2, 20));
        assert_eq!(out.merged.files[&c.copy_path], e(2, 20));
        // The local loser's bytes are already on disk: never an apply.
        assert_eq!(out.apply_from_remote.changed, vec!["f"]);
        assert!(out.apply_from_remote.added.is_empty());
    }

    #[test]
    fn row_both_changed_differing_is_lww_local_newer() {
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 40))], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(2, 40), "newer local wins");
        let c = &out.conflicts[0];
        assert_eq!(c.side, ConflictSide::Remote);
        assert_eq!(c.copy_path, format!("f (conflict from remote {STAMP})"));
        assert_eq!(c.entry, e(3, 30));
        // The remote loser is ordinary remote content: assembled by apply.
        assert_eq!(out.apply_from_remote.added, vec![c.copy_path.clone()]);
        assert!(out.apply_from_remote.changed.is_empty());
    }

    #[test]
    fn row_both_added_differing_is_lww() {
        let out = run(&[], &[("f", e(2, 20))], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30));
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].side, ConflictSide::Local);
    }

    #[test]
    fn lww_tie_goes_to_the_remote() {
        let out = run(&[("f", e(1, 10))], &[("f", e(2, 30))], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], e(3, 30));
        assert_eq!(out.conflicts[0].side, ConflictSide::Local);

        // Nanoseconds break the tie before the side rule does.
        let mut local = e(2, 30);
        local.mtime_nanos = 1;
        let out = run(&[("f", e(1, 10))], &[("f", local.clone())], &[("f", e(3, 30))]);
        assert_eq!(out.merged.files["f"], local);
        assert_eq!(out.conflicts[0].side, ConflictSide::Remote);
    }

    // ---------- conflict copy naming ----------

    #[test]
    fn conflict_names_preserve_extensions_and_directories() {
        for (path, want) in [
            ("foo.rs", format!("foo (conflict from {DEV} {STAMP}).rs")),
            (
                "src/lib.rs",
                format!("src/lib (conflict from {DEV} {STAMP}).rs"),
            ),
            // A leading dot is not an extension.
            (".env", format!(".env (conflict from {DEV} {STAMP})")),
            (
                "a/.env.local",
                format!("a/.env (conflict from {DEV} {STAMP}).local"),
            ),
            // No extension at all.
            ("Makefile", format!("Makefile (conflict from {DEV} {STAMP})")),
            // Multi-dot names split at the LAST dot.
            (
                "archive.tar.gz",
                format!("archive.tar (conflict from {DEV} {STAMP}).gz"),
            ),
        ] {
            let out = run(&[(path, e(1, 10))], &[(path, e(2, 20))], &[(path, e(3, 30))]);
            assert_eq!(out.conflicts[0].copy_path, want, "naming {path}");
            assert!(out.merged.files.contains_key(&want));
        }
    }

    #[test]
    fn colliding_conflict_names_get_numbered() {
        // The un-numbered name is already a real file on the remote, and
        // ` 2` is taken by a local file: the copy lands on ` 3`.
        let first = format!("f (conflict from {DEV} {STAMP}).txt");
        let second = format!("f (conflict from {DEV} {STAMP}) 2.txt");
        let out = run(
            &[("f.txt", e(1, 10))],
            &[("f.txt", e(2, 20)), (second.as_str(), e(8, 80))],
            &[("f.txt", e(3, 30)), (first.as_str(), e(9, 90))],
        );
        assert_eq!(
            out.conflicts[0].copy_path,
            format!("f (conflict from {DEV} {STAMP}) 3.txt")
        );
        // Neither pre-existing file was clobbered.
        assert_eq!(out.merged.files[&first], e(9, 90));
        assert_eq!(out.merged.files[&second], e(8, 80));
    }

    /// A conflict copy inside `.git` never enters the manifest or the
    /// tree (an invalid refname breaks `git fsck --strict` on every device
    /// that syncs it): it becomes a LOCAL-ONLY copy under
    /// `.pear/conflicts/`, keeping the ordinary name.
    #[test]
    fn git_conflict_copies_are_local_only() {
        for (path, want) in [
            (
                ".git/refs/heads/main",
                format!(".pear/conflicts/.git/refs/heads/main (conflict from {DEV} {STAMP})"),
            ),
            // The gitfile itself counts as `.git`.
            (
                ".git",
                format!(".pear/conflicts/.git (conflict from {DEV} {STAMP})"),
            ),
        ] {
            let out = run(&[(path, e(1, 10))], &[(path, e(2, 20))], &[(path, e(3, 30))]);
            let c = &out.conflicts[0];
            assert!(c.local_only, "{path} must not sync its conflict copy");
            assert_eq!(c.copy_path, want);
            assert_eq!(c.entry, e(2, 20), "the loser's bytes are still preserved");
            // The winner stands alone in `merged`: no copy, and nothing
            // for the apply to fetch.
            assert_eq!(out.merged.files[path], e(3, 30));
            assert_eq!(out.merged.files.len(), 1);
            assert!(out.apply_from_remote.added.is_empty());
            assert_eq!(out.apply_from_remote.changed, vec![path.to_string()]);
        }

        // The remote side loses: same rule, and the copy is still absent
        // from `merged` (the converge assembles it from chunks locally).
        let path = ".git/HEAD";
        let out = run(&[(path, e(1, 10))], &[(path, e(2, 40))], &[(path, e(3, 30))]);
        let c = &out.conflicts[0];
        assert_eq!(c.side, ConflictSide::Remote);
        assert!(c.local_only);
        assert_eq!(
            c.copy_path,
            format!(".pear/conflicts/.git/HEAD (conflict from remote {STAMP})")
        );
        assert_eq!(out.merged.files.len(), 1);
        assert!(out.apply_from_remote.added.is_empty());

        // A worktree path that merely MENTIONS .git is an ordinary copy.
        let out = run(
            &[("src/.gitignore", e(1, 10))],
            &[("src/.gitignore", e(2, 20))],
            &[("src/.gitignore", e(3, 30))],
        );
        assert!(!out.conflicts[0].local_only);
        assert!(out.merged.files.contains_key(&out.conflicts[0].copy_path));
    }

    #[test]
    fn two_conflicts_in_one_merge_get_distinct_names() {
        let out = run(
            &[("a/f.txt", e(1, 10)), ("a/g.txt", e(1, 10))],
            &[("a/f.txt", e(2, 20)), ("a/g.txt", e(2, 20))],
            &[("a/f.txt", e(3, 30)), ("a/g.txt", e(3, 30))],
        );
        assert_eq!(out.conflicts.len(), 2);
        assert_ne!(out.conflicts[0].copy_path, out.conflicts[1].copy_path);
    }

    #[test]
    fn conflict_name_never_shadows_a_directory() {
        // `f` conflicts, and a directory named exactly like the copy
        // already exists: the copy must not create a file/dir collision.
        let dir_child = format!("f (conflict from {DEV} {STAMP})/inner.txt");
        let out = run(
            &[("f", e(1, 10))],
            &[("f", e(2, 20)), (dir_child.as_str(), e(8, 80))],
            &[("f", e(3, 30))],
        );
        assert_eq!(
            out.conflicts[0].copy_path,
            format!("f (conflict from {DEV} {STAMP}) 2")
        );
        // `run` already asserts the merged manifest validates.
    }

    #[test]
    fn device_names_cannot_escape_their_directory() {
        let out = merge(
            &manifest(&[("a/f", e(1, 10))]),
            &manifest(&[("a/f", e(2, 20))]),
            &manifest(&[("a/f", e(3, 30))]),
            "../../evil",
            STAMP,
        );
        manifest::validate(&out.merged).expect("a hostile device name cannot escape");
        let copy = &out.conflicts[0].copy_path;
        assert!(copy.starts_with("a/f (conflict from "), "{copy}");
        assert_eq!(
            copy.matches('/').count(),
            1,
            "the copy stays in the contested file's own directory: {copy}"
        );
    }

    // ---------- determinism and convergence ----------

    #[test]
    fn merge_is_deterministic() {
        let base = manifest(&[("f", e(1, 10)), ("g", e(1, 10))]);
        let local = manifest(&[("f", e(2, 20)), ("h", e(4, 40))]);
        let remote = manifest(&[("f", e(3, 30)), ("g", e(5, 50))]);
        let a = merge(&base, &local, &remote, DEV, STAMP);
        let b = merge(&base, &local, &remote, DEV, STAMP);
        assert_eq!(a, b);
    }

    /// §32's convergence property: A publishes `merge(base, A, B)`; B then
    /// merges its own view against that head and must land on exactly the
    /// same file set, with no new conflicts.
    #[test]
    fn the_other_device_converges_onto_the_published_head() {
        let base = manifest(&[("shared", e(1, 10)), ("gone", e(1, 10))]);
        let a = manifest(&[("shared", e(2, 20)), ("gone", e(1, 10)), ("a-only", e(6, 60))]);
        let b = manifest(&[("shared", e(3, 30)), ("b-only", e(7, 70))]);

        // Device A merges its scan against B's head and publishes.
        let head_ab = merge(&base, &a, &b, "device-a", STAMP).merged;
        // Device B (no further edits) converges against that head. Its own
        // base is still the shared ancestor, its local scan is still `b`.
        let out_b = merge(&base, &b, &head_ab, "device-b", STAMP);
        assert!(
            out_b.conflicts.is_empty(),
            "re-merging a published head must not conflict again"
        );
        assert_eq!(
            out_b.merged.files, head_ab.files,
            "B lands byte-identically on the published head"
        );
        // And A, re-merging the head it published, is already there.
        let out_a = merge(&base, &head_ab, &head_ab, "device-a", STAMP);
        assert!(out_a.conflicts.is_empty());
        assert_eq!(out_a.merged.files, head_ab.files);
    }

    #[test]
    fn conflicting_edits_converge_with_the_copy_on_both_devices() {
        let base = manifest(&[("f", e(1, 10))]);
        let a = manifest(&[("f", e(2, 20))]);
        let b = manifest(&[("f", e(3, 30))]);
        // A merges B's head: B is newer, so A's copy is preserved.
        let out_a = merge(&base, &a, &b, "device-a", STAMP);
        assert_eq!(out_a.conflicts.len(), 1);
        let head = out_a.merged.clone();
        // B converges onto A's published head: it sees the winner it
        // already has plus the conflict copy as a plain add.
        let out_b = merge(&base, &b, &head, "device-b", STAMP);
        assert!(out_b.conflicts.is_empty());
        assert_eq!(out_b.merged.files, head.files);
        assert_eq!(out_b.apply_from_remote.added.len(), 1);
    }

    #[test]
    fn delete_versus_edit_converges_both_directions() {
        let base = manifest(&[("f", e(1, 10))]);
        // Local deleted, remote edited: restored, then stable.
        let head = merge(&base, &manifest(&[]), &manifest(&[("f", e(3, 30))]), DEV, STAMP).merged;
        assert_eq!(head.files["f"], e(3, 30));
        let again = merge(&base, &manifest(&[]), &head, DEV, STAMP);
        assert_eq!(again.merged.files, head.files);

        // Local edited, remote deleted: re-published, then stable.
        let head = merge(
            &base,
            &manifest(&[("f", e(2, 20))]),
            &manifest(&[]),
            DEV,
            STAMP,
        )
        .merged;
        assert_eq!(head.files["f"], e(2, 20));
        let peer = merge(&base, &manifest(&[]), &head, DEV, STAMP);
        assert!(peer.conflicts.is_empty());
        assert_eq!(peer.merged.files, head.files);
    }

    #[test]
    fn merged_carries_the_local_workspace_id_and_scan_time() {
        let mut local = manifest(&[("f", e(1, 10))]);
        local.scanned_at_secs = 777;
        let out = merge(&Manifest::new("ws".into()), &local, &manifest(&[]), DEV, STAMP);
        assert_eq!(out.merged.workspace_id, "ws");
        assert_eq!(out.merged.scanned_at_secs, 777);
        assert_eq!(out.merged.version, FORMAT_VERSION);
    }

    #[test]
    fn conflict_stamp_formats_utc_without_colons() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_774_366_200);
        assert_eq!(conflict_stamp(t), "2026-03-24 153000");
        assert_eq!(conflict_stamp(SystemTime::UNIX_EPOCH), "1970-01-01 000000");
        // A leap day, and the last second of a year.
        let leap = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_709_208_000);
        assert_eq!(conflict_stamp(leap), "2024-02-29 120000");
        let eoy = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_599);
        assert_eq!(conflict_stamp(eoy), "2025-12-31 235959");
    }
}
