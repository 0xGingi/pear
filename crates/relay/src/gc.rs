//! §24 pool garbage collection: mark-and-sweep over the global chunk pool.
//!
//! `chunk_refs` is insert-only since §13 and blobs are never deleted, so
//! the pool grows monotonically (§20 key rotations add a generation of
//! ciphertext per rotation). One sweep:
//!
//! 1. MARK: rebuild the live set per workspace — the chunk lists of the
//!    RETAINED head rows (§13's HEAD_KEEP, applied at insert) plus every
//!    retained snapshot row of any kind, parsed from the `manifest`
//!    column exactly as commit-time validation extracted them (plaintext:
//!    Manifest files→chunks; e2e: the §24 chunk_hashes envelope — see
//!    `routes::stored_row_chunks`).
//! 2. REBUILD REFS: `chunk_refs` becomes EXACTLY that live set, one
//!    transaction for all workspaces (`Db::gc_rebuild_refs`). Unjustified
//!    rows die (that's the GC), missing justified rows are re-inserted
//!    (self-healing for refs drift: §22 WAL rollbacks, e2e force-
//!    checkpoints that commit no refs of their own). A workspace with
//!    zero retained rows keeps nothing — its refs were PUT-only and heal
//!    by re-upload, per §22's argument.
//! 3. SWEEP BLOBS: walk `chunks/<2>/<hash>`; a blob with no refs row
//!    anywhere is deleted UNLESS its mtime is younger than the grace
//!    window (10 minutes in production, §24: covers a push between
//!    chunk-upload and head-commit, refs being earned only at commit).
//!    `.tmp-*` files are skipped (`sweep_tmp` owns them) and names that
//!    are not chunk hashes are never touched.
//!
//! v1 runs the whole sweep under the one DB mutex (the caller locks
//! once): an hourly seconds-scale stall at monorepo sizes beats a
//! lock-free race (§24). GC never changes visibility semantics: a chunk
//! referenced by any current head/snapshot/checkpoint keeps its refs, so
//! `chunk_visible_to` is invariant under GC.

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use pear_core::store::LocalStore;

use crate::db::Db;

/// One sweep's tally, logged by the spawner (§24 cadence line).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct GcReport {
    /// Blob files examined (hash-shaped names under `chunks/`).
    pub(crate) scanned: usize,
    /// `chunk_refs` rows deleted by the rebuild (drift vs the live set).
    pub(crate) refs_deleted: usize,
    /// Unreferenced, grace-expired blobs unlinked.
    pub(crate) blobs_deleted: usize,
    pub(crate) bytes_deleted: u64,
    /// Workspaces left untouched because a retained row would not parse
    /// (a pre-§24 bare-`manifest_enc` e2e row, or corruption). Skipping
    /// is the conservative arm: GC never collects what it cannot
    /// understand — the workspace's refs stay as they are, so no blob it
    /// references is swept either. Self-heals once the unparseable row
    /// ages out of retention (or is rewritten by a new commit).
    pub(crate) workspaces_skipped: usize,
}

impl std::fmt::Display for GcReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scanned={}, refs_deleted={}, blobs_deleted={}, bytes_deleted={}, workspaces_skipped={}",
            self.scanned, self.refs_deleted, self.blobs_deleted, self.bytes_deleted, self.workspaces_skipped
        )
    }
}

/// One full mark-and-sweep (§24). The caller holds the DB mutex for the
/// whole call: live-set reads, the refs rebuild, and every blob unlink
/// see one consistent database. `grace` is the in-flight-push window for
/// the blob sweep (tests pass `Duration::ZERO` for determinism).
pub(crate) fn run_pool_gc(db: &Db, store: &LocalStore, grace: Duration) -> anyhow::Result<GcReport> {
    let mut report = GcReport::default();

    // MARK, per workspace. Rows are read manifest-by-manifest and folded
    // into the live set: a manifest can be tens of MiB, and 50 retained
    // heads plus snapshots must not all be resident at once.
    let mut live: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (id, e2e) in db.list_workspaces_for_gc()? {
        let mut pinned = HashSet::new();
        let mut parseable = true;
        for stored in db
            .retained_head_manifests(&id)?
            .into_iter()
            .chain(db.snapshot_manifests(&id)?)
        {
            match crate::routes::stored_row_chunks(e2e, &stored) {
                Ok(chunks) => pinned.extend(chunks),
                Err(_) => {
                    // See GcReport::workspaces_skipped: never collect what
                    // we cannot parse.
                    parseable = false;
                    break;
                }
            }
        }
        if parseable {
            live.insert(id, pinned);
        } else {
            report.workspaces_skipped += 1;
        }
    }

    // REBUILD REFS to exactly the live set (one transaction inside).
    report.refs_deleted = db.gc_rebuild_refs(&live)?;

    // SWEEP BLOBS: no refs row anywhere + mtime older than the grace
    // window = collectable.
    sweep_blobs(db, store, grace, &mut report)?;
    Ok(report)
}

/// The blob half of the sweep (§24 step 3). Only files named like a chunk
/// hash directly under a `chunks/<2>/` shard dir are even candidates —
/// everything else (`.tmp-*` temporaries owned by `sweep_tmp`, foreign or
/// corrupt names, non-files, non-shard entries) is left strictly alone.
fn sweep_blobs(
    db: &Db,
    store: &LocalStore,
    grace: Duration,
    report: &mut GcReport,
) -> anyhow::Result<()> {
    let chunks_dir = store.root().join("chunks");
    // A push that uploaded bytes but has not committed yet has no refs
    // row: the grace window is what protects it. mtimes in the future
    // (clock skew) read as "too young" and are kept.
    let cutoff = SystemTime::now().checked_sub(grace);
    let shards = match std::fs::read_dir(&chunks_dir) {
        Ok(shards) => shards,
        // No pool directory yet (never opened/empty store): nothing to do.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", chunks_dir.display())),
    };
    for shard in shards {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            continue;
        };
        for entry in std::fs::read_dir(shard.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(".tmp-") {
                continue; // crash-orphaned temporaries are sweep_tmp's
            }
            if !crate::routes::is_chunk_hash(name) {
                continue; // not a blob this relay wrote: never GC's to delete
            }
            report.scanned += 1;
            if db.hash_has_refs(name)? {
                continue;
            }
            let metadata = entry.metadata()?;
            let old_enough = cutoff.is_some_and(|cutoff| {
                metadata
                    .modified()
                    .is_ok_and(|mtime| mtime < cutoff)
            });
            if !old_enough {
                continue; // inside the in-flight-push grace window
            }
            std::fs::remove_file(entry.path())
                .with_context(|| format!("delete unreferenced blob {name}"))?;
            report.blobs_deleted += 1;
            report.bytes_deleted += metadata.len();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// A workspace, its DB, and a pool store in one tempdir.
    fn fixture() -> (tempfile::TempDir, crate::db::Db, LocalStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&dir.path().join("relay.db")).unwrap();
        let store = LocalStore::open(dir.path().join("pool")).unwrap();
        (dir, db, store)
    }

    /// A valid plaintext manifest document referencing `chunks` (one file
    /// per chunk, mirroring tests.rs's fixture shape).
    fn manifest_json(ws: &str, chunks: &[&str]) -> String {
        let files: serde_json::Map<String, serde_json::Value> = chunks
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                (
                    format!("file-{i}.txt"),
                    serde_json::json!({
                        "size": 3, "mode": 420, "mtime_secs": 1, "mtime_nanos": 0,
                        "chunks": [hash],
                    }),
                )
            })
            .collect();
        serde_json::json!({
            "version": 1,
            "workspace_id": ws,
            "scanned_at_secs": 0,
            "files": files,
        })
        .to_string()
    }

    fn create_plain(db: &crate::db::Db, ws: &str) {
        db.create_workspace(ws, "w", Some("alice"), None, false)
            .unwrap();
    }

    /// Commit a plaintext head holding `chunks` at the next seq.
    fn commit_head(db: &crate::db::Db, ws: &str, seq: i64, chunks: &[&str]) {
        let refs: HashSet<String> = chunks.iter().map(|s| s.to_string()).collect();
        let manifest = manifest_json(ws, chunks);
        let hash = blake3::hash(manifest.as_bytes()).to_hex().to_string();
        db.insert_head(ws, seq, &hash, &manifest, &refs).unwrap();
    }

    fn commit_named_snapshot(db: &crate::db::Db, ws: &str, chunks: &[&str]) -> i64 {
        let refs: HashSet<String> = chunks.iter().map(|s| s.to_string()).collect();
        let manifest = manifest_json(ws, chunks);
        db.insert_snapshot(
            ws,
            crate::db::NewSnapshot {
                name: Some("named"),
                kind: "named",
                device: "dev",
                created_at: 1_000,
                manifest: &manifest,
                refs: &refs,
            },
        )
        .unwrap()
    }

    fn commit_checkpoint(db: &crate::db::Db, ws: &str, created_at: i64, chunks: &[&str]) -> i64 {
        let refs: HashSet<String> = chunks.iter().map(|s| s.to_string()).collect();
        let manifest = manifest_json(ws, chunks);
        db.insert_snapshot(
            ws,
            crate::db::NewSnapshot {
                name: None,
                kind: "checkpoint",
                device: "dev",
                created_at,
                manifest: &manifest,
                refs: &refs,
            },
        )
        .unwrap()
    }

    fn put_blob(store: &LocalStore, data: &[u8]) -> String {
        let hash = hash_of(data);
        pear_core::store::ChunkSink::put(store, &hash, data).unwrap();
        hash
    }

    fn blob_exists(store: &LocalStore, hash: &str) -> bool {
        pear_core::store::ChunkSink::has(store, hash).unwrap()
    }

    /// §24: a chunk referenced only by a head that HEAD_KEEP retention
    /// pruned loses its refs row AND its blob; the current head's chunk
    /// is untouched. A second run is a strict no-op (mark-and-sweep is
    /// idempotent).
    #[test]
    fn superseded_head_chunks_lose_refs_and_blob() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let old = put_blob(&store, b"old content");
        let new = put_blob(&store, b"new content");
        commit_head(&db, "ws", 1, &[&old]);
        // 50 newer heads push seq 1 out of retention (HEAD_KEEP = 50).
        for seq in 2..=51 {
            commit_head(&db, "ws", seq, &[&new]);
        }

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.scanned, 2);
        assert_eq!(report.refs_deleted, 1, "only the old chunk's refs row");
        assert_eq!(report.blobs_deleted, 1);
        assert_eq!(report.bytes_deleted, b"old content".len() as u64);
        assert_eq!(report.workspaces_skipped, 0);
        assert!(!blob_exists(&store, &old), "superseded chunk collected");
        assert!(blob_exists(&store, &new), "current head chunk pinned");
        assert!(!db.hash_has_refs(&old).unwrap());
        assert!(db.hash_has_refs(&new).unwrap());

        let second = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(second, GcReport {
            scanned: 1,
            ..GcReport::default()
        });
    }

    /// §24: a named snapshot pins its chunks independently of head
    /// retention — superseding the head that introduced a chunk does not
    /// collect it while a snapshot still references it.
    #[test]
    fn named_snapshot_pins_its_chunk() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let old = put_blob(&store, b"old content");
        let snapped = put_blob(&store, b"snapshot content");
        let new = put_blob(&store, b"new content");
        commit_head(&db, "ws", 1, &[&old, &snapped]);
        commit_named_snapshot(&db, "ws", &[&snapped]);
        for seq in 2..=51 {
            commit_head(&db, "ws", seq, &[&new]);
        }

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.refs_deleted, 1, "only the exclusively-old chunk");
        assert_eq!(report.blobs_deleted, 1);
        assert!(!blob_exists(&store, &old));
        assert!(blob_exists(&store, &snapped), "the snapshot pins it");
        assert!(blob_exists(&store, &new));
    }

    /// §24's grace window: an unreferenced blob younger than the grace
    /// (a push between chunk-upload and head-commit) survives; the same
    /// blob is collectable with a zero grace (the test-only deterministic
    /// arm) once the window has effectively passed.
    #[test]
    fn young_unreferenced_blob_survives_the_grace_window() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let referenced = put_blob(&store, b"referenced");
        let in_flight = put_blob(&store, b"just uploaded");
        commit_head(&db, "ws", 1, &[&referenced]);
        // `in_flight` has no refs row anywhere: PUT-only visibility was
        // not even earned at the db level here.

        let grace = run_pool_gc(&db, &store, Duration::from_secs(600)).unwrap();
        assert_eq!(grace.scanned, 2);
        assert_eq!(grace.blobs_deleted, 0, "the grace window protects it");
        assert!(blob_exists(&store, &in_flight));

        let zero = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(zero.blobs_deleted, 1);
        assert!(!blob_exists(&store, &in_flight));
        assert!(blob_exists(&store, &referenced));
    }

    /// §24: a workspace with zero retained rows loses ALL its refs —
    /// they were PUT-only (earned at upload, justified by nothing) and
    /// heal by re-upload per §22's argument.
    #[test]
    fn workspace_with_no_retained_rows_loses_all_refs() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let stray = put_blob(&store, b"never committed");
        db.insert_chunk_refs("ws", &HashSet::from([stray.clone()]))
            .unwrap();
        assert!(db.hash_has_refs(&stray).unwrap());

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.refs_deleted, 1);
        assert_eq!(report.blobs_deleted, 1);
        assert!(!db.hash_has_refs(&stray).unwrap());
        assert!(!blob_exists(&store, &stray));
    }

    /// §24 + §14: a checkpoint pruned by time-based retention no longer
    /// pins anything — its exclusive chunk is collected, while the
    /// retained checkpoint and the head keep theirs.
    #[test]
    fn pruned_checkpoint_chunks_are_collected() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let head_chunk = put_blob(&store, b"head");
        let pruned_chunk = put_blob(&store, b"pruned checkpoint");
        let kept_chunk = put_blob(&store, b"kept checkpoint");
        commit_head(&db, "ws", 1, &[&head_chunk]);
        let now = 1_000_000_000i64;
        let doomed = commit_checkpoint(&db, "ws", now - 8 * 86_400, &[&pruned_chunk]);
        // The newer checkpoint's insert runs §14 retention with its own
        // timestamp as `now`: an 8-day-old checkpoint is always pruned.
        let _kept = commit_checkpoint(&db, "ws", now, &[&kept_chunk]);
        assert!(
            db.get_snapshot("ws", doomed).unwrap().is_none(),
            "§14 retention already deleted the row"
        );

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.refs_deleted, 1);
        assert_eq!(report.blobs_deleted, 1);
        assert!(!blob_exists(&store, &pruned_chunk));
        assert!(blob_exists(&store, &kept_chunk), "retained checkpoint pins");
        assert!(blob_exists(&store, &head_chunk), "the head pins");
    }

    /// The conservative arm: a workspace with a row GC cannot parse (a
    /// pre-§24 bare-`manifest_enc` e2e row, or a corrupt plaintext row)
    /// keeps its refs untouched — GC never collects what it cannot
    /// understand — without affecting other workspaces' sweeps.
    #[test]
    fn unparseable_rows_skip_the_workspace_conservatively() {
        let (_dir, db, store) = fixture();
        // Healthy workspace: collected normally.
        create_plain(&db, "ws-ok");
        let dead = put_blob(&store, b"dead");
        db.insert_chunk_refs("ws-ok", &HashSet::from([dead.clone()]))
            .unwrap();
        // Legacy e2e workspace: a bare base64 manifest_enc row (the §17
        // storage before §24's envelope) carries no recoverable chunk
        // list.
        db.create_workspace("ws-legacy", "w", Some("alice"), None, true)
            .unwrap();
        let legacy_chunk = put_blob(&store, b"legacy pinned");
        let bare_enc = pear_core::crypto::base64_encode(b"nonce-12-bytesciphertext");
        let refs = HashSet::from([legacy_chunk.clone()]);
        db.insert_head("ws-legacy", 1, "h", &bare_enc, &refs).unwrap();
        // Corrupt plaintext workspace.
        create_plain(&db, "ws-corrupt");
        let corrupt_chunk = put_blob(&store, b"corrupt pinned");
        let refs = HashSet::from([corrupt_chunk.clone()]);
        db.insert_head("ws-corrupt", 1, "h", "not json at all", &refs)
            .unwrap();

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.workspaces_skipped, 2);
        assert_eq!(report.refs_deleted, 1, "only the healthy workspace's");
        assert_eq!(report.blobs_deleted, 1);
        assert!(!blob_exists(&store, &dead), "healthy workspace still swept");
        assert!(blob_exists(&store, &legacy_chunk), "skipped: refs intact");
        assert!(blob_exists(&store, &corrupt_chunk), "skipped: refs intact");
        assert!(db.hash_has_refs(&legacy_chunk).unwrap());
        assert!(db.hash_has_refs(&corrupt_chunk).unwrap());
    }

    /// The sweep touches only files named like a chunk hash: `.tmp-*`
    /// temporaries (sweep_tmp's), corrupt names, and wrong-case/length
    /// near-misses all survive a zero-grace run that collects a real
    /// unreferenced blob.
    #[test]
    fn corrupt_and_tmp_files_in_the_pool_are_untouched() {
        let (_dir, db, store) = fixture();
        create_plain(&db, "ws");
        let referenced = put_blob(&store, b"referenced");
        let stray = put_blob(&store, b"stray");
        commit_head(&db, "ws", 1, &[&referenced]);
        let shard = store.root().join("chunks").join(&stray[..2]);
        let tmp = shard.join(".tmp-1234-deadbeef");
        let corrupt = shard.join("not-a-chunk-hash");
        let short = shard.join("abcd");
        // 64 UPPERCASE hex chars: near-misses the shape check. No
        // lowercase twin exists, so it is a distinct file even on
        // case-insensitive filesystems.
        let upper_shard = store.root().join("chunks").join("aa");
        std::fs::create_dir_all(&upper_shard).unwrap();
        let uppercase = upper_shard.join("A".repeat(64));
        for path in [&tmp, &corrupt, &uppercase, &short] {
            std::fs::write(path, b"x").unwrap();
        }

        let report = run_pool_gc(&db, &store, Duration::ZERO).unwrap();
        assert_eq!(report.scanned, 2, "only hash-shaped names are examined");
        assert_eq!(report.blobs_deleted, 1, "only the unreferenced blob");
        assert!(blob_exists(&store, &referenced));
        assert!(!blob_exists(&store, &stray));
        for path in [&tmp, &corrupt, &uppercase, &short] {
            assert!(path.exists(), "{} survives", path.display());
        }
    }
}
