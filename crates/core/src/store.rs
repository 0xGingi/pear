use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

/// Where chunks go. A network transport (M2) can provide another impl.
pub trait ChunkSink {
    fn has(&self, hash: &str) -> io::Result<bool>;
    /// Batch presence check: one entry per input hash, in order. The
    /// default loops `has`; transports with a batch endpoint (the relay's
    /// `chunks/missing`) override it so the writer flow never does
    /// per-chunk round trips.
    fn has_many(&self, hashes: &[String]) -> io::Result<Vec<bool>> {
        hashes.iter().map(|h| self.has(h)).collect()
    }
    /// Store the chunk if absent. Returns true if it was actually written.
    fn put(&self, hash: &str, data: &[u8]) -> io::Result<bool>;
    /// Batch store (§23): one result per input entry, in order —
    /// `Ok(true)` written, `Ok(false)` already present, `Err(reason)`
    /// this entry failed. The default loops `put`, and its FIRST io error
    /// fails the whole call: the caller then keeps every unconfirmed
    /// entry buffered, exactly as a per-chunk loop keeps the remainder on
    /// its first failure. Transports with a batch endpoint (the relay's
    /// `chunks/put_many`) override it so a push never does per-chunk
    /// round trips — there a per-entry failure stays per-entry, which is
    /// what keeps one deterministically-bad chunk from wedging the whole
    /// upload buffer.
    fn put_many(&self, entries: &[(String, Vec<u8>)]) -> io::Result<Vec<Result<bool, String>>> {
        let mut out = Vec::with_capacity(entries.len());
        for (hash, data) in entries {
            // The first io error fails the WHOLE call: the caller keeps
            // every unconfirmed entry buffered, exactly as a per-chunk
            // loop keeps the remainder on its first failure.
            let stored = self.put(hash, data)?;
            out.push(Ok(stored));
        }
        Ok(out)
    }
    /// Make every `put` issued so far durable as a group (§18; for
    /// `LocalStore` §25 sharpens this to shard-DIR fsyncs only — dirent
    /// durability, with torn DATA always caught by verify-on-get). The
    /// default is a no-op: eager sinks fsync per put and never have
    /// anything pending.
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Where chunks come from.
pub trait ChunkSource {
    fn get(&self, hash: &str) -> io::Result<Vec<u8>>;
}

/// Content-addressed chunk store on the local filesystem:
/// `<root>/chunks/<first 2 hex chars>/<full 64-char hex>`.
pub struct LocalStore {
    root: PathBuf,
    /// Set by `open_deferred` (§18/§25): `put` skips the per-chunk fsync
    /// and queues the chunk's shard dir in `pending` instead.
    deferred: bool,
    /// Deferred-mode flush queue (§25): SHARD-DIR paths of
    /// renamed-but-un-fsynced puts — one entry per put, duplicates
    /// included (dedupe happens at flush, so the threshold below keeps
    /// its §18 meaning: 64 unflushed PUTS, i.e. a bounded chunk-loss
    /// window, regardless of how puts spread over shards). No open fds:
    /// fsyncing the dir makes the rename DIRENT durable; a very recent
    /// chunk's DATA may still be power-loss-torn and is always caught by
    /// verify-on-get (the name IS the hash), healing by re-fetch/re-upload.
    /// Always empty in eager mode. A Mutex keeps `LocalStore: Sync` (the
    /// relay holds it in an Arc); it is never held across an fsync.
    /// Dropped WITHOUT a final fsync: Drop cannot report errors, and the
    /// ≤64-chunk loss window is by design recoverable — the source of
    /// truth (writer tree / relay pool) is untouched and verify-on-get
    /// heals torn chunks.
    pending: Mutex<Vec<PathBuf>>,
}
/// Pending puts at which a deferred store flushes itself (§18): caps
/// the crash-loss window at 64 un-fsynced chunks, all recoverable
/// because the source of truth (writer tree / relay pool) is untouched.
/// §25: the queue holds dir paths now, so the fd-pressure motivation is
/// gone — 64 stays purely as the loss-window bound.
const DEFERRED_FLUSH_THRESHOLD: usize = 64;

/// A chunk file name is exactly 64 lowercase hex chars (BLAKE3) —
/// stricter than `chunk_path`'s input check (any hex, any length): the
/// §24 sweep deletes only files the store could have written itself.
fn is_chunk_hash(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl LocalStore {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("chunks"))?;
        // The store holds plaintext of everything synced (including 0600
        // `.env` files): keep it owner-only, and sweep crash-orphaned
        // chunk temporaries from a `put` that died before rename.
        crate::fsutil::set_private_dir(&root)?;
        Self::sweep_tmp(&root);
        Ok(Self {
            root,
            deferred: false,
            pending: Mutex::new(Vec::new()),
        })
    }

    /// Deferred mode (§18/§25): `put` is tmp write + rename with NO
    /// fsync; the shard dir is queued and `flush` (called at sync-phase
    /// boundaries, or self-triggered at [`DEFERRED_FLUSH_THRESHOLD`]
    /// pending puts) fsyncs the queued SHARD DIRS ONLY (§25 — never the
    /// chunk files; that is the 20× fsync-count cut). After a flush a
    /// chunk's DIRENT is durable; a very recent chunk's DATA may be
    /// power-loss-torn and is ALWAYS caught by §18's mandatory
    /// verify-on-get (`get` re-hashes — the name IS the hash), healing
    /// by re-fetch/re-upload. Used by the client sync paths, and by the
    /// relay's pool under §22 (flushed AT COMMIT POINTS —
    /// put_head/create_snapshot — plus a 5 s backstop tick; a chunk
    /// referenced by a committed head/snapshot is present, and in the
    /// rare power-loss case detectably torn, never silently wrong).
    pub fn open_deferred(root: impl Into<PathBuf>) -> io::Result<Self> {
        let mut store = Self::open(root)?;
        store.deferred = true;
        Ok(store)
    }

    /// Remove crash-orphaned `.tmp-*` files left under `chunks/` by a
    /// `put` that died before rename. Only files older than a minute are
    /// touched: a fresh temp may belong to a CONCURRENTLY RUNNING pear
    /// process mid-put on the same store, and deleting it would fail
    /// that put with NotFound.
    fn sweep_tmp(root: &std::path::Path) {
        let Ok(dirs) = fs::read_dir(root.join("chunks")) else {
            return;
        };
        let Some(stale_before) =
            std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(60))
        else {
            return;
        };
        for dir in dirs.flatten() {
            let Ok(entries) = fs::read_dir(dir.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.file_name().to_string_lossy().starts_with(".tmp-") {
                    continue;
                }
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|mtime| mtime < stale_before);
                if stale {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// §24 local-store GC: delete chunk files whose hash is not in
    /// `keep`, returning (files deleted, bytes deleted). Walks the same
    /// `chunks/<2>/<hash>` layout `put` writes; `.tmp-*` files are
    /// skipped (`sweep_tmp` owns them) and names that are not chunk
    /// hashes are never touched — they are not blobs this store wrote.
    /// Empty shard dirs are left behind (256 worst case, harmless).
    ///
    /// MUST only run after a SUCCESSFUL apply + manifest commit (§24),
    /// with `keep` = the just-applied manifest's chunk set: a failed
    /// apply never sweeps, and a sweep over a stale manifest could
    /// delete chunks a later apply still needs — an M1 target store has
    /// no relay to re-fetch them from.
    pub fn sweep_unreferenced(
        &self,
        keep: &std::collections::HashSet<&str>,
    ) -> io::Result<(usize, u64)> {
        let mut deleted = 0usize;
        let mut bytes = 0u64;
        let shards = match fs::read_dir(self.root.join("chunks")) {
            Ok(shards) => shards,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e),
        };
        for shard in shards {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") {
                    continue; // crash-orphaned temporaries are sweep_tmp's
                }
                if !is_chunk_hash(name) {
                    continue; // not a blob this store wrote: never GC's to delete
                }
                if keep.contains(name) {
                    continue;
                }
                let metadata = entry.metadata()?;
                fs::remove_file(entry.path())?;
                deleted += 1;
                bytes += metadata.len();
            }
        }
        Ok((deleted, bytes))
    }

    fn chunk_path(&self, hash: &str) -> io::Result<PathBuf> {
        if hash.len() < 2 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid chunk hash {hash:?}"),
            ));
        }
        Ok(self.root.join("chunks").join(&hash[..2]).join(hash))
    }

    /// Flush point (§18, semantics sharpened by §25): fsync every queued
    /// shard dir (deduped) so the rename dirents are durable — and NOTHING
    /// else. §25 drops the per-file fsyncs: a very recent chunk's DATA can
    /// still be power-loss-torn after a successful flush, and that is safe
    /// because the name IS the hash — §18's mandatory verify-on-get
    /// re-hashes every read, so torn data is detected (delete + NotFound),
    /// never trusted, and heals by re-fetch/re-upload. The queue is
    /// drained under the lock but the fsyncs run OUTSIDE it — a slow disk
    /// must never block a concurrent `put`, and `put`'s threshold
    /// self-flush would deadlock on its own lock. On an fsync error the
    /// un-fsynced remainder (failed entry included) goes back on the
    /// queue so the next `flush` retries it, and the first error is
    /// returned. In eager mode the queue is always empty, so this is a
    /// no-op there.
    pub fn flush(&self) -> io::Result<()> {
        let mut batch = std::mem::take(&mut *self.pending.lock().unwrap());
        let result = Self::flush_batch(&mut batch);
        if !batch.is_empty() {
            // Requeue the remainder AHEAD of anything put since the
            // drain: the failed entry is retried first next flush.
            let mut pending = self.pending.lock().unwrap();
            batch.append(&mut pending);
            *pending = batch;
        }
        result
    }

    /// Fsync each queued shard dir once (dedupe at flush: the queue holds
    /// one entry per PUT, so hot shards appear repeatedly), mutating the
    /// batch down to the un-fsynced remainder on error (empty on success).
    fn flush_batch(batch: &mut Vec<PathBuf>) -> io::Result<()> {
        // One fsync per touched dir; already-synced dirs in this batch are
        // skipped. On error keep the entries of the not-yet-synced dirs so
        // the next flush retries them.
        let mut synced_dirs: std::collections::BTreeSet<PathBuf> =
            std::collections::BTreeSet::new();
        let mut dir_err = None;
        for dir in batch.iter() {
            if synced_dirs.contains(dir) {
                continue;
            }
            match fs::File::open(dir).and_then(|d| d.sync_all()) {
                Ok(()) => {
                    synced_dirs.insert(dir.clone());
                }
                Err(e) => {
                    dir_err = Some(e);
                    break;
                }
            }
        }
        match dir_err {
            Some(e) => {
                batch.retain(|d| !synced_dirs.contains(d));
                Err(e)
            }
            None => {
                batch.clear();
                Ok(())
            }
        }
    }

    /// Test-only view of the deferred flush queue (queued shard dirs —
    /// one per deferred put, duplicates included). `pub` under
    /// `debug_assertions` (not just `cfg(test)`, which never crosses a
    /// crate boundary) so downstream crates' test suites can see it too —
    /// the relay's §22 commit-point test asserts a head/snapshot commit
    /// drains the queue. Compiled out of release builds.
    #[cfg(any(test, debug_assertions))]
    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

impl ChunkSink for LocalStore {
    fn has(&self, hash: &str) -> io::Result<bool> {
        Ok(self.chunk_path(hash)?.exists())
    }

    fn put(&self, hash: &str, data: &[u8]) -> io::Result<bool> {
        // Content addressing is a VERIFIED invariant (§18): refuse bytes
        // that do not BLAKE3-hash to the claimed name before anything
        // touches disk — wrong bytes under hash H would poison every
        // future presence check for H.
        if blake3::hash(data).to_hex().as_str() != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk bytes do not hash to {hash}"),
            ));
        }
        let dest = self.chunk_path(hash)?;
        if dest.exists() {
            return Ok(false); // dedupe: content already stored
        }
        // hash is validated by chunk_path, so `hash[..2]` is safe here.
        let dir = self.root.join("chunks").join(&hash[..2]);
        fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!(
            ".tmp-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let mut f = crate::fsutil::create_private_file(&tmp)?;
        f.write_all(data)?;
        if self.deferred {
            // No fsync of data OR dirent (§25): queue the shard dir and
            // let `flush` fsync it — dirs only, never the chunk file. A
            // torn post-crash blob is always caught by verify-on-get
            // (the name IS the hash) and heals by re-fetch/re-upload.
            // The lock is dropped BEFORE the threshold self-flush —
            // `flush` takes it to drain.
            fs::rename(&tmp, &dest)?;
            let mut pending = self.pending.lock().unwrap();
            pending.push(dir);
            let full = pending.len() >= DEFERRED_FLUSH_THRESHOLD;
            drop(pending);
            if full {
                self.flush()?;
            }
        } else {
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &dest)?;
        }
        Ok(true)
    }

    fn flush(&self) -> io::Result<()> {
        LocalStore::flush(self)
    }
}

impl ChunkSource for LocalStore {
    fn get(&self, hash: &str) -> io::Result<Vec<u8>> {
        let path = self.chunk_path(hash)?;
        let data = fs::read(&path)?;
        // Verify on read (§18): a torn post-crash chunk (dirent
        // persisted, data lost) deletes itself and reports NotFound, so
        // the next cycle re-fetches or re-chunks it. `has` stays a cheap
        // existence check and never hashes.
        if blake3::hash(&data).to_hex().as_str() != hash {
            let _ = fs::remove_file(&path);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("chunk {hash} failed verification and was removed"),
            ));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_files(dir: &std::path::Path) -> usize {
        let mut n = 0;
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                n += count_files(&path);
            } else {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn put_has_get_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let hash = blake3::hash(b"hello chunk").to_hex().to_string();

        assert!(!store.has(&hash).unwrap());
        assert!(store.put(&hash, b"hello chunk").unwrap());
        assert!(store.has(&hash).unwrap());
        assert_eq!(store.get(&hash).unwrap(), b"hello chunk");
        // Path layout: chunks/<2>/<64>.
        assert!(tmp
            .path()
            .join("store/chunks")
            .join(&hash[..2])
            .join(&hash)
            .exists());
    }

    #[test]
    fn duplicate_put_stores_one_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let hash = blake3::hash(b"data").to_hex().to_string();

        assert!(store.put(&hash, b"data").unwrap());
        assert!(!store.put(&hash, b"data").unwrap(), "second put is a no-op");
        assert_eq!(count_files(&tmp.path().join("store")), 1);
    }

    #[test]
    fn has_many_default_loops_has() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let a = blake3::hash(b"a").to_hex().to_string();
        let b = blake3::hash(b"b").to_hex().to_string();
        store.put(&a, b"a").unwrap();

        let present = store.has_many(&[a, b]).unwrap();
        assert_eq!(present, vec![true, false]);
        assert!(store.has_many(&[]).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let hash = blake3::hash(b"secret").to_hex().to_string();
        store.put(&hash, b"secret").unwrap();

        // Synced content can be `.env` secrets: store dir and chunk files
        // must be owner-only regardless of umask.
        let store_mode = fs::metadata(tmp.path().join("store"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(store_mode, 0o700);
        let chunk_path = tmp.path().join("store/chunks").join(&hash[..2]).join(&hash);
        let chunk_mode = fs::metadata(chunk_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(chunk_mode, 0o600);
    }

    #[test]
    fn open_sweeps_orphaned_tmp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("store/chunks/ab");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".tmp-123-deadbeef"), b"orphan").unwrap();
        // Crash-orphaned means STALE: backdate it. A fresh temp may be a
        // concurrently running process's in-flight put and must survive.
        let hour_ago = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 3600,
            0,
        );
        filetime::set_file_mtime(dir.join(".tmp-123-deadbeef"), hour_ago).unwrap();
        fs::write(dir.join(".tmp-456-liveput"), b"in flight").unwrap();

        let _store = LocalStore::open(tmp.path().join("store")).unwrap();
        assert!(!dir.join(".tmp-123-deadbeef").exists());
        assert!(dir.join(".tmp-456-liveput").exists());
    }

    #[test]
    fn deferred_puts_are_visible_before_flush() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open_deferred(tmp.path().join("store")).unwrap();
        let hash = blake3::hash(b"deferred chunk").to_hex().to_string();

        assert!(store.put(&hash, b"deferred chunk").unwrap());
        // The rename already landed; only durability is deferred. Reads
        // (same machine, page cache) see the chunk before any flush.
        assert!(store.has(&hash).unwrap());
        assert_eq!(store.get(&hash).unwrap(), b"deferred chunk");
        assert_eq!(
            store.pending_len(),
            1,
            "shard dir queued for the group flush (§25: dirs, no fds)"
        );

        store.flush().unwrap();
        assert_eq!(store.pending_len(), 0, "flush drains the queue");
        // Idempotent: flushing an empty queue is a no-op Ok.
        store.flush().unwrap();
        assert_eq!(store.pending_len(), 0);
        // The no-crash path after a flush: dirent AND data are sane —
        // bytes read back intact. (§25's torn-DATA window only opens on
        // power loss, which verify-on-get then catches.)
        assert_eq!(store.get(&hash).unwrap(), b"deferred chunk");
    }

    #[test]
    fn deferred_queue_self_flushes_at_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open_deferred(tmp.path().join("store")).unwrap();

        // Random shard spread: the queue counts PUTS (one dir entry each,
        // deduped only at flush — §25), so pending_len tracks puts 1:1.
        for i in 0..DEFERRED_FLUSH_THRESHOLD {
            let data = format!("chunk number {i}");
            let hash = blake3::hash(data.as_bytes()).to_hex().to_string();
            store.put(&hash, data.as_bytes()).unwrap();
            if i + 1 < DEFERRED_FLUSH_THRESHOLD {
                assert_eq!(store.pending_len(), i + 1, "below threshold: queued");
            }
        }
        assert_eq!(
            store.pending_len(),
            0,
            "the {DEFERRED_FLUSH_THRESHOLD}th put triggers the self-flush"
        );
        // Everything written is still readable after the self-flush.
        let data = format!("chunk number {}", DEFERRED_FLUSH_THRESHOLD - 1);
        let hash = blake3::hash(data.as_bytes()).to_hex().to_string();
        assert_eq!(store.get(&hash).unwrap(), data.as_bytes());
    }

    /// §25 queue semantics, pinned: the deferred queue holds one shard-dir
    /// entry PER PUT (dedupe happens at flush), so the threshold
    /// self-flush is counted in puts — 64 chunks all landing in the SAME
    /// shard drain at 64 exactly like 64 chunks spread over shards. That
    /// keeps the §18 loss window a CHUNK-count bound: a dedupe-at-push
    /// queue (distinct dirs only) could absorb unlimited puts into a few
    /// hot shards without ever self-flushing.
    #[test]
    fn deferred_threshold_counts_puts_not_distinct_shard_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open_deferred(tmp.path().join("store")).unwrap();

        // Find 64 chunks in ONE shard: blake3 over sequential inputs,
        // keeping those that share one 2-hex prefix (~256 tries per hit,
        // deterministic — same inputs, same hashes, every run).
        let mut chunks: Vec<(String, String)> = Vec::new();
        for i in 0u64.. {
            let data = format!("same-shard chunk {i}");
            let hash = blake3::hash(data.as_bytes()).to_hex().to_string();
            if hash.starts_with("aa") {
                chunks.push((hash, data));
                if chunks.len() == DEFERRED_FLUSH_THRESHOLD {
                    break;
                }
            }
        }

        for (i, (hash, data)) in chunks.iter().enumerate() {
            store.put(hash, data.as_bytes()).unwrap();
            if i + 1 < DEFERRED_FLUSH_THRESHOLD {
                assert_eq!(
                    store.pending_len(),
                    i + 1,
                    "same shard: still one queue entry per put"
                );
            }
        }
        assert_eq!(
            store.pending_len(),
            0,
            "64 same-shard puts still self-flush: the queue counts puts"
        );
        // No-crash path: after the flush the queue is empty and every
        // chunk's bytes read back intact (dirent + data sane).
        for (hash, data) in &chunks {
            assert_eq!(store.get(hash).unwrap(), data.as_bytes());
        }
    }

    #[test]
    fn put_rejects_bytes_that_do_not_hash_to_their_name() {
        // Both modes: the check runs before mode-specific write logic.
        for deferred in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let store = if deferred {
                LocalStore::open_deferred(tmp.path().join("store")).unwrap()
            } else {
                LocalStore::open(tmp.path().join("store")).unwrap()
            };
            let hash = blake3::hash(b"honest bytes").to_hex().to_string();

            let err = store.put(&hash, b"forged bytes").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(!store.has(&hash).unwrap(), "nothing was written");
            assert_eq!(count_files(&tmp.path().join("store")), 0);
        }
    }

    #[test]
    fn get_self_heals_a_corrupted_chunk() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let hash = blake3::hash(b"good bytes").to_hex().to_string();
        store.put(&hash, b"good bytes").unwrap();

        // Simulate a torn post-crash chunk: dirent persisted, data lost
        // (§18 crash matrix). Overwrite the file behind the store's back.
        let chunk_path = tmp.path().join("store/chunks").join(&hash[..2]).join(&hash);
        fs::write(&chunk_path, b"torn bytes").unwrap();

        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!chunk_path.exists(), "the bad chunk deleted itself");
        assert!(!store.has(&hash).unwrap(), "gone, so the next cycle re-fetches");
    }

    /// §24: the sweep deletes exactly the real blobs outside `keep` —
    /// `.tmp-*` temporaries (sweep_tmp's) and non-hash names are never
    /// touched, and a kept blob is untouched.
    #[test]
    fn sweep_unreferenced_deletes_only_unkept_hash_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let a = blake3::hash(b"a").to_hex().to_string();
        let b = blake3::hash(b"bbb").to_hex().to_string();
        store.put(&a, b"a").unwrap();
        store.put(&b, b"bbb").unwrap();
        // Foreign names in the pool: a temporary, a corrupt name, a
        // too-short near-miss, and 64 UPPERCASE hex (no lowercase twin,
        // so it is a distinct file even on case-insensitive filesystems).
        let shard = tmp.path().join("store/chunks").join(&b[..2]);
        let foreign = [
            shard.join(".tmp-1-deadbeef"),
            shard.join("not-a-chunk-hash"),
            shard.join("beef"),
            shard.join("A".repeat(64)),
        ];
        for path in &foreign {
            fs::write(path, b"x").unwrap();
        }

        let keep: std::collections::HashSet<&str> = [a.as_str()].into_iter().collect();
        let (deleted, bytes) = store.sweep_unreferenced(&keep).unwrap();
        assert_eq!((deleted, bytes), (1, 3), "only b's 3-byte blob");
        assert!(store.has(&a).unwrap(), "the kept blob survives");
        assert!(!store.has(&b).unwrap(), "the unkept blob is gone");
        for path in &foreign {
            assert!(path.exists(), "{} survives", path.display());
        }
        // Idempotent: a second sweep finds nothing.
        let (deleted, bytes) = store.sweep_unreferenced(&keep).unwrap();
        assert_eq!((deleted, bytes), (0, 0));
    }

    /// §24: keeping everything is a strict no-op — the common case right
    /// after an apply that changed nothing structurally.
    #[test]
    fn sweep_unreferenced_keep_everything_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::open(tmp.path().join("store")).unwrap();
        let a = blake3::hash(b"a").to_hex().to_string();
        let b = blake3::hash(b"b").to_hex().to_string();
        store.put(&a, b"a").unwrap();
        store.put(&b, b"b").unwrap();

        let keep: std::collections::HashSet<&str> =
            [a.as_str(), b.as_str()].into_iter().collect();
        let (deleted, bytes) = store.sweep_unreferenced(&keep).unwrap();
        assert_eq!((deleted, bytes), (0, 0));
        assert!(store.has(&a).unwrap() && store.has(&b).unwrap());
    }
}
