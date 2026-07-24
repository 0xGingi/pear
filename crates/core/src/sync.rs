use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use crate::manifest::{self, FileEntry, Manifest};
use crate::relay::{RelayClient, RelayError};
use crate::store::{ChunkSink, LocalStore};
use crate::{apply, chunk, init_workspace, scan, FORMAT_VERSION};

/// Trust a cached chunk list only when the file's recorded mtime is at
/// least this many seconds older than the scan that recorded it. Covers
/// filesystems with 1-2s timestamp granularity (HFS+, FAT, some network
/// filesystems) where a same-tick edit would otherwise go undetected.
const CACHE_SETTLE_SECS: i64 = 2;

pub struct CycleReport {
    pub written: Vec<String>,
    pub deleted: Vec<String>,
    pub chunks_uploaded: usize,
    pub bytes_uploaded: u64,
}

/// One full convergence cycle: scan the writer -> chunk what changed ->
/// upload missing chunks to the mirror's store -> apply into the mirror.
pub fn sync_cycle(source: &Path, target: &Path) -> Result<CycleReport> {
    if !source.is_dir() {
        bail!("source {} is not a directory", source.display());
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;
    // Containment is checked before anything is created: a rejected sync
    // must leave no filesystem side effects.
    let target = canonicalize_lenient(target)?;
    if source == target || target.starts_with(&source) || source.starts_with(&target) {
        bail!("source and target must not contain each other");
    }
    fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;

    // Deferred store (§18): the scan/chunk pass below puts every changed
    // chunk without a per-chunk fsync; one group flush lands before the
    // apply phase instead.
    let store = LocalStore::open_deferred(target.join(".pear").join("store"))?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut chunks_uploaded = 0usize;
    let mut bytes_uploaded = 0u64;
    let build = scan_build_manifest(&source, &store, false, |path| {
        chunk_and_upload(
            path,
            &store,
            &mut seen,
            &mut chunks_uploaded,
            &mut bytes_uploaded,
        )
    })?;
    // Flush point (§18/§25): every chunk this cycle wrote gets its
    // dirent fsynced as a group before the apply starts assembling
    // files from them (data is always re-hashed on read, §18).
    store.flush()?;

    // Apply the batch into the mirror, then persist both manifests. The
    // target never materializes setuid/setgid/sticky bits (apply masks
    // them): record the masked manifest there too, or a reverse sync
    // sees a phantom mode change and strips the bits on the source.
    // The SOURCE manifest keeps the true bits.
    let old_target = manifest::load(&target.join(".pear").join("manifest.json"))?
        .unwrap_or_else(|| Manifest::new(build.new.workspace_id.clone()));
    let mut for_target = build.new.clone();
    for entry in for_target.files.values_mut() {
        entry.mode &= 0o777;
    }
    let report = apply::apply(&target, &old_target, &for_target, &store)?;
    manifest::write_atomic(&source.join(".pear").join("manifest.json"), &build.new)?;

    // §24 local-store GC (M1 target store): the apply and the manifest
    // commit succeeded, so delete chunks the new manifest no longer
    // references (superseded content). Skipped when the cycle neither
    // changed the target nor uploaded anything — a steady-state no-op
    // poll must not pay a directory walk. A sweep failure warns and
    // NEVER fails the cycle: GC must not break convergence.
    if !report.written.is_empty() || !report.deleted.is_empty() || chunks_uploaded > 0 {
        let keep: HashSet<&str> = for_target
            .files
            .values()
            .flat_map(|entry| entry.chunks.iter().map(String::as_str))
            .collect();
        if let Err(e) = store.sweep_unreferenced(&keep) {
            eprintln!("pear: local store sweep failed (retried after the next change): {e}");
        }
    }

    Ok(CycleReport {
        written: report.written,
        deleted: report.deleted,
        chunks_uploaded,
        bytes_uploaded,
    })
}

/// The shared writer-side scan result: the source manifest as it was
/// before this cycle and the freshly built one.
pub(crate) struct ScanBuild {
    pub(crate) old: Manifest,
    pub(crate) new: Manifest,
    /// Directories the built-in name excludes or `pear.toml` `exclude`
    /// entries pruned during the scan — surfaced so preservation commands
    /// can report what is not captured.
    pub(crate) excluded: Vec<String>,
}

/// Shared writer-side pipeline (§11): scan the workspace, chunk what
/// changed, upload missing chunks to `sink` via `upload`, and assemble the
/// new manifest. Local sync, the relay push, and `pear snapshot` differ
/// only in how file chunks reach the sink — M1 streams each chunk straight
/// into the mirror's store, the writer flow batches presence checks
/// against the relay.
pub(crate) fn scan_build_manifest(
    source: &Path,
    sink: &dyn ChunkSink,
    strict: bool,
    mut upload: impl FnMut(&Path) -> Result<Vec<String>>,
) -> Result<ScanBuild> {
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let (meta, _) = init_workspace(source, None)?;
    let old = manifest::load(&source.join(".pear").join("manifest.json"))?
        .unwrap_or_else(|| Manifest::new(meta.id.clone()));

    // Scan: reuse chunk lists only for files that are unchanged (size +
    // mtime), whose mtime is settled enough that coarse filesystem
    // timestamps cannot hide a same-tick edit, and whose chunks are all
    // present in the sink (a fresh mirror must not trust the source-side
    // cache). Presence for every chunk the old manifest could reuse is
    // checked in ONE batched call per cycle — never per-file HTTP (§11).
    let scanned = scan::scan(source)?;
    // Strict mode (preservation snapshots): complete capture or fail.
    // Sync tolerates these and retains last-good state instead. Ignored
    // unreadable dirs can only hide `.env*` files — warn, don't fail.
    if strict && !scanned.unreadable.is_empty() {
        bail!(
            "cannot capture: {} unreadable path(s): {}",
            scanned.unreadable.len(),
            scanned.unreadable.join(", ")
        );
    }
    if strict && !scanned.unreadable_ignored.is_empty() {
        eprintln!(
            "pear: warning: {} ignored path(s) unreadable (may hide .env files): {}",
            scanned.unreadable_ignored.len(),
            scanned.unreadable_ignored.join(", ")
        );
    }
    if strict && !scanned.skipped.is_empty() {
        bail!(
            "cannot capture: {} skipped path(s) (symlinks, non-UTF-8 names): {}",
            scanned.skipped.len(),
            scanned.skipped.join(", ")
        );
    }
    let mut want: Vec<String> = Vec::new();
    let mut want_seen: HashSet<&str> = HashSet::new();
    for entry in old.files.values() {
        for hash in &entry.chunks {
            if want_seen.insert(hash.as_str()) {
                want.push(hash.clone());
            }
        }
    }
    let present: HashSet<String> = want
        .iter()
        .cloned()
        .zip(sink.has_many(&want)?)
        .filter_map(|(h, p)| p.then_some(h))
        .collect();
    let chunks_present = |entry: &FileEntry| entry.chunks.iter().all(|h| present.contains(h));
    let mut files = BTreeMap::new();
    for f in &scanned.files {
        let cached = match old.files.get(&f.rel_path) {
            Some(e)
                if e.size == f.size
                    && e.mtime_secs == f.mtime_secs
                    && e.mtime_nanos == f.mtime_nanos
                    && f.mtime_secs + CACHE_SETTLE_SECS <= old.scanned_at_secs
                    && chunks_present(e) =>
            {
                Some(e)
            }
            _ => None,
        };
        let chunks = match cached {
            Some(entry) => entry.chunks.clone(),
            None => match upload(&source.join(&f.rel_path)) {
                Ok(hashes) => hashes,
                Err(e) => {
                    if strict {
                        // A preservation snapshot is complete or fails.
                        return Err(e.context("snapshot must capture every file"));
                    }
                    // A persistently unreadable file must not freeze the
                    // whole workspace: keep the mirror's last-good entry when
                    // its chunks are there (otherwise drop the file from this
                    // cycle), warn, and converge everything else.
                    eprintln!(
                        "pear: cannot sync {}, skipping this cycle: {e:#}",
                        f.rel_path
                    );
                    if let Some(old_entry) = old.files.get(&f.rel_path) {
                        if chunks_present(old_entry) {
                            files.insert(f.rel_path.clone(), old_entry.clone());
                        }
                    }
                    continue;
                }
            },
        };
        files.insert(
            f.rel_path.clone(),
            FileEntry {
                size: f.size,
                mode: f.mode,
                mtime_secs: f.mtime_secs,
                mtime_nanos: f.mtime_nanos,
                chunks,
            },
        );
    }
    // Files under prefixes that were unreadable this scan are absent from
    // the fresh scan, and absence means deletion to apply. Retain their
    // last-good entries when the mirror still has the content, so a
    // transient error does not wipe the subtree from the mirror.
    if !scanned.unreadable.is_empty() || !scanned.unreadable_ignored.is_empty() {
        for (rel, entry) in &old.files {
            if files.contains_key(rel) {
                continue;
            }
            let under_unreadable = scanned
                .unreadable
                .iter()
                .chain(&scanned.unreadable_ignored)
                .any(|p| rel == p || rel.starts_with(format!("{p}/").as_str()));
            if under_unreadable && chunks_present(entry) {
                files.insert(rel.clone(), entry.clone());
            }
        }
    }

    let new = Manifest {
        version: FORMAT_VERSION,
        workspace_id: meta.id,
        scanned_at_secs: started_at,
        files,
    };
    Ok(ScanBuild {
        old,
        new,
        excluded: scanned.excluded,
    })
}

/// Chunk one file lazily, streaming each chunk into the store as it is
/// produced. Memory stays bounded to one chunk, never the whole file.
fn chunk_and_upload(
    path: &Path,
    store: &LocalStore,
    seen: &mut HashSet<String>,
    chunks_uploaded: &mut usize,
    bytes_uploaded: &mut u64,
) -> Result<Vec<String>> {
    let mut hashes = Vec::new();
    for c in chunk::chunk_file(path).with_context(|| format!("chunk {}", path.display()))? {
        let c = c.with_context(|| format!("chunk {}", path.display()))?;
        if seen.contains(&c.hash) {
            hashes.push(c.hash);
            continue;
        }
        // Only mark the chunk seen once it is confirmed present: a failed
        // `put` must not suppress a later file sharing the same chunk.
        if !store.has(&c.hash)? && store.put(&c.hash, &c.data)? {
            *chunks_uploaded += 1;
            *bytes_uploaded += c.data.len() as u64;
        }
        seen.insert(c.hash.clone());
        hashes.push(c.hash);
    }
    Ok(hashes)
}

/// Flush the pending upload buffer once it holds at least this many bytes:
/// keeps writer memory bounded while presence checks stay batched.
const UPLOAD_FLUSH_BYTES: u64 = 32 * 1024 * 1024;

/// The writer flow's per-file uploader (§11): buffer a file's chunks, then
/// batch `chunks/missing` and store only what the sink lacks — one
/// `put_many` call (§23), so no per-chunk round trips happen even on the
/// upload leg. Chunks the sink already has never cross the wire. A failed
/// flush keeps the unconfirmed chunks buffered: an error must not
/// suppress a later file sharing the same chunk.
pub(crate) struct BatchUploader<'a> {
    sink: &'a dyn ChunkSink,
    seen: HashSet<String>,
    pending: Vec<(String, Vec<u8>)>,
    pending_hashes: HashSet<String>,
    pending_bytes: u64,
    pub(crate) uploaded: usize,
    pub(crate) bytes: u64,
}

impl<'a> BatchUploader<'a> {
    pub(crate) fn new(sink: &'a dyn ChunkSink) -> Self {
        Self {
            sink,
            seen: HashSet::new(),
            pending: Vec::new(),
            pending_hashes: HashSet::new(),
            pending_bytes: 0,
            uploaded: 0,
            bytes: 0,
        }
    }

    pub(crate) fn upload_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        let mut hashes = Vec::new();
        for c in chunk::chunk_file(path)? {
            let c = c?;
            self.buffer_chunk(c.hash.clone(), c.data)?;
            hashes.push(c.hash);
        }
        Ok(hashes)
    }

    /// Buffer one pre-chunked (hash, data) pair for the next batched
    /// presence check + upload. The e2e uploader feeds encrypted chunks
    /// through here (§17); `upload_file` feeds plaintext. Dedupe is by
    /// hash, so convergent ciphertext dedupes exactly like plaintext.
    pub(crate) fn buffer_chunk(&mut self, hash: String, data: Vec<u8>) -> io::Result<()> {
        if self.seen.contains(&hash) || self.pending_hashes.contains(&hash) {
            return Ok(());
        }
        self.pending_bytes += data.len() as u64;
        self.pending_hashes.insert(hash.clone());
        self.pending.push((hash, data));
        if self.pending_bytes >= UPLOAD_FLUSH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let hashes: Vec<String> = self.pending.iter().map(|(h, _)| h.clone()).collect();
        // A `has_many` error leaves the whole buffer pending (the type's
        // contract): nothing was attempted, nothing is lost.
        let present = self.sink.has_many(&hashes)?;
        let mut to_upload: Vec<(String, Vec<u8>)> = Vec::new();
        for ((hash, data), present) in std::mem::take(&mut self.pending).into_iter().zip(present) {
            if present {
                // Confirmed by the presence check alone — only
                // confirmed-present chunks are marked seen.
                self.seen.insert(hash.clone());
                self.pending_hashes.remove(&hash);
            } else {
                to_upload.push((hash, data));
            }
        }
        // §23: ONE batched store call for everything the sink lacks (the
        // relay splits into ≤256-entry/32 MiB sub-batches internally; the
        // default impl loops `put`).
        let results = match self.sink.put_many(&to_upload) {
            Ok(results) => results,
            Err(e) => {
                // Whole-call failure (transport, or the default loop's
                // first io error): nothing not-present is confirmed, so
                // every unconfirmed chunk goes back on the buffer in
                // original order — today's keep-the-remainder behavior.
                // Entries the sink DID write before failing are simply
                // re-confirmed via the presence check (dedupe) on the
                // retry, never lost.
                self.pending_bytes = to_upload.iter().map(|(_, d)| d.len() as u64).sum();
                self.pending = to_upload;
                return Err(e);
            }
        };
        if results.len() != to_upload.len() {
            // The trait pins one result per entry, in order: statuses map
            // POSITIONALLY, so a misaligned answer must not confirm ANY
            // chunk — marking an unstored chunk seen would suppress its
            // upload permanently.
            let e = io::Error::other(format!(
                "put_many returned {} results for {} entries",
                results.len(),
                to_upload.len()
            ));
            self.pending_bytes = to_upload.iter().map(|(_, d)| d.len() as u64).sum();
            self.pending = to_upload;
            return Err(e);
        }
        let mut kept: Vec<(String, Vec<u8>)> = Vec::new();
        let mut error: Option<io::Error> = None;
        for ((hash, data), result) in to_upload.into_iter().zip(results) {
            match result {
                Ok(stored) => {
                    if stored {
                        self.uploaded += 1;
                        self.bytes += data.len() as u64;
                    }
                    // Ok(false): became present concurrently — confirmed
                    // like a presence-check hit, just not uploaded by us.
                    // Only confirmed-present chunks are marked seen.
                    self.seen.insert(hash.clone());
                    self.pending_hashes.remove(&hash);
                }
                Err(reason) => {
                    // §23: one bad entry keeps ONLY itself buffered — an
                    // all-or-nothing batch would wedge the buffer on one
                    // deterministic failure. The flush still reports the
                    // first failure so the sync cycle surfaces it.
                    if error.is_none() {
                        error = Some(io::Error::other(format!("chunk {hash}: {reason}")));
                    }
                    kept.push((hash, data));
                }
            }
        }
        self.pending_bytes = kept.iter().map(|(_, d)| d.len() as u64).sum();
        self.pending = kept;
        match error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// The e2e writer's per-file uploader (§17/§20): each chunk is
/// `encrypt_chunk`'d under the keyring's NEWEST generation (§20: only
/// writes move to the new generation); the hash recorded in the manifest
/// is BLAKE3 of the CIPHERTEXT blob (content-addressing of ciphertext —
/// convergent encryption keeps dedupe semantics unchanged per generation;
/// across generations the same plaintext has different ciphertext, which
/// is fine because only post-rotation edits use the new generation).
/// Presence checks and uploads run on ciphertext hashes/bytes through the
/// shared [`BatchUploader`]; the relay treats chunks as opaque. §31: that
/// ciphertext path is the writer's ONLY chunk path — the vestigial local
/// plaintext store is gone (nothing ever read it: upload dedupe runs on
/// ciphertext hashes against the relay, unchanged files ride the scan
/// cache).
pub(crate) struct E2eUploader<'a> {
    inner: BatchUploader<'a>,
    key: [u8; 32],
}

impl<'a> E2eUploader<'a> {
    pub(crate) fn new(sink: &'a dyn ChunkSink, key: [u8; 32]) -> io::Result<Self> {
        Ok(Self {
            inner: BatchUploader::new(sink),
            key,
        })
    }

    pub(crate) fn upload_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        let mut hashes = Vec::new();
        for c in chunk::chunk_file(path)? {
            let c = c?;
            let blob = crate::crypto::encrypt_chunk(&self.key, &c.data);
            let ciphertext_hash = blake3::hash(&blob).to_hex().to_string();
            self.inner.buffer_chunk(ciphertext_hash.clone(), blob)?;
            hashes.push(ciphertext_hash);
        }
        Ok(hashes)
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The two writer pipelines: plaintext chunks on plain workspaces,
/// ciphertext chunks on e2e ones (§17). Everything downstream — batched
/// presence checks, upload counters — is shared.
pub(crate) enum Uploader<'a> {
    Plain(BatchUploader<'a>),
    E2e(E2eUploader<'a>),
}

impl Uploader<'_> {
    pub(crate) fn upload_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        match self {
            Uploader::Plain(u) => u.upload_file(path),
            Uploader::E2e(u) => u.upload_file(path),
        }
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        match self {
            Uploader::Plain(u) => u.flush(),
            Uploader::E2e(u) => u.flush(),
        }
    }

    pub(crate) fn uploaded(&self) -> usize {
        match self {
            Uploader::Plain(u) => u.uploaded,
            Uploader::E2e(u) => u.inner.uploaded,
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        match self {
            Uploader::Plain(u) => u.bytes,
            Uploader::E2e(u) => u.inner.bytes,
        }
    }
}

/// Outcome of one writer cycle against the relay.
#[derive(Debug)]
pub struct PushReport {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
    pub chunks_uploaded: usize,
    pub bytes_uploaded: u64,
    /// Head sequence after this cycle (0 = the workspace still has no head).
    pub head_seq: u64,
    /// Whether this cycle committed a new head.
    pub committed: bool,
}

/// Why a push failed. Fenced/head-conflict are fatal to the writer: it no
/// longer owns the head (§11). Anything else is transient and retryable.
#[derive(Debug)]
pub enum PushError {
    Fenced(String),
    HeadConflict {
        current_seq: u64,
    },
    /// A deterministic rejection (HTTP 4xx other than fencing/conflict —
    /// bad token, invalid manifest, version skew): retrying cannot help.
    Client(String),
    Other(anyhow::Error),
}

impl PushError {
    fn from_relay(e: RelayError) -> Self {
        match e {
            RelayError::Fenced(why) => PushError::Fenced(why),
            RelayError::HeadConflict { current_seq } => PushError::HeadConflict { current_seq },
            RelayError::Fatal(msg) => PushError::Client(msg),
            // Only the relay contract's own deterministic statuses are
            // fatal; transient 4xx from intermediaries (408, 429) retries.
            RelayError::Http { status, body } if matches!(status, 400 | 401 | 403 | 404) => {
                PushError::Client(format!(
                    "relay rejected the request (HTTP {status}): {body}"
                ))
            }
            other => PushError::Other(anyhow::Error::new(other)),
        }
    }
}

/// Classify an error from the chunk data path: `ChunkSink` flattens
/// `RelayError` into `io::Error`, which hides it from `source()` but
/// exposes it via `get_ref()` — deterministic auth/role failures
/// (401/403/404) still go fatal instead of retrying forever.
fn push_from_anyhow(e: anyhow::Error) -> PushError {
    fn classify(err: &(dyn std::error::Error + 'static)) -> Option<PushError> {
        if let Some(relay) = err.downcast_ref::<RelayError>() {
            return push_from_relay_ref(relay);
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if let Some(relay) = io
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<RelayError>())
            {
                return push_from_relay_ref(relay);
            }
        }
        None
    }
    // The anyhow deref target is the root error itself; then any context
    // layers' sources.
    let root: &(dyn std::error::Error + 'static) = &*e;
    if let Some(pe) = classify(root) {
        return pe;
    }
    let mut source = std::error::Error::source(&*e);
    while let Some(err) = source {
        if let Some(pe) = classify(err) {
            return pe;
        }
        source = err.source();
    }
    PushError::Other(e)
}

fn push_from_relay_ref(e: &RelayError) -> Option<PushError> {
    match e {
        RelayError::Fenced(why) => Some(PushError::Fenced(why.clone())),
        RelayError::HeadConflict { current_seq } => Some(PushError::HeadConflict {
            current_seq: *current_seq,
        }),
        RelayError::Http { status, body } if matches!(status, 400 | 401 | 403 | 404) => {
            Some(PushError::Client(format!(
                "relay rejected the request (HTTP {status}): {body}"
            )))
        }
        _ => None,
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushError::Fenced(why) => write!(f, "fenced: {why}"),
            PushError::HeadConflict { current_seq } => {
                write!(f, "head conflict: relay head is at seq {current_seq}")
            }
            PushError::Client(why) => write!(f, "{why}"),
            PushError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for PushError {}

impl From<anyhow::Error> for PushError {
    fn from(e: anyhow::Error) -> Self {
        PushError::Other(e)
    }
}

/// One writer cycle against the relay (§11): scan -> chunk -> upload only
/// the chunks the relay is missing (batch check) -> `PUT /head` with
/// `base_seq` and the lease headers. 409/403 surface as typed errors: the
/// writer no longer owns the head and must stop, not retry. `force_commit`
/// commits even when the scan matches the local cache: right after a
/// forced takeover the contract is "this tree becomes the head".
pub fn push_cycle(
    source: &Path,
    client: &RelayClient,
    base_seq: u64,
    force_commit: bool,
) -> Result<PushReport, PushError> {
    push_inner(source, client, base_seq, force_commit, None)
}

/// The e2e writer cycle (§17/§20): chunks are encrypted under the
/// keyring's newest generation before upload (content-addressed by
/// ciphertext hash — unchanged files keep their cached ciphertext hashes
/// via the ordinary scan-cache reuse, so a rotation re-uploads nothing
/// but the next real edits), and the head commits the encrypted manifest
/// plus the ciphertext chunk list. All scan/CAS/fencing semantics are the
/// plaintext cycle's, unchanged.
pub fn push_cycle_e2e(
    source: &Path,
    client: &RelayClient,
    base_seq: u64,
    force_commit: bool,
    keyring: &crate::e2e::Keyring,
) -> Result<PushReport, PushError> {
    push_inner(source, client, base_seq, force_commit, Some(keyring))
}

#[allow(clippy::too_many_arguments)]
fn push_inner(
    source: &Path,
    client: &RelayClient,
    base_seq: u64,
    force_commit: bool,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> Result<PushReport, PushError> {
    if !source.is_dir() {
        return Err(anyhow!("source {} is not a directory", source.display()).into());
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;

    let mut uploader = match e2e_key {
        Some(keyring) => Uploader::E2e(
            // Only the newest generation ever encrypts (§20); older
            // generations exist for reads, not writes.
            E2eUploader::new(client, *keyring.newest().1)
                .map_err(|e| PushError::Other(e.into()))?,
        ),
        None => Uploader::Plain(BatchUploader::new(client)),
    };
    let build = scan_build_manifest(&source, client, false, |path| {
        uploader
            .upload_file(path)
            .with_context(|| format!("chunk {}", path.display()))
    })
    .map_err(push_from_anyhow)?;

    let d = manifest::diff(&build.old, &build.new);
    // A writer must never commit another workspace's manifest: the local
    // id comes from `.pear/workspace.json`, the client's from its target.
    if build.new.workspace_id != client.workspace_id() {
        return Err(anyhow!(
            "local workspace {} does not match relay workspace {}",
            build.new.workspace_id,
            client.workspace_id()
        )
        .into());
    }
    // §28: the workspace's team forbids `.env` sync (learned at watch
    // startup) and the scan captured `.env*` files — REFUSE the cycle
    // before anything uploads. Deterministic: retrying cannot help until
    // the files go or the policy lifts, so this is `Client`, which the
    // watch loop classifies fatal (it exits) — refusing beats silently
    // excluding a file the user expects synced. A workspace with no
    // `.env*` files in the captured set watches normally. Client-side is
    // the ONLY line for e2e (the relay cannot see encrypted paths);
    // plaintext commits are also 409d relay-side as a backstop. The path
    // test is the scanner's own `is_dotenv`: the switch forbids exactly
    // what the product promise syncs — no more, no less.
    if let Some(team) = client.env_sync_forbidden_by() {
        let dotenv: Vec<&str> = build
            .new
            .files
            .keys()
            .filter(|p| crate::scan::is_dotenv(p))
            .map(String::as_str)
            .collect();
        if !dotenv.is_empty() {
            return Err(PushError::Client(format!(
                "team {team} forbids .env sync — refusing to watch: the scan captures \
                 .env* files ({}) — remove the .env files or ask a team owner to lift \
                 the policy (`pear team policy {team} --env on`)",
                dotenv.join(", ")
            )));
        }
    }
    // Flush before the commit decision, not inside it: an unchanged tree
    // may still be missing chunks on the relay (pool loss, visibility
    // change), and uploads are idempotent — the writer repairs the pool
    // either way. Buffered chunks go out before any head references them.
    uploader
        .flush()
        .map_err(|e| push_from_anyhow(anyhow::Error::new(e)))?;
    // Commit only when the file set actually moved: an unchanged scan must
    // not bump the seq and wake every mirror for nothing — except right
    // after a forced takeover, where "this tree becomes the head" holds
    // even when it matches the local cache. A headless workspace
    // (base_seq 0) always commits, even an empty tree. The comparison is
    // against the last COMMITTED file set (remote.json), never just the
    // scan cache: a local `pear sync` writes that cache without
    // committing, and gating on it alone would leave mirrors stale.
    let mut head_seq = base_seq;
    let mut committed = false;
    let cache_poisoned = load_remote_state(&source)
        .and_then(|s| s.files_fingerprint)
        .is_some_and(|fp| fp != fingerprint_files(&build.new.files));
    if force_commit || base_seq == 0 || build.old.files != build.new.files || cache_poisoned {
        let attempted = match e2e_key {
            // §17: the head carries the encrypted manifest (base64) and
            // the ciphertext hashes it references — the relay validates
            // the list but never sees a path or a plaintext byte. §20: the
            // envelope seals under the newest generation.
            Some(keyring) => {
                let manifest_enc =
                    crate::e2e::encrypt_manifest(keyring, &build.new).map_err(PushError::Other)?;
                let chunk_hashes = crate::e2e::manifest_chunk_hashes(&build.new);
                client.put_head_e2e(base_seq, &manifest_enc, &chunk_hashes)
            }
            None => client.put_head(base_seq, &build.new),
        };
        let commit = match attempted {
            Ok(commit) => commit,
            // A lost commit response leaves the relay head at our own
            // commit: base+1 holding exactly the manifest we attempted.
            // Compare file sets, not the per-cycle scan timestamp — the
            // retrying cycle scans with a fresh `scanned_at_secs`, so
            // whole-struct equality would spuriously fail and self-fence.
            // (E2E heads re-encrypt per commit — random nonce — so the
            // comparison decrypts the relay's head with our key.)
            Err(RelayError::HeadConflict { current_seq }) if current_seq == base_seq + 1 => {
                match client.get_head().map_err(PushError::from_relay)? {
                    Some(head)
                        if head.seq == current_seq
                            && head_matches(&head, &build.new, e2e_key) =>
                    {
                        crate::relay::HeadCommit {
                            seq: head.seq,
                            hash: head.hash,
                        }
                    }
                    _ => return Err(PushError::HeadConflict { current_seq }),
                }
            }
            Err(e) => return Err(PushError::from_relay(e)),
        };
        head_seq = commit.seq;
        committed = true;
        // Persist what this device knows of the head: watch startup reads
        // it to prove a resume is not a rewind (§11 writer guard).
        let state = serde_json::to_vec(&RemoteState {
            seq: commit.seq,
            hash: commit.hash.clone(),
            files_fingerprint: Some(fingerprint_files(&build.new.files)),
        })
        .map_err(anyhow::Error::new)?;
        manifest::write_file_atomic(&remote_state_path(&source), &state)?;
    }
    // The source manifest is the writer's chunk cache; persist it after
    // the head commit so a failed commit is re-attempted from the
    // previous base (the committed-tree gate lives in remote.json).
    manifest::write_atomic(&source.join(".pear").join("manifest.json"), &build.new)?;

    Ok(PushReport {
        added: d.added,
        changed: d.changed,
        deleted: d.deleted,
        chunks_uploaded: uploader.uploaded(),
        bytes_uploaded: uploader.bytes(),
        head_seq,
        committed,
    })
}

/// The lost-commit recovery comparison: does the relay's head hold exactly
/// the file set we attempted to commit? Plain heads compare directly; an
/// e2e head must decrypt under our keyring first (the manifest re-encrypts
/// with a random nonce on every attempt, so byte comparison would always
/// miss). §20: the keyring tries newest → oldest, so the comparison also
/// succeeds for a head committed just before a rotation.
fn head_matches(
    head: &crate::relay::HeadInfo,
    new: &Manifest,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> bool {
    match e2e_key {
        Some(keyring) => head
            .manifest_enc
            .as_deref()
            .and_then(|enc| crate::e2e::decrypt_manifest(keyring, enc).ok())
            .is_some_and(|m| m.workspace_id == new.workspace_id && m.files == new.files),
        None => head.manifest.workspace_id == new.workspace_id && head.manifest.files == new.files,
    }
}

/// Outcome of one mirror cycle against the relay.
#[derive(Debug)]
pub struct PullReport {
    /// Remote head sequence observed (0 = the workspace has no head).
    pub head_seq: u64,
    /// Whether the local tree changed this pull.
    pub changed: bool,
    pub written: Vec<String>,
    pub deleted: Vec<String>,
    pub chunks_fetched: usize,
    pub bytes_fetched: u64,
}

impl PullReport {
    fn idle(head_seq: u64) -> Self {
        Self {
            head_seq,
            changed: false,
            written: Vec::new(),
            deleted: Vec::new(),
            chunks_fetched: 0,
            bytes_fetched: 0,
        }
    }
}

/// What the mirror last applied — and, on a writer, the last COMMITTED
/// state — kept in `.pear/remote.json` so a restart does not re-apply
/// the same head.
#[derive(serde::Serialize, serde::Deserialize)]
struct RemoteState {
    seq: u64,
    hash: String,
    /// Fingerprint of the last committed file set (writers only; absent
    /// on mirrors). The writer's commit gate compares the scanned tree
    /// against THIS, not against the shared scan cache: a local
    /// `pear sync` writing that cache must never hide edits from the
    /// relay (§14 autoreview).
    #[serde(default)]
    files_fingerprint: Option<String>,
}

/// A stable fingerprint of a manifest's file set (canonical JSON under
/// BLAKE3), recorded as the writer's last-committed tree.
fn fingerprint_files(files: &std::collections::BTreeMap<String, manifest::FileEntry>) -> String {
    blake3::hash(&serde_json::to_vec(files).expect("file map serializes"))
        .to_hex()
        .to_string()
}

fn remote_state_path(mirror: &Path) -> PathBuf {
    mirror.join(".pear").join("remote.json")
}

fn load_remote_state(mirror: &Path) -> Option<RemoteState> {
    let data = fs::read(remote_state_path(mirror)).ok()?;
    serde_json::from_slice(&data).ok()
}

/// The head seq this mirror last applied (`.pear/remote.json`), if any —
/// what a checkout offers as its synced-to-head proof (§11).
pub fn last_applied_seq(mirror: &Path) -> Option<u64> {
    load_remote_state(mirror).map(|s| s.seq)
}

/// The head seq a writer may resume from: its own known head (last
/// committed/applied seq), or the relay's when the workspace is fresh or
/// the takeover is an explicit `--force`. Anything else is a silent head
/// rewind — a stale tree committed on top of newer state — and is refused
/// (§11: only `force` may strand changes).
pub fn writer_base_seq(source: &Path, client: &RelayClient, force: bool) -> Result<u64> {
    let head = client.get_head()?;
    let relay_seq = head.as_ref().map(|h| h.seq).unwrap_or(0);
    // The local proof must match the relay head in seq AND content hash:
    // seqs alone can coincide after a relay wipe or restore.
    let known = load_remote_state(source);
    let in_sync = match (&known, &head) {
        (Some(k), Some(h)) => k.seq == h.seq && k.hash == h.hash,
        (None, None) => true, // a fresh workspace on both sides
        _ => false,
    };
    if force || in_sync {
        return Ok(relay_seq);
    }
    let local = known
        .map(|s| s.seq.to_string())
        .unwrap_or_else(|| "none".into());
    bail!(
        "this device knows head seq {local} but the relay is at {relay_seq}; \
         `pear snapshot` preserves this tree as a snapshot first, then \
         `pear mirror` adopts the relay head (can overwrite local changes) or \
         `pear watch --relay --force` makes this tree the head instead"
    )
}

/// Load the mirror's local manifest. A corrupt one can never heal by
/// retrying the same head — operator action is required — so it is
/// Fatal, not a transient poll error.
fn load_mirror_manifest(mirror: &Path) -> Result<Option<Manifest>> {
    manifest::load(&mirror.join(".pear").join("manifest.json")).map_err(|e| {
        anyhow::Error::new(RelayError::Fatal(format!(
            "local manifest is unreadable (delete .pear/manifest.json to re-clone): {e:#}"
        )))
    })
}

/// One mirror cycle (§11): `GET /head` (404 -> no-op) -> diff against the
/// local manifest -> batch `chunks/missing` -> fetch missing chunks into
/// the local `.pear/store` -> apply with the M1 engine -> write the local
/// manifest. An unchanged seq (already applied) is an idle no-op; a
/// missing local manifest is an initial clone and pulls everything.
pub fn pull_once(mirror: &Path, client: &RelayClient) -> Result<PullReport> {
    pull_inner(mirror, client, None)
}

/// The e2e mirror cycle (§17/§20): the head's encrypted manifest is
/// decrypted under the keyring (newest generation first, so heads
/// committed before a rotation still read), validated (client-side MUST —
/// the relay cannot), and applied through a decrypting chunk source over
/// ciphertext chunks stored locally by ciphertext hash. Everything else —
/// idle checks, hash verification on the wire, apply — is the plaintext
/// cycle's, unchanged.
pub fn pull_once_e2e(
    mirror: &Path,
    client: &RelayClient,
    keyring: &crate::e2e::Keyring,
) -> Result<PullReport> {
    pull_inner(mirror, client, Some(keyring))
}

/// §30 fetch planning: split the chunks a pull must download into
/// `get_many`-sized batches by walking FILES — a file's chunks partition
/// it exactly, so each entry contributes its chunks as one atomic group
/// whose byte cost is exactly `size` (the manifest knows per-FILE totals,
/// not per-chunk sizes, but a group's total is what a batch needs). A
/// batch closes when the next group would push it past either cap —
/// `GET_MANY_MAX_HASHES` hashes or `GET_MANY_TARGET_BYTES` bytes —
/// first-fit, mirroring the put side. A single file larger than the
/// budget, or with more chunks than the hash cap, forms its own oversized
/// batch (bounded by one file; the client's internal ≤128 split stays as
/// the safety net on the hash side). A chunk hash shared by several files
/// is planned once, with the FIRST file needing it — the second file's
/// full `size` still counts against its batch (dedupe can over-estimate a
/// batch's wire bytes, never under-estimate). Batches come back in fetch
/// order; their concatenation is the deduped need list.
fn plan_fetch_batches(needed: &[(String, &FileEntry)]) -> Vec<Vec<String>> {
    let mut batches: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut current_bytes = 0u64;
    let mut planned: HashSet<&str> = HashSet::new();
    for item in needed {
        let entry = item.1;
        let new: Vec<&String> = entry
            .chunks
            .iter()
            .filter(|h| planned.insert(h.as_str()))
            .collect();
        if !current.is_empty()
            && (current.len() + new.len() > crate::chunk_frame::GET_MANY_MAX_HASHES
                || current_bytes + entry.size > crate::chunk_frame::GET_MANY_TARGET_BYTES)
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.extend(new.into_iter().cloned());
        current_bytes += entry.size;
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

fn pull_inner(
    mirror: &Path,
    client: &RelayClient,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> Result<PullReport> {
    fs::create_dir_all(mirror).with_context(|| format!("create {}", mirror.display()))?;
    let mirror = mirror
        .canonicalize()
        .with_context(|| format!("canonicalize {}", mirror.display()))?;

    let (meta, _) = init_workspace(&mirror, Some(client.workspace_id()))?;
    if meta.id != client.workspace_id() {
        // Deterministic: this mirror will never match the relay client,
        // so the loop must exit rather than poll forever.
        return Err(RelayError::Fatal(format!(
            "{} is workspace {} but the relay client targets {}; init the mirror with the workspace id",
            mirror.display(),
            meta.id,
            client.workspace_id()
        ))
        .into());
    }

    // Cheap idle check first (§11): the workspace record carries head
    // seq+hash, so an unchanged head costs a tiny request instead of the
    // full manifest body every poll. A missing workspace errors here.
    let ws = client.get_workspace()?;
    // §17 flavor pinning, client side: an e2e workspace must be pulled
    // with its workspace key, a plain one never with a key — no
    // downgrade in either direction. Deterministic, so Fatal.
    match (ws.e2e, e2e_key) {
        (true, None) => {
            return Err(RelayError::Fatal(format!(
                "workspace {} is end-to-end encrypted; this device needs its workspace key — \
                 re-run with --name <name> (after `pear user keygen --name <name>`) so pear can fetch your wrapped key",
                meta.id
            ))
            .into());
        }
        (false, Some(_)) => {
            return Err(RelayError::Fatal(format!(
                "workspace {} is not end-to-end encrypted; refusing to pull it with a workspace key",
                meta.id
            ))
            .into());
        }
        _ => {}
    }
    if ws.head_seq == 0 {
        // No head anywhere while this mirror has applied state means the
        // relay was wiped and the workspace re-registered — the same
        // class of staleness every other path surfaces loudly (the idle
        // checks compare head HASH because "seqs alone can coincide
        // after a relay wipe or restore"). Never idle silently over it.
        if load_remote_state(&mirror).is_some() {
            bail!(
                "relay workspace {} has no head, but this mirror has applied state \
                 (relay wiped?); `pear watch --relay --force` on the writer restores it",
                meta.id
            );
        }
        return Ok(PullReport::idle(0));
    }
    if load_remote_state(&mirror)
        .is_some_and(|s| s.seq == ws.head_seq && ws.head_hash.as_deref() == Some(s.hash.as_str()))
        && load_mirror_manifest(&mirror)?.is_some()
    {
        return Ok(PullReport::idle(ws.head_seq));
    }

    let Some(head) = client.get_head()? else {
        // Metadata says there is a head but it is gone (partially wiped
        // relay): surface it, never idle silently.
        bail!(
            "relay workspace {} reports head seq {} but has no head",
            meta.id,
            ws.head_seq
        );
    };
    // §17: an e2e head's manifest is decrypted under the workspace key
    // before anything trusts it. The manifest is network input either
    // way: validate before it touches disk (client-side MUST for e2e —
    // the relay cannot validate what it cannot read), and refuse a head
    // that belongs to a different workspace. Both are deterministic —
    // the same head fails every poll — so they are Fatal: the mirror
    // loop exits instead of retrying forever.
    let decrypted;
    let wire_ref = match e2e_key {
        Some(keyring) => {
            let enc = head.manifest_enc.as_deref().ok_or_else(|| {
                anyhow::Error::new(RelayError::Fatal(
                    "the relay's e2e head carries no manifest_enc".to_string(),
                ))
            })?;
            decrypted = crate::e2e::decrypt_manifest(keyring, enc).map_err(|e| {
                anyhow::Error::new(RelayError::Fatal(format!(
                    "cannot decrypt the relay's e2e head: {e:#}"
                )))
            })?;
            &decrypted
        }
        None => &head.manifest,
    };
    manifest::validate(wire_ref).map_err(|e| {
        anyhow::Error::new(RelayError::Fatal(format!(
            "invalid manifest from relay: {e:#}"
        )))
    })?;
    if wire_ref.workspace_id != meta.id {
        return Err(RelayError::Fatal(format!(
            "relay head belongs to workspace {}, this mirror is {}",
            wire_ref.workspace_id, meta.id
        ))
        .into());
    }
    // The mirror never materializes setuid/setgid/sticky bits (apply
    // masks them, §15): it must diff and RECORD the masked manifest, or
    // the file looks eternally changed and a role reversal reports a
    // phantom mode change back toward the origin. The relay (and
    // remote.json's head hash) keep the true bits.
    let mut wire = wire_ref.clone();
    for entry in wire.files.values_mut() {
        entry.mode &= 0o777;
    }

    let local = load_mirror_manifest(&mirror)?;
    // Idle only when the stored head matches in seq AND content hash:
    // seqs alone can coincide after a relay wipe or restore.
    if local.is_some()
        && load_remote_state(&mirror).is_some_and(|s| s.seq == head.seq && s.hash == head.hash)
    {
        return Ok(PullReport::idle(head.seq));
    }
    let local = local.unwrap_or_else(|| Manifest::new(meta.id.clone()));
    // Deferred store (§18): fetched chunks are written without a
    // per-chunk fsync; one group flush lands before the apply below.
    let store = LocalStore::open_deferred(mirror.join(".pear").join("store"))?;

    // Fetch what the head added or changed and this mirror lacks locally.
    // (E2E: the hashes are ciphertext hashes and the fetched bytes are
    // ciphertext — the same content-addressing integrity check applies.)
    // §30: the fetch is planned by FILE (see plan_fetch_batches) so each
    // get_many call is bounded by a byte budget derived from manifest
    // sizes, not just by the ≤128-hash wire cap.
    let d = manifest::diff(&local, &wire);
    let needed: Vec<(String, &FileEntry)> = d
        .added
        .iter()
        .chain(d.changed.iter())
        .map(|rel| (rel.clone(), &wire.files[rel]))
        .collect();
    let batches = plan_fetch_batches(&needed);
    let need: Vec<String> = batches.iter().flatten().cloned().collect();
    let mut chunks_fetched = 0usize;
    let mut bytes_fetched = 0u64;
    if !need.is_empty() {
        let present = store.has_many(&need)?;
        let to_fetch: Vec<String> = need
            .iter()
            .zip(present)
            .filter_map(|(h, p)| if p { None } else { Some(h.clone()) })
            .collect();
        if !to_fetch.is_empty() {
            // Fail before applying anything if the relay's pool cannot
            // serve the head — never mid-apply.
            let missing = client.chunks_missing(&to_fetch)?;
            if !missing.is_empty() {
                bail!(
                    "relay is missing {} chunk(s) the head references (e.g. {}): cannot converge",
                    missing.len(),
                    missing[0]
                );
            }
            // §23/§30: one get_chunks call per planned batch — chunks the
            // local store already has are filtered out per batch, so a
            // batch that is fully present costs no request at all. The
            // per-chunk BLAKE3 wire-verify does NOT move: content
            // addressing is still the integrity check on the wire, and
            // wrong bytes must never enter the store.
            let to_fetch_set: HashSet<&str> = to_fetch.iter().map(String::as_str).collect();
            for batch in &batches {
                let fetch: Vec<String> = batch
                    .iter()
                    .filter(|h| to_fetch_set.contains(h.as_str()))
                    .cloned()
                    .collect();
                if fetch.is_empty() {
                    continue;
                }
                for (hash, data) in client.get_chunks(&fetch)? {
                    if blake3::hash(&data).to_hex().as_str() != hash {
                        bail!("fetched chunk {hash} does not match its BLAKE3 content hash");
                    }
                    bytes_fetched += data.len() as u64;
                    if store.put(&hash, &data)? {
                        chunks_fetched += 1;
                    }
                }
            }
        }
    }

    // Flush point (§18/§25): every chunk the fetch loop wrote gets its
    // dirent fsynced as a group before the apply starts reading them
    // from this store (reads re-hash, §18).
    store.flush()?;

    let report = {
        // E2E: apply reads ciphertext from the store and decrypts under
        // the keyring, newest generation first (hash-verified again at
        // read time).
        let decrypting;
        let source: &dyn crate::store::ChunkSource = match e2e_key {
            Some(keyring) => {
                decrypting = crate::e2e::DecryptingSource {
                    inner: &store,
                    keyring,
                };
                &decrypting
            }
            None => &store,
        };
        apply::apply(&mirror, &local, &wire, source).map_err(|e| {
            // A deterministic apply-time refusal (case-colliding keys) fails
            // identically on every poll: Fatal, never retried.
            if e.downcast_ref::<apply::ApplyRejection>().is_some() {
                anyhow::Error::new(RelayError::Fatal(format!("{e:#}")))
            } else {
                e
            }
        })?
    };
    manifest::write_file_atomic(
        &remote_state_path(&mirror),
        &serde_json::to_vec(&RemoteState {
            seq: head.seq,
            hash: head.hash,
            files_fingerprint: None,
        })?,
    )?;

    let changed = !report.written.is_empty() || !report.deleted.is_empty();
    // §24 local-store GC (mirror store): the apply and the remote.json
    // commit succeeded, so every chunk the applied head needs is in the
    // store — delete what the just-applied manifest no longer
    // references. A failed apply never reaches here (a sweep over a
    // stale manifest could delete chunks the next apply still needs).
    // Idle pulls skip the walk entirely — no syscall churn per 2s poll —
    // and a sweep failure warns without failing the cycle: GC must never
    // break convergence. (E2E mirror: `wire`'s hashes are ciphertext
    // hashes, the store's own key space, so the pin set is well-defined.)
    if changed || chunks_fetched > 0 {
        let keep: HashSet<&str> = wire
            .files
            .values()
            .flat_map(|entry| entry.chunks.iter().map(String::as_str))
            .collect();
        if let Err(e) = store.sweep_unreferenced(&keep) {
            eprintln!("pear: local store sweep failed (retried after the next apply): {e}");
        }
    }

    Ok(PullReport {
        head_seq: head.seq,
        changed,
        written: report.written,
        deleted: report.deleted,
        chunks_fetched,
        bytes_fetched,
    })
}

/// Canonicalize a path that may not exist yet: canonicalize the nearest
/// existing ancestor, then reattach the missing tail components. Lets the
/// containment check run before anything is created on disk.
fn canonicalize_lenient(path: &Path) -> Result<PathBuf> {
    let path =
        std::path::absolute(path).with_context(|| format!("absolutize {}", path.display()))?;
    let mut missing = Vec::new();
    let mut cursor = path.as_path();
    loop {
        match cursor.canonicalize() {
            Ok(mut base) => {
                for part in missing.iter().rev() {
                    base.push(part);
                }
                return Ok(base);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match (cursor.file_name(), cursor.parent()) {
                    (Some(name), Some(parent)) => {
                        missing.push(name.to_os_string());
                        cursor = parent;
                    }
                    _ => {
                        return Err(e).with_context(|| format!("canonicalize {}", path.display()));
                    }
                }
            }
            Err(e) => return Err(e).with_context(|| format!("canonicalize {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that fails on the Nth put, then succeeds.
    struct FlakySink {
        present: std::cell::RefCell<HashSet<String>>,
        fail_on: usize,
        calls: std::cell::Cell<usize>,
    }

    impl FlakySink {
        fn new(fail_on: usize) -> Self {
            Self {
                present: std::cell::RefCell::new(HashSet::new()),
                fail_on,
                calls: std::cell::Cell::new(0),
            }
        }
    }

    impl ChunkSink for FlakySink {
        fn has(&self, hash: &str) -> io::Result<bool> {
            Ok(self.present.borrow().contains(hash))
        }

        fn put(&self, hash: &str, _data: &[u8]) -> io::Result<bool> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == self.fail_on {
                return Err(io::Error::other("injected put failure"));
            }
            self.present.borrow_mut().insert(hash.to_string());
            Ok(true)
        }
    }

    #[test]
    fn failed_flush_keeps_pending_chunks() {
        let sink = FlakySink::new(1); // first put fails
        let mut uploader = BatchUploader::new(&sink);
        uploader.pending = vec![
            ("h1".to_string(), b"one".to_vec()),
            ("h2".to_string(), b"two".to_vec()),
        ];
        uploader.pending_hashes = ["h1".to_string(), "h2".to_string()].into_iter().collect();
        uploader.pending_bytes = 6;

        assert!(uploader.flush().is_err(), "injected failure must surface");
        assert_eq!(uploader.pending.len(), 2, "both chunks stay buffered");
        assert_eq!(uploader.pending_bytes, 6);
        assert!(uploader.seen.is_empty(), "nothing confirmed on failure");

        // Retry uploads everything; seen and counters are exact.
        uploader.flush().unwrap();
        assert!(uploader.pending.is_empty());
        assert_eq!(uploader.pending_bytes, 0);
        assert_eq!(uploader.uploaded, 2);
        assert!(uploader.seen.contains("h1") && uploader.seen.contains("h2"));
    }

    #[test]
    fn upload_file_defers_flushing_until_threshold_or_explicit_flush() {
        let sink = FlakySink::new(usize::MAX); // never fails
        let mut uploader = BatchUploader::new(&sink);
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("small.txt");
        std::fs::write(&f, b"small payload\n").unwrap();

        uploader.upload_file(&f).unwrap();
        assert_eq!(
            sink.calls.get(),
            0,
            "below the threshold, nothing uploads yet"
        );
        uploader.flush().unwrap();
        assert_eq!(sink.calls.get(), 1);
    }

    /// A sink whose `put_many` reports per-entry failures, the §23 relay
    /// shape: entries named in `bad` fail with a reason, the rest store.
    #[derive(Default)]
    struct PickySink {
        present: std::cell::RefCell<HashSet<String>>,
        bad: std::cell::RefCell<HashSet<String>>,
    }

    impl ChunkSink for PickySink {
        fn has(&self, hash: &str) -> io::Result<bool> {
            Ok(self.present.borrow().contains(hash))
        }

        fn put(&self, _hash: &str, _data: &[u8]) -> io::Result<bool> {
            unreachable!("the batched path must not fall back to single puts")
        }

        fn put_many(
            &self,
            entries: &[(String, Vec<u8>)],
        ) -> io::Result<Vec<Result<bool, String>>> {
            Ok(entries
                .iter()
                .map(|(hash, _)| {
                    if self.bad.borrow().contains(hash) {
                        Err("the relay rejected this entry".to_string())
                    } else {
                        self.present.borrow_mut().insert(hash.clone());
                        Ok(true)
                    }
                })
                .collect())
        }
    }

    /// §23: a per-entry failure keeps ONLY the failed chunks buffered —
    /// the rest of the batch lands, is counted, and is marked seen —
    /// while the flush still surfaces the first failure.
    #[test]
    fn per_entry_failure_keeps_only_the_failed_chunks() {
        let sink = PickySink {
            bad: std::cell::RefCell::new(["h2".to_string()].into_iter().collect()),
            ..Default::default()
        };
        let mut uploader = BatchUploader::new(&sink);
        uploader.pending = vec![
            ("h1".to_string(), b"one".to_vec()),
            ("h2".to_string(), b"two".to_vec()),
            ("h3".to_string(), b"three".to_vec()),
        ];
        uploader.pending_hashes = ["h1".to_string(), "h2".to_string(), "h3".to_string()]
            .into_iter()
            .collect();
        uploader.pending_bytes = 11;

        let err = uploader.flush().unwrap_err();
        assert!(
            format!("{err}").contains("h2"),
            "the failure names its chunk: {err}"
        );
        assert_eq!(
            uploader.pending,
            vec![("h2".to_string(), b"two".to_vec())],
            "only the failed entry stays buffered"
        );
        assert_eq!(uploader.pending_bytes, 3);
        assert_eq!(uploader.uploaded, 2, "the good entries landed");
        assert!(uploader.seen.contains("h1") && uploader.seen.contains("h3"));
        assert!(
            !uploader.seen.contains("h2") && uploader.pending_hashes.contains("h2"),
            "the failed chunk is neither seen nor dropped"
        );

        // Healed, the buffered chunk flushes clean on retry; the others
        // are already seen and never re-upload.
        sink.bad.borrow_mut().clear();
        uploader.flush().unwrap();
        assert!(uploader.pending.is_empty());
        assert_eq!(uploader.pending_bytes, 0);
        assert_eq!(uploader.uploaded, 3);
        assert!(uploader.seen.contains("h2"));
    }

    /// A sink whose `put_many` misaligns (too few results): statuses map
    /// positionally, so nothing may be confirmed and everything must stay
    /// buffered — marking an unstored chunk seen would suppress its
    /// upload permanently.
    #[test]
    fn short_put_many_result_confirms_nothing() {
        struct ShortSink;
        impl ChunkSink for ShortSink {
            fn has(&self, _hash: &str) -> io::Result<bool> {
                Ok(false)
            }
            fn put(&self, _hash: &str, _data: &[u8]) -> io::Result<bool> {
                unreachable!()
            }
            fn put_many(
                &self,
                _entries: &[(String, Vec<u8>)],
            ) -> io::Result<Vec<Result<bool, String>>> {
                Ok(vec![Ok(true)]) // one result for two entries
            }
        }

        let sink = ShortSink;
        let mut uploader = BatchUploader::new(&sink);
        uploader.pending = vec![
            ("h1".to_string(), b"one".to_vec()),
            ("h2".to_string(), b"two".to_vec()),
        ];
        uploader.pending_hashes = ["h1".to_string(), "h2".to_string()].into_iter().collect();
        uploader.pending_bytes = 6;

        assert!(uploader.flush().is_err());
        assert_eq!(uploader.pending.len(), 2, "everything stays buffered");
        assert_eq!(uploader.pending_bytes, 6);
        assert_eq!(uploader.uploaded, 0);
        assert!(uploader.seen.is_empty());
    }

    /// An in-memory chunk sink holding ciphertext blobs by hash.
    #[derive(Default)]
    struct MemSink {
        blobs: std::cell::RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl ChunkSink for MemSink {
        fn has(&self, hash: &str) -> io::Result<bool> {
            Ok(self.blobs.borrow().contains_key(hash))
        }

        fn put(&self, hash: &str, data: &[u8]) -> io::Result<bool> {
            Ok(self
                .blobs
                .borrow_mut()
                .insert(hash.to_string(), data.to_vec())
                .is_none())
        }
    }

    /// §20's no-re-upload property at the writer pipeline level: after a
    /// rotation, an UNCHANGED file uploads nothing (its cached ciphertext
    /// hashes are reused) while a CHANGED file's chunks land under the new
    /// generation only — and a keyring holding just generation 1 cannot
    /// decrypt those, while the full ring reads old and new alike.
    #[test]
    fn rotation_reuploads_nothing_unchanged_and_rekeys_changes() {
        let sink = MemSink::default();
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path();
        std::fs::write(src.join("same.txt"), b"unchanged\n").unwrap();
        std::fs::write(src.join("edit.txt"), b"v1\n").unwrap();
        // Backdate the unchanged file BEFORE the first cycle, so its cache
        // entry is already settled at cycle 2 (CACHE_SETTLE_SECS in
        // production; the test cannot wait out the settle window).
        let long_ago = filetime::FileTime::from_unix_time(1_000_000, 0);
        filetime::set_file_mtime(src.join("same.txt"), long_ago).unwrap();
        let mut keyring = crate::e2e::Keyring::from_legacy(rand::random());
        let gen1_key = *keyring.newest().1;

        // Cycle 1 under generation 1 (what push_inner does, minus the head).
        let mut up1 = E2eUploader::new(&sink, gen1_key).unwrap();
        let build1 = scan_build_manifest(src, &sink, false, |p| {
            up1.upload_file(p).map_err(anyhow::Error::new)
        })
        .unwrap();
        up1.flush().unwrap();
        crate::manifest::write_atomic(&src.join(".pear/manifest.json"), &build1.new).unwrap();
        let chunks_v1: HashSet<String> = build1
            .new
            .files
            .values()
            .flat_map(|e| e.chunks.iter().cloned())
            .collect();

        // Rotate, then edit one file.
        keyring.rotate();
        let gen2_key = *keyring.newest().1;
        std::fs::write(src.join("edit.txt"), b"v2 after rotation\n").unwrap();

        // Cycle 2 under generation 2.
        let mut up2 = E2eUploader::new(&sink, gen2_key).unwrap();
        let build2 = scan_build_manifest(src, &sink, false, |p| {
            up2.upload_file(p).map_err(anyhow::Error::new)
        })
        .unwrap();
        up2.flush().unwrap();

        // The unchanged file reuses its gen-1 ciphertext hashes verbatim
        // and never touched the uploader: only the edited file's one new
        // chunk crossed the sink.
        assert_eq!(
            build2.new.files["same.txt"].chunks, build1.new.files["same.txt"].chunks,
            "cached ciphertext hashes reused across the rotation"
        );
        assert_eq!(up2.inner.uploaded, 1, "only edit.txt's new chunk uploaded");
        let new_chunks = &build2.new.files["edit.txt"].chunks;
        assert_ne!(
            new_chunks, &build1.new.files["edit.txt"].chunks,
            "the edit sealed under generation 2: new ciphertext hashes"
        );

        // The new chunks decrypt under generation 2 ONLY: the full ring
        // reads them, a removed member's gen-1-only ring does not.
        let gen1_only = crate::e2e::Keyring::from_legacy(gen1_key);
        let blobs = sink.blobs.borrow();
        for hash in new_chunks {
            let blob = &blobs[hash];
            assert!(crate::crypto::decrypt_chunk(&gen2_key, blob).is_ok());
            assert!(crate::crypto::decrypt_chunk(&gen1_key, blob).is_err());
            assert!(keyring.decrypt("chunk", |k| crate::crypto::decrypt_chunk(k, blob)).is_ok());
            assert!(gen1_only
                .decrypt("chunk", |k| crate::crypto::decrypt_chunk(k, blob))
                .is_err());
        }
        // And every pre-rotation chunk still reads under the full ring.
        for hash in &chunks_v1 {
            let blob = &blobs[hash];
            let plain = keyring
                .decrypt("chunk", |k| crate::crypto::decrypt_chunk(k, blob))
                .unwrap();
            assert!(!plain.is_empty(), "old chunk {hash} still decrypts");
        }
    }

    /// Every blob file name under a store's `chunks/<2>/` layout.
    fn store_chunk_names(store_root: &Path) -> Vec<String> {
        let mut names = Vec::new();
        for shard in std::fs::read_dir(store_root.join("chunks")).unwrap() {
            for entry in std::fs::read_dir(shard.unwrap().path()).unwrap() {
                names.push(entry.unwrap().file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        names
    }

    /// §24: after a converging second sync_cycle, the M1 target store no
    /// longer holds the superseded content's chunk — the applied
    /// manifest's chunk set is exactly what survives.
    #[test]
    fn sync_cycle_sweeps_superseded_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("f.txt"), b"version one\n").unwrap();
        sync_cycle(&source, &target).unwrap();
        let store_root = target.join(".pear/store");
        let before = store_chunk_names(&store_root);
        assert_eq!(before.len(), 1, "one file, one chunk");

        std::fs::write(source.join("f.txt"), b"version two, changed\n").unwrap();
        sync_cycle(&source, &target).unwrap();
        let after = store_chunk_names(&store_root);
        assert_eq!(after.len(), 1, "the superseded chunk was swept");
        assert_ne!(before, after, "what survives is the new content's chunk");
        assert_eq!(
            std::fs::read(target.join("f.txt")).unwrap(),
            b"version two, changed\n"
        );
    }

    // ---- §30 plan_fetch_batches ----

    /// A manifest entry with `n` fabricated chunks totalling `size` bytes.
    fn fetch_entry(size: u64, prefix: &str, n: usize) -> FileEntry {
        FileEntry {
            size,
            mode: 0o644,
            mtime_secs: 0,
            mtime_nanos: 0,
            chunks: (0..n).map(|i| format!("{prefix}-{i:04}")).collect(),
        }
    }

    fn plan(files: &[(&str, FileEntry)]) -> Vec<Vec<String>> {
        let needed: Vec<(String, &FileEntry)> = files
            .iter()
            .map(|(rel, entry)| (rel.to_string(), entry))
            .collect();
        plan_fetch_batches(&needed)
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn plan_fetch_batches_empty() {
        assert!(plan(&[]).is_empty());
        // Files with no chunks (empty files) form no batch either.
        assert!(plan(&[("empty.txt", fetch_entry(0, "e", 0))]).is_empty());
    }

    #[test]
    fn plan_fetch_batches_packs_small_files_to_the_caps() {
        // Hash cap: 13 files × 10 tiny chunks. 12 files (120 hashes) fit;
        // the 13th would make 130 > 128, so it starts a second batch even
        // though the byte budget is nowhere near.
        let files: Vec<(String, FileEntry)> = (0..13)
            .map(|i| (format!("f{i}.txt"), fetch_entry(10, &format!("h{i}"), 10)))
            .collect();
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (rel.as_str(), e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 2, "{batches:?}");
        assert_eq!(batches[0].len(), 120);
        assert_eq!(batches[1].len(), 10);

        // Byte cap: 8 MiB files pack four to a batch (4 × 8 = 32 MiB);
        // the fifth overflows into its own batch.
        let files: Vec<(String, FileEntry)> = (0..5)
            .map(|i| (format!("b{i}.bin"), fetch_entry(8 * MIB, &format!("b{i}"), 2)))
            .collect();
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (rel.as_str(), e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 2, "{batches:?}");
        assert_eq!(batches[0].len(), 8, "four files × two chunks");
        assert_eq!(batches[1].len(), 2);
    }

    #[test]
    fn plan_fetch_batches_byte_boundary_is_exact() {
        // 8 × 4 MiB = exactly the 32 MiB budget: all eight fit one batch;
        // a ninth file of ONE byte still overflows it.
        let mut files: Vec<(String, FileEntry)> = (0..8)
            .map(|i| (format!("b{i}.bin"), fetch_entry(4 * MIB, &format!("b{i}"), 1)))
            .collect();
        files.push(("tiny.txt".to_string(), fetch_entry(1, "t", 1)));
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (rel.as_str(), e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 2, "{batches:?}");
        assert_eq!(batches[0].len(), 8);
        assert_eq!(batches[1], vec!["t-0000".to_string()]);
    }

    #[test]
    fn plan_fetch_batches_oversized_file_rides_alone() {
        // A file bigger than the whole budget forms its own batch without
        // dragging neighbours in, on either side.
        let files = [
            ("a.txt", fetch_entry(1, "a", 1)),
            ("huge.bin", fetch_entry(64 * MIB, "h", 17)),
            ("b.txt", fetch_entry(1, "b", 1)),
        ];
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (*rel, e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 3, "{batches:?}");
        assert_eq!(batches[0], vec!["a-0000".to_string()]);
        assert_eq!(batches[1].len(), 17, "the oversized file alone");
        assert!(batches[1].iter().all(|h| h.starts_with("h-")));
        assert_eq!(batches[2], vec!["b-0000".to_string()]);

        // Same on the hash side: a small file with MORE than 128 chunks
        // is its own oversized batch (the client's ≤128 split is the
        // safety net for it).
        let files = [("many.bin", fetch_entry(4096, "m", 200))];
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (*rel, e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 200);
    }

    #[test]
    fn plan_fetch_batches_never_splits_a_chunk_group() {
        // Ten 8 MiB files of 3 chunks each → batches of 4, 4, 2 files by
        // the byte budget. Every file's chunks must land together in
        // exactly one batch.
        let files: Vec<(String, FileEntry)> = (0..10)
            .map(|i| (format!("f{i}.bin"), fetch_entry(8 * MIB, &format!("f{i}"), 3)))
            .collect();
        let refs: Vec<(&str, FileEntry)> = files
            .iter()
            .map(|(rel, e)| (rel.as_str(), e.clone()))
            .collect();
        let batches = plan(&refs);
        assert_eq!(batches.len(), 3, "{batches:?}");
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![12, 12, 6]
        );
        let batch_of: std::collections::HashMap<&str, usize> = batches
            .iter()
            .enumerate()
            .flat_map(|(i, b)| b.iter().map(move |h| (h.as_str(), i)))
            .collect();
        for (_, entry) in &refs {
            let homes: HashSet<usize> = entry.chunks.iter().map(|h| batch_of[h.as_str()]).collect();
            assert_eq!(homes.len(), 1, "a chunk group straddled batches");
        }
    }

    #[test]
    fn plan_fetch_batches_plans_a_shared_chunk_once() {
        // Two files sharing chunk "s-0000": it is fetched with the FIRST
        // file only; the flattened batches are the deduped need list.
        let a = FileEntry {
            size: 100,
            chunks: vec!["a-0000".to_string(), "s-0000".to_string()],
            ..fetch_entry(0, "x", 0)
        };
        let b = FileEntry {
            size: 100,
            chunks: vec!["s-0000".to_string(), "b-0000".to_string()],
            ..fetch_entry(0, "x", 0)
        };
        let batches = plan(&[("a.txt", a), ("b.txt", b)]);
        let flat: Vec<String> = batches.concat();
        assert_eq!(
            flat,
            vec!["a-0000".to_string(), "s-0000".to_string(), "b-0000".to_string()]
        );
    }
}
