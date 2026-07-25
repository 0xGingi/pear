//! The §32 converge step: one bidirectional pass for a Writer device.
//!
//! `base` (`.pear/manifest.json`, the last converged state), `local` (a
//! fresh scan) and `remote` (the relay head) go into the pure 3-way
//! [`crate::merge`]; the result is materialized with the existing staged
//! [`apply`] engine and published with the head CAS. There is no lease and
//! no fencing: `put_head`'s compare-and-swap on `base_seq` is the whole of
//! the concurrency control, and a 409 just re-runs the merge against the
//! head that won.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};

use crate::manifest::{self, FileEntry, Manifest};
use crate::merge::{self, ConflictSide, MergeOutcome};
use crate::relay::{HeadInfo, RelayClient, RelayError};
use crate::store::{ChunkSink, ChunkSource, LocalStore};
use crate::sync::{
    fingerprint_files, load_mirror_manifest, plan_fetch_batches, push_from_anyhow,
    remote_state_path, scan_build_manifest, BatchUploader, E2eUploader, PushError, RemoteState,
    Uploader,
};
use crate::{apply, init_workspace};

/// How many times one converge re-merges after a lost CAS race before
/// giving up. Each 409 means another writer advanced the head, so the loop
/// terminates in practice; the bound only keeps a pathological relay (or a
/// storm of writers) from spinning a device forever.
const MAX_ATTEMPTS: u32 = 32;

/// What one converge did, for the loops that log it.
#[derive(Debug)]
pub struct ConvergeReport {
    /// Whether this converge committed a new head.
    pub pushed: bool,
    /// Head sequence after this converge (0 = the workspace has no head).
    pub head_seq: u64,
    /// Paths materialized from the remote side (adds and changes).
    pub written: Vec<String>,
    /// Paths deleted locally because the remote deleted them.
    pub deleted: Vec<String>,
    /// Conflict copies created, by path (§32: never auto-deleted).
    pub conflict_copies: Vec<String>,
    pub chunks_uploaded: usize,
    pub bytes_uploaded: u64,
    pub chunks_fetched: usize,
    pub bytes_fetched: u64,
    /// Merge attempts spent, counting CAS retries.
    pub attempts: u32,
}

/// One converge pass (§32). `device` names this device — it labels the
/// conflict copies whose local side loses a last-writer-wins race.
/// `keyring` selects the e2e flavor exactly as the push/pull cycles do.
pub fn converge_once(
    source: &Path,
    client: &RelayClient,
    device: &str,
    keyring: Option<&crate::e2e::Keyring>,
) -> Result<ConvergeReport, PushError> {
    if !source.is_dir() {
        return Err(anyhow!("source {} is not a directory", source.display()).into());
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;
    // A converging device adopts the relay's workspace id (a `join` into an
    // empty directory is a clone); a mismatch is refused, never re-targeted.
    let (meta, _) = init_workspace(&source, Some(client.workspace_id()))?;

    // The last state this device and the relay agreed on. Held in memory
    // across CAS retries: after a lost race the correct common ancestor is
    // the head we just merged against, not what is on disk.
    let mut base = load_mirror_manifest(&source)?.unwrap_or_else(|| Manifest::new(meta.id.clone()));
    // Injected once per converge so every retry names its conflict copies
    // identically — the merge itself never reads the clock.
    let stamp = merge::conflict_stamp(SystemTime::now());

    let mut chunks_uploaded = 0usize;
    let mut bytes_uploaded = 0u64;
    let mut chunks_fetched = 0usize;
    let mut bytes_fetched = 0u64;

    // §17 flavor pinning, client side: an e2e workspace is never converged
    // without its workspace key, a plain one never with one — no downgrade
    // in either direction, and a headless e2e workspace must not have a
    // plaintext head published onto it. Deterministic, so Fatal.
    let ws = client.get_workspace().map_err(PushError::from_relay)?;
    match (ws.e2e, keyring) {
        (true, None) => {
            return Err(PushError::Other(anyhow::Error::new(RelayError::Fatal(
                format!(
                    "workspace {} is end-to-end encrypted; this device needs its workspace key",
                    meta.id
                ),
            ))));
        }
        (false, Some(_)) => {
            return Err(PushError::Other(anyhow::Error::new(RelayError::Fatal(
                format!(
                    "workspace {} is not end-to-end encrypted; refusing to converge it with a \
                     workspace key",
                    meta.id
                ),
            ))));
        }
        _ => {}
    }

    for attempt in 1..=MAX_ATTEMPTS {
        // 1. Remote head. No head yet = an empty remote manifest at seq 0.
        let head = client.get_head().map_err(PushError::from_relay)?;
        let remote = remote_manifest(head.as_ref(), keyring, &meta.id)?;
        let remote_seq = head.as_ref().map(|h| h.seq).unwrap_or(0);

        // 2. Fresh scan. Chunks stream to the relay exactly as the writer
        //    cycle does (ciphertext under e2e); the local store below only
        //    ever holds chunks fetched back from the relay.
        let store = LocalStore::open_deferred(source.join(".pear").join("store"))
            .map_err(|e| PushError::Other(anyhow::Error::new(e)))?;
        let mut uploader = match keyring {
            Some(keyring) => Uploader::E2e(
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
        let local = build.new;
        if local.workspace_id != client.workspace_id() {
            return Err(anyhow!(
                "local workspace {} does not match relay workspace {}",
                local.workspace_id,
                client.workspace_id()
            )
            .into());
        }
        refuse_forbidden_dotenv(client, &local)?;

        // 3. The pure 3-way merge.
        let out = merge::merge(&base, &local, &remote, device, &stamp);
        manifest::validate(&out.merged)
            .context("the 3-way merge produced an invalid manifest")
            .map_err(PushError::Other)?;

        // 4. Fetch what the apply needs, then materialize. The store flush
        //    (§18/§25) lands before apply reads a byte back out of it.
        let (fetched, bytes) = fetch_for_apply(client, &store, &out)?;
        chunks_fetched += fetched;
        bytes_fetched += bytes;
        store.flush().map_err(|e| PushError::Other(e.into()))?;
        let materialized = {
            let decrypting;
            let chunks: &dyn ChunkSource = match keyring {
                Some(keyring) => {
                    decrypting = crate::e2e::DecryptingSource {
                        inner: &store,
                        keyring,
                    };
                    &decrypting
                }
                None => &store,
            };
            materialize(&source, &local, &remote, &out, chunks)?
        };

        // Buffered chunks go out before any head can reference them.
        uploader
            .flush()
            .map_err(|e| push_from_anyhow(anyhow::Error::new(e)))?;
        chunks_uploaded += uploader.uploaded();
        bytes_uploaded += uploader.bytes();

        // 5. Publish, unless the merge already agrees with the head. A
        //    workspace with no head always publishes, even an empty tree:
        //    that is what creates the head other devices converge onto.
        let done = |pushed: bool, head_seq: u64| ConvergeReport {
            pushed,
            head_seq,
            written: materialized.written.clone(),
            deleted: materialized.deleted.clone(),
            conflict_copies: materialized.conflict_copies.clone(),
            chunks_uploaded,
            bytes_uploaded,
            chunks_fetched,
            bytes_fetched,
            attempts: attempt,
        };
        // File sets, not whole manifests: `scanned_at_secs` is this
        // device's cache hint and differs on every scan.
        if out.merged.files == remote.files {
            if let Some(head) = &head {
                commit(&source, &out.merged, head.seq, &head.hash, &store)?;
                return Ok(done(false, head.seq));
            }
        }
        let attempted = match keyring {
            Some(keyring) => {
                let manifest_enc = crate::e2e::encrypt_manifest(keyring, &out.merged)
                    .map_err(PushError::Other)?;
                let chunk_hashes = crate::e2e::manifest_chunk_hashes(&out.merged);
                client.put_head_e2e(remote_seq, &manifest_enc, &chunk_hashes)
            }
            None => client.put_head(remote_seq, &out.merged),
        };
        match attempted {
            Ok(head) => {
                commit(&source, &out.merged, head.seq, &head.hash, &store)?;
                return Ok(done(true, head.seq));
            }
            // Another writer advanced the head between our fetch and our
            // commit. Re-merge against the winner: the correct common
            // ancestor is the head we just merged against (the tree on
            // disk now descends from it), NOT what `.pear/manifest.json`
            // holds.
            Err(RelayError::HeadConflict { .. }) => base = remote,
            Err(e) => return Err(PushError::from_relay(e)),
        }
    }
    Err(PushError::Other(anyhow!(
        "converge lost the head race {MAX_ATTEMPTS} times in a row; another writer is \
         publishing faster than this device can merge"
    )))
}

/// The head's manifest, decrypted (e2e) and validated. A head is network
/// input: nothing trusts it before `validate`, and a flavor mismatch or a
/// foreign workspace id is deterministic, so both are `Fatal`.
fn remote_manifest(
    head: Option<&HeadInfo>,
    keyring: Option<&crate::e2e::Keyring>,
    workspace_id: &str,
) -> Result<Manifest, PushError> {
    let Some(head) = head else {
        return Ok(Manifest::new(workspace_id.to_string()));
    };
    let fatal = |msg: String| PushError::Other(anyhow::Error::new(RelayError::Fatal(msg)));
    let manifest = match (head.e2e, keyring) {
        (true, Some(keyring)) => {
            let enc = head
                .manifest_enc
                .as_deref()
                .ok_or_else(|| fatal("the relay's e2e head carries no manifest_enc".to_string()))?;
            crate::e2e::decrypt_manifest(keyring, enc)
                .map_err(|e| fatal(format!("cannot decrypt the relay's e2e head: {e:#}")))?
        }
        (false, None) => head.manifest.clone(),
        (true, None) => {
            return Err(fatal(format!(
                "workspace {workspace_id} is end-to-end encrypted; this device needs its \
                 workspace key"
            )));
        }
        (false, Some(_)) => {
            return Err(fatal(format!(
                "workspace {workspace_id} is not end-to-end encrypted; refusing to converge \
                 it with a workspace key"
            )));
        }
    };
    manifest::validate(&manifest).map_err(|e| fatal(format!("invalid manifest from relay: {e:#}")))?;
    if manifest.workspace_id != workspace_id {
        return Err(fatal(format!(
            "relay head belongs to workspace {}, this device is {workspace_id}",
            manifest.workspace_id
        )));
    }
    Ok(manifest)
}

/// §28: a team that forbids `.env` sync refuses the whole cycle rather
/// than silently excluding files the product promise syncs. Deterministic,
/// so `Client` — the loop exits instead of retrying.
fn refuse_forbidden_dotenv(client: &RelayClient, local: &Manifest) -> Result<(), PushError> {
    let Some(team) = client.env_sync_forbidden_by() else {
        return Ok(());
    };
    let dotenv: Vec<&str> = local
        .files
        .keys()
        .filter(|p| crate::scan::is_dotenv(p))
        .map(String::as_str)
        .collect();
    if dotenv.is_empty() {
        return Ok(());
    }
    Err(PushError::Client(format!(
        "team {team} forbids .env sync — refusing to converge: the scan captures .env* files \
         ({}) — remove the .env files or ask a team owner to lift the policy \
         (`pear team policy {team} --env on`)",
        dotenv.join(", ")
    )))
}

/// Download the chunks the apply will read that the local store lacks.
/// Planning and wire-verification are the mirror path's (§23/§30): batch
/// by file, verify every fetched chunk against its BLAKE3 name, and fail
/// BEFORE applying anything if the relay's pool cannot serve the head.
fn fetch_for_apply(
    client: &RelayClient,
    store: &LocalStore,
    out: &MergeOutcome,
) -> Result<(usize, u64), PushError> {
    let needed: Vec<(String, &FileEntry)> = out
        .apply_from_remote
        .added
        .iter()
        .chain(out.apply_from_remote.changed.iter())
        .map(|rel| (rel.clone(), &out.merged.files[rel]))
        // A local-only copy of a REMOTE loser is assembled from chunks
        // like any apply, but it is not in `merged`, so the diff above
        // never asks for it.
        .chain(
            out.conflicts
                .iter()
                .filter(|c| c.local_only && c.side == ConflictSide::Remote)
                .map(|c| (c.copy_path.clone(), &c.entry)),
        )
        .collect();
    if needed.is_empty() {
        return Ok((0, 0));
    }
    let batches = plan_fetch_batches(&needed);
    let need: Vec<String> = batches.iter().flatten().cloned().collect();
    let present = store.has_many(&need).map_err(anyhow::Error::new)?;
    let to_fetch: HashSet<&str> = need
        .iter()
        .zip(present)
        .filter_map(|(h, p)| (!p).then_some(h.as_str()))
        .collect();
    if to_fetch.is_empty() {
        return Ok((0, 0));
    }
    let listed: Vec<String> = to_fetch.iter().map(|h| (*h).to_string()).collect();
    let missing = client.chunks_missing(&listed).map_err(PushError::from_relay)?;
    if !missing.is_empty() {
        return Err(PushError::Other(anyhow!(
            "relay is missing {} chunk(s) the head references (e.g. {}): cannot converge",
            missing.len(),
            missing[0]
        )));
    }
    let mut fetched = 0usize;
    let mut bytes = 0u64;
    for batch in &batches {
        let fetch: Vec<String> = batch
            .iter()
            .filter(|h| to_fetch.contains(h.as_str()))
            .cloned()
            .collect();
        if fetch.is_empty() {
            continue;
        }
        for (hash, data) in client.get_chunks(&fetch).map_err(PushError::from_relay)? {
            if blake3::hash(&data).to_hex().as_str() != hash {
                return Err(PushError::Other(anyhow!(
                    "fetched chunk {hash} does not match its BLAKE3 content hash"
                )));
            }
            bytes += data.len() as u64;
            if store.put(&hash, &data).map_err(anyhow::Error::new)? {
                fetched += 1;
            }
        }
    }
    Ok((fetched, bytes))
}

/// What a materialization changed on disk.
#[derive(Debug, Default)]
pub(crate) struct Materialized {
    pub(crate) written: Vec<String>,
    pub(crate) deleted: Vec<String>,
    pub(crate) conflict_copies: Vec<String>,
}

/// Put the merge on disk. Takes a plain [`ChunkSource`], so it is testable
/// against a local store with no relay in sight.
///
/// `pre_push_base` is the remote head this merge ran against; it — not
/// `merged` — is what lands in `.pear/manifest.json` here (see
/// [`apply::apply_commit`]): the merged state becomes the converged base
/// only once the head publishing it is committed.
///
/// ORDER IS THE §32 INVARIANT: a converge never loses a byte of local user
/// data. A local file that lost its path is copied to its conflict-copy
/// name and fsynced FIRST, before the staged apply writes the remote
/// version over the original. Local losers are byte copies of a file that
/// is already on disk — no chunk source, no network, nothing that can fail
/// halfway and leave the only copy of the user's edit unwritten.
///
/// Losers under `.git` are preserved the same way but LOCALLY, under
/// `.pear/conflicts/<path> (conflict from …)`: a conflict copy inside a
/// repository is an invalid refname (`git fsck --strict` reports
/// `badRefName`), and `.pear` never enters a manifest, so these copies
/// stay on the device that made them. Each device keeps its own losing
/// side; the winner is still the one lineage in the repo.
pub(crate) fn materialize(
    root: &Path,
    local: &Manifest,
    pre_push_base: &Manifest,
    out: &MergeOutcome,
    chunks: &dyn ChunkSource,
) -> Result<Materialized> {
    let mut on_disk = local.clone();
    let mut conflict_copies = Vec::new();
    for copy in &out.conflicts {
        match (copy.local_only, copy.side) {
            // A `.git` loser never enters the manifest or the tree: it is
            // preserved under `.pear/conflicts/` on this device only.
            (true, ConflictSide::Local) => copy_local_loser(root, copy)?,
            (true, ConflictSide::Remote) => assemble_local_copy(root, copy, chunks)?,
            (false, ConflictSide::Local) => {
                copy_local_loser(root, copy)?;
                // The copy now exists with exactly the merged entry, so
                // the apply below sees no work for it.
                on_disk
                    .files
                    .insert(copy.copy_path.clone(), copy.entry.clone());
            }
            // An ordinary remote loser is plain remote content: the apply
            // assembles it from chunks with everything else.
            (false, ConflictSide::Remote) => {}
        }
        conflict_copies.push(copy.copy_path.clone());
    }

    let d = manifest::diff(&on_disk, &out.merged);
    if d.added.is_empty() && d.changed.is_empty() && d.deleted.is_empty() {
        return Ok(Materialized {
            conflict_copies,
            ..Default::default()
        });
    }
    let report = apply::apply_commit(root, &on_disk, &out.merged, chunks, pre_push_base)?;
    // Remote losers are assembled by the apply like any other add; report
    // them as conflict copies, not as ordinary remote content.
    let copies: HashSet<&str> = conflict_copies.iter().map(String::as_str).collect();
    Ok(Materialized {
        written: report
            .written
            .into_iter()
            .filter(|p| !copies.contains(p.as_str()))
            .collect(),
        deleted: report.deleted,
        conflict_copies,
    })
}

/// Copy the local loser's bytes to its conflict-copy name and make it
/// durable. `fs::copy` carries the mode across; the mtime is restored so
/// the next scan matches the entry the merge already published (a
/// local-only copy under `.pear/` is never scanned at all).
fn copy_local_loser(root: &Path, copy: &merge::ConflictCopy) -> Result<()> {
    let from = root.join(&copy.path);
    let to = conflict_dest(root, copy)?;
    fs::copy(&from, &to)
        .with_context(|| format!("preserve {} as {}", from.display(), to.display()))?;
    filetime::set_file_mtime(
        &to,
        filetime::FileTime::from_unix_time(
            copy.entry.mtime_secs,
            copy.entry.mtime_nanos.clamp(0, 999_999_999) as u32,
        ),
    )
    .with_context(|| format!("restore mtime on {}", to.display()))?;
    // Not deferred to the apply's group flush: the invariant is that this
    // copy is DURABLE before the remote version overwrites the original.
    fs::File::open(&to)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("fsync {}", to.display()))?;
    if let Some(parent) = to.parent() {
        manifest::sync_dir(parent);
    }
    Ok(())
}

/// Assemble a REMOTE loser that must not enter the tree (a `.git` path)
/// into its local-only conflict copy, straight from the chunk source —
/// the same assembly the staged apply does, without the staging dance:
/// nothing is being overwritten, and the device those bytes came from
/// preserves its own losing side itself, so a torn write here costs a
/// convenience copy, never the only copy of someone's work.
fn assemble_local_copy(
    root: &Path,
    copy: &merge::ConflictCopy,
    chunks: &dyn ChunkSource,
) -> Result<()> {
    use std::io::Write;
    let to = conflict_dest(root, copy)?;
    {
        let mut f = crate::fsutil::create_private_file(&to)
            .with_context(|| format!("create {}", to.display()))?;
        for hash in &copy.entry.chunks {
            let data = chunks
                .get(hash)
                .with_context(|| format!("fetch chunk {hash} for {}", copy.copy_path))?;
            f.write_all(&data)?;
        }
        f.sync_all()
            .with_context(|| format!("fsync {}", to.display()))?;
    }
    if let Some(parent) = to.parent() {
        manifest::sync_dir(parent);
    }
    Ok(())
}

/// Resolve a conflict copy's destination and prepare its directory: no
/// symlinked ancestor inside the tree (the copy path is derived from
/// network input), parents created, and `.pear/conflicts` owner-only like
/// the rest of `.pear` — a `.git` loser's bytes are as private as the
/// tree's.
fn conflict_dest(root: &Path, copy: &merge::ConflictCopy) -> Result<PathBuf> {
    let to = root.join(&copy.copy_path);
    crate::fsutil::ensure_real_ancestors(root, &to)?;
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if copy.local_only {
        let dir = root.join(merge::LOCAL_CONFLICT_DIR);
        crate::fsutil::set_private_dir(&dir)
            .with_context(|| format!("restrict {}", dir.display()))?;
    }
    Ok(to)
}

/// The converge commit point, matching the push/pull cycles': record the
/// head this device now holds (`remote.json`), then swap the converged
/// manifest pointer. §18/§25: the local store's deferred dirents are
/// flushed before either write, so nothing is called committed while the
/// chunks behind it are still only in the page cache.
fn commit(
    source: &Path,
    merged: &Manifest,
    seq: u64,
    hash: &str,
    store: &LocalStore,
) -> Result<(), PushError> {
    store.flush().map_err(|e| PushError::Other(e.into()))?;
    let state = serde_json::to_vec(&RemoteState {
        seq,
        hash: hash.to_string(),
        files_fingerprint: Some(fingerprint_files(&merged.files)),
    })
    .map_err(anyhow::Error::new)?;
    manifest::write_file_atomic(&remote_state_path(source), &state)?;
    manifest::write_atomic(&source.join(".pear").join("manifest.json"), merged)?;
    // §24: the commit landed, so chunks the converged manifest no longer
    // references are dead. A sweep failure warns and never fails the
    // converge — GC must not break convergence.
    let keep: HashSet<&str> = merged
        .files
        .values()
        .flat_map(|entry| entry.chunks.iter().map(String::as_str))
        .collect();
    if let Err(e) = store.sweep_unreferenced(&keep) {
        eprintln!("pear: local store sweep failed (retried after the next converge): {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk;
    use std::io::Write;

    const STAMP: &str = "2026-07-24 153000";

    struct Fixture {
        dir: tempfile::TempDir,
        store: LocalStore,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = LocalStore::open(dir.path().join(".pear").join("store")).unwrap();
            fs::create_dir_all(dir.path().join(".pear")).unwrap();
            Self { dir, store }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }

        /// Write `body` at `rel` with mtime `mtime`, and return the entry a
        /// scan would record for it.
        fn write(&self, rel: &str, body: &str, mtime: i64) -> FileEntry {
            let path = self.root().join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            drop(f);
            filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(mtime, 0)).unwrap();
            self.entry(body, mtime)
        }

        /// The entry for `body` WITHOUT putting it on disk, with its chunks
        /// stored (what a remote-only file looks like locally).
        fn entry(&self, body: &str, mtime: i64) -> FileEntry {
            let tmp = self.dir.path().join(".pear").join("entry.tmp");
            fs::write(&tmp, body.as_bytes()).unwrap();
            let mut chunks = Vec::new();
            for c in chunk::chunk_file(&tmp).unwrap() {
                let c = c.unwrap();
                self.store.put(&c.hash, &c.data).unwrap();
                chunks.push(c.hash);
            }
            fs::remove_file(&tmp).unwrap();
            FileEntry {
                size: body.len() as u64,
                mode: 0o644,
                mtime_secs: mtime,
                mtime_nanos: 0,
                chunks,
            }
        }

        fn read(&self, rel: &str) -> String {
            fs::read_to_string(self.root().join(rel)).unwrap()
        }
    }

    fn manifest(entries: &[(&str, FileEntry)]) -> Manifest {
        let mut m = Manifest::new("ws".into());
        for (path, entry) in entries {
            m.files.insert((*path).to_string(), entry.clone());
        }
        m
    }

    /// The §32 invariant, end to end on real files: the local edit loses
    /// the LWW race, the remote version lands at the path, and the local
    /// bytes survive under the conflict-copy name.
    #[test]
    fn local_loser_is_on_disk_before_the_remote_overwrites_it() {
        let fx = Fixture::new();
        let base_entry = fx.entry("base\n", 10);
        let local_entry = fx.write("notes.txt", "mine\n", 20);
        let remote_entry = fx.entry("theirs\n", 30);

        let base = manifest(&[("notes.txt", base_entry)]);
        let local = manifest(&[("notes.txt", local_entry)]);
        let remote = manifest(&[("notes.txt", remote_entry)]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);

        let done = materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        let copy = format!("notes (conflict from laptop {STAMP}).txt");
        assert_eq!(done.conflict_copies, vec![copy.clone()]);
        assert_eq!(fx.read("notes.txt"), "theirs\n", "the winner is at the path");
        assert_eq!(fx.read(&copy), "mine\n", "the local edit survives");
        // The copy's mtime matches the entry the merge published, so the
        // next scan does not see it as a fresh change.
        let md = fs::metadata(fx.root().join(&copy)).unwrap();
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&md).unix_seconds(),
            20
        );
    }

    /// The remote loser has no local bytes: it is assembled from chunks by
    /// the ordinary staged apply.
    #[test]
    fn remote_loser_is_assembled_from_chunks() {
        let fx = Fixture::new();
        let base_entry = fx.entry("base\n", 10);
        let local_entry = fx.write("notes.txt", "mine\n", 40);
        let remote_entry = fx.entry("theirs\n", 30);

        let base = manifest(&[("notes.txt", base_entry)]);
        let local = manifest(&[("notes.txt", local_entry)]);
        let remote = manifest(&[("notes.txt", remote_entry)]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);

        let done = materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        let copy = format!("notes (conflict from remote {STAMP}).txt");
        assert_eq!(done.conflict_copies, vec![copy.clone()]);
        assert_eq!(fx.read("notes.txt"), "mine\n", "our newer edit wins");
        assert_eq!(fx.read(&copy), "theirs\n");
        assert!(
            done.written.is_empty(),
            "a conflict copy is not reported as ordinary remote content"
        );
    }

    /// The `.git` rule on real files: neither side's conflict copy lands
    /// in the repository (it would be an invalid refname) — the loser's
    /// bytes go to `.pear/conflicts/`, which never syncs, while the winner
    /// alone holds the contested path.
    #[test]
    fn git_losers_are_preserved_outside_the_repository() {
        let fx = Fixture::new();
        // Our ref loses to a newer remote one; the remote's HEAD loses to
        // our newer one — both directions in one merge.
        let base_ref = fx.entry("base-ref\n", 10);
        let local_ref = fx.write(".git/refs/heads/main", "mine-ref\n", 20);
        let remote_ref = fx.entry("theirs-ref\n", 30);
        let base_head = fx.entry("base-head\n", 10);
        let local_head = fx.write(".git/HEAD", "mine-head\n", 40);
        let remote_head = fx.entry("theirs-head\n", 30);

        let base = manifest(&[
            (".git/refs/heads/main", base_ref),
            (".git/HEAD", base_head),
        ]);
        let local = manifest(&[
            (".git/refs/heads/main", local_ref),
            (".git/HEAD", local_head),
        ]);
        let remote = manifest(&[
            (".git/refs/heads/main", remote_ref),
            (".git/HEAD", remote_head),
        ]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);

        let done = materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        let ref_copy =
            format!(".pear/conflicts/.git/refs/heads/main (conflict from laptop {STAMP})");
        let head_copy = format!(".pear/conflicts/.git/HEAD (conflict from remote {STAMP})");
        assert_eq!(done.conflict_copies, vec![head_copy.clone(), ref_copy.clone()]);

        // Winners hold the contested paths, in one lineage each.
        assert_eq!(fx.read(".git/refs/heads/main"), "theirs-ref\n");
        assert_eq!(fx.read(".git/HEAD"), "mine-head\n");
        // Both losers survive — ours copied from disk, theirs assembled
        // from chunks — outside the repository.
        assert_eq!(fx.read(&ref_copy), "mine-ref\n");
        assert_eq!(fx.read(&head_copy), "theirs-head\n");
        // Nothing extra landed inside `.git`: the ref directory holds the
        // one ref, not a copy beside it.
        let refs: Vec<String> = std::fs::read_dir(fx.root().join(".git/refs/heads"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(refs, vec!["main".to_string()]);
        assert!(!done.written.iter().any(|p| p.starts_with(".pear/")));
    }

    #[test]
    fn remote_adds_and_deletes_are_applied() {
        let fx = Fixture::new();
        let keep = fx.write("keep.txt", "keep\n", 10);
        let gone = fx.write("gone.txt", "gone\n", 10);
        let added = fx.entry("new\n", 30);

        let base = manifest(&[("keep.txt", keep.clone()), ("gone.txt", gone.clone())]);
        let local = base.clone();
        let remote = manifest(&[("keep.txt", keep), ("added.txt", added)]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);

        let done = materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        assert_eq!(done.written, vec!["added.txt"]);
        assert_eq!(done.deleted, vec!["gone.txt"]);
        assert_eq!(fx.read("added.txt"), "new\n");
        assert!(!fx.root().join("gone.txt").exists());
        assert_eq!(fx.read("keep.txt"), "keep\n");
    }

    /// Until the head that publishes `merged` is committed,
    /// `.pear/manifest.json` must hold the remote head the merge ran
    /// against — never `merged` (see [`apply::apply_commit`]).
    #[test]
    fn the_converged_base_stays_at_the_remote_head_until_the_push_lands() {
        let fx = Fixture::new();
        let local_entry = fx.write("mine.txt", "mine\n", 20);
        let remote_entry = fx.entry("theirs\n", 30);

        let base = manifest(&[]);
        let local = manifest(&[("mine.txt", local_entry)]);
        let remote = manifest(&[("theirs.txt", remote_entry)]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);
        materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();

        let committed = manifest::load(&fx.root().join(".pear").join("manifest.json"))
            .unwrap()
            .expect("the apply committed a pointer");
        assert_eq!(
            committed.files, remote.files,
            "an unpublished merge must not become the converged base"
        );
        // Re-merging from that base keeps the local file: the crash window
        // cannot let the older head delete an unpublished edit.
        let again = merge::merge(&committed, &out.merged, &remote, "laptop", STAMP);
        assert!(again.merged.files.contains_key("mine.txt"));
        assert!(again.conflicts.is_empty());
    }

    #[test]
    fn a_merge_with_nothing_to_do_touches_nothing() {
        let fx = Fixture::new();
        let entry = fx.write("f.txt", "same\n", 10);
        let m = manifest(&[("f.txt", entry)]);
        let out = merge::merge(&m, &m, &m, "laptop", STAMP);
        let done = materialize(fx.root(), &m, &m, &out, &fx.store).unwrap();
        assert!(done.written.is_empty() && done.deleted.is_empty());
        assert!(done.conflict_copies.is_empty());
        assert!(
            !fx.root().join(".pear").join("manifest.json").exists(),
            "a no-op materialization does not move the manifest pointer"
        );
    }

    /// Delete-vs-edit, both directions, on real files.
    #[test]
    fn edit_beats_delete_on_disk() {
        let fx = Fixture::new();
        // Local deleted the file, remote edited it: it comes back.
        let base_entry = fx.entry("base\n", 10);
        let remote_entry = fx.entry("theirs\n", 30);
        let base = manifest(&[("f.txt", base_entry.clone())]);
        let local = manifest(&[]);
        let remote = manifest(&[("f.txt", remote_entry)]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);
        materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        assert_eq!(fx.read("f.txt"), "theirs\n");

        // Local edited, remote deleted: the file stays, untouched.
        let local_entry = fx.write("g.txt", "mine\n", 20);
        let base = manifest(&[("g.txt", base_entry)]);
        let local = manifest(&[("g.txt", local_entry)]);
        let remote = manifest(&[]);
        let out = merge::merge(&base, &local, &remote, "laptop", STAMP);
        let done = materialize(fx.root(), &local, &remote, &out, &fx.store).unwrap();
        assert_eq!(fx.read("g.txt"), "mine\n");
        assert!(done.deleted.is_empty());
    }
}
