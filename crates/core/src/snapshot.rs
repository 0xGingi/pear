//! Snapshots (§12): `pear snapshot` preserves the local tree as an
//! immutable snapshot on the relay — head-synced or not — and
//! `pear clone` materializes a snapshot into a fresh directory with a new
//! workspace id (forked lineage, §6). Snapshotting unsynced state is the
//! divergent-snapshot answer to force takeovers and the lost-response
//! wedge (§10).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::{self, Manifest};
use crate::relay::{RelayClient, RelayError};
use crate::store::{ChunkSink, LocalStore};
use crate::sync::{scan_build_manifest, BatchUploader, Uploader};
use crate::{apply, init_workspace, load_workspace};

/// Outcome of `push_snapshot`.
#[derive(Debug)]
pub struct SnapshotReport {
    pub id: u64,
    pub created_at: i64,
    pub files: usize,
    pub chunks_uploaded: usize,
    pub bytes_uploaded: u64,
    /// Directories the built-in name excludes or `pear.toml` `exclude`
    /// entries pruned during the capture — reported so the user knows
    /// what is NOT in the snapshot.
    pub excluded: Vec<String>,
}

/// Preserve the local tree as a snapshot on the relay (§12): the writer
/// pipeline (scan -> chunk -> upload only the chunks the relay is missing)
/// then `POST /snapshots`. Works on any pear workspace regardless of head
/// state — no lease, no CAS — which is exactly how unsynced state is
/// preserved before choosing mirror or force.
pub fn push_snapshot(
    source: &Path,
    client: &RelayClient,
    name: Option<&str>,
) -> Result<SnapshotReport> {
    push_snapshot_inner(source, client, name, None)
}

/// The e2e snapshot (§17/§20): chunks are encrypted under the keyring's
/// newest generation before upload, and the snapshot commits the encrypted
/// manifest plus the ciphertext chunk list — same trust boundary as the
/// e2e head.
pub fn push_snapshot_e2e(
    source: &Path,
    client: &RelayClient,
    name: Option<&str>,
    keyring: &crate::e2e::Keyring,
) -> Result<SnapshotReport> {
    push_snapshot_inner(source, client, name, Some(keyring))
}

fn push_snapshot_inner(
    source: &Path,
    client: &RelayClient,
    name: Option<&str>,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> Result<SnapshotReport> {
    if !source.is_dir() {
        bail!("source {} is not a directory", source.display());
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;
    // A snapshot must belong to an existing workspace: never mint one here,
    // or a typo'd path would silently fork the workspace id.
    let Some(meta) = load_workspace(&source)? else {
        bail!(
            "{} is not a pear workspace; run `pear init` first",
            source.display()
        );
    };
    // A snapshot is stored under the client's workspace: refuse a mismatch
    // here rather than let the relay's 400 say it worse.
    if meta.id != client.workspace_id() {
        bail!(
            "local workspace {} does not match relay workspace {}",
            meta.id,
            client.workspace_id()
        );
    }

    let mut uploader = match e2e_key {
        Some(keyring) => Uploader::E2e(crate::sync::E2eUploader::new(
            client,
            *keyring.newest().1,
        )?),
        None => Uploader::Plain(BatchUploader::new(client)),
    };
    // Strict: a preservation snapshot is complete or fails — never
    // silently omit files (§12).
    let build = scan_build_manifest(&source, client, true, |path| {
        uploader
            .upload_file(path)
            .with_context(|| format!("chunk {}", path.display()))
    })?;

    // The uploader batches flushes by threshold: the final buffered
    // chunks go out before the snapshot may reference them.
    uploader.flush()?;
    let not_found = || {
        anyhow!(
            "relay has no workspace {}; create it with `pear watch --relay` first",
            client.workspace_id()
        )
    };
    let commit = match e2e_key {
        Some(keyring) => {
            let manifest_enc = crate::e2e::encrypt_manifest(keyring, &build.new)?;
            let chunk_hashes = crate::e2e::manifest_chunk_hashes(&build.new);
            client
                .create_snapshot_e2e(name, &manifest_enc, &chunk_hashes)
                .map_err(|e| match e {
                    RelayError::NotFound(_) => not_found(),
                    other => anyhow::Error::new(other),
                })?
        }
        None => client
            .create_snapshot(name, &build.new)
            .map_err(|e| match e {
                RelayError::NotFound(_) => not_found(),
                other => anyhow::Error::new(other),
            })?,
    };
    // Deliberately no local state writes: `.pear/manifest.json` is the
    // writer's last-committed state for the push gate (sync.rs), and a
    // snapshot is not a head commit. The next cycle pays a one-time
    // re-chunk for it; `.pear/remote.json` stays untouched too.

    Ok(SnapshotReport {
        id: commit.id,
        created_at: commit.created_at,
        files: build.new.files.len(),
        chunks_uploaded: uploader.uploaded(),
        bytes_uploaded: uploader.bytes(),
        excluded: build.excluded,
    })
}

/// What a clone records about its provenance in `.pear/origin.json` (§12):
/// the source workspace, the snapshot, and when the clone happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneOrigin {
    pub workspace_id: String,
    pub snapshot_id: u64,
    pub name: Option<String>,
    pub cloned_at: i64,
}

/// Outcome of `clone_from_snapshot`.
#[derive(Debug)]
pub struct CloneReport {
    /// The clone's own workspace id — fresh, never the source's (forked
    /// lineage).
    pub workspace_id: String,
    pub files_written: usize,
    pub chunks_fetched: usize,
    pub bytes_fetched: u64,
}

/// Materialize a snapshot into `target` as a NEW workspace (§12): fetch
/// the snapshot, batch-check and fetch its chunks into the clone's
/// `.pear/store`, apply with the M1 engine, and record provenance in
/// `.pear/origin.json`. Clone never registers, mirrors, or pushes.
pub fn clone_from_snapshot(
    target: &Path,
    client: &RelayClient,
    snapshot_id: u64,
) -> Result<CloneReport> {
    clone_inner(target, client, snapshot_id, None)
}

/// The e2e clone (§17/§20): the snapshot's encrypted manifest is decrypted
/// under the keyring (newest generation first — a snapshot taken before a
/// rotation still reads) and validated, its ciphertext chunks are fetched
/// (hash-verified) and applied through the decrypting chunk source.
/// Everything else — forked lineage, provenance — is the plaintext
/// clone's, unchanged.
pub fn clone_from_snapshot_e2e(
    target: &Path,
    client: &RelayClient,
    snapshot_id: u64,
    keyring: &crate::e2e::Keyring,
) -> Result<CloneReport> {
    clone_inner(target, client, snapshot_id, Some(keyring))
}

fn clone_inner(
    target: &Path,
    client: &RelayClient,
    snapshot_id: u64,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> Result<CloneReport> {
    // Fetch and validate before any filesystem side effect.
    let snapshot = client.get_snapshot(snapshot_id).map_err(|e| match e {
        RelayError::NotFound(what) => anyhow!("not found: {what}"),
        other => anyhow::Error::new(other),
    })?;
    // §17 flavor pinning: an e2e snapshot requires its workspace key, a
    // plaintext snapshot must not be read as e2e — no downgrade either way.
    match (&snapshot.manifest_enc, &e2e_key) {
        (Some(_), None) => bail!(
            "snapshot {snapshot_id} is end-to-end encrypted; fetch the workspace key first \
             (re-run with --name <name> so pear can unwrap your key)"
        ),
        (None, Some(_)) => bail!(
            "snapshot {snapshot_id} is not end-to-end encrypted; refusing to clone it with a workspace key"
        ),
        _ => {}
    }
    // The manifest is network input: validate before it touches disk, and
    // refuse a snapshot that belongs to a different workspace than the one
    // the client targets. (E2E: decrypted under the keyring first —
    // client-side validation is a MUST, the relay cannot see the paths.)
    let decrypted;
    let wire_ref = match e2e_key {
        Some(keyring) => {
            decrypted = crate::e2e::decrypt_manifest(
                keyring,
                snapshot
                    .manifest_enc
                    .as_deref()
                    .expect("flavor checked above"),
            )
            .context("cannot decrypt the snapshot's manifest")?;
            &decrypted
        }
        None => &snapshot.manifest,
    };
    manifest::validate(wire_ref).context("invalid manifest from relay")?;
    if wire_ref.workspace_id != client.workspace_id() {
        bail!(
            "snapshot {snapshot_id} belongs to workspace {}, but the client targets {}",
            wire_ref.workspace_id,
            client.workspace_id()
        );
    }
    let wire = wire_ref.clone();

    // Refusal checks BEFORE any filesystem side effect: a rejected clone
    // must not leave even a freshly created empty directory behind.
    // Forked lineage: a clone is always a NEW workspace, never a silent
    // re-target of an existing one — and never into a directory that
    // already has content: apply would overwrite colliding files.
    if load_workspace(target)?.is_some() {
        bail!(
            "{} is already a pear workspace; clone needs a fresh directory",
            target.display()
        );
    }
    if fs::read_dir(target).is_ok_and(|mut entries| entries.next().is_some()) {
        bail!(
            "{} is not empty; clone needs a fresh directory",
            target.display()
        );
    }

    fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    let target = target
        .canonicalize()
        .with_context(|| format!("canonicalize {}", target.display()))?;
    let (meta, _) = init_workspace(&target, None)?;
    // E2E: cache the keyring the clone was onboarded with (§17), so
    // later e2e reads from this directory skip the fetch+unwrap round trip.
    if let Some(keyring) = e2e_key {
        crate::e2e::store_workspace_keyring(&target, keyring)?;
    }
    clone_apply(&target, client, &wire, &snapshot.info, &meta, e2e_key).inspect_err(|_| {
        // The target was empty before we started, so everything in it now
        // is ours: remove it all. A mid-apply failure can leave partial
        // files behind, not just `.pear`, and leftovers would block the
        // retry this cleanup exists to enable.
        if let Ok(entries) = fs::read_dir(&target) {
            for entry in entries.flatten() {
                let path = entry.path();
                let _ = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
            }
        }
    })
}

/// The post-init body of a clone, so any failure can clean up `.pear`
/// whole (see above).
fn clone_apply(
    target: &Path,
    client: &RelayClient,
    wire: &Manifest,
    info: &crate::relay::SnapshotInfo,
    meta: &crate::WorkspaceMeta,
    e2e_key: Option<&crate::e2e::Keyring>,
) -> Result<CloneReport> {
    let store = LocalStore::open(target.join(".pear").join("store"))?;

    // Fetch every chunk the snapshot references and the clone lacks
    // locally. Fail before applying anything if the relay's pool cannot
    // serve the snapshot — never mid-apply. (E2E: ciphertext hashes and
    // ciphertext bytes — the same content-addressing check applies.)
    let mut need: Vec<String> = Vec::new();
    let mut need_seen: HashSet<&str> = HashSet::new();
    for entry in wire.files.values() {
        for hash in &entry.chunks {
            if need_seen.insert(hash.as_str()) {
                need.push(hash.clone());
            }
        }
    }
    let mut chunks_fetched = 0usize;
    let mut bytes_fetched = 0u64;
    if !need.is_empty() {
        let present = store.has_many(&need)?;
        let to_fetch: Vec<String> = need
            .into_iter()
            .zip(present)
            .filter_map(|(h, p)| (!p).then_some(h))
            .collect();
        if !to_fetch.is_empty() {
            let missing = client.chunks_missing(&to_fetch)?;
            if !missing.is_empty() {
                bail!(
                    "relay is missing {} chunk(s) the snapshot references (e.g. {}): cannot clone",
                    missing.len(),
                    missing[0]
                );
            }
            for hash in &to_fetch {
                let data = client.get_chunk(hash)?;
                // Content addressing is the integrity check on the wire:
                // wrong bytes must never enter the store.
                if blake3::hash(&data).to_hex().as_str() != hash {
                    bail!("fetched chunk {hash} does not match its BLAKE3 content hash");
                }
                bytes_fetched += data.len() as u64;
                if store.put(hash, &data)? {
                    chunks_fetched += 1;
                }
            }
        }
    }

    // Apply with the M1 engine onto an empty base. The clone's local
    // manifest carries the clone's own workspace id from here on — the
    // file set is the snapshot's, the lineage is not. Modes are masked
    // to what apply actually materializes (no setuid bits, §15), so the
    // recorded manifest matches the disk and a later scan sees no
    // phantom change. (E2E: apply reads ciphertext, decrypts on the fly.)
    let mut new_manifest = wire.clone();
    new_manifest.workspace_id = meta.id.clone();
    for entry in new_manifest.files.values_mut() {
        entry.mode &= 0o777;
    }
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
    let report = apply::apply(
        target,
        &Manifest::new(meta.id.clone()),
        &new_manifest,
        source,
    )?;

    let origin = CloneOrigin {
        workspace_id: client.workspace_id().to_string(),
        snapshot_id: info.id,
        name: info.name.clone(),
        cloned_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    manifest::write_file_atomic(
        &target.join(".pear").join("origin.json"),
        &serde_json::to_vec_pretty(&origin)?,
    )?;

    Ok(CloneReport {
        workspace_id: meta.id.clone(),
        files_written: report.written.len(),
        chunks_fetched,
        bytes_fetched,
    })
}
