//! E2E workspace-key management and manifest envelope (DESIGN.md §17/§20).
//!
//! §20: the workspace key is a KEYRING of generations, stored at
//! `.pear/workspace_keys` (0600 JSON `{gen: key_hex}`; the `.pear` dir
//! never syncs). Generation 1 IS the pre-§20 single key: a legacy
//! `.pear/workspace_key` file (32 raw bytes) or a 32-byte legacy wrap blob
//! migrates to `{1: key}` on load — no operator action. Writes encrypt
//! under the NEWEST generation only; reads try newest → oldest and let the
//! AEAD tag disambiguate, so a rotation re-uploads nothing (unchanged
//! files keep their ciphertext) and current members keep full history.
//!
//! The writer generates the keyring at the first E2E push and wraps it —
//! the whole ring, every generation — to every team member's registered
//! X25519 pubkey; the relay stores only the opaque wrap blobs. A
//! mirror/clone onboards by fetching its wrap (`GET keys/me`) and
//! unwrapping it with the local user keypair (`~/.pear/keys/<name>.x25519`),
//! then caching the keyring 0600 for next time. §19 restricts who gets
//! wrapped to: members whose signed key bundle verifies and matches the
//! writer-side `known_keys` pin. §20's rotation-maintenance additionally
//! compares the team against `.pear/wrapped_members.json` at loop start:
//! a VANISHED member rotates the ring and loses their wrap row; a pure
//! addition never rotates (new members receive the full history). §32
//! makes every writer device run that pass, so a rotation first MERGES
//! the relay's copy of this device's own wrapped ring into the local one
//! (relay wins a same-generation mismatch) and only then mints
//! `max(generation) + 1` — concurrent writers extend one ring instead of
//! forking a generation number.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroize;

use crate::crypto;
use crate::known_keys;
use crate::manifest::Manifest;
use crate::relay::{RelayClient, RelayError};
use crate::store::{ChunkSource, LocalStore};

/// The workspace keyRING (§20): every key generation the workspace has
/// ever used, keyed by generation number. Writes use the NEWEST generation
/// only; reads try newest → oldest. Rings stay small — one entry per
/// member removal in the workspace's history. The keys are zeroized on
/// drop and redacted from `Debug`, like the user keypairs'.
#[derive(Clone, PartialEq, Eq)]
pub struct Keyring {
    keys: BTreeMap<u32, [u8; 32]>,
}

impl Keyring {
    /// A keyring holding exactly one key, at generation 1 — every legacy
    /// single-key workspace is this (§20: gen 1 = the pre-§20 key).
    pub fn from_legacy(key: [u8; 32]) -> Self {
        Self {
            keys: BTreeMap::from([(1, key)]),
        }
    }

    /// The newest generation and its key — what every write encrypts
    /// under. (Construction and loads enforce a non-empty ring.)
    pub fn newest(&self) -> (u32, &[u8; 32]) {
        let (gen, key) = self.keys.iter().next_back().expect("a keyring is never empty");
        (*gen, key)
    }

    /// Rotate to a fresh generation: insert a new random key at newest+1
    /// and return the new generation number. Old generations stay in the
    /// ring — existing ciphertext must keep decrypting (§20: no history
    /// loss for current members).
    pub fn rotate(&mut self) -> u32 {
        let next = self.newest().0 + 1;
        self.keys.insert(next, rand::random());
        next
    }

    /// Union `other`'s generations into this ring (§32's merge-before-
    /// rotate): a generation this ring LACKS is adopted, and on a
    /// same-generation key MISMATCH `other` wins — the relay's wrapped
    /// copy is canonical, so two devices that forked a generation
    /// number converge on one key instead of stranding each other's
    /// ciphertext. Returns the generations this ring gained or replaced,
    /// ascending (empty = the rings already agreed).
    pub fn union_from(&mut self, other: &Keyring) -> Vec<u32> {
        let mut adopted = Vec::new();
        for (gen, key) in &other.keys {
            match self.keys.get_mut(gen) {
                Some(mine) if mine == key => continue,
                Some(mine) => {
                    // A ring holds ONE key per generation, so the local
                    // branch's key is dropped. §32 makes the relay's copy
                    // canonical exactly so that every device drops the
                    // same side of a forked generation.
                    mine.zeroize();
                    *mine = *key;
                }
                None => {
                    self.keys.insert(*gen, *key);
                }
            }
            adopted.push(*gen);
        }
        adopted
    }

    /// Run `attempt` against each generation, NEWEST first, returning the
    /// first success. The AEAD tag is the disambiguator: a blob sealed
    /// under generation N fails cleanly under every other key, so "every
    /// generation failed" means corrupt data — or a generation this ring
    /// lacks, e.g. a removed member's stale ring facing post-removal
    /// content (§20's cutoff).
    pub fn decrypt<T>(&self, what: &str, attempt: impl Fn(&[u8; 32]) -> Result<T>) -> Result<T> {
        let mut last = None;
        for key in self.keys.values().rev() {
            match attempt(key) {
                Ok(value) => return Ok(value),
                Err(e) => last = Some(e),
            }
        }
        match last {
            Some(e) => Err(e.context(format!(
                "{what} does not decrypt under any of this keyring's {} generation(s)",
                self.keys.len()
            ))),
            None => Err(anyhow!("{what}: the keyring is empty")),
        }
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Generations only — the keys are secret.
        f.debug_struct("Keyring")
            .field("generations", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// The on-disk and on-wire keyring encoding (§20): a JSON object mapping
/// generation number to the key's lowercase hex — `{"1":"ab…","2":"cd…"}`.
/// A `BTreeMap<u32, String>` serializes to exactly that (JSON object keys
/// are strings). This is BOTH the `.pear/workspace_keys` file content and
/// the member wrap payload: a member always receives the full history.
fn keyring_json(keyring: &Keyring) -> Result<Vec<u8>> {
    let hexed: BTreeMap<u32, String> = keyring
        .keys
        .iter()
        .map(|(gen, key)| (*gen, crypto::hex_encode(key)))
        .collect();
    Ok(serde_json::to_vec(&hexed)?)
}

/// Parse a `{gen: key_hex}` JSON keyring. Garbage, an empty map, generation
/// 0, and non-32-byte keys are all errors, never panics: this decodes both
/// local files and relay-served wrap payloads — corrupt or hostile input.
fn keyring_from_json(bytes: &[u8]) -> Result<Keyring> {
    let hexed: BTreeMap<u32, String> =
        serde_json::from_slice(bytes).context("not a {generation: key_hex} keyring")?;
    let mut keys = BTreeMap::new();
    for (gen, hex) in &hexed {
        if *gen == 0 {
            bail!("generation 0 is invalid: key generations start at 1");
        }
        let mut raw = crypto::hex_decode(hex)
            .with_context(|| format!("generation {gen}'s key is not hex"))?;
        let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            anyhow!(
                "generation {gen} holds {} bytes; a workspace key is exactly 32",
                raw.len()
            )
        })?;
        raw.zeroize();
        keys.insert(*gen, key);
    }
    if keys.is_empty() {
        bail!("a keyring holds at least one generation");
    }
    Ok(Keyring { keys })
}

/// Decode an unwrapped wrap payload (§20): exactly 32 bytes is a legacy
/// pre-§20 single-key wrap and migrates to `{1: key}`; anything else must
/// be the JSON keyring map. Garbage is an error, never a panic.
fn keyring_from_wrap_payload(bytes: &[u8]) -> Result<Keyring> {
    if bytes.len() == 32 {
        let key: [u8; 32] = bytes.try_into().expect("length checked");
        return Ok(Keyring::from_legacy(key));
    }
    keyring_from_json(bytes)
}

/// `<workspace>/.pear/workspace_keys` — the keyring's home (0600 JSON).
fn keys_path(root: &Path) -> PathBuf {
    root.join(".pear").join("workspace_keys")
}

/// `<workspace>/.pear/workspace_key` — the pre-§20 single-key file, still
/// read as the `{1: key}` keyring when no keyring file exists.
fn legacy_key_path(root: &Path) -> PathBuf {
    root.join(".pear").join("workspace_key")
}

/// The locally stored keyring, if this device has one. The keyring file
/// wins; a legacy single-key file migrates to `{1: key}` on load (§20: no
/// operator action). Owner-only like an SSH private key; a loose mode,
/// corrupt JSON, or a wrong length is an error, never a silent re-key.
pub fn load_workspace_keyring(root: &Path) -> Result<Option<Keyring>> {
    let path = keys_path(root);
    if path.exists() {
        let bytes = crypto::read_private(&path)?;
        return keyring_from_json(&bytes)
            .with_context(|| format!("parse {}", path.display()))
            .map(Some);
    }
    let legacy = legacy_key_path(root);
    if !legacy.exists() {
        return Ok(None);
    }
    let bytes = crypto::read_private(&legacy)?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "{} holds {} bytes; a workspace key is exactly 32",
            legacy.display(),
            bytes.len()
        )
    })?;
    Ok(Some(Keyring::from_legacy(key)))
}

/// The writer side (first E2E push, §17): the local keyring when present,
/// a fresh generation-1 ring written 0600 otherwise. Only the writer may
/// call this — generating a NEW key on a device that simply lacks one
/// would fork the encryption (the new key cannot decrypt existing heads),
/// so every non-writer path goes through `load_workspace_keyring` /
/// `workspace_key_for_reader` instead.
pub fn load_or_create_workspace_keyring(root: &Path) -> Result<Keyring> {
    if let Some(keyring) = load_workspace_keyring(root)? {
        return Ok(keyring);
    }
    let keyring = Keyring::from_legacy(rand::random());
    store_workspace_keyring(root, &keyring)?;
    Ok(keyring)
}

/// Write the keyring 0600 as `.pear/workspace_keys`, creating the `.pear`
/// dir owner-only when needed (init has always run by the time keys are
/// stored). The legacy single-key file is then removed best-effort: the
/// keyring file shadows it on every load, and one source of truth on disk
/// keeps a stale legacy key from ever being mistaken for current state.
pub fn store_workspace_keyring(root: &Path, keyring: &Keyring) -> Result<()> {
    let path = keys_path(root);
    let pear_dir = path.parent().expect("keys_path always has a parent");
    fs::create_dir_all(pear_dir).with_context(|| format!("create {}", pear_dir.display()))?;
    crate::fsutil::set_private_dir(pear_dir)?;
    crypto::write_private_0600(&path, &keyring_json(keyring)?)?;
    let _ = fs::remove_file(legacy_key_path(root));
    Ok(())
}

/// The reader side (mirror onboarding, §17): the local keyring file when
/// present; otherwise fetch + unwrap + store as below.
pub fn workspace_key_for_reader(
    root: &Path,
    client: &RelayClient,
    keys_dir: &Path,
    name: Option<&str>,
) -> Result<Keyring> {
    if let Some(keyring) = load_workspace_keyring(root)? {
        return Ok(keyring);
    }
    let keyring = fetch_and_unwrap_workspace_key(client, keys_dir, name)?;
    store_workspace_keyring(root, &keyring)?;
    Ok(keyring)
}

/// Fetch the caller's wrap from the relay (`GET keys/me`) and unwrap it
/// with the local user keypair `name` from `keys_dir` — pure: nothing is
/// stored (the fork-clone stores it itself after init, so a refused clone
/// keeps its no-side-effects guarantee). The failure modes are spelled
/// out for the operator: a missing local identity says to `pear user
/// keygen` first; a missing wrap says the writer must re-run join/share
/// AFTER the user keygenned.
pub fn fetch_and_unwrap_workspace_key(
    client: &RelayClient,
    keys_dir: &Path,
    name: Option<&str>,
) -> Result<Keyring> {
    let name = name.ok_or_else(|| {
        anyhow!(
            "workspace {} is end-to-end encrypted and this device has no key for it yet; \
             re-run with --name <name> — the user name you enrolled with `pear user keygen --name <name>`",
            client.workspace_id()
        )
    })?;
    let keypair = local_user_keypair(keys_dir, name)?;
    let blob_hex = client.get_my_wrapped_key().map_err(|e| match e {
        RelayError::NotFound(_) => anyhow!(
            "workspace {} is end-to-end encrypted but no key is wrapped for {name:?}: \
             the writer must run `pear join --relay <url> --e2e` (or `pear share --team <team>`) again \
             AFTER you registered your key with `pear user keygen --name {name}`",
            client.workspace_id()
        ),
        other => anyhow::Error::new(other),
    })?;
    unwrap_keyring(&keypair, &blob_hex, name)
}

/// The local user keypair `name` lives under `keys_dir`, with the operator
/// instruction spelled out when it does not.
fn local_user_keypair(keys_dir: &Path, name: &str) -> Result<crypto::UserKeypair> {
    let secret = crypto::user_keypair_export(keys_dir, name).map_err(|e| {
        anyhow!(
            "no usable identity key for {name:?} in {} ({e:#}); \
             run `pear user keygen --name {name} --relay <url>` first",
            keys_dir.join(format!("{name}.x25519")).display()
        )
    })?;
    Ok(crypto::UserKeypair::from_secret_bytes(secret))
}

/// Unwrap one relay-served wrap blob into the keyring it carries.
fn unwrap_keyring(keypair: &crypto::UserKeypair, blob_hex: &str, name: &str) -> Result<Keyring> {
    let blob = crypto::hex_decode(blob_hex).context("wrapped key from the relay is not hex")?;
    let mut payload = crypto::unwrap_key(keypair, &blob).with_context(|| {
        format!(
            "the wrapped key on the relay does not decrypt for {name:?} — the writer wrapped \
             for a different (stale?) pubkey; ask them to run `pear join --relay <url> --e2e` again"
        )
    })?;
    // §20: the payload is the serialized keyring; a 32-byte payload is a
    // legacy single-key wrap and migrates to `{1: key}`.
    let decoded = keyring_from_wrap_payload(&payload);
    payload.zeroize();
    decoded.context("the unwrapped payload is not a workspace keyring")
}

/// §32 merge-before-rotate: union the relay's copy of THIS user's wrapped
/// keyring into `keyring`, so a rotation mints `max(known generation) + 1`
/// rather than forking a generation number another device already used.
/// Returns the generations adopted (see [`Keyring::union_from`]) or, as
/// `Err` of the inner result, why the merge could not run at all — no
/// local identity to unwrap with, or no wrap row on the relay yet (the
/// first writer, or wraps not pushed). Both are ordinary states, so the
/// caller proceeds with the local ring; a relay or crypto failure is a
/// real error and propagates.
fn merge_relay_keyring(
    client: &RelayClient,
    keyring: &mut Keyring,
    keys_dir: &Path,
    name: Option<&str>,
) -> Result<Result<Vec<u32>, String>> {
    let Some(name) = name else {
        return Ok(Err(
            "this device has no --name identity to unwrap its own wrapped keyring with".to_string(),
        ));
    };
    let keypair = match local_user_keypair(keys_dir, name) {
        Ok(keypair) => keypair,
        Err(e) => return Ok(Err(format!("{e:#}"))),
    };
    let blob_hex = match client.get_my_wrapped_key() {
        Ok(blob_hex) => blob_hex,
        Err(RelayError::NotFound(_)) => {
            return Ok(Err(format!(
                "no keyring is wrapped for {name:?} on the relay yet"
            )))
        }
        Err(e) => return Err(anyhow::Error::new(e)),
    };
    let relay_ring = unwrap_keyring(&keypair, &blob_hex, name)?;
    Ok(Ok(keyring.union_from(&relay_ring)))
}

/// What a wrap-maintenance pass did (§17/§19).
#[derive(Debug, Default)]
pub struct WrapReport {
    /// Team members the workspace key was wrapped for: a valid signed
    /// bundle whose identity matches the pin (or was pinned at first
    /// sight this pass). Re-wrapping is idempotent and replaces.
    pub wrapped: Vec<String>,
    /// Team members skipped because they never registered a key at all;
    /// they onboard after `pear user keygen` plus the next writer refresh.
    pub skipped: Vec<String>,
    /// Team members with a legacy pre-§19 pubkey and no signed bundle:
    /// skipped ("re-run `pear user keygen` to sign your key"), never
    /// wrapped to again — their old wraps still unwrap (the X25519 key
    /// never moved), but nothing new is wrapped to an unsigned key.
    pub unsigned: Vec<String>,
    /// Team members whose served bundle does not decode or verify:
    /// skipped and reported as a SECURITY event (possible relay/key
    /// tampering); never wrapped to.
    pub bad_sig: Vec<String>,
    /// Team members with a valid bundle whose identity differs from the
    /// known_keys pin: skipped ("identity changed since first wrap; if
    /// expected, run `pear trust <user>`"). A pin is never updated
    /// implicitly on mismatch.
    pub pin_changed: Vec<String>,
    /// (user, ed25519 fingerprint) pairs pinned at first sight during this
    /// pass — the CLI prints them as an invitation to compare out-of-band.
    pub newly_pinned: Vec<(String, String)>,
}

/// How one team member's served key material classifies for
/// wrap-maintenance (§19). Pure: the relay's answer is hostile input, so
/// every malformed case is a bucket, never an error — one bad member must
/// never block the pass for the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MemberClass {
    /// No registered key at all.
    NoKey,
    /// Legacy pubkey-only row (no signed bundle).
    Unsigned,
    /// The bundle does not decode or its signature does not verify.
    BadSig,
    /// Valid bundle, but its identity differs from the pin.
    PinChanged,
    /// Valid bundle; wrap to this X25519 pubkey. `first_sight` = no pin
    /// existed, so this pass pins the identity.
    Wrap { x25519_pub: [u8; 32], first_sight: bool },
}

/// Classify one member against the pins (§19). Signature verification
/// re-runs here, writer-side: the relay enforced well-formedness at PUT,
/// but the whole point of the pin model is not to take the relay's word.
fn classify_member(member: &crate::relay::MemberInfo, pins: &known_keys::KnownKeys) -> MemberClass {
    let Some(pubkey_hex) = member.pubkey.as_deref() else {
        return MemberClass::NoKey;
    };
    let (Some(ed_hex), Some(sig_hex)) = (member.ed25519.as_deref(), member.sig.as_deref())
    else {
        return MemberClass::Unsigned;
    };
    let decode32 = |hex: &str| -> Option<[u8; 32]> {
        crypto::hex_decode(hex).ok()?.try_into().ok()
    };
    let (Some(x25519_pub), Some(ed_pub), Some(sig)) = (
        decode32(pubkey_hex),
        decode32(ed_hex),
        crypto::hex_decode(sig_hex)
            .ok()
            .and_then(|b| b.try_into().ok()),
    ) else {
        return MemberClass::BadSig;
    };
    if !crypto::ed_verify(&ed_pub, &crypto::bundle_statement(&member.user, &x25519_pub), &sig)
    {
        return MemberClass::BadSig;
    }
    match known_keys::check(pins, &member.user, ed_hex) {
        known_keys::PinCheck::Mismatch => MemberClass::PinChanged,
        known_keys::PinCheck::Match => MemberClass::Wrap {
            x25519_pub,
            first_sight: false,
        },
        known_keys::PinCheck::FirstSight => MemberClass::Wrap {
            x25519_pub,
            first_sight: true,
        },
    }
}

/// §17+§19+§20 writer wrap-maintenance, run at `pear join --relay --e2e`
/// startup and after `pear share`: every member of the workspace's
/// attached team whose SIGNED key bundle verifies and matches the
/// known_keys pin (`known_keys_path`) gets the keyring wrapped to them
/// (`PUT keys/:user`); first-sight identities are pinned. Members
/// without a key, with a legacy unsigned key, with a bad signature, or
/// with a changed pin are classified into their report buckets and never
/// wrapped to — the pass itself always succeeds on member data (relay/IO
/// errors still propagate). The pin file is saved once per pass, only when
/// first-sight pins changed it. A workspace with no attached team wraps
/// for no one (the writer's other devices onboard via `pear user`
/// export/import).
///
/// The wrap payload is the serialized keyring — one sealed box per member,
/// ALL generations included (§20: a member always receives the full
/// history; only a rotation + wrap-row deletion cuts a member off).
pub fn wrap_maintenance(
    client: &RelayClient,
    keyring: &Keyring,
    known_keys_path: &Path,
) -> Result<WrapReport> {
    let mut report = WrapReport::default();
    let Some(team_id) = client.get_workspace()?.team_id else {
        return Ok(report);
    };
    let mut payload = keyring_json(keyring)?;
    let mut pins = known_keys::load(known_keys_path)?;
    let mut pins_dirty = false;
    for member in client.team_members(&team_id)? {
        let x25519_pub = match classify_member(&member, &pins) {
            MemberClass::NoKey => {
                report.skipped.push(member.user);
                continue;
            }
            MemberClass::Unsigned => {
                report.unsigned.push(member.user);
                continue;
            }
            MemberClass::BadSig => {
                report.bad_sig.push(member.user);
                continue;
            }
            MemberClass::PinChanged => {
                report.pin_changed.push(member.user);
                continue;
            }
            MemberClass::Wrap {
                x25519_pub,
                first_sight,
            } => {
                if first_sight {
                    // The pin file is written once at the end of the pass;
                    // the fingerprint rides along for the CLI to print.
                    let ed_hex = member
                        .ed25519
                        .clone()
                        .expect("Wrap implies a full bundle");
                    known_keys::pin(&mut pins, &member.user, &ed_hex);
                    pins_dirty = true;
                    report.newly_pinned.push((member.user.clone(), ed_hex));
                }
                x25519_pub
            }
        };
        let blob = crypto::wrap_key(&payload, &x25519_pub)
            .with_context(|| format!("cannot wrap the workspace keyring for {:?}", member.user))?;
        client.put_wrapped_key(&member.user, &crypto::hex_encode(&blob))?;
        report.wrapped.push(member.user);
    }
    // The plaintext ring serialization held every key; drop it hard.
    payload.zeroize();
    if pins_dirty {
        known_keys::save(known_keys_path, &pins)?;
    }
    Ok(report)
}

/// The head/snapshot commit envelope (§17/§20): the manifest JSON
/// encrypted as one blob under the keyring's NEWEST generation (random
/// nonce — no dedup need), base64'd as `manifest_enc`.
pub fn encrypt_manifest(keyring: &Keyring, manifest: &Manifest) -> Result<String> {
    let json = serde_json::to_vec(manifest)?;
    Ok(crypto::base64_encode(&crypto::encrypt_blob(
        keyring.newest().1,
        &json,
    )))
}

/// Inverse of `encrypt_manifest` (§20): tried against every generation,
/// newest first — a head or snapshot committed before a rotation stays
/// readable. The base64 is relay-held and the ciphertext is only as
/// trustworthy as the keyring allows — both failure modes are errors,
/// never panics.
pub fn decrypt_manifest(keyring: &Keyring, manifest_enc: &str) -> Result<Manifest> {
    let blob = crypto::base64_decode(manifest_enc).context("manifest_enc is not valid base64")?;
    let json = keyring.decrypt("the encrypted manifest", |key| {
        crypto::decrypt_blob(key, &blob)
    })?;
    serde_json::from_slice(&json).context("the decrypted manifest is not a pear manifest")
}

/// Every ciphertext hash a manifest references, deduped and sorted — the
/// `chunk_hashes` list of an e2e head/snapshot commit.
pub fn manifest_chunk_hashes(manifest: &Manifest) -> Vec<String> {
    let set: std::collections::BTreeSet<String> = manifest
        .files
        .values()
        .flat_map(|entry| entry.chunks.iter().cloned())
        .collect();
    set.into_iter().collect()
}

/// A `ChunkSource` adapter for e2e mirrors/clones (§17/§20): the local
/// store holds ciphertext keyed by ciphertext hash; reads verify the
/// content hash, then decrypt under the keyring — newest generation first,
/// so chunks written before a rotation still read.
pub struct DecryptingSource<'a> {
    pub inner: &'a LocalStore,
    pub keyring: &'a Keyring,
}

impl ChunkSource for DecryptingSource<'_> {
    fn get(&self, hash: &str) -> io::Result<Vec<u8>> {
        let blob = self.inner.get(hash)?;
        // The store is content-addressed by ciphertext hash: verify before
        // trusting the bytes with the key (a poisoned local store must
        // fail the pull, not feed garbage into AES-GCM).
        if blake3::hash(&blob).to_hex().as_str() != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stored chunk {hash} does not match its BLAKE3 content hash"),
            ));
        }
        self.keyring
            .decrypt("stored chunk", |key| crypto::decrypt_chunk(key, &blob))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// `.pear/wrapped_members.json` — the team members the writer last wrapped
/// the keyring for: usernames only (no secrets, and the `.pear` dir is
/// 0700 anyway). §20's vanish detector: a member in this file but no
/// longer in the team holds a stale keyring, so their departure must
/// rotate the ring.
fn wrapped_members_path(root: &Path) -> PathBuf {
    root.join(".pear").join("wrapped_members.json")
}

/// The recorded last-wrapped member set, `None` when no pass ever
/// persisted one (a pre-§20 workspace's first pass: nothing to compare,
/// nothing rotates). A CORRUPT file is an error, never a silent reset —
/// quietly dropping the record would skip the rotation a departed member
/// requires.
pub fn load_wrapped_members(root: &Path) -> Result<Option<BTreeSet<String>>> {
    let path = wrapped_members_path(root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let members: BTreeSet<String> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(members))
}

/// Persist the wrapped member set atomically (tmp + fsync + rename, like
/// the manifests): a torn write must never leave a truncated file that
/// `load_wrapped_members` would then refuse as corrupt. The `.pear` dir
/// is created owner-only when needed (init has always run by the time a
/// pass persists the record — the keyring lives there too).
pub fn store_wrapped_members(root: &Path, members: &BTreeSet<String>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(members)?;
    let path = wrapped_members_path(root);
    let pear_dir = path.parent().expect("wrapped_members_path always has a parent");
    fs::create_dir_all(pear_dir).with_context(|| format!("create {}", pear_dir.display()))?;
    crate::fsutil::set_private_dir(pear_dir)?;
    crate::manifest::write_file_atomic(&path, &bytes)
}

/// What one §20 rotation-maintenance pass did.
#[derive(Debug)]
pub struct RotationReport {
    /// Members wrapped for last time but absent from the team now: their
    /// wrapped-key rows were deleted and the keyring rotated.
    pub departed: Vec<String>,
    /// Whether this pass rotated the keyring (a departure, or `force`).
    pub rotated: bool,
    /// The keyring's generation after the pass.
    pub generation: u32,
    /// §32 merge-before-rotate: generations this pass took from the
    /// relay's copy of this user's wrapped ring before minting a new one
    /// (gained, or replaced on a same-generation mismatch).
    pub merged_from_relay: Vec<u32>,
    /// Why merge-before-rotate did not run, when a rotation happened
    /// without it (no local identity, no wrap row yet): the rotation used
    /// the local ring alone.
    pub merge_skipped: Option<String>,
    /// The ordinary §19 wrap pass over the (possibly rotated) keyring.
    pub wrap: WrapReport,
}

/// §20 rotation-maintenance, run at converge-loop startup BEFORE the
/// first converge — and, with `force`, by
/// `pear rekey` (the operator-initiated compromise response). The pass
/// compares the attached team's current members against
/// `.pear/wrapped_members.json`: any member who VANISHED since the last
/// wrap means rotate to a fresh generation, delete the departed members'
/// wrapped-key rows, then wrap the (new) keyring to the current set via
/// the ordinary §19 pass — a removed member's stale ring stops decrypting
/// at this generation while current members keep full history. A pure
/// ADDITION never rotates: new members receive the whole ring.
///
/// §32: every writer device runs this at converge-loop startup, so two
/// devices can race a rotation. Before a rotation mints anything, the
/// device therefore MERGES first (`merge_relay_keyring`): it fetches its
/// own wrapped ring from the relay, unions it in — the relay's copy wins
/// a same-generation mismatch — persists the result, and only then mints
/// `max(known generation) + 1`, so a device that missed a peer's rotation
/// extends the ring instead of forking its newest generation number. With
/// no wrap row on the relay yet (the first writer) or no `name` identity
/// to unwrap with, the local ring rotates as before and the report says
/// so. A workspace with no attached team has nobody to compare: nothing
/// to do — unless `force`, which is an error (rotating with nobody to
/// re-wrap would only orphan readers).
///
/// `keys_dir`/`name` are this device's local identity (`~/.pear/keys`,
/// the `pear user keygen --name` name), the same pair
/// `workspace_key_for_reader` unwraps with.
pub fn rotation_maintenance(
    client: &RelayClient,
    root: &Path,
    keyring: &mut Keyring,
    known_keys_path: &Path,
    keys_dir: &Path,
    name: Option<&str>,
    force: bool,
) -> Result<RotationReport> {
    let Some(team_id) = client.get_workspace()?.team_id else {
        if force {
            bail!(
                "workspace {} has no attached team; `pear share --team <team>` first",
                client.workspace_id()
            );
        }
        return Ok(RotationReport {
            departed: Vec::new(),
            rotated: false,
            generation: keyring.newest().0,
            merged_from_relay: Vec::new(),
            merge_skipped: None,
            wrap: WrapReport::default(),
        });
    };
    let current: BTreeSet<String> = client
        .team_members(&team_id)?
        .into_iter()
        .map(|m| m.user)
        .collect();
    let last = load_wrapped_members(root)?.unwrap_or_default();
    // Vanished = wrapped for last time, gone from the team now. A member
    // who was never wrapped (no valid key) is not in the record, so their
    // departure loses nothing and must not rotate.
    let departed: Vec<String> = last.difference(&current).cloned().collect();
    let rotated = force || !departed.is_empty();
    let mut merged_from_relay = Vec::new();
    let mut merge_skipped = None;
    if rotated {
        // §32 merge-before-rotate: adopt every generation the relay's copy
        // of our own wrap already knows, so the mint below lands above the
        // newest generation ANY device has used, not just ours.
        match merge_relay_keyring(client, keyring, keys_dir, name)? {
            Ok(adopted) => {
                if !adopted.is_empty() {
                    // Persisted before the mint: a crash between here and
                    // the rotation must not lose generations we just
                    // learned about — content sealed under them would be
                    // unreadable on this device.
                    store_workspace_keyring(root, keyring)?;
                    merged_from_relay = adopted;
                }
            }
            Err(why) => merge_skipped = Some(why),
        }
        keyring.rotate();
        // Persist the rotated ring BEFORE touching the relay: the wrap
        // rows are re-creatable, the new generation is not.
        store_workspace_keyring(root, keyring)?;
    }
    for user in &departed {
        // The relay's DELETE is idempotent (204 whether or not a row
        // existed): a retry after a crash mid-pass converges instead of
        // failing on the first already-deleted row.
        client.delete_wrapped_key(user)?;
    }
    let wrap = wrap_maintenance(client, keyring, known_keys_path)?;
    // Record the set actually wrapped for (the `wrapped` bucket): members
    // skipped for missing/unsigned/bad/changed keys never enter the
    // record, so their later departure correctly never rotates — they
    // never held the keyring.
    store_wrapped_members(root, &wrap.wrapped.iter().cloned().collect())?;
    Ok(RotationReport {
        departed,
        rotated,
        generation: keyring.newest().0,
        merged_from_relay,
        merge_skipped,
        wrap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ChunkSink;

    #[test]
    fn keyring_rotate_newest_and_decrypt_order() {
        let first = rand::random::<[u8; 32]>();
        let mut keyring = Keyring::from_legacy(first);
        assert_eq!(keyring.newest(), (1, &first));

        // Rotations land at newest+1 and keep every older generation.
        assert_eq!(keyring.rotate(), 2);
        let second = *keyring.newest().1;
        assert_ne!(second, first);
        assert_eq!(keyring.rotate(), 3);
        let third = *keyring.newest().1;
        assert_eq!(keyring.newest().0, 3);

        // `decrypt` finds the right generation among several, newest
        // first: a blob sealed under ANY held generation opens.
        for (gen, key) in [(1u32, first), (2, second), (3, third)] {
            let blob = crypto::encrypt_chunk(&key, format!("sealed under gen {gen}").as_bytes());
            let plain = keyring
                .decrypt("test blob", |k| crypto::decrypt_chunk(k, &blob))
                .unwrap();
            assert_eq!(plain, format!("sealed under gen {gen}").into_bytes());
        }
        // A ring missing the sealing generation fails — the §20 cutoff.
        let gen1_only = Keyring::from_legacy(first);
        let blob = crypto::encrypt_chunk(&third, b"post-removal content");
        assert!(gen1_only.decrypt("test blob", |k| crypto::decrypt_chunk(k, &blob)).is_err());
    }

    /// §32 merge-before-rotate, at the ring level: a union adopts the
    /// generations the local ring lacks, the relay's key wins a
    /// same-generation mismatch, and the rotation that follows mints
    /// `max(known generation) + 1` — the concrete fork of §32, where the
    /// local ring holds {1, 2a} and the relay's wrap holds {1, 2b, 3}.
    #[test]
    fn union_takes_missing_generations_and_the_relays_side_of_a_fork() {
        let gen1: [u8; 32] = rand::random();
        let gen2a: [u8; 32] = rand::random();
        let gen2b: [u8; 32] = rand::random();
        let gen3: [u8; 32] = rand::random();
        let ring = |keys: &[(u32, [u8; 32])]| Keyring {
            keys: keys.iter().copied().collect(),
        };

        // Identical rings union to nothing at all.
        let mut local = ring(&[(1, gen1), (2, gen2a)]);
        assert!(local.union_from(&ring(&[(1, gen1), (2, gen2a)])).is_empty());

        // The fork: gen 3 is gained, gen 2 is REPLACED by the relay's key.
        let adopted = local.union_from(&ring(&[(1, gen1), (2, gen2b), (3, gen3)]));
        assert_eq!(adopted, vec![2, 3]);
        assert_eq!(local, ring(&[(1, gen1), (2, gen2b), (3, gen3)]));
        // Content sealed under the relay's generation 2 now opens; the
        // local branch's key is gone.
        let sealed_2b = crypto::encrypt_chunk(&gen2b, b"the relay's branch");
        assert!(local
            .decrypt("chunk", |k| crypto::decrypt_chunk(k, &sealed_2b))
            .is_ok());
        let sealed_2a = crypto::encrypt_chunk(&gen2a, b"our branch");
        assert!(local
            .decrypt("chunk", |k| crypto::decrypt_chunk(k, &sealed_2a))
            .is_err());

        // And the rotation after the merge mints max+1 = 4, not 3: the
        // fork does not repeat.
        assert_eq!(local.rotate(), 4);
        assert_eq!(local.newest().0, 4);

        // A union that only ADDS leaves the shared generations alone.
        let mut behind = ring(&[(1, gen1)]);
        assert_eq!(behind.union_from(&ring(&[(1, gen1), (2, gen2b)])), vec![2]);
        assert_eq!(behind, ring(&[(1, gen1), (2, gen2b)]));
        // A ring that is AHEAD keeps what the other side never had.
        let mut ahead = ring(&[(1, gen1), (2, gen2b), (3, gen3)]);
        assert!(ahead.union_from(&ring(&[(1, gen1)])).is_empty());
        assert_eq!(ahead.newest().0, 3);
    }

    #[test]
    fn workspace_keyring_load_or_create_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let created = load_or_create_workspace_keyring(dir.path()).unwrap();
        assert_eq!(load_or_create_workspace_keyring(dir.path()).unwrap(), created);
        assert_eq!(load_workspace_keyring(dir.path()).unwrap(), Some(created.clone()));
        // The fresh ring starts at generation 1, stored 0600 as JSON.
        assert_eq!(created.newest().0, 1);
        let mode_path = keys_path(dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&mode_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // A corrupted keyring file is an error, never a silent re-key.
        crypto::write_private_0600(&mode_path, b"not json {").unwrap();
        assert!(load_workspace_keyring(dir.path()).is_err());
    }

    #[test]
    fn legacy_workspace_key_file_migrates_to_generation_1() {
        let dir = tempfile::tempdir().unwrap();
        let pear = dir.path().join(".pear");
        fs::create_dir_all(&pear).unwrap();
        crate::fsutil::set_private_dir(&pear).unwrap();
        let legacy: [u8; 32] = rand::random();
        crypto::write_private_0600(&legacy_key_path(dir.path()), &legacy).unwrap();

        // The legacy file loads as the {1: key} ring — no operator action.
        let loaded = load_workspace_keyring(dir.path()).unwrap().unwrap();
        assert_eq!(loaded, Keyring::from_legacy(legacy));
        assert_eq!(loaded.newest(), (1, &legacy));

        // Storing rewrites as `workspace_keys` and removes the legacy file:
        // one source of truth on disk from then on.
        store_workspace_keyring(dir.path(), &loaded).unwrap();
        assert!(keys_path(dir.path()).exists());
        assert!(!legacy_key_path(dir.path()).exists());
        assert_eq!(
            load_workspace_keyring(dir.path()).unwrap(),
            Some(Keyring::from_legacy(legacy))
        );

        // A corrupted legacy file is an error, never a silent re-key.
        fs::remove_file(keys_path(dir.path())).unwrap();
        crypto::write_private_0600(&legacy_key_path(dir.path()), b"too short").unwrap();
        assert!(load_workspace_keyring(dir.path()).is_err());
    }

    #[test]
    fn keyring_json_validation_rejects_garbage() {
        // Garbage JSON, an empty map, generation 0, non-hex, and
        // wrong-length keys are all errors, never panics.
        for bad in [
            b"not json {".to_vec(),
            b"{}".to_vec(),
            br#"{"0":"abab"}"#.to_vec(),
            br#"{"1":"zz"}"#.to_vec(),
            br#"{"1":"abab"}"#.to_vec(),
            // A JSON array of keys is not the {gen: hex} map.
            br#"["abab"]"#.to_vec(),
        ] {
            assert!(keyring_from_json(&bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn wrap_payload_decodes_legacy_and_keyring() {
        // A 32-byte payload is the legacy single-key wrap → {1: key}.
        let legacy: [u8; 32] = rand::random();
        assert_eq!(
            keyring_from_wrap_payload(&legacy).unwrap(),
            Keyring::from_legacy(legacy)
        );
        // The JSON payload decodes the full map, generation order intact.
        let mut keyring = Keyring::from_legacy(rand::random());
        keyring.rotate();
        keyring.rotate();
        let decoded = keyring_from_wrap_payload(&keyring_json(&keyring).unwrap()).unwrap();
        assert_eq!(decoded, keyring);
        assert_eq!(decoded.newest().0, 3);
        // Anything else — neither 32 bytes nor the JSON map — is an error.
        assert!(keyring_from_wrap_payload(b"short").is_err());
        assert!(keyring_from_wrap_payload(&[0u8; 33]).is_err());
    }

    #[test]
    fn wrap_unwrap_multi_gen_keyring_round_trip() {
        // What wrap-maintenance PUTs and a member unwraps (§20): the whole
        // ring in one sealed box.
        let mut keyring = Keyring::from_legacy(rand::random());
        keyring.rotate();
        let recipient = crypto::UserKeypair::generate();
        let payload = keyring_json(&keyring).unwrap();
        let blob = crypto::wrap_key(&payload, &recipient.public).unwrap();
        // A multi-generation wrap no longer fits the §17 fixed blob size
        // (92 bytes for one 32-byte key) — the length rides the payload.
        assert!(blob.len() > 32 + 12 + 32 + 16);
        let unwrapped = crypto::unwrap_key(&recipient, &blob).unwrap();
        assert_eq!(keyring_from_wrap_payload(&unwrapped).unwrap(), keyring);

        // And a legacy single-key wrap still unwraps to the {1: key} ring:
        // pre-§20 wraps made by old writers keep onboarding new readers.
        let legacy: [u8; 32] = rand::random();
        let blob = crypto::wrap_key(&legacy, &recipient.public).unwrap();
        let unwrapped = crypto::unwrap_key(&recipient, &blob).unwrap();
        assert_eq!(
            keyring_from_wrap_payload(&unwrapped).unwrap(),
            Keyring::from_legacy(legacy)
        );
    }

    #[test]
    fn wrapped_members_record_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        // No record yet: None — the first pass has nothing to compare.
        assert_eq!(load_wrapped_members(dir.path()).unwrap(), None);
        let members: BTreeSet<String> = ["alice", "bob"].into_iter().map(String::from).collect();
        store_wrapped_members(dir.path(), &members).unwrap();
        assert_eq!(load_wrapped_members(dir.path()).unwrap(), Some(members));
        // A corrupt record is an error, never a silent reset (a skipped
        // rotation would leave a departed member decrypting).
        fs::write(wrapped_members_path(dir.path()), b"not json {").unwrap();
        assert!(load_wrapped_members(dir.path()).is_err());
    }

    #[test]
    fn manifest_envelope_round_trip_and_tamper() {
        let keyring = Keyring::from_legacy(rand::random());
        let mut m = Manifest::new("ws-1".to_string());
        m.files.insert(
            "src/main.rs".to_string(),
            crate::manifest::FileEntry {
                size: 3,
                mode: 0o644,
                mtime_secs: 1,
                mtime_nanos: 0,
                chunks: vec![blake3::hash(b"foo").to_hex().to_string()],
            },
        );
        let enc = encrypt_manifest(&keyring, &m).unwrap();
        // The envelope never carries the manifest in the clear.
        assert!(!enc.contains("src/main.rs"));
        assert_eq!(decrypt_manifest(&keyring, &enc).unwrap(), m);
        // Another commit of the same manifest encrypts differently (random
        // nonce) yet decrypts identically.
        let enc2 = encrypt_manifest(&keyring, &m).unwrap();
        assert_ne!(enc, enc2);
        assert_eq!(decrypt_manifest(&keyring, &enc2).unwrap(), m);
        assert!(decrypt_manifest(&Keyring::from_legacy(rand::random()), &enc).is_err());
        assert!(decrypt_manifest(&keyring, "not base64").is_err());
        assert_eq!(
            manifest_chunk_hashes(&m),
            vec![blake3::hash(b"foo").to_hex().to_string()]
        );
    }

    #[test]
    fn manifest_envelope_spans_generations() {
        // §20: writes encrypt under the NEWEST generation; reads try the
        // ring newest → oldest — old envelopes stay readable, a ring
        // missing the sealing generation is cut off.
        let mut keyring = Keyring::from_legacy(rand::random());
        let gen1 = Keyring::from_legacy(*keyring.newest().1);
        let m = Manifest::new("ws-1".to_string());
        let old_enc = encrypt_manifest(&keyring, &m).unwrap();
        keyring.rotate();
        let new_enc = encrypt_manifest(&keyring, &m).unwrap();
        // Old and new both read under the full ring...
        assert_eq!(decrypt_manifest(&keyring, &old_enc).unwrap(), m);
        assert_eq!(decrypt_manifest(&keyring, &new_enc).unwrap(), m);
        // ...while the gen-1-only ring reads the old one and fails the new.
        assert_eq!(decrypt_manifest(&gen1, &old_enc).unwrap(), m);
        let err = format!("{:#}", decrypt_manifest(&gen1, &new_enc).unwrap_err());
        assert!(err.contains("generation"), "{err}");
    }

    #[test]
    fn decrypting_source_verifies_then_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(dir.path().join("store")).unwrap();
        let keyring = Keyring::from_legacy(rand::random());
        let blob = crypto::encrypt_chunk(keyring.newest().1, b"plaintext");
        let hash = blake3::hash(&blob).to_hex().to_string();
        store.put(&hash, &blob).unwrap();

        let source = DecryptingSource {
            inner: &store,
            keyring: &keyring,
        };
        assert_eq!(source.get(&hash).unwrap(), b"plaintext");

        // A store poisoned under the right hash fails the hash check.
        let other_hash = blake3::hash(b"junk").to_hex().to_string();
        store.put(&other_hash, b"junk").unwrap();
        assert!(source.get(&other_hash).is_err());
        // And a ring without the sealing generation fails the GCM tag check.
        let wrong = DecryptingSource {
            inner: &store,
            keyring: &Keyring::from_legacy(rand::random()),
        };
        assert!(wrong.get(&hash).is_err());
    }

    #[test]
    fn decrypting_source_finds_the_sealing_generation() {
        // §20: chunks sealed under different generations coexist in one
        // store; the source must find each one's key, newest first.
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(dir.path().join("store")).unwrap();
        let mut keyring = Keyring::from_legacy(rand::random());
        let mut hashes = Vec::new();
        for gen in 1..=3u32 {
            let blob = crypto::encrypt_chunk(
                keyring.newest().1,
                format!("sealed under gen {gen}").as_bytes(),
            );
            let hash = blake3::hash(&blob).to_hex().to_string();
            store.put(&hash, &blob).unwrap();
            hashes.push(hash);
            if gen < 3 {
                keyring.rotate();
            }
        }
        let source = DecryptingSource {
            inner: &store,
            keyring: &keyring,
        };
        for (i, hash) in hashes.iter().enumerate() {
            assert_eq!(
                source.get(hash).unwrap(),
                format!("sealed under gen {}", i + 1).into_bytes()
            );
        }
    }

    /// A §19 member row with a real, valid bundle signed for `user`.
    fn signed_member(user: &str) -> (crate::relay::MemberInfo, crypto::EdKeypair, [u8; 32]) {
        let x = crypto::UserKeypair::generate();
        let ed = crypto::EdKeypair::generate();
        let sig = ed.sign(&crypto::bundle_statement(user, &x.public));
        let member = crate::relay::MemberInfo {
            user: user.to_string(),
            role: "writer".to_string(),
            pubkey: Some(crypto::hex_encode(&x.public)),
            ed25519: Some(crypto::hex_encode(&ed.public)),
            sig: Some(crypto::hex_encode(&sig)),
        };
        (member, ed, x.public)
    }

    #[test]
    fn classify_member_four_buckets_and_first_sight() {
        let pins = known_keys::KnownKeys::new();

        // No key at all → NoKey (the `skipped` bucket).
        let bare = crate::relay::MemberInfo {
            user: "carol".to_string(),
            role: "reader".to_string(),
            pubkey: None,
            ed25519: None,
            sig: None,
        };
        assert_eq!(classify_member(&bare, &pins), MemberClass::NoKey);

        // Legacy pubkey-only row → Unsigned, never wrapped to.
        let legacy = crate::relay::MemberInfo {
            pubkey: Some(crypto::hex_encode(&crypto::UserKeypair::generate().public)),
            ..bare.clone()
        };
        assert_eq!(classify_member(&legacy, &pins), MemberClass::Unsigned);

        // A valid bundle at first sight → Wrap with pinning due.
        let (alice, _, x_pub) = signed_member("alice");
        assert_eq!(
            classify_member(&alice, &pins),
            MemberClass::Wrap {
                x25519_pub: x_pub,
                first_sight: true
            }
        );

        // Once pinned, the same bundle is a plain Wrap...
        let mut pins = known_keys::KnownKeys::new();
        known_keys::pin(&mut pins, "alice", alice.ed25519.as_deref().unwrap());
        assert_eq!(
            classify_member(&alice, &pins),
            MemberClass::Wrap {
                x25519_pub: x_pub,
                first_sight: false
            }
        );

        // ...and a valid bundle under a DIFFERENT identity is PinChanged
        // (the pin is not updated implicitly — `pear trust` re-pins).
        let (rotated, _, _) = signed_member("alice");
        assert_eq!(classify_member(&rotated, &pins), MemberClass::PinChanged);

        // Tampered/forged bundles are BadSig: a flipped signature bit, a
        // bundle signed for another user, and non-hex fields alike.
        let (mut forged, _, _) = signed_member("alice");
        let mut sig = crypto::hex_decode(forged.sig.as_deref().unwrap()).unwrap();
        sig[3] ^= 1;
        forged.sig = Some(crypto::hex_encode(&sig));
        assert_eq!(classify_member(&forged, &pins), MemberClass::BadSig);
        let (bob_bundle, _, _) = signed_member("bob");
        let replayed = crate::relay::MemberInfo {
            user: "alice".to_string(),
            ..bob_bundle
        };
        assert_eq!(classify_member(&replayed, &pins), MemberClass::BadSig);
        let garbage = crate::relay::MemberInfo {
            sig: Some("not hex".to_string()),
            ..alice.clone()
        };
        assert_eq!(classify_member(&garbage, &pins), MemberClass::BadSig);
    }

    #[test]
    fn known_keys_pins_persist_across_saves() {
        // The wrap pass's pin-file contract, at the module level: pins
        // written once survive a reload, byte for byte.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_keys");
        let mut pins = known_keys::KnownKeys::new();
        let (alice, _, _) = signed_member("alice");
        known_keys::pin(&mut pins, "alice", alice.ed25519.as_deref().unwrap());
        known_keys::save(&path, &pins).unwrap();
        let reloaded = known_keys::load(&path).unwrap();
        assert_eq!(
            known_keys::check(&reloaded, "alice", alice.ed25519.as_deref().unwrap()),
            known_keys::PinCheck::Match
        );
    }
}
