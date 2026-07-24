//! E2E encryption primitives (DESIGN.md §17): HKDF-SHA256 key derivation,
//! AES-256-GCM convergent chunk encryption, and X25519 sealed-box wrapping of
//! workspace key material to user keypairs — §20 generalizes the wrap payload
//! from exactly one 32-byte workspace key to arbitrary bytes (the serialized
//! keyring). §19 adds the long-term ed25519 device identity that signs each
//! user's X25519 key bundle.
//!
//! The `hkdf`/`hmac`/`x25519-dalek` crates are not in the offline registry, so
//! HMAC is implemented directly over `sha2` and X25519 over curve25519-dalek's
//! clamped Montgomery multiplication; both are pinned to their RFC vectors in
//! the tests below, and ed25519-dalek to the RFC 8032 vectors.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// HMAC-SHA256 (RFC 2104) over `sha2` — the `hmac` crate is not in the
/// offline registry. 64-byte block size, key hashed first when longer.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(key_block.map(|b| b ^ 0x36));
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(key_block.map(|b| b ^ 0x5c));
    outer.update(inner_hash);
    key_block.zeroize();
    outer.finalize().into()
}

/// HKDF-SHA256 extract+expand (RFC 5869). `salt: None` means the RFC's
/// all-zero HashLen salt — the key wrap below has no natural salt.
///
/// Panics if `out_len` exceeds the RFC maximum (255 * 32 bytes); that is a
/// caller bug, not runtime input.
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(
        out_len <= 255 * 32,
        "HKDF-SHA256 out_len {out_len} exceeds the RFC 5869 maximum"
    );
    let zero_salt = [0u8; 32];
    let salt = salt.unwrap_or(&zero_salt);
    let mut prk = hmac_sha256(salt, ikm);
    let mut okm = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    for i in 0..out_len.div_ceil(32) {
        let mut data = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push((i + 1) as u8);
        t = hmac_sha256(&prk, &data).to_vec();
        data.zeroize();
        let take = (out_len - okm.len()).min(32);
        okm.extend_from_slice(&t[..take]);
    }
    prk.zeroize();
    t.zeroize();
    okm
}

/// Encrypt one chunk under the workspace key with a *convergent* nonce: the
/// first 12 bytes of keyed-BLAKE3(workspace_key, plaintext). Identical
/// plaintext under one workspace key yields an identical blob, so dedupe by
/// ciphertext hash works exactly as in the plaintext model (DESIGN.md §17);
/// GCM nonce reuse only ever covers identical plaintext, which is safe.
/// Output layout: nonce(12) || ciphertext || tag(16).
pub fn encrypt_chunk(workspace_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let digest = blake3::keyed_hash(workspace_key, plaintext);
    let nonce: &[u8; GCM_NONCE_LEN] = digest.as_bytes()[..GCM_NONCE_LEN]
        .try_into()
        .expect("a 32-byte hash yields 12 bytes");
    encrypt_with_nonce(workspace_key, nonce, plaintext)
}

/// Encrypt one whole blob (the head/snapshot manifest, §17) under the
/// workspace key with a RANDOM nonce: there is no dedup need, and the
/// convergent-nonce argument for chunks does not apply to a commit-only
/// document. Same layout: nonce(12) || ciphertext || tag(16).
pub fn encrypt_blob(workspace_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce = rand::random::<[u8; GCM_NONCE_LEN]>();
    encrypt_with_nonce(workspace_key, &nonce, plaintext)
}

fn encrypt_with_nonce(
    workspace_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(workspace_key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("AES-GCM encrypt fails only on inputs near 2^36 bytes");
    let mut blob = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Inverse of `encrypt_chunk`. Wrong key, tampered bytes, and truncated blobs
/// are errors, never panics: blobs come from the relay and are hostile input.
pub fn decrypt_chunk(workspace_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        bail!(
            "encrypted chunk is {} bytes; nonce + tag alone are {}",
            blob.len(),
            GCM_NONCE_LEN + GCM_TAG_LEN
        );
    }
    let (nonce, ciphertext) = blob.split_at(GCM_NONCE_LEN);
    let cipher = Aes256Gcm::new(workspace_key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("chunk does not decrypt under this workspace key"))
}

/// Inverse of `encrypt_blob` — the same nonce||ciphertext||tag layout as
/// chunks; only the nonce derivation differs.
pub fn decrypt_blob(workspace_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    decrypt_chunk(workspace_key, blob)
}

/// X25519 (RFC 7748): clamped scalar multiplication of the peer's
/// u-coordinate. curve25519-dalek ships no `x25519()` free function, but
/// `MontgomeryPoint::mul_clamped` is exactly RFC 7748 clamping + ladder.
fn x25519(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint(*public).mul_clamped(*secret).to_bytes()
}

/// X25519 base multiplication: a keypair's public half from its private half.
fn x25519_base(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// An X25519 user keypair (DESIGN.md §17 Keys), stored as the raw 32-byte
/// private half at `~/.pear/keys/<name>.x25519`, mode 0600. The private half
/// is zeroized on drop and redacted from `Debug`.
pub struct UserKeypair {
    secret: [u8; 32],
    pub public: [u8; 32],
}

impl UserKeypair {
    /// Fresh random keypair.
    pub fn generate() -> Self {
        Self::from_secret_bytes(rand::random())
    }

    /// Rebuild a keypair from its private half (e.g. loaded from a key file);
    /// the public half is re-derived, never stored.
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let public = x25519_base(&secret);
        Self { secret, public }
    }

    /// The 32-byte private half — needed only for key-file storage and
    /// export; treat the bytes accordingly.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl Drop for UserKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for UserKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omits the private half.
        write!(
            f,
            "UserKeypair {{ public: {}, .. }}",
            hex_encode(&self.public)
        )
    }
}

/// An ed25519 user identity (DESIGN.md §19): the long-term signing key that
/// binds the user's X25519 encryption key to their name. The public key IS
/// the identity — its full hex is the fingerprint `pear user id` prints and
/// `known_keys` pins. Stored as the raw 32-byte seed at
/// `~/.pear/keys/<name>.ed25519`, mode 0600; the seed is zeroized on drop
/// (our copy, and the `SigningKey`'s via its `zeroize` feature) and
/// redacted from `Debug`, exactly like the X25519 half.
pub struct EdKeypair {
    signing: ed25519_dalek::SigningKey,
    seed: [u8; 32],
    pub public: [u8; 32],
}

impl EdKeypair {
    /// Fresh random identity (seed from the OS RNG).
    pub fn generate() -> Self {
        Self::from_secret_bytes(rand::random())
    }

    /// Rebuild an identity from its 32-byte seed (e.g. loaded from a key
    /// file); the public half is re-derived, never stored.
    pub fn from_secret_bytes(seed: [u8; 32]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        Self {
            signing,
            seed,
            public,
        }
    }

    /// The 32-byte seed — needed only for key-file storage and export;
    /// treat the bytes accordingly.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The 64-byte ed25519 signature over `msg` (RFC 8032).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(msg).to_bytes()
    }
}

impl Drop for EdKeypair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for EdKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omits the seed.
        write!(f, "EdKeypair {{ public: {}, .. }}", hex_encode(&self.public))
    }
}

/// The domain separator prefixing every signed key-bundle statement (§19):
/// a signature made for any other purpose can never double as a bundle
/// signature, and vice versa.
const BUNDLE_DOMAIN: &[u8] = b"pear device key v1\0";

/// The canonical statement a key bundle's signature must cover (§19):
/// `"pear device key v1\0" ‖ name ‖ x25519_pub_raw32`. Binding the user
/// NAME means a bundle cannot be replayed for another user; the fixed
/// 32-byte key at the tail keeps the concatenation unambiguous without a
/// second separator.
pub fn bundle_statement(name: &str, x25519_pub: &[u8; 32]) -> Vec<u8> {
    let mut stmt = Vec::with_capacity(BUNDLE_DOMAIN.len() + name.len() + 32);
    stmt.extend_from_slice(BUNDLE_DOMAIN);
    stmt.extend_from_slice(name.as_bytes());
    stmt.extend_from_slice(x25519_pub);
    stmt
}

/// Verify an ed25519 bundle signature (§19), strict variant: non-canonical
/// signatures and small-order keys are rejected too — the key and signature
/// are relay-held, hostile input. False on any parse or verify failure,
/// never a panic.
pub fn ed_verify(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(ed_pub) else {
        return false;
    };
    key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// HKDF info string for the workspace-key wrap: domain separation so a wrap
/// key can never collide with any other derived key.
const WRAP_INFO: &[u8] = b"pear workspace key wrap v1";

/// Sealed-box blob layout: ephemeral public (32) || nonce (12) ||
/// AES-256-GCM ciphertext of the payload || tag (16). §20 generalized the
/// payload from exactly one 32-byte workspace key to arbitrary bytes (the
/// serialized keyring), so a blob's length varies with its payload and the
/// §17 fixed-size check retired to this floor: shorter than an empty
/// payload's box cannot be a wrap at all.
pub const WRAPPED_KEY_MIN_LEN: usize = 32 + GCM_NONCE_LEN + GCM_TAG_LEN;

/// Largest wrap blob accepted on the wire (§20). One JSON keyring entry is
/// ~80 bytes (`"NNN":"<64 hex>",`), so 64 KiB of payload covers ~800
/// member removals — generous headroom that still caps what a hostile or
/// buggy writer makes every member download.
pub const WRAPPED_KEY_MAX_LEN: usize = 64 * 1024;

/// Derive the one-time wrap key from an X25519 shared secret. The all-zero
/// secret of a low-order peer public key is rejected (RFC 7748 §6.1): without
/// the check, a malicious public key would force a publicly-known wrap key.
fn derive_wrap_key(shared: &mut [u8; 32]) -> Result<[u8; 32]> {
    if *shared == [0u8; 32] {
        bail!("X25519 shared secret is all zero: peer public key is low-order");
    }
    let mut okm = hkdf_sha256(shared, None, WRAP_INFO, 32);
    shared.zeroize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    okm.zeroize();
    Ok(key)
}

/// Wrap a payload to a recipient's public key, sealed-box style (DESIGN.md
/// §17/§20): fresh ephemeral keypair, shared = X25519(ephemeral,
/// recipient), wrap key = HKDF-SHA256(shared). The payload was exactly one
/// 32-byte workspace key pre-§20; it is now the serialized keyring, so any
/// byte string goes.
///
/// The nonce is random, not convergent: the wrap key is used exactly once, so
/// GCM nonce reuse is impossible and convergence would buy nothing.
pub fn wrap_key(payload: &[u8], recipient_public: &[u8; 32]) -> Result<Vec<u8>> {
    let ephemeral = UserKeypair::generate();
    let mut shared = x25519(ephemeral.secret_bytes(), recipient_public);
    let mut key = derive_wrap_key(&mut shared)?;
    let nonce = rand::random::<[u8; GCM_NONCE_LEN]>();
    let cipher = Aes256Gcm::new((&key).into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .expect("AES-GCM encrypt fails only on inputs near 2^36 bytes");
    key.zeroize();
    let mut blob = Vec::with_capacity(32 + GCM_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&ephemeral.public);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Inverse of `wrap_key`: the raw payload bytes (the caller decodes — a
/// 32-byte plaintext is a legacy single-key wrap, anything else a §20
/// keyring). Wrong recipient, tampered blob, and too-short blob are all
/// errors, never panics: blobs come from the relay and are hostile input.
pub fn unwrap_key(recipient: &UserKeypair, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < WRAPPED_KEY_MIN_LEN {
        bail!(
            "wrapped key blob is {} bytes; a sealed box is at least {}",
            blob.len(),
            WRAPPED_KEY_MIN_LEN
        );
    }
    let ephemeral_public: &[u8; 32] = blob[..32].try_into().expect("length checked above");
    let nonce = &blob[32..32 + GCM_NONCE_LEN];
    let ciphertext = &blob[32 + GCM_NONCE_LEN..];
    let mut shared = x25519(recipient.secret_bytes(), ephemeral_public);
    let mut key = derive_wrap_key(&mut shared)?;
    let cipher = Aes256Gcm::new((&key).into());
    // The plaintext is the return value, so it is NOT zeroized here — it
    // becomes the caller's secret to manage.
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("wrapped key does not decrypt for this recipient"))?;
    key.zeroize();
    Ok(plaintext)
}

/// Write `bytes` to `path` with owner-only permissions, like an SSH private
/// key. The mode is also clamped on a pre-existing file (`OpenOptions.mode`
/// only applies at creation).
pub fn write_private_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = crate::fsutil::create_private_file(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

/// Read a file that must be owner-only, refusing group/other-readable modes.
/// A loose mode on a private key is a configuration error; reading it anyway
/// would normalize the mistake (ssh(1) refuses the same way).
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} has mode {:o}; private key files must not be group/other-readable (chmod 600 {})",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

/// `<dir>/<name>.<ext>` for one half of a user's identity (`x25519` /
/// `ed25519`, §17/§19). The name becomes a filename holding a private key,
/// so reject anything that could escape `dir` or alias special entries.
fn user_key_path(dir: &Path, name: &str, ext: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        bail!("invalid user name {name:?} for a key file");
    }
    Ok(dir.join(format!("{name}.{ext}")))
}

/// Read a raw 32-byte key file (`x25519` secret or `ed25519` seed) that
/// must exist, with the file's kind named in the error.
fn read_key_file(path: &Path, kind: &str) -> Result<[u8; 32]> {
    let bytes = read_private(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "{} holds {} bytes; a {kind} file is exactly 32",
            path.display(),
            bytes.len()
        )
    })
}

/// Load `<dir>/<name>.x25519` (raw 32-byte private half), generating it on
/// first use. `dir` is created owner-only — it holds private keys.
pub fn user_keypair_load_or_create(dir: &Path, name: &str) -> Result<UserKeypair> {
    let path = user_key_path(dir, name, "x25519")?;
    if path.exists() {
        return Ok(UserKeypair::from_secret_bytes(read_key_file(
            &path,
            "X25519 private key",
        )?));
    }
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    crate::fsutil::set_private_dir(dir).with_context(|| format!("chmod {}", dir.display()))?;
    let keypair = UserKeypair::generate();
    write_private_0600(&path, keypair.secret_bytes())?;
    Ok(keypair)
}

/// Load `<dir>/<name>.ed25519` (raw 32-byte seed, §19), generating it on
/// first use — same storage rules as the X25519 half.
pub fn ed_keypair_load_or_create(dir: &Path, name: &str) -> Result<EdKeypair> {
    let path = user_key_path(dir, name, "ed25519")?;
    if path.exists() {
        return Ok(EdKeypair::from_secret_bytes(read_key_file(
            &path,
            "ed25519 seed",
        )?));
    }
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    crate::fsutil::set_private_dir(dir).with_context(|| format!("chmod {}", dir.display()))?;
    let keypair = EdKeypair::generate();
    write_private_0600(&path, keypair.secret_bytes())?;
    Ok(keypair)
}

/// The raw 32-byte private half of `<dir>/<name>.x25519`, for moving an
/// identity between machines like an SSH key (DESIGN.md §17 Keys).
pub fn user_keypair_export(dir: &Path, name: &str) -> Result<[u8; 32]> {
    read_key_file(
        &user_key_path(dir, name, "x25519")?,
        "X25519 private key",
    )
}

/// The FULL identity of `<dir>/<name>` as secret bytes, for moving it
/// between machines (§19): `x25519_secret ‖ ed25519_seed` (64 bytes) when
/// the ed25519 half exists, the legacy 32-byte x25519-only export
/// otherwise — a pre-§19 identity moves unchanged and gains its ed25519
/// half at the next `pear user keygen` on the new machine. An ed25519-only
/// identity cannot be represented (a 32-byte export IS x25519-only by
/// definition) and is an error, never a silent half-move.
pub fn user_identity_export(dir: &Path, name: &str) -> Result<Vec<u8>> {
    let x_path = user_key_path(dir, name, "x25519")?;
    let ed_path = user_key_path(dir, name, "ed25519")?;
    if !x_path.exists() {
        if ed_path.exists() {
            bail!(
                "{} exists but there is no x25519 key for {name:?}; an identity export needs both halves",
                ed_path.display()
            );
        }
        bail!("no identity for {name:?} in {}", dir.display());
    }
    let mut x_secret = read_key_file(&x_path, "X25519 private key")?;
    if !ed_path.exists() {
        let out = x_secret.to_vec();
        x_secret.zeroize();
        return Ok(out);
    }
    let mut ed_seed = read_key_file(&ed_path, "ed25519 seed")?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&x_secret);
    out.extend_from_slice(&ed_seed);
    x_secret.zeroize();
    ed_seed.zeroize();
    Ok(out)
}

/// Install an exported identity as `<dir>/<name>.{x25519,ed25519}` (both
/// 0600, §19): 64 bytes = `x25519_secret ‖ ed25519_seed`, 32 bytes = the
/// legacy x25519-only export (its ed25519 half is minted at the next
/// `pear user keygen`). Refuses to overwrite ANY existing identity file
/// for the name — importing over a live identity would silently re-target
/// it (mirroring `init_workspace`'s refusal to re-target a workspace).
pub fn user_identity_import(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let x_path = user_key_path(dir, name, "x25519")?;
    let ed_path = user_key_path(dir, name, "ed25519")?;
    if x_path.exists() || ed_path.exists() {
        bail!(
            "{name:?} already has an identity in {}; refusing to overwrite it",
            dir.display()
        );
    }
    let (x_secret, ed_seed): (&[u8; 32], Option<&[u8; 32]>) = match bytes.len() {
        32 => (bytes.try_into().expect("length checked"), None),
        64 => (
            bytes[..32].try_into().expect("length checked"),
            Some(bytes[32..].try_into().expect("length checked")),
        ),
        n => bail!(
            "an exported identity is 32 bytes (x25519 only) or 64 (x25519 + ed25519), not {n}"
        ),
    };
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    crate::fsutil::set_private_dir(dir).with_context(|| format!("chmod {}", dir.display()))?;
    write_private_0600(&x_path, x_secret)?;
    if let Some(ed_seed) = ed_seed {
        // A failed second write must not strand a half-imported identity:
        // the next import would refuse (files exist) and the user wedges.
        if let Err(e) = write_private_0600(&ed_path, ed_seed) {
            let _ = fs::remove_file(&x_path);
            return Err(e);
        }
    }
    Ok(())
}

/// Install an exported private half as `<dir>/<name>.x25519` (0600). Refuses
/// to overwrite an existing key rather than silently re-targeting the name
/// (mirroring `init_workspace`'s refusal to re-target a workspace).
pub fn user_keypair_import(dir: &Path, name: &str, secret: &[u8; 32]) -> Result<UserKeypair> {
    let path = user_key_path(dir, name, "x25519")?;
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite an existing key",
            path.display()
        );
    }
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    crate::fsutil::set_private_dir(dir).with_context(|| format!("chmod {}", dir.display()))?;
    write_private_0600(&path, secret)?;
    Ok(UserKeypair::from_secret_bytes(*secret))
}

/// Lowercase hex, no separators — the wire encoding for pubkeys and
/// wrapped-key blobs (§17).
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of `hex_encode`. Odd lengths and non-hex bytes are errors:
/// these strings come off the wire and are never trusted.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("hex string of odd length {}", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow!("non-hex byte at {i}")))
        .collect()
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648, `+`/`/` alphabet, `=` padding) — the wire
/// encoding for `manifest_enc` (§17). Hand-rolled because the `base64`
/// crate is not a direct dependency and the offline registry is fixed.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(B64_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Inverse of `base64_encode`. Anything but clean RFC 4648 — wrong length,
/// foreign bytes, misplaced or non-canonical padding — is an error: this
/// decodes relay-held data that is hostile by default.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(4) {
        bail!("base64 input of length {} is not a multiple of 4", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut groups = s.as_bytes().chunks_exact(4);
    let n_groups = groups.len();
    for (idx, group) in groups.by_ref().enumerate() {
        let last = idx + 1 == n_groups;
        let pad = group.iter().filter(|&&b| b == b'=').count();
        if pad > 0 && (!last || pad > 2 || !group[4 - pad..].iter().all(|&b| b == b'=')) {
            bail!("base64 padding is only allowed as the final 1-2 chars");
        }
        let mut n = 0u32;
        for (i, &b) in group.iter().enumerate() {
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 4 - pad => 0,
                _ => bail!("invalid base64 byte {b:#04x}"),
            };
            n = n << 6 | u32::from(v);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        // RFC 4231 test cases 1, 2 and 6 (case 6 exercises the
        // longer-than-block-size key path).
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There").to_vec(),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .to_vec(),
            unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case_1() {
        let okm = hkdf_sha256(
            &[0x0b; 22],
            Some(&unhex("000102030405060708090a0b0c")),
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            42,
        );
        assert_eq!(
            okm,
            unhex(concat!(
                "3cb25f25faacd57a90434f64d0362f2a",
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            ))
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case_2() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 82);
        assert_eq!(
            okm,
            unhex(concat!(
                "b11e398dc80327a1c8e7f78c596a4934",
                "4f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09",
                "da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f",
                "1d87"
            ))
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case_3_zero_salt_and_info() {
        // Exercises the salt: None path the key wrap relies on.
        let okm = hkdf_sha256(&[0x0b; 22], None, b"", 42);
        assert_eq!(
            okm,
            unhex(concat!(
                "8da4e775a563c18f715f802a063c5a31",
                "b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8"
            ))
        );
    }

    #[test]
    fn hkdf_sha256_length_and_info_separation() {
        assert_eq!(hkdf_sha256(b"ikm", None, b"info", 13).len(), 13);
        assert_ne!(
            hkdf_sha256(b"ikm", None, b"info a", 32),
            hkdf_sha256(b"ikm", None, b"info b", 32)
        );
    }

    #[test]
    fn chunk_round_trip() {
        let key = rand::random::<[u8; 32]>();
        let data = b"chunk contents that are definitely secret";
        let blob = encrypt_chunk(&key, data);
        assert_eq!(blob.len(), GCM_NONCE_LEN + data.len() + GCM_TAG_LEN);
        assert_eq!(decrypt_chunk(&key, &blob).unwrap(), data);
    }

    #[test]
    fn chunk_empty_plaintext_round_trip() {
        let key = rand::random::<[u8; 32]>();
        let blob = encrypt_chunk(&key, b"");
        assert_eq!(blob.len(), GCM_NONCE_LEN + GCM_TAG_LEN);
        assert_eq!(decrypt_chunk(&key, &blob).unwrap(), b"");
    }

    #[test]
    fn chunk_encryption_is_convergent() {
        // Dedupe depends on this: identical plaintext under one workspace key
        // must produce an identical blob.
        let key = rand::random::<[u8; 32]>();
        let data = b"same bytes every time";
        assert_eq!(encrypt_chunk(&key, data), encrypt_chunk(&key, data));
        let other = encrypt_chunk(&key, b"different bytes");
        assert_ne!(
            &encrypt_chunk(&key, data)[..GCM_NONCE_LEN],
            &other[..GCM_NONCE_LEN]
        );
    }

    #[test]
    fn chunk_decrypt_rejects_wrong_key_tamper_and_truncation() {
        let key = rand::random::<[u8; 32]>();
        let blob = encrypt_chunk(&key, b"payload");
        let wrong_key = rand::random::<[u8; 32]>();
        assert!(decrypt_chunk(&wrong_key, &blob).is_err());

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_chunk(&key, &tampered).is_err());

        assert!(decrypt_chunk(&key, &blob[..GCM_NONCE_LEN + GCM_TAG_LEN - 1]).is_err());
        assert!(decrypt_chunk(&key, &[]).is_err());
    }

    #[test]
    fn x25519_rfc7748_section_5_2() {
        // RFC 7748 §5.2, first X25519 vector (Alice/Bob), both directions.
        let alice_secret: [u8; 32] =
            unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap();
        let alice_public: [u8; 32] =
            unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .try_into()
                .unwrap();
        let bob_public: [u8; 32] =
            unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .try_into()
                .unwrap();
        let shared: [u8; 32] =
            unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .try_into()
                .unwrap();
        assert_eq!(x25519_base(&alice_secret), alice_public);
        assert_eq!(x25519(&alice_secret, &bob_public), shared);
        let bob_secret: [u8; 32] =
            unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .try_into()
                .unwrap();
        assert_eq!(x25519(&bob_secret, &alice_public), shared);
    }

    #[test]
    fn keypair_public_half_is_derived_from_private() {
        let keypair = UserKeypair::generate();
        assert_eq!(
            UserKeypair::from_secret_bytes(*keypair.secret_bytes()).public,
            keypair.public
        );
    }

    #[test]
    fn keypair_debug_redacts_private_half() {
        let keypair = UserKeypair::generate();
        let debug = format!("{keypair:?}");
        assert!(!debug.contains(&hex_encode(keypair.secret_bytes())));
        assert!(debug.contains(&hex_encode(&keypair.public)));
    }

    #[test]
    fn blob_round_trip_with_fresh_random_nonces() {
        let key = rand::random::<[u8; 32]>();
        let data = br#"{"version":1,"workspace_id":"ws","files":{}}"#;
        let a = encrypt_blob(&key, data);
        let b = encrypt_blob(&key, data);
        // Random nonces: identical plaintext blobs differ, unlike chunks.
        assert_ne!(a, b);
        assert_eq!(decrypt_blob(&key, &a).unwrap(), data);
        assert_eq!(decrypt_blob(&key, &b).unwrap(), data);
        // Wrong key / tampered: errors, never panics.
        assert!(decrypt_blob(&rand::random(), &a).is_err());
        let mut tampered = a.clone();
        tampered[GCM_NONCE_LEN] ^= 1;
        assert!(decrypt_blob(&key, &tampered).is_err());
    }

    #[test]
    fn hex_round_trip_and_rejection() {
        let bytes = rand::random::<[u8; 32]>();
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode("abc").is_err(), "odd length");
        assert!(hex_decode("zz").is_err(), "non-hex");
    }

    #[test]
    fn base64_rfc4648_vectors() {
        // RFC 4648 §10 test vectors.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
        // Binary round trip, including a 0xFF-heavy input.
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn base64_decode_rejects_malformed_input() {
        for bad in [
            "Zg=",       // not a multiple of 4
            "Zm9v====",  // too much padding
            "Zm9=Zg==",  // padding mid-stream
            "Zm9v Yg==", // whitespace is not base64
            "Zm9\x01v",  // foreign byte
        ] {
            assert!(base64_decode(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let workspace_key = rand::random::<[u8; 32]>();
        let recipient = UserKeypair::generate();
        let blob = wrap_key(&workspace_key, &recipient.public).unwrap();
        // A 32-byte payload keeps the §17 single-key blob size exactly.
        assert_eq!(blob.len(), 32 + GCM_NONCE_LEN + 32 + GCM_TAG_LEN);
        assert_eq!(unwrap_key(&recipient, &blob).unwrap(), workspace_key);
    }

    #[test]
    fn wrap_unwrap_arbitrary_payload_lengths() {
        // §20: the payload generalized from one 32-byte key to the
        // serialized keyring — any length must round-trip.
        let recipient = UserKeypair::generate();
        for len in [0usize, 1, 31, 32, 33, 100, 4096] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = wrap_key(&payload, &recipient.public).unwrap();
            assert_eq!(blob.len(), 32 + GCM_NONCE_LEN + len + GCM_TAG_LEN);
            assert_eq!(unwrap_key(&recipient, &blob).unwrap(), payload);
        }
    }

    #[test]
    fn wrap_uses_fresh_ephemeral_and_nonce() {
        let workspace_key = rand::random::<[u8; 32]>();
        let recipient = UserKeypair::generate();
        let a = wrap_key(&workspace_key, &recipient.public).unwrap();
        let b = wrap_key(&workspace_key, &recipient.public).unwrap();
        assert_ne!(a, b);
        assert_eq!(unwrap_key(&recipient, &a).unwrap(), workspace_key);
        assert_eq!(unwrap_key(&recipient, &b).unwrap(), workspace_key);
    }

    #[test]
    fn unwrap_rejects_wrong_recipient_tamper_and_bad_length() {
        let workspace_key = rand::random::<[u8; 32]>();
        let recipient = UserKeypair::generate();
        let blob = wrap_key(&workspace_key, &recipient.public).unwrap();

        let stranger = UserKeypair::generate();
        assert!(unwrap_key(&stranger, &blob).is_err());

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unwrap_key(&recipient, &tampered).is_err());

        // Anything shorter than an empty payload's box is not a wrap.
        assert!(unwrap_key(&recipient, &blob[..WRAPPED_KEY_MIN_LEN - 1]).is_err());
        assert!(unwrap_key(&recipient, &[]).is_err());
    }

    #[test]
    fn low_order_public_keys_are_rejected() {
        // An all-zero public key forces an all-zero shared secret (RFC 7748
        // §6.1); wrapping to it would use a publicly-known wrap key.
        let workspace_key = rand::random::<[u8; 32]>();
        assert!(wrap_key(&workspace_key, &[0u8; 32]).is_err());

        let recipient = UserKeypair::generate();
        let mut blob = wrap_key(&workspace_key, &recipient.public).unwrap();
        blob[..32].copy_from_slice(&[0u8; 32]);
        assert!(unwrap_key(&recipient, &blob).is_err());
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn private_file_write_clamps_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        write_private_0600(&path, b"bytes").unwrap();
        assert_eq!(read_private(&path).unwrap(), b"bytes");
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&path), 0o600);
            // A pre-existing loose file is clamped too.
            set_mode(&path, 0o644);
            write_private_0600(&path, b"new").unwrap();
            assert_eq!(mode_of(&path), 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_private_refuses_group_or_other_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        write_private_0600(&path, b"bytes").unwrap();
        set_mode(&path, 0o640);
        assert!(read_private(&path).is_err());
        set_mode(&path, 0o604);
        assert!(read_private(&path).is_err());
        set_mode(&path, 0o400);
        assert!(read_private(&path).is_ok());
    }

    #[test]
    fn keypair_load_or_create_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let created = user_keypair_load_or_create(&keys, "alice").unwrap();
        let key_path = keys.join("alice.x25519");
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
        #[cfg(unix)]
        assert_eq!(mode_of(&key_path), 0o600);

        let loaded = user_keypair_load_or_create(&keys, "alice").unwrap();
        assert_eq!(loaded.public, created.public);
        assert_eq!(loaded.secret_bytes(), created.secret_bytes());

        // A corrupted key file is an error, never a silently new identity.
        write_private_0600(&key_path, b"too short").unwrap();
        assert!(user_keypair_load_or_create(&keys, "alice").is_err());
    }

    #[test]
    fn keypair_export_import_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let original = user_keypair_load_or_create(&keys, "alice").unwrap();

        let exported = user_keypair_export(&keys, "alice").unwrap();
        assert_eq!(&exported, original.secret_bytes());

        let other = dir.path().join("other-keys");
        let imported = user_keypair_import(&other, "alice", &exported).unwrap();
        assert_eq!(imported.public, original.public);

        // Import never overwrites an existing identity.
        assert!(user_keypair_import(&other, "alice", &exported).is_err());
        // Names that could escape the keys dir are rejected.
        assert!(user_keypair_load_or_create(&keys, "../escape").is_err());
        assert!(user_keypair_import(&other, "", &exported).is_err());
    }

    #[test]
    fn ed25519_rfc8032_section_7_1_test_1() {
        // RFC 8032 §7.1 TEST 1: empty message.
        let seed: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let public: [u8; 32] =
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .try_into()
                .unwrap();
        let sig: [u8; 64] = unhex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ))
        .try_into()
        .unwrap();
        let keypair = EdKeypair::from_secret_bytes(seed);
        assert_eq!(keypair.public, public);
        assert_eq!(keypair.sign(b""), sig);
        assert!(ed_verify(&public, b"", &sig));
    }

    #[test]
    fn ed25519_rfc8032_section_7_1_test_3() {
        // RFC 8032 §7.1 TEST 3: 2-byte message.
        let seed: [u8; 32] =
            unhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .try_into()
                .unwrap();
        let public: [u8; 32] =
            unhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .try_into()
                .unwrap();
        let msg = unhex("af82");
        let sig: [u8; 64] = unhex(concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ))
        .try_into()
        .unwrap();
        let keypair = EdKeypair::from_secret_bytes(seed);
        assert_eq!(keypair.public, public);
        assert_eq!(keypair.sign(&msg), sig);
        assert!(ed_verify(&public, &msg, &sig));
    }

    #[test]
    fn bundle_statement_binds_name_and_key() {
        // §19: a bundle signature is valid only for the exact (name, x25519
        // pub) pair it was made over — no replay for another user, no swap
        // of the encryption key.
        let ed = EdKeypair::generate();
        let x = UserKeypair::generate();
        let sig = ed.sign(&bundle_statement("alice", &x.public));
        assert!(ed_verify(&ed.public, &bundle_statement("alice", &x.public), &sig));
        assert!(!ed_verify(&ed.public, &bundle_statement("bob", &x.public), &sig));
        let other_x = UserKeypair::generate();
        assert!(!ed_verify(
            &ed.public,
            &bundle_statement("alice", &other_x.public),
            &sig
        ));
        // ...and only under the signing identity.
        let stranger = EdKeypair::generate();
        assert!(!ed_verify(
            &stranger.public,
            &bundle_statement("alice", &x.public),
            &sig
        ));
    }

    #[test]
    fn ed_verify_never_panics_on_garbage() {
        // Keys and signatures come off the wire: any byte pattern must be a
        // plain `false`, including small-order points and non-canonical
        // signatures (verify_strict rejects those).
        for pub_bytes in [[0u8; 32], [0xff; 32], [0x01; 32]] {
            for sig_bytes in [[0u8; 64], [0xff; 64]] {
                assert!(!ed_verify(&pub_bytes, b"anything", &sig_bytes));
            }
        }
        let ed = EdKeypair::generate();
        let x = UserKeypair::generate();
        let mut sig = ed.sign(&bundle_statement("alice", &x.public));
        sig[10] ^= 1;
        assert!(!ed_verify(
            &ed.public,
            &bundle_statement("alice", &x.public),
            &sig
        ));
    }

    #[test]
    fn ed_keypair_debug_redacts_seed() {
        let keypair = EdKeypair::generate();
        let debug = format!("{keypair:?}");
        assert!(!debug.contains(&hex_encode(keypair.secret_bytes())));
        assert!(debug.contains(&hex_encode(&keypair.public)));
    }

    #[test]
    fn ed_keypair_load_or_create_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let created = ed_keypair_load_or_create(&keys, "alice").unwrap();
        let key_path = keys.join("alice.ed25519");
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
        #[cfg(unix)]
        assert_eq!(mode_of(&key_path), 0o600);

        let loaded = ed_keypair_load_or_create(&keys, "alice").unwrap();
        assert_eq!(loaded.public, created.public);
        assert_eq!(loaded.secret_bytes(), created.secret_bytes());

        // A corrupted key file is an error, never a silently new identity.
        write_private_0600(&key_path, b"too short").unwrap();
        assert!(ed_keypair_load_or_create(&keys, "alice").is_err());
    }

    #[test]
    fn identity_export_import_moves_the_full_identity() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let x = user_keypair_load_or_create(&keys, "alice").unwrap();
        let ed = ed_keypair_load_or_create(&keys, "alice").unwrap();

        // Both halves: a 64-byte export that reinstalls the full identity.
        let exported = user_identity_export(&keys, "alice").unwrap();
        assert_eq!(exported.len(), 64);
        let other = dir.path().join("other-keys");
        user_identity_import(&other, "alice", &exported).unwrap();
        assert_eq!(
            user_keypair_load_or_create(&other, "alice").unwrap().public,
            x.public
        );
        assert_eq!(
            ed_keypair_load_or_create(&other, "alice").unwrap().public,
            ed.public
        );
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&other.join("alice.x25519")), 0o600);
            assert_eq!(mode_of(&other.join("alice.ed25519")), 0o600);
        }
        // Import refuses to overwrite ANY existing identity file...
        assert!(user_identity_import(&other, "alice", &exported).is_err());
        // ...including a lone ed25519 half facing an x25519-only import.
        let ed_only = dir.path().join("ed-only");
        ed_keypair_load_or_create(&ed_only, "bob").unwrap();
        let legacy: Vec<u8> = user_keypair_export(&keys, "alice").unwrap().to_vec();
        assert!(user_identity_import(&ed_only, "bob", &legacy).is_err());
        // Bad lengths never import.
        assert!(user_identity_import(&dir.path().join("c"), "carol", &[0u8; 33]).is_err());
    }

    #[test]
    fn identity_export_import_legacy_x25519_only() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let x = user_keypair_load_or_create(&keys, "alice").unwrap();

        // No ed25519 half yet: the export stays the legacy 32 bytes, and
        // the import lands x25519-only (keygen mints the ed half later).
        let exported = user_identity_export(&keys, "alice").unwrap();
        assert_eq!(exported.len(), 32);
        let other = dir.path().join("other-keys");
        user_identity_import(&other, "alice", &exported).unwrap();
        assert_eq!(
            user_keypair_load_or_create(&other, "alice").unwrap().public,
            x.public
        );
        assert!(!other.join("alice.ed25519").exists());

        // An ed25519-only identity is not exportable (ambiguous with the
        // legacy 32-byte shape), and a name with no keys at all errors too.
        let ed_only = dir.path().join("ed-only");
        ed_keypair_load_or_create(&ed_only, "bob").unwrap();
        assert!(user_identity_export(&ed_only, "bob").is_err());
        assert!(user_identity_export(&keys, "nobody").is_err());
    }
}
