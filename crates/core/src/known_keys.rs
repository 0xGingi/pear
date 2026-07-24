//! Writer-side identity pinning (DESIGN.md §19): `$PEAR_HOME/known_keys`
//! maps user name → ed25519 fingerprint (the full hex of the identity
//! public key), pinned at the first VERIFIED wrap for that user — the SSH
//! known_hosts model, global across workspaces. A mismatch between the
//! served bundle and the pin is a loud, operator-visible event: pins are
//! never updated implicitly, only by `pear trust`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// The pin map: user name → ed25519 fingerprint (64 lowercase hex).
pub type KnownKeys = BTreeMap<String, String>;

/// The outcome of checking a served identity against the pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// No pin yet for this user: the first VERIFIED wrap pins it
    /// (identity-level TOFU — closed out-of-band via `pear user id`).
    FirstSight,
    /// The served identity matches the pin.
    Match,
    /// The served identity differs from the pin — possible relay/key
    /// tampering. The user is never wrapped to until `pear trust` re-pins
    /// explicitly.
    Mismatch,
}

/// Load the pins from `path`; a missing file is an empty map. A CORRUPT
/// file is an error, never a silent reset: quietly dropping the pins would
/// re-open the substitution window the file exists to close, so the
/// operator fixes or removes the file by hand.
pub fn load(path: &Path) -> Result<KnownKeys> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parse {} — the identity pins were NOT reset; fix or remove the file by hand",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KnownKeys::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Check a served ed25519 fingerprint against the pins.
pub fn check(map: &KnownKeys, user: &str, ed_hex: &str) -> PinCheck {
    match map.get(user) {
        None => PinCheck::FirstSight,
        Some(pinned) if pinned == ed_hex => PinCheck::Match,
        Some(_) => PinCheck::Mismatch,
    }
}

/// Pin `user` to `ed_hex`, replacing any previous pin. Callers: first-sight
/// pinning during wrap-maintenance, and the explicit `pear trust` re-pin —
/// never an implicit update on mismatch.
pub fn pin(map: &mut KnownKeys, user: &str, ed_hex: &str) {
    map.insert(user.to_string(), ed_hex.to_string());
}

/// Persist the pins owner-only (0600), atomically (tmp + fsync + rename,
/// like the manifests): a torn write must never leave a truncated file
/// that `load` would then refuse as corrupt.
pub fn save(path: &Path, map: &KnownKeys) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(map)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        // The file pins identities for private-key operations; its home is
        // owner-only like the keys dir.
        crate::fsutil::set_private_dir(parent).with_context(|| format!("chmod {}", parent.display()))?;
    }
    crate::manifest::write_file_atomic(path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn load_save_round_trip_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("home").join("known_keys");

        // A missing file is an empty map, not an error.
        assert_eq!(load(&path).unwrap(), KnownKeys::new());

        let mut pins = KnownKeys::new();
        pin(&mut pins, "alice", &"aa".repeat(32));
        pin(&mut pins, "bob", &"bb".repeat(32));
        save(&path, &pins).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(load(&path).unwrap(), pins);
    }

    #[test]
    fn check_buckets() {
        let mut pins = KnownKeys::new();
        let fp = "cc".repeat(32);
        assert_eq!(check(&pins, "alice", &fp), PinCheck::FirstSight);
        pin(&mut pins, "alice", &fp);
        assert_eq!(check(&pins, "alice", &fp), PinCheck::Match);
        assert_eq!(check(&pins, "alice", &"dd".repeat(32)), PinCheck::Mismatch);
        // A different user is still first sight.
        assert_eq!(check(&pins, "bob", &fp), PinCheck::FirstSight);
    }

    #[test]
    fn corrupt_file_is_an_error_never_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_keys");
        fs::write(&path, b"not json {").unwrap();
        let err = format!("{:#}", load(&path).unwrap_err());
        assert!(err.contains("NOT reset"), "{err}");
        // The file is left exactly as found for the operator.
        assert_eq!(fs::read(&path).unwrap(), b"not json {");
    }
}
