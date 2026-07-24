//! Small filesystem helpers shared by the store and the apply engine.

use std::fs;
use std::io;
use std::path::Path;

/// Create (or truncate) a file readable/writable only by the owner: chunk
/// and staging contents can be secrets (`.env`) regardless of the source
/// file's mode.
#[cfg(unix)]
pub(crate) fn create_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

/// Restrict a directory to the owner (rwx------).
#[cfg(unix)]
pub(crate) fn set_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn set_private_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Reject a destination if any ancestor between `root` (exclusive) and the
/// destination's parent (inclusive) is a symlink. Manifests are network
/// input from M2 on: following a planted symlink would write or delete
/// outside the target tree. Missing ancestors are fine — they will be
/// created as real directories.
pub(crate) fn ensure_real_ancestors(root: &Path, dest: &Path) -> io::Result<()> {
    let mut cursor = dest.parent();
    while let Some(dir) = cursor {
        if dir == root {
            break;
        }
        match fs::symlink_metadata(dir) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing to follow symlinked ancestor {}", dir.display()),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        cursor = dir.parent();
    }
    Ok(())
}
