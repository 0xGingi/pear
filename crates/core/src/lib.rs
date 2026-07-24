pub mod apply;
pub mod chunk;
pub mod chunk_frame;
pub mod crypto;
pub mod e2e;
mod fsutil;
pub mod known_keys;
pub mod manifest;
pub mod relay;
pub mod scan;
pub mod snapshot;
pub mod store;
pub mod sync;
pub mod watch;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

/// Identity and format version of a managed workspace, kept in
/// `<workspace>/.pear/workspace.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMeta {
    pub id: String,
    pub version: u32,
}

/// Create `<path>/.pear/workspace.json` with a workspace id: `id` when
/// given (a mirror adopts the remote workspace's id), a fresh random one
/// otherwise. Idempotent: returns the existing metadata if already
/// initialized — but an explicit `id` that disagrees with the existing id
/// is an error, never a silent re-target.
pub fn init_workspace(path: &Path, id: Option<&str>) -> Result<(WorkspaceMeta, bool)> {
    if let Some(meta) = load_workspace(path)? {
        if let Some(want) = id {
            if meta.id != want {
                anyhow::bail!(
                    "{} is already workspace {}; refusing to re-target it to {want}",
                    path.display(),
                    meta.id
                );
            }
        }
        return Ok((meta, false));
    }
    let pear_dir = path.join(".pear");
    fs::create_dir_all(&pear_dir).with_context(|| format!("create {}", pear_dir.display()))?;
    // Holds workspace metadata and manifests: owner-only.
    crate::fsutil::set_private_dir(&pear_dir)?;
    let id = id
        .map(str::to_string)
        .unwrap_or_else(|| to_hex(&rand::random::<[u8; 16]>()));
    let meta = WorkspaceMeta {
        id,
        version: FORMAT_VERSION,
    };
    let json = serde_json::to_vec_pretty(&meta)?;
    manifest::write_file_atomic(&pear_dir.join("workspace.json"), &json)?;
    Ok((meta, true))
}

/// Load workspace metadata without creating anything: flows that must
/// target an existing workspace (checkout) use this instead of
/// `init_workspace`, which would otherwise mint a fresh id.
pub fn load_workspace(path: &Path) -> Result<Option<WorkspaceMeta>> {
    let meta_path = path.join(".pear").join("workspace.json");
    match fs::read(&meta_path) {
        Ok(data) => {
            Ok(Some(serde_json::from_slice(&data).with_context(|| {
                format!("parse {}", meta_path.display())
            })?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", meta_path.display())),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
