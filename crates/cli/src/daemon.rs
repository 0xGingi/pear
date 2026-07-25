//! `peard` daemon IPC surface (§16), shared by the `pear` CLI (client) and
//! `peard` (server). Newline-delimited JSON over a unix socket at
//! `$PEAR_HOME/daemon.sock` — one request, one response, no TCP.
//!
//! Tokens travel in `add_*` requests but live in daemon memory only: the
//! persisted [`Registration`] has no token field at all, and no response
//! echoes one.
//!
//! The module is compiled into both binaries; each uses only part of it
//! (the client sends, the server serves), so the `mod daemon;` declarations
//! carry `#[allow(dead_code)]`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::loops::LoopControl;

/// `$PEAR_HOME`, defaulting to `~/.pear`.
pub fn pear_home() -> Result<PathBuf> {
    match std::env::var_os("PEAR_HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home)),
        _ => {
            let home = std::env::var_os("HOME").context("neither PEAR_HOME nor HOME is set")?;
            Ok(PathBuf::from(home).join(".pear"))
        }
    }
}

pub fn socket_path(home: &Path) -> PathBuf {
    home.join("daemon.sock")
}

pub fn state_path(home: &Path) -> PathBuf {
    home.join("daemon.json")
}

/// A client request: one JSON line on the socket.
///
/// §32 BREAKING CHANGE: `add_watch` is now the LOCAL two-directory watch
/// only (`target` is required, and the relay/lease fields are gone), and
/// relay work registers as `add_converge`. A `daemon.json` written by a
/// pre-§32 peard holding relay watches fails to load on the role field —
/// personal project, no migration: delete it and re-`join`.
pub enum Request {
    /// `{"type":"add_watch","path":..,"target":..}`
    AddWatch { path: PathBuf, target: PathBuf },
    /// `{"type":"add_converge","path":..,"relay":..,"token":..,
    /// "workspace":..|null,"device":..|null,"team":..|null,"e2e":bool,
    /// "name":..|null,"tls_ca_cert":..|null}` — the §32 converge loop.
    AddConverge {
        path: PathBuf,
        relay: String,
        token: String,
        workspace: Option<String>,
        device: Option<String>,
        team: Option<String>,
        e2e: bool,
        name: Option<String>,
        tls_ca_cert: Option<PathBuf>,
    },
    /// `{"type":"add_mirror","path":..,"workspace":..,"relay":..,"token":..,
    /// "name":..|null,"tls_ca_cert":..|null}`
    AddMirror {
        path: PathBuf,
        workspace: String,
        relay: String,
        token: String,
        name: Option<String>,
        tls_ca_cert: Option<PathBuf>,
    },
    /// `{"type":"list"}`
    List,
    /// `{"type":"remove","path":..}`
    Remove { path: PathBuf },
    /// `{"type":"status","path":..|null}`
    Status { path: Option<PathBuf> },
    /// `{"type":"shutdown"}`
    Shutdown,
}

impl Request {
    pub fn to_json(&self) -> Value {
        match self {
            Request::AddWatch { path, target } => json!({
                "type": "add_watch",
                "path": path.to_string_lossy(),
                "target": target.to_string_lossy(),
            }),
            Request::AddConverge {
                path,
                relay,
                token,
                workspace,
                device,
                team,
                e2e,
                name,
                tls_ca_cert,
            } => json!({
                "type": "add_converge",
                "path": path.to_string_lossy(),
                "relay": relay,
                "token": token,
                "workspace": workspace,
                "device": device,
                "team": team,
                "e2e": e2e,
                "name": name,
                "tls_ca_cert": tls_ca_cert.as_ref().map(|t| t.to_string_lossy()),
            }),
            Request::AddMirror {
                path,
                workspace,
                relay,
                token,
                name,
                tls_ca_cert,
            } => json!({
                "type": "add_mirror",
                "path": path.to_string_lossy(),
                "workspace": workspace,
                "relay": relay,
                "token": token,
                "name": name,
                "tls_ca_cert": tls_ca_cert.as_ref().map(|t| t.to_string_lossy()),
            }),
            Request::List => json!({ "type": "list" }),
            Request::Remove { path } => {
                json!({ "type": "remove", "path": path.to_string_lossy() })
            }
            Request::Status { path } => json!({
                "type": "status",
                "path": path.as_ref().map(|p| p.to_string_lossy()),
            }),
            Request::Shutdown => json!({ "type": "shutdown" }),
        }
    }

    /// Parse one request. Anything unrecognized — bad JSON shape, unknown
    /// `type`, wrong field types — is an `Err`, never a panic (§16).
    pub fn from_json(v: &Value) -> Result<Request> {
        match opt_str(v, "type")?.as_deref() {
            Some("add_watch") => Ok(Request::AddWatch {
                path: PathBuf::from(req_str(v, "path")?),
                target: PathBuf::from(req_str(v, "target")?),
            }),
            Some("add_converge") => Ok(Request::AddConverge {
                path: PathBuf::from(req_str(v, "path")?),
                relay: req_str(v, "relay")?,
                token: req_str(v, "token")?,
                workspace: opt_str(v, "workspace")?,
                device: opt_str(v, "device")?,
                team: opt_str(v, "team")?,
                e2e: opt_bool(v, "e2e")?,
                name: opt_str(v, "name")?,
                tls_ca_cert: opt_str(v, "tls_ca_cert")?.map(PathBuf::from),
            }),
            Some("add_mirror") => Ok(Request::AddMirror {
                path: PathBuf::from(req_str(v, "path")?),
                workspace: req_str(v, "workspace")?,
                relay: req_str(v, "relay")?,
                token: req_str(v, "token")?,
                name: opt_str(v, "name")?,
                tls_ca_cert: opt_str(v, "tls_ca_cert")?.map(PathBuf::from),
            }),
            Some("list") => Ok(Request::List),
            Some("remove") => Ok(Request::Remove {
                path: PathBuf::from(req_str(v, "path")?),
            }),
            Some("status") => Ok(Request::Status {
                path: opt_str(v, "path")?.map(PathBuf::from),
            }),
            Some("shutdown") => Ok(Request::Shutdown),
            Some(other) => bail!("unknown request type {other:?}"),
            None => bail!("request is missing its \"type\" field"),
        }
    }
}

/// The one response to a request: `{"ok":true,"result":..}` or
/// `{"ok":false,"error":..}`.
pub struct Response {
    pub result: Option<Value>,
    pub error: Option<String>,
}

impl Response {
    pub fn ok(result: Value) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(message.into()),
        }
    }

    pub fn to_json(&self) -> Value {
        match &self.error {
            Some(error) => json!({ "ok": false, "error": error }),
            None => json!({ "ok": true, "result": self.result }),
        }
    }

    pub fn from_json(v: &Value) -> Result<Response> {
        match v.get("ok").and_then(Value::as_bool) {
            Some(true) => Ok(Response {
                result: v.get("result").cloned(),
                error: None,
            }),
            Some(false) => Ok(Response {
                result: None,
                error: Some(req_str(v, "error")?),
            }),
            None => bail!("response is missing its \"ok\" field"),
        }
    }

    /// The result payload, or the daemon's error message as an `Err`.
    pub fn into_result(self) -> Result<Value> {
        match self.error {
            Some(error) => bail!("peard: {error}"),
            None => Ok(self.result.unwrap_or(Value::Null)),
        }
    }
}

/// One workspace's live state, as reported by `list`/`status`. Never
/// carries a token (§16).
pub struct EntryInfo {
    pub path: PathBuf,
    /// "sync" (§32 converge) | "watch" (local) | "mirror"
    pub role: String,
    pub target: Option<PathBuf>,
    pub relay: Option<String>,
    pub workspace: Option<String>,
    /// "running" | "stopped" | "error"
    pub state: String,
    /// Last committed/applied head seq; 0 = none known.
    pub head_seq: u64,
    pub error: Option<String>,
}

impl EntryInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path.to_string_lossy(),
            "role": self.role,
            "target": self.target.as_ref().map(|t| t.to_string_lossy()),
            "relay": self.relay,
            "workspace": self.workspace,
            "state": self.state,
            "head_seq": self.head_seq,
            "error": self.error,
        })
    }

    pub fn from_json(v: &Value) -> Result<EntryInfo> {
        Ok(EntryInfo {
            path: PathBuf::from(req_str(v, "path")?),
            role: req_str(v, "role")?,
            target: opt_str(v, "target")?.map(PathBuf::from),
            relay: opt_str(v, "relay")?,
            workspace: opt_str(v, "workspace")?,
            state: req_str(v, "state")?,
            head_seq: opt_u64(v, "head_seq")?,
            error: opt_str(v, "error")?,
        })
    }

    /// Parse a `list`/`status` result payload (`{"workspaces":[..]}`).
    pub fn list_from_json(v: &Value) -> Result<Vec<EntryInfo>> {
        let entries = v
            .get("workspaces")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("result is missing its \"workspaces\" list"))?;
        entries.iter().map(EntryInfo::from_json).collect()
    }

    /// One-line summary for CLI confirmations.
    pub fn summary(&self) -> String {
        match self.role.as_str() {
            "sync" => format!(
                "sync {} (workspace {}, relay {})",
                self.path.display(),
                self.workspace.as_deref().unwrap_or("local id"),
                self.relay.as_deref().unwrap_or("?")
            ),
            "watch" => match &self.target {
                Some(target) => {
                    format!("watch {} -> {}", self.path.display(), target.display())
                }
                None => format!("watch {}", self.path.display()),
            },
            "mirror" => format!(
                "mirror {} (workspace {}, relay {})",
                self.path.display(),
                self.workspace.as_deref().unwrap_or("?"),
                self.relay.as_deref().unwrap_or("?")
            ),
            other => format!("{other} {}", self.path.display()),
        }
    }
}

/// The persisted registration list (`daemon.json`): paths + args, **no
/// tokens** (§16) — there is deliberately no token field to serialize. The
/// §17 CA, if any, is a PATH (public cert material), read at loop start.
#[derive(Clone)]
pub enum Registration {
    /// §32: one bidirectional converge loop for a relay workspace.
    Converge {
        path: PathBuf,
        relay: String,
        workspace: Option<String>,
        device: Option<String>,
        team: Option<String>,
        e2e: bool,
        name: Option<String>,
        tls_ca_cert: Option<PathBuf>,
    },
    /// Local two-directory watch (no relay).
    Watch { path: PathBuf, target: PathBuf },
    Mirror {
        path: PathBuf,
        workspace: String,
        relay: String,
        name: Option<String>,
        tls_ca_cert: Option<PathBuf>,
    },
}

impl Registration {
    pub fn path(&self) -> &Path {
        match self {
            Registration::Converge { path, .. }
            | Registration::Watch { path, .. }
            | Registration::Mirror { path, .. } => path,
        }
    }

    /// Registry key: the canonical path string recorded at registration.
    pub fn key(&self) -> String {
        self.path().to_string_lossy().into_owned()
    }

    pub fn role(&self) -> &'static str {
        match self {
            Registration::Converge { .. } => "sync",
            Registration::Watch { .. } => "watch",
            Registration::Mirror { .. } => "mirror",
        }
    }

    /// Relay workspaces need a bearer token to run; local watches do not.
    pub fn needs_token(&self) -> bool {
        !matches!(self, Registration::Watch { .. })
    }

    /// The live status view of a registered worker.
    pub fn entry_info(&self, control: &LoopControl) -> EntryInfo {
        let error = control.error();
        let (target, relay, workspace) = match self {
            Registration::Converge {
                relay, workspace, ..
            } => (None, Some(relay.clone()), workspace.clone()),
            Registration::Watch { target, .. } => (Some(target.clone()), None, None),
            Registration::Mirror {
                workspace, relay, ..
            } => (None, Some(relay.clone()), Some(workspace.clone())),
        };
        EntryInfo {
            path: self.path().to_path_buf(),
            role: self.role().to_string(),
            target,
            relay,
            workspace,
            state: if error.is_some() {
                "error"
            } else if control.stopped() {
                "stopped"
            } else {
                "running"
            }
            .to_string(),
            head_seq: control.head_seq(),
            error,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Registration::Converge {
                path,
                relay,
                workspace,
                device,
                team,
                e2e,
                name,
                tls_ca_cert,
            } => json!({
                "role": "sync",
                "path": path.to_string_lossy(),
                "relay": relay,
                "workspace": workspace,
                "device": device,
                "team": team,
                "e2e": e2e,
                "name": name,
                "tls_ca_cert": tls_ca_cert.as_ref().map(|t| t.to_string_lossy()),
            }),
            Registration::Watch { path, target } => json!({
                "role": "watch",
                "path": path.to_string_lossy(),
                "target": target.to_string_lossy(),
            }),
            Registration::Mirror {
                path,
                workspace,
                relay,
                name,
                tls_ca_cert,
            } => json!({
                "role": "mirror",
                "path": path.to_string_lossy(),
                "workspace": workspace,
                "relay": relay,
                "name": name,
                "tls_ca_cert": tls_ca_cert.as_ref().map(|t| t.to_string_lossy()),
            }),
        }
    }

    pub fn from_json(v: &Value) -> Result<Registration> {
        match opt_str(v, "role")?.as_deref() {
            Some("sync") => Ok(Registration::Converge {
                path: PathBuf::from(req_str(v, "path")?),
                relay: req_str(v, "relay")?,
                workspace: opt_str(v, "workspace")?,
                device: opt_str(v, "device")?,
                team: opt_str(v, "team")?,
                e2e: opt_bool(v, "e2e")?,
                name: opt_str(v, "name")?,
                tls_ca_cert: opt_str(v, "tls_ca_cert")?.map(PathBuf::from),
            }),
            Some("watch") => Ok(Registration::Watch {
                path: PathBuf::from(req_str(v, "path")?),
                target: PathBuf::from(req_str(v, "target")?),
            }),
            Some("mirror") => Ok(Registration::Mirror {
                path: PathBuf::from(req_str(v, "path")?),
                workspace: req_str(v, "workspace")?,
                relay: req_str(v, "relay")?,
                name: opt_str(v, "name")?,
                tls_ca_cert: opt_str(v, "tls_ca_cert")?.map(PathBuf::from),
            }),
            Some(other) => bail!("unknown registration role {other:?}"),
            None => bail!("registration is missing its \"role\" field"),
        }
    }
}

/// Persist the registration list as `$PEAR_HOME/daemon.json`, atomically
/// (tmp + rename) so a crash mid-write cannot corrupt the previous state.
pub fn save_state(home: &Path, registrations: &[Registration]) -> Result<()> {
    let doc = json!({
        "workspaces": registrations.iter().map(Registration::to_json).collect::<Vec<_>>(),
    });
    let tmp = home.join("daemon.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, state_path(home)).context("rename daemon.json into place")?;
    Ok(())
}

/// Load the persisted registration list; a missing file is an empty list,
/// a corrupt one is a startup error (never silently dropped state).
pub fn load_state(home: &Path) -> Result<Vec<Registration>> {
    let path = state_path(home);
    let data = match std::fs::read_to_string(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let doc: Value =
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    let list = doc
        .get("workspaces")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{}: missing \"workspaces\" list", path.display()))?;
    list.iter()
        .map(|v| Registration::from_json(v).with_context(|| format!("parse {}", path.display())))
        .collect()
}

/// The `"..."` string field `key`, or an error naming it.
fn req_str(v: &Value, key: &str) -> Result<String> {
    opt_str(v, key)?.ok_or_else(|| anyhow!("missing or invalid field {key:?}"))
}

/// An optional string field: absent and explicit null both mean `None`.
fn opt_str(v: &Value, key: &str) -> Result<Option<String>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => bail!("field {key:?} must be a string or null"),
    }
}

/// An optional boolean field, defaulting to false.
fn opt_bool(v: &Value, key: &str) -> Result<bool> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        _ => bail!("field {key:?} must be a boolean"),
    }
}

/// An optional u64 field, defaulting to 0.
fn opt_u64(v: &Value, key: &str) -> Result<u64> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| anyhow!("field {key:?} must be a non-negative integer")),
        _ => bail!("field {key:?} must be a non-negative integer"),
    }
}

#[cfg(unix)]
pub use transport::send;

/// The client transport: one request, one response (§16).
#[cfg(unix)]
mod transport {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    /// Send one request to the daemon at `$PEAR_HOME/daemon.sock` and read
    /// its one-line response. The socket must live in a 0700 same-uid
    /// `$PEAR_HOME` and itself be a 0700 same-uid socket — anything else
    /// could be another user's plant, and requests carry tokens.
    pub fn send(home: &Path, request: &Request) -> Result<Response> {
        let sock = socket_path(home);
        check_socket(home, &sock)?;
        let stream = UnixStream::connect(&sock).map_err(|e| match e.kind() {
            std::io::ErrorKind::ConnectionRefused => anyhow!(
                "no peard daemon is running (stale socket {}); start peard first",
                sock.display()
            ),
            _ => anyhow!("connect {}: {e}", sock.display()),
        })?;
        let mut writer = stream.try_clone()?;
        writeln!(writer, "{}", request.to_json())?;
        writer.flush()?;
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line)? == 0 {
            bail!("peard closed the connection without a response");
        }
        let doc: Value =
            serde_json::from_str(&line).context("peard sent an unparseable response")?;
        Response::from_json(&doc)
    }

    /// Same-uid 0700 checks on `$PEAR_HOME` and the socket (§16): the CLI
    /// refuses anything else rather than send tokens across a boundary.
    fn check_socket(home: &Path, sock: &Path) -> Result<()> {
        let dir = std::fs::metadata(home).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!(
                "no peard daemon is running ($PEAR_HOME {} does not exist); start peard first",
                home.display()
            ),
            _ => anyhow!("stat {}: {e}", home.display()),
        })?;
        let md = std::fs::symlink_metadata(sock).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!(
                "no peard daemon is running (no socket at {}); start peard first",
                sock.display()
            ),
            _ => anyhow!("stat {}: {e}", sock.display()),
        })?;
        let uid = our_uid(home)?;
        if dir.uid() != uid || dir.permissions().mode() & 0o777 != 0o700 {
            bail!(
                "refusing {}: $PEAR_HOME must be mode 0700 and owned by you (found mode {:o})",
                home.display(),
                dir.permissions().mode() & 0o777
            );
        }
        if !md.file_type().is_socket()
            || md.uid() != uid
            || md.permissions().mode() & 0o777 != 0o700
        {
            bail!(
                "refusing {}: the peard socket must be a socket of mode 0700 owned by you (found mode {:o})",
                sock.display(),
                md.permissions().mode() & 0o777
            );
        }
        Ok(())
    }

    /// std has no geteuid: the owner of a file we just created is us.
    fn our_uid(home: &Path) -> Result<u32> {
        let probe = home.join(format!(".uid-probe-{}", std::process::id()));
        let probe_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .with_context(|| {
                format!(
                    "cannot verify {} ownership (probe file failed)",
                    home.display()
                )
            })?;
        drop(probe_file);
        let uid = std::fs::metadata(&probe)?.uid();
        let _ = std::fs::remove_file(&probe);
        Ok(uid)
    }
}

#[cfg(not(unix))]
pub fn send(_home: &Path, _request: &Request) -> Result<Response> {
    bail!("peard IPC is only available on unix (§16)")
}
