//! Blocking HTTP client for the pear relay (§11), used by the writer
//! (`push_cycle`) and mirror (`pull_once`) flows. Blocking by design:
//! pear-core is a synchronous crate; the CLI runs cycles on plain threads.
//!
//! Wire conventions pinned by §11: bearer token on every request, JSON
//! bodies, `X-Pear-Device`/`X-Pear-Generation` lease headers on head
//! commits. Sequence numbers are `u64` with **0 meaning "no head yet"** —
//! sent as `0` rather than `null` so both `u64` and `Option<u64>` server
//! shapes accept it.

use std::fmt;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;
use crate::store::{ChunkSink, ChunkSource};

/// A lease generation that has not been acquired yet.
const NO_GENERATION: u64 = 0;

/// Per-request ceiling for control-plane calls so a wedged relay cannot
/// block a sync cycle forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling for data-path calls (head, chunks): the contract allows 256 MiB
/// bodies, and a large manifest over a slow link must not hit a permanent
/// timeout wall.
const DATA_TIMEOUT: Duration = Duration::from_secs(600);

/// Max hashes per `chunks/missing` call, matching the relay's cap: each
/// hash costs a visibility query under the relay's single DB mutex, so
/// one call must not stall every route. `chunks_missing` splits larger
/// lists transparently.
const MISSING_BATCH: usize = 50_000;

/// Errors from relay calls, split so the writer/mirror flows can tell a
/// lost lease (fatal) from a transient transport failure (retry).
#[derive(Debug)]
pub enum RelayError {
    /// 403: the lease is held by another device, the generation is stale,
    /// or the lease expired. The writer no longer owns the head.
    Fenced(String),
    /// 409 on `PUT /head`: the head moved past our `base_seq`.
    HeadConflict { current_seq: u64 },
    /// 409 on lease acquire: another device holds a valid lease.
    LeaseHeld {
        holder: String,
        expires_at: Option<String>,
    },
    /// 409 on lease transfer: requester not synced to head, or the current
    /// lease is neither expired nor the requester's.
    TransferRejected {
        holder: Option<String>,
        expires_at: Option<String>,
    },
    /// 404: workspace, head, or chunk does not exist.
    NotFound(String),
    /// A deterministic local-side rejection of relay data (invalid
    /// manifest, workspace-id mismatch): retrying cannot help, so loops
    /// must exit instead of polling forever.
    Fatal(String),
    /// Any other non-2xx response.
    Http { status: u16, body: String },
    /// Transport failure or an unparseable response.
    Transport(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::Fenced(why) => write!(f, "fenced: {why}"),
            RelayError::HeadConflict { current_seq } => {
                write!(f, "head conflict: relay head is at seq {current_seq}")
            }
            RelayError::LeaseHeld { holder, expires_at } => {
                write!(f, "lease held by {holder}{}", fmt_expiry(expires_at))
            }
            RelayError::TransferRejected { holder, expires_at } => match holder {
                Some(holder) => write!(
                    f,
                    "transfer rejected: lease held by {holder}{}",
                    fmt_expiry(expires_at)
                ),
                None => write!(f, "transfer rejected: requester not synced to head"),
            },
            RelayError::NotFound(what) => write!(f, "not found: {what}"),
            RelayError::Fatal(what) => write!(f, "fatal: {what}"),
            RelayError::Http { status, body } => write!(f, "HTTP {status}: {body}"),
            RelayError::Transport(why) => write!(f, "transport: {why}"),
        }
    }
}

impl std::error::Error for RelayError {}

fn fmt_expiry(expires_at: &Option<String>) -> String {
    expires_at
        .as_ref()
        .map(|e| format!(" (expires {e})"))
        .unwrap_or_default()
}

/// From a 403 body: lease fencing carries `"fenced": true` and maps to
/// `Fenced`; any other 403 is an auth/role failure and stays a generic
/// `Http` error, so the CLI's "token or role revoked" diagnostic can
/// fire instead of the misleading "LEASE LOST".
fn forbidden_from(body: &str) -> RelayError {
    #[derive(Deserialize)]
    struct ErrBody {
        error: String,
        #[serde(default)]
        fenced: bool,
    }
    match serde_json::from_str::<ErrBody>(body) {
        Ok(parsed) if parsed.fenced => RelayError::Fenced(parsed.error),
        _ => RelayError::Http {
            status: 403,
            body: body.to_string(),
        },
    }
}

/// From a 409 on `PUT /head`: a CAS conflict carries `current_seq`; the
/// §17 flavor mismatch (`kind: "e2e_mismatch"` — a plaintext head on an
/// e2e workspace or the reverse) is a deterministic rejection, so it maps
/// to `Fatal` and the writer exits instead of retrying it forever. §28's
/// `kind: "sync_env"` (a `.env*` manifest on a team that forbids it) is
/// deterministic the same way — nothing changes until the files go or an
/// owner lifts the policy — so it is `Fatal` too: even a client that
/// never learned the policy stops loudly instead of hammering the relay.
fn head_conflict(body: &str) -> RelayError {
    #[derive(Deserialize)]
    struct Conflict {
        #[serde(default)]
        current_seq: Option<u64>,
        #[serde(default)]
        kind: String,
        #[serde(default)]
        error: String,
    }
    match serde_json::from_str::<Conflict>(body) {
        Ok(c) if c.kind == "e2e_mismatch" => RelayError::Fatal(c.error),
        Ok(c) if c.kind == "sync_env" => RelayError::Fatal(c.error),
        Ok(c) if c.current_seq.is_some() => RelayError::HeadConflict {
            current_seq: c.current_seq.unwrap_or(0),
        },
        _ => RelayError::Http {
            status: 409,
            body: body.to_string(),
        },
    }
}

#[derive(Debug, Deserialize)]
pub struct LeaseInfo {
    pub holder: String,
    pub generation: u64,
    /// Server-defined timestamp (unix secs or RFC3339); carried opaquely.
    #[serde(default)]
    pub expires_at: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceInfo {
    pub id: String,
    pub name: String,
    /// Head sequence, normalized: 0 = no head committed yet.
    pub head_seq: u64,
    #[serde(default)]
    pub head_hash: Option<String>,
    #[serde(default)]
    pub lease: Option<LeaseInfo>,
    /// The team this workspace is attached to, if any.
    #[serde(default)]
    pub team_id: Option<String>,
    /// §17: end-to-end encrypted workspace (set at create, immutable).
    #[serde(default)]
    pub e2e: bool,
}

/// Raw wire shape so both `0` and `null` head fields parse.
#[derive(Deserialize)]
struct WorkspaceWire {
    id: String,
    name: String,
    #[serde(default)]
    head_seq: Option<u64>,
    #[serde(default)]
    head_hash: Option<String>,
    #[serde(default)]
    lease: Option<LeaseInfo>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    e2e: bool,
}

impl From<WorkspaceWire> for WorkspaceInfo {
    fn from(wire: WorkspaceWire) -> Self {
        Self {
            id: wire.id,
            name: wire.name,
            head_seq: wire.head_seq.unwrap_or(0),
            head_hash: wire.head_hash,
            lease: wire.lease,
            team_id: wire.team_id,
            e2e: wire.e2e,
        }
    }
}

#[derive(Debug)]
pub struct HeadInfo {
    pub seq: u64,
    pub hash: String,
    /// The manifest of a PLAIN head. An e2e head carries `manifest_enc`
    /// instead; this is then an empty placeholder — never read on the e2e
    /// path, which decrypts `manifest_enc` first.
    pub manifest: Manifest,
    /// §17 e2e head: base64 of the encrypted manifest blob.
    pub manifest_enc: Option<String>,
    /// Which manifest flavor this head carries (§17).
    pub e2e: bool,
}

#[derive(Debug, Deserialize)]
pub struct HeadCommit {
    pub seq: u64,
    pub hash: String,
}

/// A snapshot's metadata, as listed by `GET .../snapshots` (§12). `kind`
/// is `named` (CLI-made) or `checkpoint` (relay-made on lease force).
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotInfo {
    pub id: u64,
    pub name: Option<String>,
    pub kind: String,
    pub device: String,
    pub created_at: i64,
}

/// A fetched snapshot: metadata plus the immutable manifest. On an e2e
/// workspace the manifest is encrypted: `manifest_enc` carries the base64
/// blob and `manifest` is an empty placeholder (§17).
#[derive(Debug)]
pub struct Snapshot {
    pub info: SnapshotInfo,
    pub manifest: Manifest,
    pub manifest_enc: Option<String>,
    pub e2e: bool,
}

/// What the relay returns from `POST .../snapshots` (201).
#[derive(Debug, Deserialize)]
pub struct SnapshotCommit {
    pub id: u64,
    pub created_at: i64,
}

/// A freshly created user (§13): the token is returned once, at creation.
#[derive(Debug, Deserialize)]
pub struct UserCreated {
    pub name: String,
    pub token: String,
}

/// A team as listed by `GET /v1/teams` (§13). `sync_env` is the §28
/// `.env` kill switch; a pre-§28 relay does not serve the field, and the
/// default-true matches what such a relay enforces (nothing).
#[derive(Debug, Clone, Deserialize)]
pub struct TeamInfo {
    pub id: String,
    pub name: String,
    #[serde(default = "default_sync_env")]
    pub sync_env: bool,
}

fn default_sync_env() -> bool {
    true
}

/// A team membership as listed by `GET /v1/teams/:id/members` (§13); the
/// §17 pubkey is the member's registered X25519 public key, if enrolled.
/// §19 adds the nullable ed25519 identity and bundle signature halves —
/// null together on legacy pubkey-only rows and never-enrolled members.
#[derive(Debug, Clone, Deserialize)]
pub struct MemberInfo {
    pub user: String,
    pub role: String,
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub ed25519: Option<String>,
    #[serde(default)]
    pub sig: Option<String>,
}

/// A user's key bundle as served by `GET /v1/users/:name/key` (§19): the
/// §17 X25519 pubkey plus the nullable ed25519 identity and its signature
/// over the bundle statement for that name. All-null = never enrolled.
#[derive(Debug, Clone, Default)]
pub struct UserKeyBundle {
    pub pubkey: Option<String>,
    pub ed25519: Option<String>,
    pub sig: Option<String>,
}

/// Blocking client for one workspace on one relay. Cheap to clone; clones
/// share the connection pool and the lease generation, so a heartbeat
/// thread and the writer loop always fence on the same state.
#[derive(Clone)]
pub struct RelayClient {
    base_url: String,
    auth: String,
    workspace_id: String,
    device_id: String,
    generation: Arc<AtomicU64>,
    agent: ureq::Agent,
    /// Separate agent for data-path calls (head, chunks): large payloads
    /// get the longer DATA_TIMEOUT ceiling instead of the 30s default.
    data_agent: ureq::Agent,
    /// §17: an extra CA (self-signed/private deployments) trusted IN PLACE
    /// OF the default roots for both HTTPS and the §14 wss feed — curl
    /// `--cacert` semantics. `None` keeps ureq/tungstenite defaults.
    tls_ca: Option<Arc<Vec<CertificateDer<'static>>>>,
    /// §28: the attached team's `.env` policy as learned by the writer at
    /// watch startup. `Some(team_name)` = that team FORBIDS `.env` sync,
    /// and a push cycle whose scan captures `.env*` files refuses loudly
    /// (the only line for e2e; the relay 409s plaintext commits itself).
    /// Shared across clones like the lease generation: every clone of this
    /// client must agree on the policy.
    env_sync_forbidden_by: Arc<std::sync::Mutex<Option<String>>>,
}

impl RelayClient {
    pub fn new(base_url: &str, token: &str, workspace_id: &str, device_id: &str) -> Self {
        Self::build(base_url, token, workspace_id, device_id, None)
    }

    /// `new` with a private CA for the relay's TLS (§17): the PEM blocks
    /// are the only roots trusted by this client, applied uniformly to the
    /// ureq agents and the `head_changes` wss listener. Bad PEM fails here,
    /// before any request.
    pub fn with_tls_ca(
        base_url: &str,
        token: &str,
        workspace_id: &str,
        device_id: &str,
        tls_ca_pem: Option<&[u8]>,
    ) -> Result<Self, RelayError> {
        let tls_ca = tls_ca_pem.map(parse_ca_certs).transpose()?.map(Arc::new);
        Ok(Self::build(
            base_url,
            token,
            workspace_id,
            device_id,
            tls_ca,
        ))
    }

    fn build(
        base_url: &str,
        token: &str,
        workspace_id: &str,
        device_id: &str,
        tls_ca: Option<Arc<Vec<CertificateDer<'static>>>>,
    ) -> Self {
        let config = agent_config(REQUEST_TIMEOUT, &tls_ca);
        let data_config = agent_config(DATA_TIMEOUT, &tls_ca);
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth: format!("Bearer {token}"),
            workspace_id: workspace_id.to_string(),
            device_id: device_id.to_string(),
            generation: Arc::new(AtomicU64::new(NO_GENERATION)),
            agent: ureq::Agent::new_with_config(config),
            data_agent: ureq::Agent::new_with_config(data_config),
            tls_ca,
            // Default: no policy — a client that never learns one syncs
            // exactly as before §28 (the relay enforces its own side).
            env_sync_forbidden_by: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// §28: record the attached team's `.env` policy, learned at watch
    /// startup. `Some(team_name)` forbids `.env` sync (push cycles whose
    /// scan captures `.env*` files refuse); `None` allows it — either the
    /// team does or the workspace has no team at all.
    pub fn set_env_sync_policy(&self, forbidden_by: Option<String>) {
        *self
            .env_sync_forbidden_by
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = forbidden_by;
    }

    /// The team forbidding `.env` sync on this client's workspace, if any.
    pub fn env_sync_forbidden_by(&self) -> Option<String> {
        self.env_sync_forbidden_by
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// A client for relay-level calls that are not bound to one workspace
    /// (§13: users, teams, name resolution). Workspace-scoped calls on it
    /// address an empty id and will simply 404.
    pub fn unbound(base_url: &str, token: &str, device_id: &str) -> Self {
        Self::new(base_url, token, "", device_id)
    }

    /// `unbound` with a private CA for the relay's TLS (§17).
    pub fn unbound_with_tls_ca(
        base_url: &str,
        token: &str,
        device_id: &str,
        tls_ca_pem: Option<&[u8]>,
    ) -> Result<Self, RelayError> {
        Self::with_tls_ca(base_url, token, "", device_id, tls_ca_pem)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The lease generation this device believes it holds; `None` until a
    /// successful acquire/transfer/force sets it.
    pub fn generation(&self) -> Option<u64> {
        match self.generation.load(Ordering::SeqCst) {
            NO_GENERATION => None,
            g => Some(g),
        }
    }

    /// Record a generation handed out by the relay. Public so tests and
    /// future flows can adopt an externally observed generation.
    pub fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::SeqCst);
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/v1/workspaces/{}{path}",
            self.base_url,
            encode_segment(&self.workspace_id)
        )
    }

    /// Idempotent workspace registration: 201 created or 409 already there.
    pub fn create_workspace(&self, name: &str) -> Result<(), RelayError> {
        self.create_workspace_inner(name, None, false)
    }

    /// Idempotent workspace registration, optionally attached to a team at
    /// create (§13: same rule as the attach route — owner/writer in the
    /// team; 403/404 surface as errors).
    pub fn create_workspace_with_team(
        &self,
        name: &str,
        team_id: Option<&str>,
    ) -> Result<(), RelayError> {
        self.create_workspace_inner(name, team_id, false)
    }

    /// §17: register as an end-to-end encrypted workspace (immutable).
    /// Re-registering an existing PLAIN workspace as e2e (or the reverse)
    /// is the relay's `e2e_mismatch` 409 and surfaces as an error, not an
    /// idempotent success.
    pub fn create_workspace_e2e(
        &self,
        name: &str,
        team_id: Option<&str>,
    ) -> Result<(), RelayError> {
        self.create_workspace_inner(name, team_id, true)
    }

    fn create_workspace_inner(
        &self,
        name: &str,
        team_id: Option<&str>,
        e2e: bool,
    ) -> Result<(), RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            id: &'a str,
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            team_id: Option<&'a str>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            e2e: bool,
        }
        let mut resp = self
            .agent
            .post(format!("{}/v1/workspaces", self.base_url))
            .header("Authorization", &self.auth)
            .send_json(Body {
                id: &self.workspace_id,
                name,
                team_id,
                e2e,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            201 => Ok(()),
            // A 409 is only benign for `id_conflict` (already registered,
            // same flavor). A `name_conflict` or an `e2e_mismatch` means
            // the workspace was NOT (re)created.
            409 => {
                #[derive(Deserialize)]
                struct Conflict {
                    #[serde(default)]
                    kind: String,
                }
                let body = body_string(&mut resp);
                match serde_json::from_str::<Conflict>(&body) {
                    // Benign: already registered (idempotent re-register).
                    Ok(c) if c.kind == "id_conflict" => Ok(()),
                    // A name conflict, an e2e flavor mismatch — or anything
                    // unrecognized (empty, proxy-mangled, or a future body
                    // shape): the workspace was NOT created; fail here, not
                    // later with a confusing 404/403.
                    _ => Err(RelayError::Http {
                        status: 409,
                        body: format!("create workspace failed: {body}"),
                    }),
                }
            }
            status => Err(http_error("create workspace", status, &mut resp)),
        }
    }

    pub fn get_workspace(&self) -> Result<WorkspaceInfo, RelayError> {
        let mut resp = self
            .agent
            .get(self.url(""))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let wire: WorkspaceWire = read_json(&mut resp, "workspace")?;
                Ok(wire.into())
            }
            404 => Err(RelayError::NotFound(format!(
                "workspace {}",
                self.workspace_id
            ))),
            status => Err(http_error("get workspace", status, &mut resp)),
        }
    }

    /// The committed head, or `None` when the workspace has none (404). An
    /// e2e head carries `manifest_enc` (base64 of the encrypted manifest);
    /// a plain head carries `manifest`. Both flavors are required to be
    /// present for their type — a head missing its flavor is a protocol
    /// error, not an empty tree.
    pub fn get_head(&self) -> Result<Option<HeadInfo>, RelayError> {
        let mut resp = self
            .data_agent
            .get(self.url("/head"))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct Body {
                    seq: u64,
                    hash: String,
                    #[serde(default)]
                    e2e: bool,
                    #[serde(default)]
                    manifest: Option<Manifest>,
                    #[serde(default)]
                    manifest_enc: Option<String>,
                }
                let body: Body = read_json(&mut resp, "head")?;
                let manifest = match (body.e2e, body.manifest, body.manifest_enc) {
                    (true, _, Some(enc)) => enc,
                    (true, _, None) => {
                        return Err(RelayError::Transport(
                            "e2e head response carries no manifest_enc".to_string(),
                        ));
                    }
                    (false, Some(manifest), _) => {
                        return Ok(Some(HeadInfo {
                            seq: body.seq,
                            hash: body.hash,
                            manifest,
                            manifest_enc: None,
                            e2e: false,
                        }));
                    }
                    (false, None, _) => {
                        return Err(RelayError::Transport(
                            "head response carries no manifest".to_string(),
                        ));
                    }
                };
                Ok(Some(HeadInfo {
                    seq: body.seq,
                    hash: body.hash,
                    manifest: Manifest::new(self.workspace_id.clone()),
                    manifest_enc: Some(manifest),
                    e2e: true,
                }))
            }
            404 => Ok(None),
            status => Err(http_error("get head", status, &mut resp)),
        }
    }

    /// Commit a new head (compare-and-swap on `base_seq`, 0 = no head yet).
    /// Carries the lease headers; 403 means fenced, 409 means the head moved.
    pub fn put_head(&self, base_seq: u64, manifest: &Manifest) -> Result<HeadCommit, RelayError> {
        let generation = self.generation().ok_or_else(|| {
            RelayError::Fenced("no lease generation: acquire the lease first".to_string())
        })?;
        #[derive(Serialize)]
        struct Body<'a> {
            base_seq: u64,
            manifest: &'a Manifest,
        }
        let mut resp = self
            .data_agent
            .put(self.url("/head"))
            .header("Authorization", &self.auth)
            .header("X-Pear-Device", &self.device_id)
            .header("X-Pear-Generation", generation.to_string())
            .send_json(Body { base_seq, manifest })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => read_json(&mut resp, "head commit"),
            403 => Err(forbidden_from(&body_string(&mut resp))),
            409 => Err(head_conflict(&body_string(&mut resp))),
            status => Err(http_error("put head", status, &mut resp)),
        }
    }

    /// §17: commit a new head on an e2e workspace — the encrypted manifest
    /// (base64) plus the ciphertext hashes it references. Same CAS and
    /// fencing as `put_head`; the relay cannot see the manifest itself.
    pub fn put_head_e2e(
        &self,
        base_seq: u64,
        manifest_enc: &str,
        chunk_hashes: &[String],
    ) -> Result<HeadCommit, RelayError> {
        let generation = self.generation().ok_or_else(|| {
            RelayError::Fenced("no lease generation: acquire the lease first".to_string())
        })?;
        #[derive(Serialize)]
        struct Body<'a> {
            base_seq: u64,
            manifest_enc: &'a str,
            chunk_hashes: &'a [String],
        }
        let mut resp = self
            .data_agent
            .put(self.url("/head"))
            .header("Authorization", &self.auth)
            .header("X-Pear-Device", &self.device_id)
            .header("X-Pear-Generation", generation.to_string())
            .send_json(Body {
                base_seq,
                manifest_enc,
                chunk_hashes,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => read_json(&mut resp, "head commit"),
            403 => Err(forbidden_from(&body_string(&mut resp))),
            409 => Err(head_conflict(&body_string(&mut resp))),
            status => Err(http_error("put head", status, &mut resp)),
        }
    }

    /// Batch presence check against the relay's global chunk pool: the
    /// subset of `hashes` the relay does *not* have. Splits into
    /// `MISSING_BATCH`-sized calls — the relay caps each request to
    /// bound the DB work any single call can hold the mutex for.
    pub fn chunks_missing(&self, hashes: &[String]) -> Result<Vec<String>, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            hashes: &'a [String],
        }
        #[derive(Deserialize)]
        struct Missing {
            missing: Vec<String>,
        }
        let mut out = Vec::new();
        for batch in hashes.chunks(MISSING_BATCH) {
            let mut resp = self
                .data_agent
                .post(self.url("/chunks/missing"))
                .header("Authorization", &self.auth)
                .send_json(Body { hashes: batch })
                .map_err(transport)?;
            match resp.status().as_u16() {
                200 => out.extend(read_json::<Missing>(&mut resp, "chunks/missing")?.missing),
                status => return Err(http_error("chunks/missing", status, &mut resp)),
            }
        }
        Ok(out)
    }

    pub fn put_chunk(&self, hash: &str, data: &[u8]) -> Result<(), RelayError> {
        let mut resp = self
            .data_agent
            .put(self.url(&format!("/chunks/{}", encode_segment(hash))))
            .header("Authorization", &self.auth)
            .send(data)
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            status => Err(http_error("put chunk", status, &mut resp)),
        }
    }

    pub fn get_chunk(&self, hash: &str) -> Result<Vec<u8>, RelayError> {
        let mut resp = self
            .data_agent
            .get(self.url(&format!("/chunks/{}", encode_segment(hash))))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => read_body_capped(&mut resp, "chunk", crate::chunk::MAX_CHUNK_SIZE as u64),
            404 => Err(RelayError::NotFound(format!("chunk {hash}"))),
            status => Err(http_error("get chunk", status, &mut resp)),
        }
    }

    /// §23 batched upload: `entries` are (hash, blob) pairs sent through
    /// `chunks/put_many` as octet-stream frames, split transparently into
    /// ≤256-entry/≤32 MiB sub-batches (the caps live in `chunk_frame` and
    /// are enforced by the relay too). Results concatenate in request
    /// order: (hash, status, reason?) with status `"stored" | "present" |
    /// "error"`. A sub-batch that fails at the HTTP level aborts the whole
    /// call — the results already collected are discarded, so the caller
    /// must treat unconfirmed entries as not uploaded (dedupe makes their
    /// retry cheap).
    pub fn put_chunks(
        &self,
        entries: &[(String, Vec<u8>)],
    ) -> Result<Vec<(String, String, Option<String>)>, RelayError> {
        #[derive(Deserialize)]
        struct PutResult {
            hash: String,
            status: String,
            reason: Option<String>,
        }
        #[derive(Deserialize)]
        struct PutManyResponse {
            results: Vec<PutResult>,
        }
        let mut out = Vec::with_capacity(entries.len());
        let mut start = 0;
        while start < entries.len() {
            // First-fit sub-batch under both caps. A lone entry bigger
            // than the byte cap cannot come from the chunker (4 MiB max),
            // but a hand-fed one is sent alone for the relay's per-entry
            // validation to reject — never an infinite loop here.
            let mut end = start;
            let mut bytes = 0u64;
            while end < entries.len()
                && end - start < crate::chunk_frame::PUT_MANY_MAX_ENTRIES
                && bytes + entries[end].1.len() as u64 <= crate::chunk_frame::PUT_MANY_MAX_BYTES
            {
                bytes += entries[end].1.len() as u64;
                end += 1;
            }
            if end == start {
                end += 1;
            }
            let batch = &entries[start..end];
            let frame =
                crate::chunk_frame::encode(batch.iter().map(|(h, d)| (h.as_str(), d.as_slice())));
            let mut resp = self
                .data_agent
                .post(self.url("/chunks/put_many"))
                .header("Authorization", &self.auth)
                .header("Content-Type", "application/octet-stream")
                .send(frame)
                .map_err(transport)?;
            match resp.status().as_u16() {
                200 => {
                    let body: PutManyResponse = read_json(&mut resp, "chunks/put_many")?;
                    // One result per entry, in order: statuses map
                    // POSITIONALLY onto the request entries, so a short or
                    // long answer is a protocol error, never a partial
                    // success to align by hash.
                    if body.results.len() != batch.len() {
                        return Err(RelayError::Transport(format!(
                            "chunks/put_many returned {} results for {} entries",
                            body.results.len(),
                            batch.len()
                        )));
                    }
                    out.extend(
                        body.results
                            .into_iter()
                            .map(|r| (r.hash, r.status, r.reason)),
                    );
                }
                status => return Err(http_error("chunks/put_many", status, &mut resp)),
            }
            start = end;
        }
        Ok(out)
    }

    /// §23 batched download: the chunks for `hashes`, in request order,
    /// fetched through `chunks/get_many` in ≤128-hash sub-batches. That
    /// internal split is only the safety net (the hard wire cap): callers
    /// with manifest knowledge budget BYTES per batch — a file's chunks
    /// partition it exactly, so `FileEntry::size` is the exact cost of its
    /// chunk group (§30, `chunk_frame::GET_MANY_TARGET_BYTES`). A
    /// response whose entry count differs from the request's is a
    /// protocol error, never a silent truncation. The per-chunk BLAKE3
    /// wire-verify is the CALLER's job and does not move (§23).
    pub fn get_chunks(&self, hashes: &[String]) -> Result<Vec<(String, Vec<u8>)>, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            hashes: &'a [String],
        }
        let mut out = Vec::with_capacity(hashes.len());
        for batch in hashes.chunks(crate::chunk_frame::GET_MANY_MAX_HASHES) {
            let mut resp = self
                .data_agent
                .post(self.url("/chunks/get_many"))
                .header("Authorization", &self.auth)
                .send_json(Body { hashes: batch })
                .map_err(transport)?;
            match resp.status().as_u16() {
                200 => {
                    // The response is structurally bounded: ≤128 chunks ×
                    // MAX_CHUNK_SIZE plus per-entry headers (§23) — a
                    // compromised or buggy relay (§7: semi-trusted) must
                    // not exhaust client memory past that.
                    let cap = crate::chunk_frame::GET_MANY_MAX_HASHES as u64
                        * (crate::chunk::MAX_CHUNK_SIZE as u64 + 72)
                        + 4;
                    let frame = read_body_capped(&mut resp, "chunks/get_many", cap)?;
                    let entries = crate::chunk_frame::decode(&frame).map_err(|e| {
                        RelayError::Transport(format!("invalid chunks/get_many frame: {e:#}"))
                    })?;
                    if entries.len() != batch.len() {
                        return Err(RelayError::Transport(format!(
                            "chunks/get_many returned {} entries for {} hashes",
                            entries.len(),
                            batch.len()
                        )));
                    }
                    out.extend(entries);
                }
                // The relay names the offending hash in the body: callers
                // pre-check via chunks/missing, so this is the
                // heal-delete race firing loud (§23).
                404 => {
                    return Err(RelayError::NotFound(format!(
                        "chunks/get_many: {}",
                        body_string(&mut resp)
                    )));
                }
                status => return Err(http_error("chunks/get_many", status, &mut resp)),
            }
        }
        Ok(out)
    }

    /// Record an immutable snapshot of `manifest` (§12): no lease, no CAS —
    /// a snapshot moves nothing. This device is recorded as the creator.
    pub fn create_snapshot(
        &self,
        name: Option<&str>,
        manifest: &Manifest,
    ) -> Result<SnapshotCommit, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            name: Option<&'a str>,
            device: &'a str,
            manifest: &'a Manifest,
        }
        let mut resp = self
            .data_agent
            .post(self.url("/snapshots"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                name,
                device: &self.device_id,
                manifest,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            201 => read_json(&mut resp, "snapshot commit"),
            404 => Err(RelayError::NotFound(format!(
                "workspace {}",
                self.workspace_id
            ))),
            status => Err(http_error("create snapshot", status, &mut resp)),
        }
    }

    /// §17: record an immutable snapshot of an e2e workspace — the
    /// encrypted manifest (base64) plus the ciphertext hashes it
    /// references. Same trust boundary as `create_snapshot`.
    pub fn create_snapshot_e2e(
        &self,
        name: Option<&str>,
        manifest_enc: &str,
        chunk_hashes: &[String],
    ) -> Result<SnapshotCommit, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            name: Option<&'a str>,
            device: &'a str,
            manifest_enc: &'a str,
            chunk_hashes: &'a [String],
        }
        let mut resp = self
            .data_agent
            .post(self.url("/snapshots"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                name,
                device: &self.device_id,
                manifest_enc,
                chunk_hashes,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            201 => read_json(&mut resp, "snapshot commit"),
            404 => Err(RelayError::NotFound(format!(
                "workspace {}",
                self.workspace_id
            ))),
            status => Err(http_error("create snapshot", status, &mut resp)),
        }
    }

    /// All snapshots of this workspace, newest first.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            snapshots: Vec<SnapshotInfo>,
        }
        let mut resp = self
            .agent
            .get(self.url("/snapshots"))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(read_json::<Body>(&mut resp, "snapshot list")?.snapshots),
            404 => Err(RelayError::NotFound(format!(
                "workspace {}",
                self.workspace_id
            ))),
            status => Err(http_error("list snapshots", status, &mut resp)),
        }
    }

    /// One snapshot with its manifest; a missing snapshot (or workspace)
    /// surfaces as `NotFound`. On an e2e workspace the snapshot carries
    /// `manifest_enc` (base64 of the encrypted manifest) and `manifest` is
    /// an empty placeholder (§17).
    pub fn get_snapshot(&self, id: u64) -> Result<Snapshot, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            id: u64,
            name: Option<String>,
            kind: String,
            device: String,
            created_at: i64,
            #[serde(default)]
            e2e: bool,
            #[serde(default)]
            manifest: Option<Manifest>,
            #[serde(default)]
            manifest_enc: Option<String>,
        }
        let mut resp = self
            .data_agent
            .get(self.url(&format!("/snapshots/{id}")))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let body: Body = read_json(&mut resp, "snapshot")?;
                let info = SnapshotInfo {
                    id: body.id,
                    name: body.name,
                    kind: body.kind,
                    device: body.device,
                    created_at: body.created_at,
                };
                match (body.e2e, body.manifest, body.manifest_enc) {
                    (true, _, Some(enc)) => Ok(Snapshot {
                        info,
                        manifest: Manifest::new(self.workspace_id.clone()),
                        manifest_enc: Some(enc),
                        e2e: true,
                    }),
                    (true, _, None) => Err(RelayError::Transport(
                        "e2e snapshot response carries no manifest_enc".to_string(),
                    )),
                    (false, Some(manifest), _) => Ok(Snapshot {
                        info,
                        manifest,
                        manifest_enc: None,
                        e2e: false,
                    }),
                    (false, None, _) => Err(RelayError::Transport(
                        "snapshot response carries no manifest".to_string(),
                    )),
                }
            }
            404 => Err(RelayError::NotFound(format!(
                "snapshot {id} in workspace {}",
                self.workspace_id
            ))),
            status => Err(http_error("get snapshot", status, &mut resp)),
        }
    }

    /// Acquire (or re-affirm) the lease; stores the generation on success.
    pub fn acquire(&self) -> Result<u64, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            device_id: &'a str,
        }
        #[derive(Deserialize)]
        struct Granted {
            generation: u64,
        }
        let mut resp = self
            .agent
            .post(self.url("/lease/acquire"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                device_id: &self.device_id,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let granted: Granted = read_json(&mut resp, "lease acquire")?;
                self.set_generation(granted.generation);
                Ok(granted.generation)
            }
            409 => {
                let body = body_string(&mut resp);
                Err(match lease_holder(&body) {
                    Some((holder, expires_at)) => RelayError::LeaseHeld { holder, expires_at },
                    None => RelayError::Http { status: 409, body },
                })
            }
            status => Err(http_error("lease acquire", status, &mut resp)),
        }
    }

    /// Heartbeat the held lease; 403 means we have been fenced.
    pub fn heartbeat(&self) -> Result<(), RelayError> {
        let generation = self.generation().ok_or_else(|| {
            RelayError::Fenced("no lease generation: acquire the lease first".to_string())
        })?;
        #[derive(Serialize)]
        struct Body<'a> {
            device_id: &'a str,
            generation: u64,
        }
        let mut resp = self
            .agent
            .post(self.url("/lease/heartbeat"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                device_id: &self.device_id,
                generation,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            403 => Err(forbidden_from(&body_string(&mut resp))),
            status => Err(http_error("lease heartbeat", status, &mut resp)),
        }
    }

    /// Ask the relay to hand the lease to this device (§11: allowed when
    /// synced to head and the current lease is expired or already ours).
    /// Sends the last observed generation, read from the workspace record.
    pub fn transfer(&self, base_seq: u64) -> Result<u64, RelayError> {
        let observed = self
            .get_workspace()?
            .lease
            .map(|l| l.generation)
            .unwrap_or(NO_GENERATION);
        #[derive(Serialize)]
        struct Body<'a> {
            device_id: &'a str,
            generation: u64,
            base_seq: u64,
        }
        #[derive(Deserialize)]
        struct Granted {
            generation: u64,
        }
        let mut resp = self
            .agent
            .post(self.url("/lease/transfer"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                device_id: &self.device_id,
                generation: observed,
                base_seq,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let granted: Granted = read_json(&mut resp, "lease transfer")?;
                self.set_generation(granted.generation);
                Ok(granted.generation)
            }
            409 => {
                let body = body_string(&mut resp);
                let (holder, expires_at) = lease_holder(&body).unwrap_or((String::new(), None));
                Err(RelayError::TransferRejected {
                    holder: if holder.is_empty() {
                        None
                    } else {
                        Some(holder)
                    },
                    expires_at,
                })
            }
            status => Err(http_error("lease transfer", status, &mut resp)),
        }
    }

    /// Force-take the lease; always succeeds, bumps the generation and
    /// fences the previous writer.
    pub fn force(&self) -> Result<u64, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            device_id: &'a str,
        }
        #[derive(Deserialize)]
        struct Granted {
            generation: u64,
        }
        let mut resp = self
            .agent
            .post(self.url("/lease/force"))
            .header("Authorization", &self.auth)
            .send_json(Body {
                device_id: &self.device_id,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let granted: Granted = read_json(&mut resp, "lease force")?;
                self.set_generation(granted.generation);
                Ok(granted.generation)
            }
            status => Err(http_error("lease force", status, &mut resp)),
        }
    }

    // --- users and teams (§13) --------------------------------------------

    /// Create a user (admin only; 403 for a user token). The returned token
    /// is shown once — it is never listed back.
    pub fn create_user(&self, name: &str) -> Result<UserCreated, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            name: &'a str,
        }
        let mut resp = self
            .agent
            .post(format!("{}/v1/users", self.base_url))
            .header("Authorization", &self.auth)
            .send_json(Body { name })
            .map_err(transport)?;
        match resp.status().as_u16() {
            201 => read_json(&mut resp, "create user"),
            status => Err(http_error("create user", status, &mut resp)),
        }
    }

    /// Register the caller's signed key bundle (§19): self only — the
    /// relay 403s when the token's user is not `:name`, and 400s unless
    /// the signature verifies over the canonical statement for `:name`.
    /// Re-registration replaces the bundle.
    pub fn put_key_bundle(
        &self,
        name: &str,
        x25519_hex: &str,
        ed25519_hex: &str,
        sig_hex: &str,
    ) -> Result<(), RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            x25519: &'a str,
            ed25519: &'a str,
            sig: &'a str,
        }
        let mut resp = self
            .agent
            .put(format!(
                "{}/v1/users/{}/key",
                self.base_url,
                encode_segment(name)
            ))
            .header("Authorization", &self.auth)
            .send_json(Body {
                x25519: x25519_hex,
                ed25519: ed25519_hex,
                sig: sig_hex,
            })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            status => Err(http_error("register key bundle", status, &mut resp)),
        }
    }

    /// A user's registered key bundle (§19) — any authenticated user may
    /// read it: pubkeys are public by design. All-null fields mean the
    /// user never enrolled; a null ed25519/sig pair on a non-null pubkey
    /// is a legacy pre-§19 row. A missing user is a typed 404.
    pub fn get_key(&self, name: &str) -> Result<UserKeyBundle, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            pubkey: Option<String>,
            ed25519: Option<String>,
            sig: Option<String>,
        }
        let mut resp = self
            .agent
            .get(format!(
                "{}/v1/users/{}/key",
                self.base_url,
                encode_segment(name)
            ))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let body = read_json::<Body>(&mut resp, "user key")?;
                Ok(UserKeyBundle {
                    pubkey: body.pubkey,
                    ed25519: body.ed25519,
                    sig: body.sig,
                })
            }
            404 => Err(RelayError::NotFound(format!("user {name}"))),
            status => Err(http_error("get key", status, &mut resp)),
        }
    }

    /// Store the workspace key wrapped for a member (§17): workspace
    /// writer/owner only. `blob_hex` is the hex of one sealed-box wrap.
    pub fn put_wrapped_key(&self, user: &str, blob_hex: &str) -> Result<(), RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            blob: &'a str,
        }
        let mut resp = self
            .agent
            .put(self.url(&format!("/keys/{}", encode_segment(user))))
            .header("Authorization", &self.auth)
            .send_json(Body { blob: blob_hex })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("put wrapped key", status, &mut resp)),
        }
    }

    /// The caller's own wrapped workspace key (hex) — how a mirror/clone
    /// onboards on an e2e workspace (§17). A 404 means the writer never
    /// wrapped a key for this user (or the caller has no role at all).
    pub fn get_my_wrapped_key(&self) -> Result<String, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            blob: String,
        }
        let mut resp = self
            .agent
            .get(self.url("/keys/me"))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(read_json::<Body>(&mut resp, "wrapped key")?.blob),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("get wrapped key", status, &mut resp)),
        }
    }

    /// Delete the wrapped key stored for a member (§20), when their team
    /// removal rotated the keyring: their old wrap must not keep unwrapping
    /// for anyone who somehow holds their identity. Workspace writer/owner
    /// only (same gate as the PUT). Idempotent — the relay answers 204
    /// whether or not a row existed, so a retried rotation pass converges.
    pub fn delete_wrapped_key(&self, user: &str) -> Result<(), RelayError> {
        let mut resp = self
            .agent
            .delete(self.url(&format!("/keys/{}", encode_segment(user))))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            204 => Ok(()),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("delete wrapped key", status, &mut resp)),
        }
    }

    /// Create a team; the caller becomes its first owner.
    pub fn create_team(&self, name: &str) -> Result<TeamInfo, RelayError> {
        self.create_team_inner(name, None)
    }

    /// §28: create a team with its `.env` policy set (`--no-env` passes
    /// false). An absent flag means true — the product promise.
    pub fn create_team_with_policy(
        &self,
        name: &str,
        sync_env: bool,
    ) -> Result<TeamInfo, RelayError> {
        self.create_team_inner(name, Some(sync_env))
    }

    fn create_team_inner(
        &self,
        name: &str,
        sync_env: Option<bool>,
    ) -> Result<TeamInfo, RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            sync_env: Option<bool>,
        }
        let mut resp = self
            .agent
            .post(format!("{}/v1/teams", self.base_url))
            .header("Authorization", &self.auth)
            .send_json(Body { name, sync_env })
            .map_err(transport)?;
        match resp.status().as_u16() {
            201 => read_json(&mut resp, "create team"),
            status => Err(http_error("create team", status, &mut resp)),
        }
    }

    /// Set a team's §28 `.env` policy (`PUT /v1/teams/:id/policy`). Team
    /// owner only — the relay 403s everyone else, including the admin.
    pub fn set_team_policy(&self, team_id: &str, sync_env: bool) -> Result<TeamInfo, RelayError> {
        #[derive(Serialize)]
        struct Body {
            sync_env: bool,
        }
        let mut resp = self
            .agent
            .put(format!(
                "{}/v1/teams/{}/policy",
                self.base_url,
                encode_segment(team_id)
            ))
            .header("Authorization", &self.auth)
            .send_json(Body { sync_env })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => read_json(&mut resp, "set team policy"),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("set team policy", status, &mut resp)),
        }
    }

    /// The teams the caller belongs to (admin: all teams).
    pub fn list_teams(&self) -> Result<Vec<TeamInfo>, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            teams: Vec<TeamInfo>,
        }
        let mut resp = self
            .agent
            .get(format!("{}/v1/teams", self.base_url))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(read_json::<Body>(&mut resp, "team list")?.teams),
            status => Err(http_error("list teams", status, &mut resp)),
        }
    }

    /// Add (or re-role) a team member. Team owner only; 404 when the team
    /// or the target user does not exist.
    pub fn team_add_member(&self, team_id: &str, user: &str, role: &str) -> Result<(), RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            user: &'a str,
            role: &'a str,
        }
        let mut resp = self
            .agent
            .post(format!(
                "{}/v1/teams/{}/members",
                self.base_url,
                encode_segment(team_id)
            ))
            .header("Authorization", &self.auth)
            .send_json(Body { user, role })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("add team member", status, &mut resp)),
        }
    }

    /// A team's members (members only).
    pub fn team_members(&self, team_id: &str) -> Result<Vec<MemberInfo>, RelayError> {
        #[derive(Deserialize)]
        struct Body {
            members: Vec<MemberInfo>,
        }
        let mut resp = self
            .agent
            .get(format!(
                "{}/v1/teams/{}/members",
                self.base_url,
                encode_segment(team_id)
            ))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(read_json::<Body>(&mut resp, "member list")?.members),
            404 => Err(RelayError::NotFound(format!("team {team_id}"))),
            status => Err(http_error("list team members", status, &mut resp)),
        }
    }

    /// Remove a member from a team (§20): team owner, or any member
    /// removing themselves (leaving). Idempotent — the relay answers 204
    /// whether or not the user was a member; removing the team's last
    /// owner is a 409. The departed member's wrapped workspace keys die
    /// with the membership.
    pub fn team_remove_member(&self, team_id: &str, user: &str) -> Result<(), RelayError> {
        let mut resp = self
            .agent
            .delete(format!(
                "{}/v1/teams/{}/members/{}",
                self.base_url,
                encode_segment(team_id),
                encode_segment(user)
            ))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            204 => Ok(()),
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("remove team member", status, &mut resp)),
        }
    }

    /// Attach this client's workspace to a team (§13: workspace owner who
    /// is also owner/writer in the team).
    pub fn attach_team(&self, team_id: &str) -> Result<(), RelayError> {
        #[derive(Serialize)]
        struct Body<'a> {
            team_id: &'a str,
        }
        let mut resp = self
            .agent
            .post(self.url("/team"))
            .header("Authorization", &self.auth)
            .send_json(Body { team_id })
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            // A 404 here also covers "you have no role on this workspace"
            // (§13 existence hiding) — it stays `NotFound`.
            404 => Err(RelayError::NotFound(body_string(&mut resp))),
            status => Err(http_error("attach team", status, &mut resp)),
        }
    }

    /// Resolve a `team/name` reference to the workspace record (§13
    /// onboarding). Any role on the workspace suffices; a 404 means the
    /// team, the workspace, or the caller's role does not exist.
    pub fn resolve_workspace(&self, team: &str, name: &str) -> Result<WorkspaceInfo, RelayError> {
        let mut resp = self
            .agent
            .get(format!(
                "{}/v1/teams/{}/workspaces/{}",
                self.base_url,
                encode_segment(team),
                encode_segment(name)
            ))
            .header("Authorization", &self.auth)
            .call()
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => {
                let wire: WorkspaceWire = read_json(&mut resp, "workspace")?;
                Ok(wire.into())
            }
            404 => Err(RelayError::NotFound(format!("workspace {team}/{name}"))),
            status => Err(http_error("resolve workspace", status, &mut resp)),
        }
    }

    /// Subscribe to the relay's head feed (§14 hints, §21 catch-up):
    /// `ws(s)://<relay>/v1/ws?workspace=<id>` with the same bearer token,
    /// on a blocking tungstenite listener thread. The thread is a §21
    /// reconnect supervisor: it runs the one-shot listener, and on any
    /// exit sleeps a backoff (1s, ×2 per consecutive failure, capped at
    /// 30s, reset after a connection stayed up ≥ 2× keepalive) and
    /// respawns. §14's "no reconnect storm" objection is answered by the
    /// backoff rather than by giving up forever, and each reconnect is
    /// productive because the relay's `head_now` catch-up reports the
    /// current head. Returns `None` when the base URL is not http(s).
    pub fn head_changes(&self) -> Option<HeadFeed> {
        let url = self.ws_url()?;
        let (tx, rx) = std::sync::mpsc::channel();
        let connected = Arc::new(AtomicBool::new(false));
        {
            let auth = self.auth.clone();
            let workspace = self.workspace_id.clone();
            let connected = connected.clone();
            let tls_ca = self.tls_ca.clone();
            // Detached: the caller polls whenever the feed is not live.
            let _ = std::thread::spawn(move || {
                ws_listen(&url, &auth, &workspace, tx, connected, tls_ca)
            });
        }
        Some(HeadFeed { rx, connected })
    }

    /// The `ws://`/`wss://` URL of this workspace's `head_changed` feed
    /// (§14), derived from the relay base URL.
    fn ws_url(&self) -> Option<String> {
        let base = if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            let rest = self.base_url.strip_prefix("https://")?;
            format!("wss://{rest}")
        };
        Some(format!(
            "{base}/v1/ws?workspace={}",
            encode_segment(&self.workspace_id)
        ))
    }
}

/// The relay is a `ChunkSink` for the writer flow: presence checks and
/// uploads go through the batch endpoints (§23) so a push never does
/// per-chunk HTTP calls.
impl ChunkSink for RelayClient {
    fn has(&self, hash: &str) -> std::io::Result<bool> {
        // Presence via the batch endpoint too: downloading the whole chunk
        // just to test existence would be a silent regression.
        let missing = self
            .chunks_missing(std::slice::from_ref(&hash.to_string()))
            .map_err(io_other)?;
        Ok(missing.is_empty())
    }

    fn has_many(&self, hashes: &[String]) -> std::io::Result<Vec<bool>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        let missing: std::collections::HashSet<String> = self
            .chunks_missing(hashes)
            .map_err(io_other)?
            .into_iter()
            .collect();
        Ok(hashes.iter().map(|h| !missing.contains(h)).collect())
    }

    fn put(&self, hash: &str, data: &[u8]) -> std::io::Result<bool> {
        // The endpoint is idempotent and does not report prior presence;
        // the writer flow only calls this for chunks the batch check
        // reported missing, so every put here is a real upload.
        self.put_chunk(hash, data).map_err(io_other)?;
        Ok(true)
    }

    fn put_many(&self, entries: &[(String, Vec<u8>)]) -> std::io::Result<Vec<Result<bool, String>>> {
        // §23: one batched call (split internally). A transport/HTTP
        // failure fails the WHOLE call — the BatchUploader then keeps
        // every unconfirmed chunk buffered, exactly like the first
        // failure in a per-chunk loop. A per-entry `"error"` status maps
        // to Err(reason) for just that entry, so one deterministically
        // bad chunk cannot wedge the rest of the batch.
        let results = self.put_chunks(entries).map_err(io_other)?;
        Ok(results
            .into_iter()
            .map(|(hash, status, reason)| match status.as_str() {
                "stored" => Ok(true),
                "present" => Ok(false),
                // An UNKNOWN status is an error too: never confirm a chunk
                // the relay did not explicitly store or dedupe.
                _ => Err(reason
                    .unwrap_or_else(|| format!("unexpected put_many status {status:?} for {hash}"))),
            })
            .collect())
    }
}

/// The relay is a `ChunkSource` too (mirror fetch path goes through the
/// local store, but the trait keeps the seam symmetric).
impl ChunkSource for RelayClient {
    fn get(&self, hash: &str) -> std::io::Result<Vec<u8>> {
        self.get_chunk(hash).map_err(|e| match e {
            RelayError::NotFound(what) => std::io::Error::new(std::io::ErrorKind::NotFound, what),
            other => io_other(other),
        })
    }
}

fn io_other(e: RelayError) -> std::io::Error {
    std::io::Error::other(e)
}

/// Percent-encode one URL path segment (RFC 3986 unreserved set): team
/// and workspace names may contain spaces or other reserved bytes, and
/// must round-trip through the resolve route.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn transport(e: ureq::Error) -> RelayError {
    RelayError::Transport(e.to_string())
}

/// One agent config (control or data plane). Without a private CA the
/// ureq defaults apply (WebPKI roots); with one, exactly those certs are
/// trusted (§17 — no skip-verify mode anywhere).
fn agent_config(
    timeout: Duration,
    tls_ca: &Option<Arc<Vec<CertificateDer<'static>>>>,
) -> ureq::config::Config {
    let builder = ureq::Agent::config_builder()
        // 4xx/5xx carry typed meaning (fencing, conflicts): read their
        // bodies instead of letting ureq flatten them into one error.
        .http_status_as_error(false)
        .timeout_global(Some(timeout));
    match tls_ca {
        Some(certs) => {
            let certs: Vec<ureq::tls::Certificate<'static>> = certs
                .iter()
                .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
                .collect();
            builder
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                        .build(),
                )
                .build()
        }
        None => builder.build(),
    }
}

/// Parse the PEM of `--tls-ca-cert`/`PEAR_TLS_CA` (§17) into DER certs,
/// failing on bad PEM or on material webpki cannot use as roots — loudly,
/// before any request goes out.
fn parse_ca_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, RelayError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RelayError::Fatal(format!("invalid TLS CA PEM: {e}")))?;
    let mut store = rustls::RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(certs.iter().cloned());
    if added == 0 {
        return Err(RelayError::Fatal(
            "TLS CA PEM has no usable CA certificates".to_string(),
        ));
    }
    Ok(certs)
}

fn read_json<T: serde::de::DeserializeOwned>(
    resp: &mut ureq::http::Response<ureq::Body>,
    what: &str,
) -> Result<T, RelayError> {
    let bytes = read_body(resp, what)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| RelayError::Transport(format!("invalid {what} response: {e}")))
}

/// Read a JSON or manifest response body without ureq's Body helpers:
/// their default read limit (10 MB) is far below the relay's manifest
/// contract (256 MiB). Still capped — a compromised or buggy relay (§7:
/// semi-trusted) must not exhaust client memory with an unbounded
/// stream before any hash/parse validation runs.
fn read_body(
    resp: &mut ureq::http::Response<ureq::Body>,
    what: &str,
) -> Result<Vec<u8>, RelayError> {
    read_body_capped(resp, what, 256 * 1024 * 1024)
}

fn read_body_capped(
    resp: &mut ureq::http::Response<ureq::Body>,
    what: &str,
    cap: u64,
) -> Result<Vec<u8>, RelayError> {
    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| RelayError::Transport(format!("read {what} body: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(RelayError::Transport(format!(
            "{what} body exceeds the {cap}-byte limit"
        )));
    }
    Ok(buf)
}

fn body_string(resp: &mut ureq::http::Response<ureq::Body>) -> String {
    read_body(resp, "error")
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

fn http_error(op: &str, status: u16, resp: &mut ureq::http::Response<ureq::Body>) -> RelayError {
    RelayError::Http {
        status,
        body: format!("{op} failed: {}", body_string(resp)),
    }
}

/// Parse a `{ holder, expires_at }` conflict body; `expires_at` may be a
/// string or a unix timestamp.
fn lease_holder(body: &str) -> Option<(String, Option<String>)> {
    #[derive(Deserialize)]
    struct Held {
        holder: String,
        #[serde(default)]
        expires_at: serde_json::Value,
    }
    let held: Held = serde_json::from_str(body).ok()?;
    let expires_at = match &held.expires_at {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    };
    Some((held.holder, expires_at))
}

// --- WebSocket head feed (§14 hints, §21 catch-up + reconnect) --------------

/// A mirror's view of the relay's head stream: head seq hints arrive over
/// an mpsc channel while the listener thread holds a WebSocket open —
/// `head_now` on (re)connect (§21), then `head_changed` per commit (§14).
/// The hints are a latency optimization only — the mirror's poll remains
/// the correctness mechanism.
pub struct HeadFeed {
    rx: std::sync::mpsc::Receiver<u64>,
    connected: Arc<AtomicBool>,
}

impl HeadFeed {
    /// True while a listener attempt holds an open WebSocket: the mirror
    /// may relax its poll interval. False means pure polling (between
    /// §21 reconnect attempts included).
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Wait up to `dur` for the next head seq hint. The §21 supervisor
    /// keeps its sender alive across reconnect attempts, so a `Disconnected`
    /// should not occur in production; if the listener thread ever dies
    /// with its sender dropped, `recv_timeout` would return it early and
    /// the mirror would busy-loop instead of falling back to polling —
    /// normalize that case into waiting out the REST of the interval,
    /// exactly what pure polling does between pulls.
    pub fn recv_timeout(&self, dur: Duration) -> Result<u64, std::sync::mpsc::RecvTimeoutError> {
        let start = std::time::Instant::now();
        match self.rx.recv_timeout(dur) {
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(dur.saturating_sub(start.elapsed()));
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            }
            other => other,
        }
    }

    /// Drop hints queued ahead of a pull: the pull covers them. Hints
    /// arriving during the pull stay queued and wake the next wait.
    pub fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }
}

/// §21 reconnect supervisor behind [`RelayClient::head_changes`]: run the
/// one-shot listener, and on ANY exit (connect refused, dead read,
/// lag-close from the relay) sleep the backoff and respawn. The backoff
/// answers §14's "no reconnect storm" objection; the relay's `head_now`
/// catch-up makes each reconnect productive, so a blip (sleep, roam,
/// relay restart) no longer demotes the mirror to pure polling forever.
/// The mpsc channel is created once by the caller and shared by every
/// attempt (sender cloned per attempt), so hints from any generation of
/// the connection land in the same stream; `connected` flips per attempt
/// (false during the backoff sleep, so the mirror polls fast while
/// disconnected). The loop ends only when the hint channel's receiver is
/// gone — with no mirror reading, respawning would just burn a relay
/// connection slot forever.
fn ws_listen(
    url: &str,
    auth: &str,
    workspace: &str,
    tx: std::sync::mpsc::Sender<u64>,
    connected: Arc<AtomicBool>,
    tls_ca: Option<Arc<Vec<CertificateDer<'static>>>>,
) {
    let mut backoff = WS_RECONNECT_MIN;
    loop {
        let attempt_start = std::time::Instant::now();
        let exit = ws_listen_keepalive(
            url,
            auth,
            workspace,
            tx.clone(),
            connected.clone(),
            WS_KEEPALIVE,
            tls_ca.clone(),
        );
        if let FeedExit::Orphaned = exit {
            return;
        }
        // Sleep the CURRENT delay, then schedule the next: a long-lived
        // connection was healthy until now, so its death is a fresh blip
        // and the schedule restarts at 1s; otherwise it doubles, capped.
        std::thread::sleep(backoff);
        backoff = next_backoff(backoff, attempt_start.elapsed() >= WS_RECONNECT_RESET);
    }
}

/// First reconnect delay after a failed listener attempt (§21).
const WS_RECONNECT_MIN: Duration = Duration::from_secs(1);

/// Cap of the §21 reconnect backoff: the storm objection is answered by
/// never letting consecutive retries come faster than this apart.
const WS_RECONNECT_MAX: Duration = Duration::from_secs(30);

/// A connection that stayed up at least this long counts as stable, so
/// the backoff schedule resets to [`WS_RECONNECT_MIN`] (2× the keepalive:
/// a feed this old has already proven it can live through ping cycles).
const WS_RECONNECT_RESET: Duration = Duration::from_secs(90);

/// The §21 backoff schedule, pure so it is unit-testable: after a stable
/// connection (`was_stable`) the next failure is a fresh blip — restart at
/// 1s; otherwise double the current delay, capped at 30s.
fn next_backoff(current: Duration, was_stable: bool) -> Duration {
    if was_stable {
        WS_RECONNECT_MIN
    } else {
        current.saturating_mul(2).min(WS_RECONNECT_MAX)
    }
}

/// Why one listener attempt ended (§21): the supervisor respawns on every
/// exit EXCEPT a gone receiver.
#[derive(Debug, PartialEq, Eq)]
enum FeedExit {
    /// Connect/read failure, protocol close, lag-close from the relay:
    /// back off and respawn.
    Dead,
    /// The hint channel's receiver is dropped (the mirror is gone):
    /// stop supervising.
    Orphaned,
}

/// Connect the §14 feed socket. Without a private CA this is exactly
/// `tungstenite::connect`; with one, the TCP connect happens here (the
/// crate's one-shot `connect` takes no connector) and the handshake runs
/// over a rustls config trusting exactly the `--tls-ca-cert` roots (§17)
/// — the same root set the ureq agents use.
fn ws_connect(
    request: tungstenite::http::Request<()>,
    tls_ca: Option<&[CertificateDer<'static>]>,
) -> tungstenite::Result<(
    tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    tungstenite::handshake::client::Response,
)> {
    let Some(certs) = tls_ca else {
        return tungstenite::connect(request);
    };
    use tungstenite::stream::Mode;
    let mode = tungstenite::client::uri_mode(request.uri())?;
    let host = request.uri().host().ok_or(tungstenite::Error::Url(
        tungstenite::error::UrlError::NoHostName,
    ))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = request.uri().port_u16().unwrap_or(match mode {
        Mode::Plain => 80,
        Mode::Tls => 443,
    });
    let stream = std::net::TcpStream::connect((host, port))?;
    stream.set_nodelay(true)?;
    let connector = tungstenite::Connector::Rustls(rustls_client_config(certs));
    tungstenite::client_tls_with_config(request, stream, None, Some(connector)).map_err(|e| {
        match e {
            tungstenite::HandshakeError::Failure(f) => f,
            // Blocking stream: the handshake never suspends mid-way.
            tungstenite::HandshakeError::Interrupted(_) => {
                unreachable!("blocking handshake cannot be interrupted")
            }
        }
    })
}

/// A rustls client config trusting exactly `certs` as roots (§17).
fn rustls_client_config(certs: &[CertificateDer<'static>]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(certs.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Silence tolerance of the WS keepalive: after this much quiet the
/// listener pings; no pong within one more interval means the feed is
/// dead. A relay that vanishes without a FIN (partition, NAT expiry)
/// must not pin the mirror on the 5-minute "live feed" poll forever —
/// the §21 supervisor respawns the listener, but only once the death is
/// noticed.
const WS_KEEPALIVE: Duration = Duration::from_secs(45);

/// One listener attempt (§14/§21): connect, forward every head seq hint
/// for our workspace (`head_now` on connect, then `head_changed`), and
/// report how the attempt ended so the §21 supervisor can decide whether
/// to respawn. `connected` tracks the live socket and is reset on exit.
fn ws_listen_keepalive(
    url: &str,
    auth: &str,
    workspace: &str,
    tx: std::sync::mpsc::Sender<u64>,
    connected: Arc<AtomicBool>,
    keepalive: Duration,
    tls_ca: Option<Arc<Vec<CertificateDer<'static>>>>,
) -> FeedExit {
    /// Flip the feed to disconnected on every exit path below.
    struct DisconnectOnDrop(Arc<AtomicBool>);
    impl Drop for DisconnectOnDrop {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _reset_on_exit = DisconnectOnDrop(connected);

    // `IntoClientRequest` fills in the handshake headers (Host, key, …);
    // a bare `http::Request` would be rejected as headerless. The bearer
    // token rides along exactly like on the HTTP calls.
    let Ok(mut request) = tungstenite::client::IntoClientRequest::into_client_request(url) else {
        return FeedExit::Dead;
    };
    let Ok(auth) = tungstenite::http::HeaderValue::from_str(auth) else {
        return FeedExit::Dead;
    };
    request.headers_mut().insert("Authorization", auth);
    // A relay without the /ws route, a hidden workspace (404), a refused
    // connection: the attempt is Dead, and between the supervisor's
    // backoff-spaced retries the mirror stays in pure polling, exactly as
    // before §14.
    let Ok((mut socket, _response)) =
        ws_connect(request, tls_ca.as_ref().map(|certs| certs.as_slice()))
    else {
        return FeedExit::Dead;
    };
    _reset_on_exit.0.store(true, Ordering::SeqCst);
    // Bound every read: a silently dead relay sends no FIN, so an
    // unbounded read would keep `connected` true forever and the mirror
    // would idle on the 5-minute "live feed" poll with no hints ever
    // coming. After one quiet interval we ping; no pong by the next means
    // dead.
    {
        use tungstenite::stream::MaybeTlsStream;
        let timeout_set = match socket.get_mut() {
            MaybeTlsStream::Plain(tcp) => tcp.set_read_timeout(Some(keepalive)),
            MaybeTlsStream::Rustls(tls) => tls.sock.set_read_timeout(Some(keepalive)),
            _ => Ok(()),
        };
        if timeout_set.is_err() {
            return FeedExit::Dead;
        }
    }
    let mut ping_outstanding = false;
    loop {
        match socket.read() {
            Ok(msg) => {
                ping_outstanding = false;
                if let tungstenite::Message::Text(text) = msg {
                    if let Some(seq) = parse_head_hint(text.as_str(), workspace) {
                        // The mirror is gone; nothing left to hint, and the
                        // supervisor must not respawn for nobody.
                        if tx.send(seq).is_err() {
                            return FeedExit::Orphaned;
                        }
                    }
                }
                // Pings (auto-ponged by tungstenite), pongs, binary
                // frames: not part of the §14 contract, but any frame
                // proves the relay is alive.
            }
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if ping_outstanding {
                    return FeedExit::Dead; // no pong within a keepalive interval
                }
                if socket
                    .send(tungstenite::Message::Ping(Vec::new().into()))
                    .is_err()
                {
                    return FeedExit::Dead;
                }
                ping_outstanding = true;
            }
            Err(_) => return FeedExit::Dead,
        }
    }
}

/// Parse one head hint — `{ "type": "head_now" | "head_changed",
/// "workspace": id, "seq": n }` (§21 / §14). Both kinds mean "pull now"
/// and feed the same seq channel; anything else — hints for another
/// workspace, unknown message types (additive-compat), junk — is ignored.
fn parse_head_hint(text: &str, workspace: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Hint {
        #[serde(rename = "type")]
        kind: String,
        workspace: String,
        seq: u64,
    }
    let hint: Hint = serde_json::from_str(text).ok()?;
    (matches!(hint.kind.as_str(), "head_now" | "head_changed") && hint.workspace == workspace)
        .then_some(hint.seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_derives_scheme_and_path() {
        let client = RelayClient::new("http://localhost:7700/", "tok", "ws-1", "dev");
        assert_eq!(
            client.ws_url().as_deref(),
            Some("ws://localhost:7700/v1/ws?workspace=ws-1")
        );
        let client = RelayClient::new("https://relay.example.com", "tok", "ws-1", "dev");
        assert_eq!(
            client.ws_url().as_deref(),
            Some("wss://relay.example.com/v1/ws?workspace=ws-1")
        );
        let client = RelayClient::new("ftp://nope", "tok", "ws-1", "dev");
        assert!(client.ws_url().is_none());
    }

    #[test]
    fn parse_head_hint_accepts_head_now_and_head_changed() {
        let hint = r#"{"type":"head_changed","workspace":"ws-1","seq":7}"#;
        assert_eq!(parse_head_hint(hint, "ws-1"), Some(7));
        // §21: the catch-up message parses identically, into the same seq.
        let now = r#"{"type":"head_now","workspace":"ws-1","seq":9}"#;
        assert_eq!(parse_head_hint(now, "ws-1"), Some(9));
        // Another workspace, another message type (additive-compat), junk:
        // all ignored.
        assert_eq!(parse_head_hint(hint, "ws-2"), None);
        assert_eq!(parse_head_hint(now, "ws-2"), None);
        let other = r#"{"type":"something_else","workspace":"ws-1","seq":7}"#;
        assert_eq!(parse_head_hint(other, "ws-1"), None);
        assert_eq!(parse_head_hint("not json", "ws-1"), None);
    }

    #[test]
    fn next_backoff_doubles_to_the_cap_and_resets_after_a_stable_run() {
        // §21 schedule: 1, 2, 4, 8, 16, 30, 30, … while failures repeat.
        let mut backoff = WS_RECONNECT_MIN;
        assert_eq!(backoff, Duration::from_secs(1));
        for want in [2, 4, 8, 16, 30, 30, 30] {
            backoff = next_backoff(backoff, false);
            assert_eq!(backoff, Duration::from_secs(want));
        }
        // A connection that stayed up ≥ 2× keepalive was stable: the next
        // failure is a fresh blip and the schedule restarts at 1s…
        assert_eq!(next_backoff(backoff, true), Duration::from_secs(1));
        // …and doubles again from there.
        assert_eq!(
            next_backoff(next_backoff(backoff, true), false),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn head_changes_stays_disconnected_when_connect_fails() {
        // Nothing listens on the port: every connect attempt fails at
        // once, and the feed reports pure-polling mode between the §21
        // supervisor's backoff-spaced retries.
        let client = RelayClient::new("http://127.0.0.1:1", "tok", "ws-1", "dev");
        let feed = client.head_changes().expect("http base url");
        assert!(!feed.connected());
        // The supervisor keeps its sender alive across retries, so the
        // wait simply times out — it must block out the full interval
        // rather than error early and busy-loop the mirror (0s-delay
        // pulls hammering the relay).
        let start = std::time::Instant::now();
        assert!(feed.recv_timeout(Duration::from_secs(2)).is_err());
        assert!(
            start.elapsed() >= Duration::from_secs(2),
            "a dead feed must wait out the poll interval, not spin"
        );
        assert!(!feed.connected());
    }

    #[test]
    fn recv_timeout_waits_out_only_the_remainder_when_the_listener_dies() {
        // The listener dies MID-WAIT: normalization must not sleep a
        // second full interval on top (the mirror would stall up to 2x
        // the poll interval before downgrading to 2s polling).
        let (tx, rx) = std::sync::mpsc::channel();
        let feed = HeadFeed {
            rx,
            connected: Arc::new(AtomicBool::new(true)),
        };
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(tx); // the listener thread dying drops its sender
        });
        let start = std::time::Instant::now();
        assert!(feed.recv_timeout(Duration::from_secs(2)).is_err());
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3),
            "the total wait must be one interval, not two: {elapsed:?}"
        );
    }

    #[test]
    fn forbidden_from_distinguishes_fencing_from_auth() {
        // Lease fencing (the relay marks the body) → Fenced.
        match forbidden_from(r#"{"error":"heartbeat fenced: not the lease holder","fenced":true}"#)
        {
            RelayError::Fenced(why) => assert!(why.contains("heartbeat fenced")),
            other => panic!("expected Fenced, got {other:?}"),
        }
        // Auth/role 403 (no marker) → generic Http, so the CLI prints its
        // "token or role revoked" diagnostic instead of "LEASE LOST".
        match forbidden_from(r#"{"error":"insufficient role"}"#) {
            RelayError::Http { status, .. } => assert_eq!(status, 403),
            other => panic!("expected Http 403, got {other:?}"),
        }
        // Free-form/empty bodies stay generic too.
        match forbidden_from("") {
            RelayError::Http { status, .. } => assert_eq!(status, 403),
            other => panic!("expected Http 403, got {other:?}"),
        }
    }

    #[test]
    fn ws_listener_exits_when_the_relay_goes_silent() {
        // A relay that dies without a FIN (partition, NAT expiry): the
        // handshake completes, then silence. The keepalive must give up —
        // a feed stuck "connected" would pin the mirror on the 5-minute
        // poll with no hints ever arriving.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ws = tungstenite::accept(stream).unwrap();
            std::thread::sleep(Duration::from_secs(60)); // never reads: no pongs
        });

        let (tx, rx) = std::sync::mpsc::channel();
        let connected = Arc::new(AtomicBool::new(false));
        let exit = ws_listen_keepalive(
            &format!("ws://{addr}/v1/ws?workspace=ws-1"),
            "test-auth",
            "ws-1",
            tx,
            connected.clone(),
            Duration::from_millis(50),
            None,
        );
        // A silent relay is a Dead exit: the §21 supervisor respawns.
        assert_eq!(exit, FeedExit::Dead);
        assert!(!connected.load(Ordering::SeqCst));
        // No hints arrived from the dead feed: the mirror falls back to
        // pure polling instead of trusting a silent feed.
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_err());
    }

    /// §21: the listener forwards the relay's `head_now` catch-up into the
    /// same seq channel as `head_changed` — both mean "pull now".
    #[test]
    fn ws_listener_forwards_head_now_then_head_changed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            ws.send(tungstenite::Message::Text(
                r#"{"type":"head_now","workspace":"ws-1","seq":9}"#.into(),
            ))
            .unwrap();
            ws.send(tungstenite::Message::Text(
                r#"{"type":"head_changed","workspace":"ws-1","seq":10}"#.into(),
            ))
            .unwrap();
            // A message for another workspace must not leak through.
            ws.send(tungstenite::Message::Text(
                r#"{"type":"head_now","workspace":"ws-2","seq":11}"#.into(),
            ))
            .unwrap();
            std::thread::sleep(Duration::from_millis(500)); // hold the socket open
        });

        let (tx, rx) = std::sync::mpsc::channel();
        let connected = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn(move || {
            ws_listen_keepalive(
                &format!("ws://{addr}/v1/ws?workspace=ws-1"),
                "test-auth",
                "ws-1",
                tx,
                connected,
                Duration::from_secs(5),
                None,
            )
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(9));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(10));
        // No third hint: ws-2's head_now was ignored.
        assert!(rx.recv_timeout(Duration::from_millis(700)).is_err());
        drop(rx);
        let _ = worker.join();
    }

    /// §21 integration: when the connection drops, the supervisor respawns
    /// the listener after the backoff and the NEW connection's `head_now`
    /// arrives on the same channel — one feed across relay restarts.
    #[test]
    fn head_changes_reconnects_and_gets_a_fresh_head_now() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Connection 1: one catch-up, then a dropped connection
            // (closing the socket is what a relay restart looks like).
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            ws.send(tungstenite::Message::Text(
                r#"{"type":"head_now","workspace":"ws-1","seq":3}"#.into(),
            ))
            .unwrap();
            drop(ws);
            drop(listener);
            // Rebind the same port (std sets SO_REUSEADDR on unix) and
            // serve the reconnect a FRESH catch-up — the head moved on
            // while the client was away.
            let listener = std::net::TcpListener::bind(addr).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            ws.send(tungstenite::Message::Text(
                r#"{"type":"head_now","workspace":"ws-1","seq":4}"#.into(),
            ))
            .unwrap();
            std::thread::sleep(Duration::from_millis(500)); // hold the socket open
        });

        let client = RelayClient::new(&format!("http://{addr}"), "tok", "ws-1", "dev");
        let feed = client.head_changes().expect("http base url");
        assert_eq!(feed.recv_timeout(Duration::from_secs(5)), Ok(3));
        // The reconnect sleeps the 1s initial backoff first; 5s is ample.
        assert_eq!(feed.recv_timeout(Duration::from_secs(5)), Ok(4));
        assert!(feed.connected());
    }
}
