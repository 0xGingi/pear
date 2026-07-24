//! HTTP surface of the relay. Endpoint paths, JSON field names, and status
//! codes are pinned by DESIGN.md §11 (M2), §12 (M3), §13 (M4: users,
//! teams, role-based ACLs), and §14 (WebSocket fan-out) — the pear-core
//! relay client is built against them in parallel.

use std::sync::MutexGuard;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use pear_core::manifest::{self, Manifest};
use pear_core::store::{ChunkSink, ChunkSource};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;

use crate::db::Db;
use crate::error::ApiError;
use crate::AppState;

/// Manifests for large trees can be tens of MiB and chunks are bounded by
/// the chunker's max size; axum's 2 MiB default body limit is too small.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/users", post(create_user).get(list_users))
        .route("/v1/users/{name}/key", put(user_put_key).get(user_get_key))
        .route("/v1/teams", post(create_team).get(list_teams))
        .route("/v1/teams/{team_id}/policy", put(team_set_policy))
        .route(
            "/v1/teams/{team_id}/members",
            post(team_add_member).get(team_members),
        )
        .route(
            "/v1/teams/{team_id}/members/{user}",
            delete(team_remove_member),
        )
        .route("/v1/teams/{team}/workspaces/{name}", get(resolve_workspace))
        .route("/v1/workspaces", post(create_workspace))
        .route("/v1/workspaces/{id}", get(get_workspace))
        .route("/v1/workspaces/{id}/team", post(attach_team))
        .route("/v1/workspaces/{id}/keys/me", get(get_my_wrapped_key))
        .route(
            "/v1/workspaces/{id}/keys/{user}",
            put(put_wrapped_key).delete(delete_wrapped_key),
        )
        .route("/v1/workspaces/{id}/chunks/missing", post(chunks_missing))
        // §23 batched transfer: the single-chunk routes below stay for
        // compat and small transfers; sync paths use these two instead.
        .route(
            "/v1/workspaces/{id}/chunks/put_many",
            post(put_many_chunks),
        )
        .route(
            "/v1/workspaces/{id}/chunks/get_many",
            post(get_many_chunks),
        )
        .route(
            "/v1/workspaces/{id}/chunks/{hash}",
            put(put_chunk)
                .get(get_chunk)
                // Chunk bodies are contract-capped at the chunker's max
                // size: don't let the router-wide manifest limit buffer
                // oversize uploads here.
                .route_layer(DefaultBodyLimit::max(
                    pear_core::chunk::MAX_CHUNK_SIZE as usize,
                )),
        )
        .route("/v1/workspaces/{id}/head", get(get_head).put(put_head))
        .route(
            "/v1/workspaces/{id}/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route("/v1/workspaces/{id}/snapshots/{sid}", get(get_snapshot))
        .route("/v1/workspaces/{id}/lease/acquire", post(lease_acquire))
        .route("/v1/workspaces/{id}/lease/heartbeat", post(lease_heartbeat))
        .route("/v1/workspaces/{id}/lease/transfer", post(lease_transfer))
        .route("/v1/workspaces/{id}/lease/force", post(lease_force))
        .route("/v1/ws", get(ws_subscribe))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state)
}

/// Who an authenticated request acts as (§13): the bootstrap token
/// (`PEAR_TOKEN` / `--token`) is the Admin credential — it may manage users
/// and is an implicit owner on every workspace; a user token authenticates
/// as that user. Inserted into request extensions by the auth middleware.
#[derive(Clone)]
pub(crate) enum Principal {
    Admin,
    User(String),
}

/// A workspace/team role (§13). Ordered: reader < writer < owner.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    Reader,
    Writer,
    Owner,
}

impl Role {
    fn parse(role: &str) -> Option<Role> {
        match role {
            "reader" => Some(Role::Reader),
            "writer" => Some(Role::Writer),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Role::Reader => "reader",
            Role::Writer => "writer",
            Role::Owner => "owner",
        }
    }
}

/// Bearer-token gate on all routes (§13). Compared as BLAKE3 digests:
/// `blake3::Hash` equality is constant-time, so the comparison leaks no
/// timing signal about the token's bytes. The admin digest is checked
/// first; a user token falls through to a linear scan over every user-token
/// digest — fine at dev scale (a handful of users), and documented in §13's
/// dev-stage trade-offs. Index by digest if the user count ever grows.
async fn auth(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response()
    };
    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return unauthorized();
    };
    let digest = blake3::hash(token.as_bytes());
    if digest == blake3::hash(state.token.as_bytes()) {
        req.extensions_mut().insert(Principal::Admin);
        return next.run(req).await;
    }
    let resolved = block(move || {
        let db = lock_db(&state)?;
        Ok(db.user_token_digests()?)
    })
    .await;
    let principal = match resolved {
        // Stored digests vs the presented token's digest, compared as
        // BLAKE3 hashes (constant-time like the admin branch above).
        // Only digests ever cross this comparison — the relay never
        // stores the tokens.
        Ok(digests) => digests.into_iter().find_map(|(name, user_digest)| {
            user_digest
                .parse::<blake3::Hash>()
                .ok()
                .filter(|stored| *stored == digest)
                .map(|_| Principal::User(name))
        }),
        Err(e) => return e.into_response(),
    };
    match principal {
        Some(principal) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        None => unauthorized(),
    }
}

/// JSON body extractor that maps every rejection (bad syntax, wrong field
/// types, missing content-type) to a plain 400, per the §11 error contract.
struct JsonBody<T>(T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::BadRequest(rejection.body_text())),
        }
    }
}

/// Current unix time in whole seconds (lease expiry granularity).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Chunk `:hash` path params must be 64 lowercase hex chars before the
/// store is touched (the store itself only rejects non-hex, not case/length).
/// Also the §24 pool GC's "is this file a blob" test.
pub(crate) fn is_chunk_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn lock_db(state: &AppState) -> Result<MutexGuard<'_, Db>, ApiError> {
    state
        .db
        .lock()
        .map_err(|_| ApiError::internal_msg("metadata db lock poisoned"))
}

/// Run one unit of blocking DB/store work off the async runtime (§14):
/// handlers never call rusqlite or the chunk store in async context, and
/// the `Mutex<Db>` is locked only inside these closures. A JoinError means
/// the blocking task panicked — a plain 500 like any internal failure.
async fn block<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::Internal(e.into()))?
}

/// A fresh random id (user tokens, team ids): 16 random bytes as hex, the
/// same shape as client-generated workspace ids (§13).
fn new_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The principal's effective role on a workspace (§13): the admin is an
/// implicit owner of everything (which also covers pre-M4 workspaces, whose
/// owner is NULL); the workspace creator is its owner; otherwise the
/// caller's role in the attached team; otherwise none.
fn role_on(
    db: &Db,
    ws: &crate::db::Workspace,
    principal: &Principal,
) -> Result<Option<Role>, ApiError> {
    let role = match principal {
        Principal::Admin => Some(Role::Owner),
        Principal::User(name) => {
            if ws.owner.as_deref() == Some(name.as_str()) {
                return Ok(Some(Role::Owner));
            }
            let Some(team_id) = ws.team_id.as_deref() else {
                return Ok(None);
            };
            // Propagate DB errors: a transient failure must be a 500
            // (retryable), never a silent "no role" (a fatal 404 for the
            // caller's clients).
            db.member_role(team_id, name)?
                .and_then(|role| Role::parse(&role))
        }
    };
    Ok(role)
}

/// Load the workspace and gate on a minimum role, applying the §13
/// existence-hiding rule: no role at all looks exactly like the workspace
/// does not exist (404, same message); a role that is present but too small
/// is a 403.
fn require_role(
    db: &Db,
    id: &str,
    principal: &Principal,
    min: Role,
) -> Result<crate::db::Workspace, ApiError> {
    let not_found = || ApiError::NotFound(format!("workspace {id:?} does not exist"));
    let Some(ws) = db.get_workspace(id)? else {
        return Err(not_found());
    };
    match role_on(db, &ws, principal)? {
        None => Err(not_found()),
        Some(role) if role < min => Err(ApiError::Forbidden(format!(
            "workspace {id:?} requires at least the {} role (you are {})",
            min.as_str(),
            role.as_str()
        ))),
        Some(_) => Ok(ws),
    }
}

/// The caller must be an owner/writer of the team — the team half of the
/// §13 attach rule. The admin credential holds no team membership and is
/// refused like any non-member.
fn require_team_writer(db: &Db, team_id: &str, principal: &Principal) -> Result<(), ApiError> {
    let role = match principal {
        Principal::Admin => None,
        Principal::User(name) => db.member_role(team_id, name)?,
    };
    match role.and_then(|r| Role::parse(&r)) {
        Some(Role::Owner | Role::Writer) => Ok(()),
        _ => Err(ApiError::Forbidden(format!(
            "attaching a workspace to team {team_id:?} requires owner/writer in the team"
        ))),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Workspace and team names become URL path segments (in `team/name`
/// resolution): they must be addressable as exactly one segment — no
/// `/`, no control characters, no dot-only segments — without banning
/// human names (spaces and unicode percent-encode fine).
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && !s.bytes().any(|b| b.is_ascii_control())
        && !s.contains('/')
}

/// Device ids are persisted on lease/snapshot rows and echoed back
/// verbatim: bound them like every other stored string.
fn check_device(device: &str) -> Result<(), ApiError> {
    if !valid_name(device) {
        return Err(ApiError::BadRequest(format!(
            "device {device:?} must be 1-128 chars, no '/', no control characters, not a dot segment"
        )));
    }
    Ok(())
}

// --- users (§13, admin only) ------------------------------------------------

#[derive(Deserialize)]
struct CreateUserRequest {
    name: String,
}

#[derive(Serialize)]
struct CreateUserResponse {
    name: String,
    token: String,
}

/// Create a user and mint their token (§13: shown once, here). Admin only —
/// a user token gets a plain 403.
async fn create_user(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<CreateUserRequest>,
) -> Result<(StatusCode, Json<CreateUserResponse>), ApiError> {
    if !matches!(principal, Principal::Admin) {
        return Err(ApiError::Forbidden("admin only".to_string()));
    }
    if !valid_name(&req.name) {
        return Err(ApiError::BadRequest(format!(
            "user name {:?} must be 1-128 chars, no '/', no control characters, not a dot segment",
            req.name
        )));
    }
    let token = new_id();
    // Only the digest is stored (§13); the plaintext is shown once, here.
    let digest = blake3::hash(token.as_bytes()).to_hex().to_string();
    let name = req.name;
    let created = block({
        let name = name.clone();
        move || {
            let db = lock_db(&state)?;
            Ok(db.create_user(&name, &digest, unix_now())?)
        }
    })
    .await?;
    if !created {
        return Err(ApiError::Conflict(
            json!({ "error": format!("user {name:?} already exists") }),
        ));
    }
    Ok((
        StatusCode::CREATED,
        Json(CreateUserResponse { name, token }),
    ))
}

#[derive(Serialize)]
struct UserListEntry {
    name: String,
    created_at: i64,
}

#[derive(Serialize)]
struct UserListResponse {
    users: Vec<UserListEntry>,
}

/// List users (admin only). Tokens are never listed — they are handed out
/// once at creation.
async fn list_users(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
) -> Result<Json<UserListResponse>, ApiError> {
    if !matches!(principal, Principal::Admin) {
        return Err(ApiError::Forbidden("admin only".to_string()));
    }
    let users = block(move || {
        let db = lock_db(&state)?;
        Ok(db.list_users()?)
    })
    .await?
    .into_iter()
    .map(|(name, created_at)| UserListEntry { name, created_at })
    .collect();
    Ok(Json(UserListResponse { users }))
}

// --- user keys (§19: one signed key bundle per user, self-registered) -----

/// The §19 PUT body: the full signed bundle. `pubkey` is the rejected
/// legacy (§17 unsigned) shape, kept in the struct only to give it a
/// precise 400.
#[derive(Deserialize)]
struct PutKeyRequest {
    x25519: Option<String>,
    ed25519: Option<String>,
    sig: Option<String>,
    pubkey: Option<String>,
}

#[derive(Serialize)]
struct UserKeyResponse {
    name: String,
    /// The §17 X25519 pubkey (kept under its old name; existing readers
    /// keep working). Null when the user never enrolled.
    pubkey: Option<String>,
    /// §19: the ed25519 identity and its signature over the bundle
    /// statement for this name; null together on legacy rows.
    ed25519: Option<String>,
    sig: Option<String>,
}

/// A fixed-size hex field from a key-bundle body: exactly N bytes as
/// lowercase hex (the same rule `is_chunk_hash` applies to chunk ids).
fn hex_field<const N: usize>(field: &str, value: &str) -> Result<[u8; N], ApiError> {
    let ok = value.len() == N * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(ApiError::BadRequest(format!(
            "{field} {value:?} is not exactly {} lowercase hex chars",
            N * 2
        )));
    }
    // Validated above: N*2 lowercase hex chars decode to exactly N bytes.
    let bytes = pear_core::crypto::hex_decode(value).expect("validated hex");
    Ok(bytes.try_into().expect("validated hex length"))
}

/// Register (or replace) the caller's signed key bundle (§19). Self only:
/// the authenticated user's name must equal `:name` — the admin credential
/// holds no user identity and cannot enroll anyone. The relay verifies the
/// signature over the canonical statement for `:name` before storing: it
/// enforces bundle WELL-FORMEDNESS, never authenticity (that is the
/// writer-side pin's job).
async fn user_put_key(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(name): Path<String>,
    JsonBody(req): JsonBody<PutKeyRequest>,
) -> Result<Json<UserKeyResponse>, ApiError> {
    let Principal::User(caller) = &principal else {
        return Err(ApiError::Forbidden(
            "users register their own keys; the admin credential cannot enroll one".to_string(),
        ));
    };
    if *caller != name {
        return Err(ApiError::Forbidden(format!(
            "you may only register a key for yourself ({caller:?}), not for {name:?}"
        )));
    }
    // §19: unsigned registrations are history — a bare {pubkey} body (or
    // any partial bundle) is rejected with the remedy.
    let (Some(x_hex), Some(ed_hex), Some(sig_hex)) = (req.x25519, req.ed25519, req.sig) else {
        return Err(ApiError::BadRequest(format!(
            "keys must be signed: PUT the full bundle {{x25519, ed25519, sig}} as produced by \
             `pear user keygen --name {name} --relay <url>`{}",
            if req.pubkey.is_some() {
                " — a bare pubkey is no longer accepted"
            } else {
                ""
            }
        )));
    };
    let x25519 = hex_field::<32>("x25519", &x_hex)?;
    let ed25519 = hex_field::<32>("ed25519", &ed_hex)?;
    let sig = hex_field::<64>("sig", &sig_hex)?;
    // Verify BEFORE storing: the signature binds this user name to these
    // exact keys, so a bundle cannot be replayed for another user.
    let statement = pear_core::crypto::bundle_statement(&name, &x25519);
    if !pear_core::crypto::ed_verify(&ed25519, &statement, &sig) {
        return Err(ApiError::BadRequest(format!(
            "the bundle signature does not verify for {name:?} over the enclosed keys — \
             sign the bundle for this user with `pear user keygen --name {name} --relay <url>`"
        )));
    }
    block(move || {
        let db = lock_db(&state)?;
        if !db.set_user_key_bundle(&name, &x_hex, &ed_hex, &sig_hex)? {
            return Err(ApiError::NotFound(format!("user {name:?} does not exist")));
        }
        Ok(Json(UserKeyResponse {
            name,
            pubkey: Some(x_hex),
            ed25519: Some(ed_hex),
            sig: Some(sig_hex),
        }))
    })
    .await
}

/// Read any user's key bundle (§19: any authenticated user — pubkeys are
/// public by design: teammates wrap to them and `pear trust` pins them).
async fn user_get_key(
    Extension(_principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<UserKeyResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        match db.user_key_bundle(&name)? {
            Some(bundle) => Ok(Json(UserKeyResponse {
                name,
                pubkey: bundle.pubkey,
                ed25519: bundle.ed_pubkey,
                sig: bundle.key_sig,
            })),
            None => Err(ApiError::NotFound(format!("user {name:?} does not exist"))),
        }
    })
    .await
}

// --- teams (§13) ------------------------------------------------------------

#[derive(Deserialize)]
struct CreateTeamRequest {
    name: String,
    /// §28: the team's `.env` policy at create (`pear team create
    /// --no-env`). Absent = true — the default IS the product promise that
    /// `.env*` files sync; the kill switch is opt-in per team.
    #[serde(default)]
    sync_env: Option<bool>,
}

#[derive(Serialize)]
struct TeamResponse {
    id: String,
    name: String,
    /// §28: whether `.env*` files may sync in this team's workspaces.
    sync_env: bool,
}

/// Create a team; the caller becomes its first owner (§13). Only a user can
/// own a team — the admin credential holds no memberships.
async fn create_team(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<CreateTeamRequest>,
) -> Result<(StatusCode, Json<TeamResponse>), ApiError> {
    let Principal::User(user) = &principal else {
        return Err(ApiError::Forbidden(
            "only a user can create a team (the admin credential owns no teams)".to_string(),
        ));
    };
    if !valid_name(&req.name) {
        return Err(ApiError::BadRequest(format!(
            "team name {:?} must be 1-128 chars, no '/', no control characters, not a dot segment",
            req.name
        )));
    }
    let id = new_id();
    let user = user.clone();
    // Absent means true: a client that predates §28 keeps creating
    // promise-keeping teams.
    let sync_env = req.sync_env.unwrap_or(true);
    block(move || {
        let db = lock_db(&state)?;
        if !db.create_team_with_owner(&id, &req.name, unix_now(), &user, sync_env)? {
            return Err(ApiError::Conflict(
                json!({ "error": format!("team {:?} already exists", req.name) }),
            ));
        }
        Ok((
            StatusCode::CREATED,
            Json(TeamResponse {
                id,
                name: req.name,
                sync_env,
            }),
        ))
    })
    .await
}

#[derive(Serialize)]
struct TeamListResponse {
    teams: Vec<TeamResponse>,
}

/// The requester's teams (§13): memberships for a user, all teams for the
/// admin.
async fn list_teams(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
) -> Result<Json<TeamListResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let teams = match &principal {
            Principal::Admin => db.list_teams()?,
            Principal::User(name) => db.list_teams_for_user(name)?,
        };
        let teams = teams
            .into_iter()
            .map(|t| TeamResponse {
                id: t.id,
                name: t.name,
                sync_env: t.sync_env,
            })
            .collect();
        Ok(Json(TeamListResponse { teams }))
    })
    .await
}

#[derive(Deserialize)]
struct TeamPolicyRequest {
    sync_env: bool,
}

/// Set a team's §28 `.env` kill switch. Team-owner gated exactly like
/// member management (the admin credential holds no membership and gets
/// the same 403 — no override). The response carries the team row with
/// the policy now in effect, so the CLI prints what the relay stored.
async fn team_set_policy(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(team_id): Path<String>,
    JsonBody(req): JsonBody<TeamPolicyRequest>,
) -> Result<Json<TeamResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let Some(team) = db.get_team(&team_id)? else {
            return Err(ApiError::NotFound(format!(
                "team {team_id:?} does not exist"
            )));
        };
        let caller_role = match &principal {
            Principal::Admin => None,
            Principal::User(name) => db.member_role(&team_id, name)?,
        };
        if caller_role.as_deref() != Some("owner") {
            return Err(ApiError::Forbidden(
                "team policy is team-owner only".to_string(),
            ));
        }
        db.set_team_sync_env(&team_id, req.sync_env)?;
        Ok(Json(TeamResponse {
            id: team.id,
            name: team.name,
            sync_env: req.sync_env,
        }))
    })
    .await
}

#[derive(Deserialize)]
struct AddMemberRequest {
    user: String,
    role: String,
}

#[derive(Serialize)]
struct MemberResponse {
    user: String,
    role: String,
    /// The member's registered X25519 public key (§17), if they enrolled one.
    pubkey: Option<String>,
    /// §19: the member's ed25519 identity and bundle signature; null
    /// together on legacy pubkey-only rows and never-enrolled members.
    ed25519: Option<String>,
    sig: Option<String>,
}

/// Add (or re-role) a team member. Team owner only; the target user must
/// exist (§13).
async fn team_add_member(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(team_id): Path<String>,
    JsonBody(req): JsonBody<AddMemberRequest>,
) -> Result<Json<MemberResponse>, ApiError> {
    let Some(role) = Role::parse(&req.role) else {
        return Err(ApiError::BadRequest(format!(
            "role {:?} is not owner, writer, or reader",
            req.role
        )));
    };
    block(move || {
        let db = lock_db(&state)?;
        if db.get_team(&team_id)?.is_none() {
            return Err(ApiError::NotFound(format!(
                "team {team_id:?} does not exist"
            )));
        }
        let caller_role = match &principal {
            Principal::Admin => None,
            Principal::User(name) => db.member_role(&team_id, name)?,
        };
        if caller_role.as_deref() != Some("owner") {
            return Err(ApiError::Forbidden(
                "team member management is team-owner only".to_string(),
            ));
        }
        if !db.user_exists(&req.user)? {
            return Err(ApiError::NotFound(format!(
                "user {:?} does not exist",
                req.user
            )));
        }
        // A team must never be left ownerless: member management is
        // owner-gated with no admin override, so the last owner may not
        // demote themselves.
        if let Principal::User(name) = &principal {
            if *name == req.user && role.as_str() != "owner" {
                let owners = db
                    .list_members(&team_id)?
                    .into_iter()
                    .filter(|m| m.role == "owner")
                    .count();
                if owners <= 1 {
                    return Err(ApiError::Conflict(
                        json!({ "error": "you are the last owner; promote another member first" }),
                    ));
                }
            }
        }
        db.add_member(&team_id, &req.user, role.as_str())?;
        let bundle = db.user_key_bundle(&req.user)?;
        Ok(Json(MemberResponse {
            user: req.user,
            role: role.as_str().to_string(),
            pubkey: bundle.as_ref().and_then(|b| b.pubkey.clone()),
            ed25519: bundle.as_ref().and_then(|b| b.ed_pubkey.clone()),
            sig: bundle.and_then(|b| b.key_sig),
        }))
    })
    .await
}

#[derive(Serialize)]
struct MemberListResponse {
    members: Vec<MemberResponse>,
}

/// Remove a member from a team (§20). Team-owner gated like the POST —
/// with one deliberate exception: a member removing THEMSELVES (leaving)
/// needs no owner role. Idempotent — 204 whether or not the row existed:
/// the caller asserts "this user is out", not "a row was here". Removing
/// the team's LAST owner is a 409 (a team must keep an owner — the add
/// route's last-owner demote guard's mirror image), whoever asks. On an
/// actual removal the departed user's wrapped-key rows in every workspace
/// attached to this team die in the same transaction: their `keys/me`
/// ends with the membership itself, not at the next writer watch. The
/// crypto cutoff (key rotation) still waits for the writer's next
/// watch-start pass (§20).
async fn team_remove_member(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((team_id, user)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        if db.get_team(&team_id)?.is_none() {
            return Err(ApiError::NotFound(format!(
                "team {team_id:?} does not exist"
            )));
        }
        let caller_role = match &principal {
            Principal::Admin => None,
            Principal::User(name) => db.member_role(&team_id, name)?,
        };
        // The admin holds no implicit membership and no override, exactly
        // as in the POST. A member's self-removal (leave) is the one
        // non-owner path — and the last-owner guard below still applies
        // to an owner leaving.
        let self_leave = matches!(&principal, Principal::User(name) if *name == user)
            && caller_role.is_some();
        if caller_role.as_deref() != Some("owner") && !self_leave {
            return Err(ApiError::Forbidden(
                "team member management is team-owner only".to_string(),
            ));
        }
        // A team must never be left ownerless, or it becomes
        // unmanageable: refuse to remove the last owner, whoever asks.
        // (Promoting another member first is the escape hatch.)
        if db.member_role(&team_id, &user)?.as_deref() == Some("owner")
            && db.owner_count(&team_id)? <= 1
        {
            return Err(ApiError::Conflict(
                json!({ "error": format!("{user:?} is the last owner of this team; promote another member first") }),
            ));
        }
        db.remove_member(&team_id, &user)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// List a team's members. Members only — including the admin, who holds no
/// implicit membership (§13).
async fn team_members(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(team_id): Path<String>,
) -> Result<Json<MemberListResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        if db.get_team(&team_id)?.is_none() {
            return Err(ApiError::NotFound(format!(
                "team {team_id:?} does not exist"
            )));
        }
        let is_member = match &principal {
            Principal::Admin => false,
            Principal::User(name) => db.member_role(&team_id, name)?.is_some(),
        };
        if !is_member {
            return Err(ApiError::Forbidden(
                "team membership is visible to members only".to_string(),
            ));
        }
        let members = db
            .list_members(&team_id)?
            .into_iter()
            .map(|m| MemberResponse {
                user: m.user_name,
                role: m.role,
                pubkey: m.pubkey,
                ed25519: m.ed_pubkey,
                sig: m.key_sig,
            })
            .collect();
        Ok(Json(MemberListResponse { members }))
    })
    .await
}

/// Name resolution for `team/name` (§13): the workspace attached to this
/// team under this name, readable by anyone with a role on it. No role (or
/// no such team/workspace) is a 404 — existence is not leaked.
async fn resolve_workspace(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((team, name)): Path<(String, String)>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let not_found = || {
            ApiError::NotFound(format!(
                "workspace {team}/{name} does not exist or is not readable"
            ))
        };
        let Some(team) = db.get_team_by_name(&team)? else {
            return Err(not_found());
        };
        let Some(ws) = db.find_workspace_in_team(&team.id, &name)? else {
            return Err(not_found());
        };
        if role_on(&db, &ws, &principal)?.is_none() {
            return Err(not_found());
        }
        workspace_response(&db, &ws)
    })
    .await
}

// --- workspaces -----------------------------------------------------------

#[derive(Deserialize)]
struct CreateWorkspaceRequest {
    id: String,
    name: String,
    #[serde(default)]
    team_id: Option<String>,
    /// §17: create as an end-to-end encrypted workspace. Absent = plain.
    /// Immutable once set — see the e2e_mismatch conflict below.
    #[serde(default)]
    e2e: bool,
}

#[derive(Serialize)]
struct CreateWorkspaceResponse {
    id: String,
}

async fn create_workspace(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<CreateWorkspaceResponse>), ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        // Ids and names both become URL path segments (resolution is
        // `team/name`): require the URL-safe id form and an addressable
        // name, or the row is unaddressable junk that still squats its
        // team-scoped name.
        if req.id.is_empty()
            || req.id.len() > 128
            || !req
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || !req.id.bytes().any(|b| b.is_ascii_alphanumeric())
        {
            return Err(ApiError::BadRequest(format!(
                "workspace id {:?} must be 1-128 chars of [A-Za-z0-9._-] with at least one letter or digit",
                req.id
            )));
        }
        if !valid_name(&req.name) {
            return Err(ApiError::BadRequest(format!(
                "workspace name {:?} must be 1-128 chars, no '/', no control characters, not a dot segment",
                req.name
            )));
        }
        // Attach at create (§13): the creator becomes the workspace owner, so
        // the attach rule reduces to owner/writer in the team.
        if let Some(team_id) = &req.team_id {
            if db.get_team(team_id)?.is_none() {
                return Err(ApiError::NotFound(format!(
                    "team {team_id:?} does not exist"
                )));
            }
            require_team_writer(&db, team_id, &principal)?;
        }
        // The creating user owns the workspace; admin-created (and all pre-M4)
        // workspaces have a NULL owner and are treated as admin-owned.
        let owner = match &principal {
            Principal::Admin => None,
            Principal::User(name) => Some(name.as_str()),
        };
        let e2e = req.e2e;
        match db.create_workspace(&req.id, &req.name, owner, req.team_id.as_deref(), e2e)? {
            crate::db::CreateWorkspaceOutcome::Created => Ok((
                StatusCode::CREATED,
                Json(CreateWorkspaceResponse { id: req.id }),
            )),
            crate::db::CreateWorkspaceOutcome::IdConflict => {
                // The caller only learns the id is taken when they hold a role
                // on the existing workspace. NOTE: this route cannot be
                // existence-proof by itself — a free id returns 201 while a
                // taken one returns 404. That asymmetry is accepted: ids are
                // 128-bit random and unguessable, so probing yields nothing
                // useful (and a fake-201 would break idempotent registration).
                let existing = require_role(&db, &req.id, &principal, Role::Reader)?;
                // §17: the e2e flag is set once at create and immutable — a
                // re-registration under the other flavor would silently
                // downgrade (or strand) the workspace, so it conflicts loudly
                // instead of reading as an idempotent re-register.
                if existing.e2e != e2e {
                    return Err(ApiError::Conflict(json!({
                        "error": format!(
                            "workspace {:?} already exists as {} and cannot be re-registered as {}",
                            req.id,
                            if existing.e2e { "e2e" } else { "plain" },
                            if e2e { "e2e" } else { "plain" }
                        ),
                        "kind": "e2e_mismatch"
                    })));
                }
                Err(ApiError::Conflict(json!({
                    "error": format!("workspace {:?} already exists", req.id),
                    "kind": "id_conflict"
                })))
            }
            crate::db::CreateWorkspaceOutcome::NameConflict => Err(ApiError::Conflict(
                json!({ "error": format!("workspace name {:?} is already used in this team", req.name), "kind": "name_conflict" }),
            )),
        }
    })
    .await
}

#[derive(Serialize)]
struct LeaseInfo {
    holder: String,
    generation: i64,
    expires_at: i64,
}

#[derive(Serialize)]
struct WorkspaceResponse {
    id: String,
    name: String,
    owner: Option<String>,
    team_id: Option<String>,
    /// §17: end-to-end encrypted workspace (set at create, immutable).
    e2e: bool,
    head_seq: Option<i64>,
    head_hash: Option<String>,
    lease: Option<LeaseInfo>,
}

/// The §11 workspace read shape (plus the §13 owner/team fields and the §17
/// e2e flag), shared by `GET /workspaces/:id` and the `team/name`
/// resolution route.
fn workspace_response(
    db: &Db,
    ws: &crate::db::Workspace,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    let head = db.current_head(&ws.id)?;
    let lease = db.get_lease(&ws.id)?;
    Ok(Json(WorkspaceResponse {
        id: ws.id.clone(),
        name: ws.name.clone(),
        owner: ws.owner.clone(),
        team_id: ws.team_id.clone(),
        e2e: ws.e2e,
        head_seq: head.as_ref().map(|h| h.seq),
        head_hash: head.map(|h| h.hash),
        lease: lease.map(|l| LeaseInfo {
            holder: l.holder,
            generation: l.generation,
            expires_at: l.expires_at,
        }),
    }))
}

async fn get_workspace(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Reader)?;
        workspace_response(&db, &ws)
    })
    .await
}

/// Attach a workspace to a team (§13): the caller must own the workspace
/// AND be owner/writer in the team.
async fn attach_team(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<AttachTeamRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Owner)?;
        if db.get_team(&req.team_id)?.is_none() {
            return Err(ApiError::NotFound(format!(
                "team {:?} does not exist",
                req.team_id
            )));
        }
        require_team_writer(&db, &req.team_id, &principal)?;
        match db.attach_team(&ws.id, &req.team_id)? {
            crate::db::AttachOutcome::Attached => {
                Ok(Json(json!({ "id": ws.id, "team_id": req.team_id })))
            }
            crate::db::AttachOutcome::NameConflict => Err(ApiError::Conflict(
                json!({ "error": format!("workspace name {:?} is already used in this team", ws.name) }),
            )),
        }
    })
    .await
}

#[derive(Deserialize)]
struct AttachTeamRequest {
    team_id: String,
}

// --- wrapped workspace keys (§17/§20) ---------------------------------------

#[derive(Deserialize)]
struct WrappedKeyPutRequest {
    blob: String,
}

#[derive(Serialize)]
struct WrappedKeyResponse {
    blob: String,
}

/// A wrapped-key blob (§17/§20): lowercase hex of one sealed-box wrap —
/// ephemeral pub ‖ nonce ‖ ciphertext ‖ tag. §20 generalized the payload
/// from exactly one 32-byte key to the serialized keyring, so validation
/// relaxes from the §17 fixed length to "hex, plausible length": between
/// an empty payload's box and a generous ceiling that still caps what a
/// hostile writer makes every member download. The blob itself stays
/// opaque to the relay — real validation is the recipient's unwrap.
fn is_wrapped_key_blob(blob: &str) -> bool {
    let raw_len = blob.len() / 2;
    blob.len().is_multiple_of(2)
        && (pear_core::crypto::WRAPPED_KEY_MIN_LEN..=pear_core::crypto::WRAPPED_KEY_MAX_LEN)
            .contains(&raw_len)
        && blob
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Wrap the workspace key for a member (§17): workspace writer/owner only,
/// and the target user must exist. The blob is opaque to the relay — the
/// wrap and the workspace key never leave the clients. Re-wrapping
/// replaces the stored blob.
async fn put_wrapped_key(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((id, user)): Path<(String, String)>,
    JsonBody(req): JsonBody<WrappedKeyPutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_wrapped_key_blob(&req.blob) {
        return Err(ApiError::BadRequest(format!(
            "blob is not a wrapped key (lowercase hex, {}..={} raw bytes)",
            pear_core::crypto::WRAPPED_KEY_MIN_LEN,
            pear_core::crypto::WRAPPED_KEY_MAX_LEN
        )));
    }
    block(move || {
        let db = lock_db(&state)?;
        // No role on the workspace is the existence-hiding 404 (§13).
        require_role(&db, &id, &principal, Role::Writer)?;
        if !db.user_exists(&user)? {
            return Err(ApiError::NotFound(format!("user {user:?} does not exist")));
        }
        db.put_wrapped_key(&id, &user, &req.blob)?;
        Ok(Json(json!({ "user": user, "blob": req.blob })))
    })
    .await
}

/// Delete the key wrapped for a member (§20), after their team removal
/// rotated the keyring: the stale wrap must not keep unwrapping for anyone
/// still holding that identity. Same gate as the PUT (workspace
/// writer/owner). Idempotent — 204 whether or not a row existed: the
/// caller asserts "this user holds no wrap", not "a row was here", so a
/// retried rotation pass converges.
async fn delete_wrapped_key(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((id, user)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        // No role on the workspace is the existence-hiding 404 (§13).
        require_role(&db, &id, &principal, Role::Writer)?;
        db.delete_wrapped_key(&id, &user)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// The caller's own wrapped workspace key (§17): how a mirror/clone
/// onboards. 404 when the writer never wrapped a key for the caller (and,
/// per §13, when the caller has no role on the workspace at all).
async fn get_my_wrapped_key(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WrappedKeyResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        require_role(&db, &id, &principal, Role::Reader)?;
        // The admin credential holds no user identity, so nothing can be
        // wrapped for it — same 404 as a user with no wrap.
        let name = match &principal {
            Principal::User(name) => name.as_str(),
            Principal::Admin => "",
        };
        match db.get_wrapped_key(&id, name)? {
            Some(blob) => Ok(Json(WrappedKeyResponse { blob })),
            None => Err(ApiError::NotFound(format!(
                "no key is wrapped for you on workspace {id:?}"
            ))),
        }
    })
    .await
}

// --- chunks (global content-addressed pool) --------------------------------

async fn put_chunk(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((id, hash)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if !is_chunk_hash(&hash) {
        return Err(ApiError::BadRequest(format!(
            "chunk hash {hash:?} is not 64 lowercase hex chars"
        )));
    }
    // Cheap rejections before hashing the body: the chunk contract caps a
    // chunk at the chunker's max size, and writes need the writer role.
    if body.len() > pear_core::chunk::MAX_CHUNK_SIZE as usize {
        return Err(ApiError::BadRequest(format!(
            "chunk is {} bytes, over the {}-byte maximum",
            body.len(),
            pear_core::chunk::MAX_CHUNK_SIZE
        )));
    }
    block(move || {
        {
            let db = lock_db(&state)?;
            require_role(&db, &id, &principal, Role::Writer)?;
        }
        // Content-addressed means the body must hash to its name: wrong bytes
        // under hash H would poison the global pool for every workspace,
        // permanently (presence checks would report H present forever).
        if blake3::hash(&body).to_hex().as_str() != hash {
            return Err(ApiError::BadRequest(
                "chunk body does not hash to its claimed BLAKE3".to_string(),
            ));
        }
        // Idempotent: the store dedupes content-addressed writes. Recording
        // the reference is how visibility is earned (§13): only a workspace
        // that actually received the bytes may later read this chunk.
        state.store.put(&hash, &body)?;
        // §22 ack semantics: the 200 below means "accepted and
        // content-verified" — durability comes LATER, at commit points:
        // `put_head`/`create_snapshot` flush the pool before the
        // head/snapshot row commits, so a chunk REFERENCED BY A COMMITTED
        // head/snapshot is PRESENT (§25: dir-durable — a rare
        // very-recent-blob tear after power loss is always caught by
        // verify-on-get and heals by re-upload, never silently wrong),
        // while an accepted-but-never-referenced
        // chunk has no guarantee at all (unreferenced garbage — its loss
        // costs nothing). Crash window = "since the last commit point",
        // and it heals with no new machinery: chunks/missing ANDs
        // refs-visibility with blob existence, and §18 verify-on-get turns
        // a torn blob into delete → 404 → "missing" → re-upload.
        {
            let db = lock_db(&state)?;
            let mut one = std::collections::HashSet::new();
            one.insert(hash.clone());
            db.insert_chunk_refs(&id, &one)?;
        }
        Ok(StatusCode::OK)
    })
    .await
}

async fn get_chunk(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((id, hash)): Path<(String, String)>,
) -> Result<Vec<u8>, ApiError> {
    if !is_chunk_hash(&hash) {
        return Err(ApiError::BadRequest(format!(
            "chunk hash {hash:?} is not 64 lowercase hex chars"
        )));
    }
    block(move || {
        {
            let db = lock_db(&state)?;
            require_role(&db, &id, &principal, Role::Reader)?;
            // The pool is global; content visibility is not: serve a chunk
            // only when some workspace the caller can read references it (§13).
            if let Principal::User(name) = &principal {
                if !db.chunk_visible_to(&hash, name)? {
                    return Err(ApiError::NotFound(format!("chunk {hash:?} not found")));
                }
            }
        }
        match state.store.get(&hash) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ApiError::NotFound(format!("chunk {hash:?} not found")))
            }
            Err(e) => Err(ApiError::from(e)),
        }
    })
    .await
}

#[derive(Deserialize)]
struct MissingRequest {
    hashes: Vec<String>,
}

#[derive(Serialize)]
struct MissingResponse {
    missing: Vec<String>,
}

async fn chunks_missing(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<MissingRequest>,
) -> Result<Json<MissingResponse>, ApiError> {
    // Bound the batch: every hash costs a visibility query under the one
    // global DB mutex, so one request must not stall every route (a
    // spuriously fenced writer's heartbeat is time-sensitive). The
    // client splits larger lists transparently (`MISSING_BATCH`).
    const MAX_MISSING_BATCH: usize = 50_000;
    if req.hashes.len() > MAX_MISSING_BATCH {
        return Err(ApiError::BadRequest(format!(
            "chunks/missing accepts at most {MAX_MISSING_BATCH} hashes per call"
        )));
    }
    for hash in &req.hashes {
        if !is_chunk_hash(hash) {
            return Err(ApiError::BadRequest(format!(
                "chunk hash {hash:?} is not 64 lowercase hex chars"
            )));
        }
    }
    // Presence is answered only for chunks the caller can read (§13):
    // everything else reports "missing" — which at worst costs the writer
    // a re-upload the store then dedupes.
    block(move || {
        let visible = {
            let db = lock_db(&state)?;
            require_role(&db, &id, &principal, Role::Reader)?;
            let mut visible = std::collections::HashSet::new();
            for hash in &req.hashes {
                let can_read = match &principal {
                    Principal::Admin => true,
                    Principal::User(name) => db.chunk_visible_to(hash, name)?,
                };
                if can_read {
                    visible.insert(hash.clone());
                }
            }
            visible
        };
        let mut missing = Vec::new();
        for hash in &req.hashes {
            if !state.store.has(hash)? || !visible.contains(hash) {
                missing.push(hash.clone());
            }
        }
        Ok(Json(MissingResponse { missing }))
    })
    .await
}

/// §23 batched upload: one octet-stream frame (`pear_core::chunk_frame`,
/// decoded defensively — hostile bytes are a 400, never a panic) carrying
/// at most 256 entries and 32 MiB of decoded blobs. Each entry gets
/// EXACTLY the single-PUT validation (hash format, size cap,
/// body-hashes-to-name) and reports its own status — `stored` / `present`
/// / `error` with a short reason — because the writer's BatchUploader
/// keeps failed chunks buffered per-chunk: an all-or-nothing batch would
/// wedge its buffer on one deterministic failure. The caps are enforced
/// here AND by the client's transparent splitting (both use the
/// `chunk_frame` constants).
async fn put_many_chunks(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    use pear_core::chunk_frame as frame;
    // Decode and both caps run BEFORE any role/DB work: the frame is
    // untrusted input, and these rejections are cheap.
    let entries = frame::decode(&body)
        .map_err(|e| ApiError::BadRequest(format!("invalid chunk frame: {e:#}")))?;
    if entries.len() > frame::PUT_MANY_MAX_ENTRIES {
        return Err(ApiError::BadRequest(format!(
            "chunks/put_many accepts at most {} entries per call",
            frame::PUT_MANY_MAX_ENTRIES
        )));
    }
    let decoded_bytes: u64 = entries.iter().map(|(_, blob)| blob.len() as u64).sum();
    if decoded_bytes > frame::PUT_MANY_MAX_BYTES {
        return Err(ApiError::BadRequest(format!(
            "chunks/put_many accepts at most {} MiB of decoded blobs per call",
            frame::PUT_MANY_MAX_BYTES / (1024 * 1024)
        )));
    }
    block(move || {
        {
            let db = lock_db(&state)?;
            require_role(&db, &id, &principal, Role::Writer)?;
        }
        let mut results = Vec::with_capacity(entries.len());
        // Refs rows for every CONFIRMED chunk — inserted once below, even
        // for deduped chunks, exactly like the single PUT under §22: that
        // unconditional re-insert is what lets a rolled-back refs row
        // heal by re-execution.
        let mut confirmed = std::collections::HashSet::new();
        for (hash, blob) in &entries {
            // The frame's decode already guarantees the hash is 64
            // lowercase hex, but the check stays so this route carries
            // the single PUT's validation verbatim.
            let reason = if !is_chunk_hash(hash) {
                Some(format!(
                    "chunk hash {hash:?} is not 64 lowercase hex chars"
                ))
            } else if blob.len() > pear_core::chunk::MAX_CHUNK_SIZE as usize {
                Some(format!(
                    "chunk is {} bytes, over the {}-byte maximum",
                    blob.len(),
                    pear_core::chunk::MAX_CHUNK_SIZE
                ))
            } else if blake3::hash(blob).to_hex().as_str() != hash {
                // Content-addressed means the blob must hash to its name:
                // wrong bytes under hash H would poison the global pool
                // for every workspace, permanently.
                Some("chunk body does not hash to its claimed BLAKE3".to_string())
            } else {
                None
            };
            if let Some(reason) = reason {
                results.push(json!({ "hash": hash, "status": "error", "reason": reason }));
                continue;
            }
            // §22 ack semantics apply to the batch too: a `stored` status
            // means accepted and content-verified — durability comes at
            // commit points (`put_head`/`create_snapshot` flush the pool
            // before the row commits, lib.rs), so a referenced-by-commit
            // chunk is PRESENT (§25: dir-durable; a rare recent-blob tear
            // is verify-on-get-detected and heals, never silently wrong)
            // and a never-referenced one has no
            // guarantee at all. A store io error
            // is not a per-entry condition: it fails the request like the
            // single PUT's 500, and the writer retries the batch.
            let stored = state.store.put(hash, blob)?;
            results.push(json!({
                "hash": hash,
                "status": if stored { "stored" } else { "present" },
            }));
            confirmed.insert(hash.clone());
        }
        {
            let db = lock_db(&state)?;
            db.insert_chunk_refs(&id, &confirmed)?;
        }
        Ok(Json(json!({ "results": results })))
    })
    .await
}

#[derive(Deserialize)]
struct GetManyRequest {
    hashes: Vec<String>,
}

/// §23 batched download: JSON `{hashes: [...]}` (≤128) → 200 octet-stream
/// frame in REQUEST order. Reader gate plus per-hash visibility EXACTLY
/// like `GET /chunks/:hash` — and one invisible hash fails the WHOLE
/// request with a 404 naming it: callers always pre-check via
/// `chunks/missing`, so this only fires on a heal-delete race, and
/// failing loud lets the next cycle re-plan. The response is bounded
/// structurally, not by a byte cap: the request is hash-capped and every
/// stored chunk is ≤ MAX_CHUNK_SIZE (worst case 128 × 4 MiB). Clients
/// with manifest knowledge additionally byte-BUDGET their calls (§30: a
/// file's chunks partition it exactly, so the manifest's per-file size is
/// a chunk group's exact cost); this route's ≤128 cap stays the hard
/// bound.
async fn get_many_chunks(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<GetManyRequest>,
) -> Result<Response, ApiError> {
    if req.hashes.len() > pear_core::chunk_frame::GET_MANY_MAX_HASHES {
        return Err(ApiError::BadRequest(format!(
            "chunks/get_many accepts at most {} hashes per call",
            pear_core::chunk_frame::GET_MANY_MAX_HASHES
        )));
    }
    for hash in &req.hashes {
        if !is_chunk_hash(hash) {
            return Err(ApiError::BadRequest(format!(
                "chunk hash {hash:?} is not 64 lowercase hex chars"
            )));
        }
    }
    block(move || {
        {
            let db = lock_db(&state)?;
            require_role(&db, &id, &principal, Role::Reader)?;
            // The pool is global; content visibility is not (§13): serve
            // a chunk only when some workspace the caller can read
            // references it. One invisible hash names itself in the 404
            // and fails everything.
            if let Principal::User(name) = &principal {
                for hash in &req.hashes {
                    if !db.chunk_visible_to(hash, name)? {
                        return Err(ApiError::NotFound(format!("chunk {hash:?} not found")));
                    }
                }
            }
        }
        let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(req.hashes.len());
        for hash in &req.hashes {
            match state.store.get(hash) {
                Ok(bytes) => entries.push((hash.clone(), bytes)),
                // §18 verify-on-get: a torn pool blob self-deleted and
                // reports NotFound — same loud 404 as the single GET.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(ApiError::NotFound(format!("chunk {hash:?} not found")));
                }
                Err(e) => return Err(ApiError::from(e)),
            }
        }
        let body = pear_core::chunk_frame::encode(
            entries.iter().map(|(h, b)| (h.as_str(), b.as_slice())),
        );
        Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
    })
    .await
}

// --- head log (CAS, generation fencing) ------------------------------------

async fn get_head(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<HeadResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Reader)?;
        let Some(head) = db.current_head(&id)? else {
            return Err(ApiError::NotFound(format!("workspace {id:?} has no head")));
        };
        if ws.e2e {
            // §17: only clients holding the workspace key can read the
            // manifest. The stored text is the §24 envelope (manifest_enc
            // + chunk_hashes); the wire contract serves bare manifest_enc,
            // and pre-§24 rows are already bare.
            Ok(Json(HeadResponse {
                seq: head.seq,
                hash: head.hash,
                e2e: true,
                manifest: None,
                manifest_enc: Some(e2e_wire_manifest(&head.manifest)),
            }))
        } else {
            // Stored bytes were validated on write; embed them verbatim.
            let manifest =
                RawValue::from_string(head.manifest).map_err(|e| ApiError::Internal(e.into()))?;
            Ok(Json(HeadResponse {
                seq: head.seq,
                hash: head.hash,
                e2e: false,
                manifest: Some(manifest),
                manifest_enc: None,
            }))
        }
    })
    .await
}

#[derive(Serialize)]
struct HeadResponse {
    seq: i64,
    hash: String,
    /// §17: which manifest flavor this head carries. Plain heads embed
    /// `manifest`; e2e heads embed `manifest_enc` (base64 of the encrypted
    /// manifest blob) — never both.
    e2e: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_enc: Option<String>,
}

#[derive(Deserialize)]
struct HeadPutRequest {
    base_seq: i64,
    #[serde(default)]
    manifest: Option<Box<RawValue>>,
    #[serde(default)]
    manifest_enc: Option<String>,
    #[serde(default)]
    chunk_hashes: Option<Vec<String>>,
}

#[derive(Serialize)]
struct HeadPutResponse {
    seq: i64,
    hash: String,
}

async fn put_head(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<HeadPutRequest>,
) -> Result<Json<HeadPutResponse>, ApiError> {
    let committed = block({
        let state = state.clone();
        let id = id.clone();
        move || {
            let db = lock_db(&state)?;
            let ws = require_role(&db, &id, &principal, Role::Writer)?;

            // Fencing first (headers only): only the current lease holder,
            // presenting the current generation of an unexpired lease, may move
            // the head — regardless of what the manifest contains.
            let device = header_str(&headers, "x-pear-device")
                .ok_or_else(|| ApiError::Forbidden("missing X-Pear-Device header".to_string()))?;
            check_device(device)?;
            let generation: i64 = header_str(&headers, "x-pear-generation")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    ApiError::Forbidden("missing or invalid X-Pear-Generation header".to_string())
                })?;
            let now = unix_now();
            let fenced = match db.get_lease(&id)? {
                Some(lease) => {
                    lease.holder != device
                        || lease.generation != generation
                        || now >= lease.expires_at
                }
                None => true,
            };
            if fenced {
                return Err(ApiError::Fenced(
                    "head write fenced: lease missing, held by another device, \
                     stale generation, or expired"
                        .to_string(),
                ));
            }

            // §17: the manifest flavor is pinned by the workspace's immutable
            // e2e flag — a plaintext manifest on an e2e workspace (or
            // manifest_enc on a plain one) is a downgrade/confusion attempt
            // and conflicts, never a silent reinterpretation.
            if ws.e2e != req.manifest_enc.is_some() {
                return Err(ApiError::Conflict(json!({
                    "error": if ws.e2e {
                        format!("workspace {id:?} is end-to-end encrypted: commit manifest_enc + chunk_hashes, not a plaintext manifest")
                    } else {
                        format!("workspace {id:?} is not end-to-end encrypted: commit a plaintext manifest, not manifest_enc")
                    },
                    "kind": "e2e_mismatch"
                })));
            }

            // What gets stored verbatim and hashed, plus the chunk
            // visibility refs to write in the same transaction. (E2E: the
            // stored text is the §24 envelope — manifest_enc + the
            // validated chunk_hashes — so pool GC can re-derive the row's
            // chunk list; the wire still serves bare manifest_enc.)
            let (stored, refs) = if ws.e2e {
                let manifest_enc = req.manifest_enc.as_deref().unwrap_or_default();
                let Some(chunk_hashes) = req.chunk_hashes else {
                    return Err(ApiError::BadRequest(
                        "an e2e head commit needs chunk_hashes (the ciphertext hashes it references)"
                            .to_string(),
                    ));
                };
                validate_e2e_commit(&state, &db, &principal, manifest_enc, &chunk_hashes)?;
                (
                    e2e_stored_manifest(manifest_enc, &chunk_hashes),
                    chunk_hashes.into_iter().collect::<std::collections::HashSet<_>>(),
                )
            } else {
                let Some(manifest) = req.manifest else {
                    return Err(ApiError::BadRequest(
                        "a plaintext head commit needs a manifest".to_string(),
                    ));
                };
                // The manifest is stored and hashed as the exact submitted bytes so
                // GET /head returns it verbatim; it is still parsed and validated first.
                let raw = manifest.get();
                let parsed = validate_submitted_manifest(&state, &db, &id, &principal, raw)?;
                (raw.to_string(), chunk_hashes(&parsed))
            };

            // CAS on the head log: base_seq must equal the current seq (0 = no head).
            let current = db.current_head(&id)?.map(|h| h.seq).unwrap_or(0);
            if req.base_seq != current {
                return Err(ApiError::Conflict(json!({ "current_seq": current })));
            }

            let seq = current + 1;
            let hash = blake3::hash(stored.as_bytes()).to_hex().to_string();
            // §22 commit point: flush the deferred pool BEFORE the head
            // row commits — after this commit the head's chunks are
            // PRESENT (§25: dir-durable; a rare very-recent-blob tear
            // after power loss is verify-on-get-detected and heals by
            // re-upload, never silently wrong).
            // Same flush-before-commit shape as §18's client
            // apply. A flush error FAILS the commit (500 via the error
            // path): a head referencing un-verifiable chunks is exactly
            // what this ordering prevents, and §18's flush requeues the
            // un-fsynced remainder so the writer's retry re-flushes it.
            // Placed after all validation/fencing/CAS so a rejected
            // commit never pays the fsync.
            state.store.flush()?;
            // Head row and its chunk-visibility refs commit in one transaction:
            // a crash between them would leave a head no team reader could fetch
            // (deduped chunks have no put_chunk-time ref here, §13).
            db.insert_head(&id, seq, &hash, &stored, &refs)?;
            Ok(Json(HeadPutResponse { seq, hash }))
        }
    })
    .await?;
    // §14 fan-out, after a successful commit only: a head_changed hint to
    // the workspace's WebSocket subscribers. The hint is not correctness —
    // no subscribers (or lagging ones) must never affect the commit.
    state.notify_head_changed(&id, committed.seq);
    Ok(committed)
}

/// The manifest trust boundary shared by `PUT /head` and snapshot create
/// (§12): parse, path safety, workspace-id match, chunk-hash format, and
/// chunk presence in the pool *visible to this caller* (§13). Fencing and
/// CAS are head-only concerns and stay in `put_head`. Manifests arrive
/// over the network and are never trusted blindly. Returns the parsed
/// manifest on success.
fn validate_submitted_manifest(
    state: &AppState,
    db: &crate::db::Db,
    id: &str,
    principal: &Principal,
    raw: &str,
) -> Result<Manifest, ApiError> {
    let manifest: Manifest = serde_json::from_str(raw)
        .map_err(|e| ApiError::BadRequest(format!("manifest is not a pear manifest: {e}")))?;
    manifest::validate(&manifest).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    // The manifest must belong to the workspace it is stored under, or
    // every mirror (and clone) wedges on it.
    if manifest.workspace_id != id {
        return Err(ApiError::BadRequest(format!(
            "manifest workspace {} does not match URL workspace {id}",
            manifest.workspace_id
        )));
    }
    // §28: when the workspace's attached team forbids `.env` sync, any
    // manifest containing a `.env*` path conflicts — even an old or
    // misconfigured client cannot push `.env` into a protected team. The
    // path test is the scanner's own `is_dotenv` (pass 2 force-syncs
    // exactly those), so the relay forbids precisely what the product
    // promise would otherwise sync. Unattached workspaces have no policy
    // anywhere and pass; e2e workspaces never reach this function (the
    // relay cannot see encrypted paths — their only line is client-side).
    if let Some((team_name, sync_env)) = db.workspace_team_env_policy(id)? {
        if !sync_env {
            if let Some(path) = manifest.files.keys().find(|p| pear_core::scan::is_dotenv(p)) {
                return Err(ApiError::Conflict(json!({
                    "error": format!(
                        "team {team_name:?} forbids .env sync (sync_env=false): \
                         manifest contains .env* path {path:?} — \
                         remove the .env files or ask a team owner to lift the policy"
                    ),
                    "kind": "sync_env"
                })));
            }
        }
    }
    // A file and its own subdirectory cannot both exist: applying such a
    // manifest fails mid-batch and wedges every mirror (and clone). Check
    // each path's ancestors — adjacent-pair checks are not enough, since
    // bytes below '/' sort between a prefix and its subdirectory.
    for path in manifest.files.keys() {
        let mut ancestor = path.as_str();
        while let Some(idx) = ancestor.rfind('/') {
            ancestor = &ancestor[..idx];
            if manifest.files.contains_key(ancestor) {
                return Err(ApiError::BadRequest(format!(
                    "path {path:?} conflicts with {ancestor:?}: a file cannot also be a directory"
                )));
            }
        }
    }
    // Every referenced chunk must satisfy the same hash format as the
    // chunk routes, or every mirror's pull wedges on it.
    for entry in manifest.files.values() {
        for hash in &entry.chunks {
            if !is_chunk_hash(hash) {
                return Err(ApiError::BadRequest(format!(
                    "chunk hash {hash:?} is not 64 lowercase hex chars"
                )));
            }
        }
    }
    // And every referenced chunk must already be in the pool AND visible
    // to this caller (§13: visibility is earned by uploading the bytes or
    // by reading a workspace that references them). Anything else is a
    // cross-tenant presence oracle and wedges every pull that trusts it.
    let mut seen = std::collections::HashSet::new();
    let mut missing = 0usize;
    let mut first_missing = "";
    for entry in manifest.files.values() {
        for hash in &entry.chunks {
            if !seen.insert(hash.as_str()) {
                continue;
            }
            let present = state.store.has(hash)?
                && match principal {
                    Principal::Admin => true,
                    Principal::User(name) => db.chunk_visible_to(hash, name)?,
                };
            if !present {
                missing += 1;
                if first_missing.is_empty() {
                    first_missing = hash;
                }
            }
        }
    }
    if missing > 0 {
        return Err(ApiError::BadRequest(format!(
            "manifest references {missing} chunk(s) not in the pool (e.g. {first_missing})"
        )));
    }
    Ok(manifest)
}

/// Every chunk hash a manifest references (for `insert_chunk_refs` after a
/// head or snapshot commit). Also the plaintext half of §24's live-set
/// extraction (`stored_row_chunks`) — same walk, no parse drift.
pub(crate) fn chunk_hashes(manifest: &Manifest) -> std::collections::HashSet<String> {
    manifest
        .files
        .values()
        .flat_map(|entry| entry.chunks.iter().cloned())
        .collect()
}

/// §24: what an e2e row's `manifest` column holds. §17 stored the bare
/// base64 `manifest_enc`, but pool GC must re-derive every retained row's
/// chunk list from the stored row alone (refs are REBUILT, not trusted),
/// so e2e commits now store this envelope: the encrypted manifest plus
/// the validated `chunk_hashes` it referenced. The wire is unchanged —
/// the GET routes unwrap the envelope and serve `manifest_enc` verbatim
/// (`e2e_wire_manifest`), and a pre-§24 row (bare base64 never parses as
/// this JSON) still reads as it always did.
///
/// Field order is pinned alphabetical (chunk_hashes < manifest_enc), the
/// same order `serde_json::json!` emits, so the stored bytes are stable
/// across writers and recomputable in tests.
#[derive(Serialize, Deserialize)]
struct E2eStoredManifest {
    chunk_hashes: Vec<String>,
    manifest_enc: String,
}

/// Store-side encode of the §24 e2e envelope. The hashes are
/// canonicalized (sorted, deduped) so byte-identical state stores
/// byte-identical text — `lease_force`'s checkpoint dedup compares
/// stored text.
pub(crate) fn e2e_stored_manifest(manifest_enc: &str, chunk_hashes: &[String]) -> String {
    let chunk_hashes: std::collections::BTreeSet<&String> = chunk_hashes.iter().collect();
    serde_json::to_string(&E2eStoredManifest {
        chunk_hashes: chunk_hashes.into_iter().cloned().collect(),
        manifest_enc: manifest_enc.to_string(),
    })
    .expect("serializing two string fields cannot fail")
}

/// Decode a stored e2e row: `Some((manifest_enc, chunk_hashes))` for a
/// §24 envelope, `None` for a pre-§24 bare-base64 row (or corruption).
pub(crate) fn e2e_stored_parse(stored: &str) -> Option<(String, Vec<String>)> {
    let parsed: E2eStoredManifest = serde_json::from_str(stored).ok()?;
    Some((parsed.manifest_enc, parsed.chunk_hashes))
}

/// What a stored e2e row serves on the wire as `manifest_enc`: the
/// envelope's encrypted half, or the stored text itself for a pre-§24
/// bare-base64 row.
fn e2e_wire_manifest(stored: &str) -> String {
    match e2e_stored_parse(stored) {
        Some((manifest_enc, _)) => manifest_enc,
        None => stored.to_string(),
    }
}

/// The chunk list a stored head/snapshot row pins, parsed from the
/// `manifest` column exactly as commit-time validation extracted it
/// (§24's live-set rule): plaintext rows parse as a Manifest and walk
/// files→chunks through the commit path's own `chunk_hashes`; e2e rows
/// read the §24 envelope's `chunk_hashes` — the same validated list the
/// commit stored. Fails on pre-§24 bare-`manifest_enc` rows and on
/// corruption: the pool GC skips such a workspace rather than guess.
pub(crate) fn stored_row_chunks(
    e2e: bool,
    stored: &str,
) -> anyhow::Result<std::collections::HashSet<String>> {
    if e2e {
        let (_, chunk_hashes) = e2e_stored_parse(stored).ok_or_else(|| {
            anyhow::anyhow!("e2e row is a pre-§24 bare manifest_enc (or corrupt): chunk list unknowable")
        })?;
        Ok(chunk_hashes.into_iter().collect())
    } else {
        let manifest: Manifest = serde_json::from_str(stored)
            .map_err(|e| anyhow::anyhow!("stored plaintext manifest does not parse: {e}"))?;
        Ok(chunk_hashes(&manifest))
    }
}

/// The e2e half of the manifest trust boundary (§17): the relay cannot
/// parse an encrypted manifest, so it validates only what it can see —
/// `manifest_enc` is base64 of at least a nonce + tag, and every
/// `chunk_hashes` entry satisfies the same format + presence + visibility
/// rule as a plaintext manifest's chunks. Full manifest validation is a
/// client-side MUST before apply.
fn validate_e2e_commit(
    state: &AppState,
    db: &crate::db::Db,
    principal: &Principal,
    manifest_enc: &str,
    chunk_hashes: &[String],
) -> Result<(), ApiError> {
    // The blob must be base64 of at least nonce(12) + tag(16) bytes, or
    // every mirror's decrypt step wedges on it.
    let decoded = pear_core::crypto::base64_decode(manifest_enc)
        .map_err(|_| ApiError::BadRequest("manifest_enc is not valid base64".to_string()))?;
    if decoded.len() < 12 + 16 {
        return Err(ApiError::BadRequest(format!(
            "manifest_enc decodes to {} bytes; an encrypted manifest is at least nonce + tag ({})",
            decoded.len(),
            12 + 16
        )));
    }
    // Every referenced chunk must satisfy the same hash format as the
    // chunk routes, or every mirror's pull wedges on it.
    for hash in chunk_hashes {
        if !is_chunk_hash(hash) {
            return Err(ApiError::BadRequest(format!(
                "chunk hash {hash:?} is not 64 lowercase hex chars"
            )));
        }
    }
    // And every referenced chunk must already be in the pool AND visible
    // to this caller — the same rule as a plaintext manifest's chunks
    // (§13). The hashes are of ciphertext the client already uploaded, so
    // the relay learns nothing it did not already know.
    let mut seen = std::collections::HashSet::new();
    let mut missing = 0usize;
    let mut first_missing = "";
    for hash in chunk_hashes {
        if !seen.insert(hash.as_str()) {
            continue;
        }
        let present = state.store.has(hash)?
            && match principal {
                Principal::Admin => true,
                Principal::User(name) => db.chunk_visible_to(hash, name)?,
            };
        if !present {
            missing += 1;
            if first_missing.is_empty() {
                first_missing = hash;
            }
        }
    }
    if missing > 0 {
        return Err(ApiError::BadRequest(format!(
            "manifest references {missing} chunk(s) not in the pool (e.g. {first_missing})"
        )));
    }
    Ok(())
}

// --- snapshots (§12) ---------------------------------------------------------

#[derive(Deserialize)]
struct SnapshotCreateRequest {
    name: Option<String>,
    device: String,
    #[serde(default)]
    manifest: Option<Box<RawValue>>,
    #[serde(default)]
    manifest_enc: Option<String>,
    #[serde(default)]
    chunk_hashes: Option<Vec<String>>,
}

#[derive(Serialize)]
struct SnapshotCreateResponse {
    id: i64,
    created_at: i64,
}

/// Store an immutable snapshot: the same manifest trust boundary as
/// `PUT /head`, minus fencing/CAS — a snapshot moves nothing, so it needs
/// no lease. CLI-made snapshots are `kind: "named"`; the relay itself only
/// makes `checkpoint` snapshots (on lease force). On an e2e workspace the
/// body is `manifest_enc` + `chunk_hashes`, exactly like the head (§17).
async fn create_snapshot(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<SnapshotCreateRequest>,
) -> Result<(StatusCode, Json<SnapshotCreateResponse>), ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Writer)?;
        // Snapshot fields are stored and echoed verbatim; named snapshots
        // are never pruned, so bound them like every other stored string.
        if let Some(name) = &req.name {
            if !valid_name(name) {
                return Err(ApiError::BadRequest(format!(
                    "snapshot name {name:?} must be 1-128 chars, no '/', no control characters, not a dot segment"
                )));
            }
        }
        check_device(&req.device)?;
        // §17: same flavor pinning as the head — no plaintext manifests on
        // an e2e workspace, no manifest_enc on a plain one.
        if ws.e2e != req.manifest_enc.is_some() {
            return Err(ApiError::Conflict(json!({
                "error": if ws.e2e {
                    format!("workspace {id:?} is end-to-end encrypted: snapshot with manifest_enc + chunk_hashes, not a plaintext manifest")
                } else {
                    format!("workspace {id:?} is not end-to-end encrypted: snapshot with a plaintext manifest, not manifest_enc")
                },
                "kind": "e2e_mismatch"
            })));
        }
        let (stored, refs) = if ws.e2e {
            let manifest_enc = req.manifest_enc.as_deref().unwrap_or_default();
            let Some(chunk_hashes) = req.chunk_hashes else {
                return Err(ApiError::BadRequest(
                    "an e2e snapshot needs chunk_hashes (the ciphertext hashes it references)"
                        .to_string(),
                ));
            };
            validate_e2e_commit(&state, &db, &principal, manifest_enc, &chunk_hashes)?;
            // §24 envelope, exactly like the head commit: the stored row
            // must yield its chunk list back to pool GC.
            (
                e2e_stored_manifest(manifest_enc, &chunk_hashes),
                chunk_hashes.into_iter().collect::<std::collections::HashSet<_>>(),
            )
        } else {
            let Some(manifest) = req.manifest else {
                return Err(ApiError::BadRequest(
                    "a plaintext snapshot needs a manifest".to_string(),
                ));
            };
            let raw = manifest.get();
            let parsed = validate_submitted_manifest(&state, &db, &id, &principal, raw)?;
            (raw.to_string(), chunk_hashes(&parsed))
        };
        let created_at = unix_now();
        // §22 commit point, same flush-before-commit shape as `put_head`:
        // after this commit the snapshot's chunks are PRESENT (§25:
        // dir-durable; a rare recent-blob tear is verify-on-get-detected
        // and heals), and a
        // flush error fails the commit (500) rather than letting a
        // snapshot reference un-verifiable chunks. (The relay's own
        // `checkpoint` snapshots need no flush — they re-reference an
        // already-committed head's chunks.)
        state.store.flush()?;
        let sid = db.insert_snapshot(
            &id,
            crate::db::NewSnapshot {
                name: req.name.as_deref(),
                kind: "named",
                device: &req.device,
                created_at,
                manifest: &stored,
                refs: &refs,
            },
        )?;
        Ok((
            StatusCode::CREATED,
            Json(SnapshotCreateResponse {
                id: sid,
                created_at,
            }),
        ))
    })
    .await
}

#[derive(Serialize)]
struct SnapshotListEntry {
    id: i64,
    name: Option<String>,
    kind: String,
    device: String,
    created_at: i64,
}

#[derive(Serialize)]
struct SnapshotListResponse {
    snapshots: Vec<SnapshotListEntry>,
}

async fn list_snapshots(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SnapshotListResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        require_role(&db, &id, &principal, Role::Reader)?;
        let snapshots = db
            .list_snapshots(&id)?
            .into_iter()
            .map(|s| SnapshotListEntry {
                id: s.id,
                name: s.name,
                kind: s.kind,
                device: s.device,
                created_at: s.created_at,
            })
            .collect();
        Ok(Json(SnapshotListResponse { snapshots }))
    })
    .await
}

#[derive(Serialize)]
struct SnapshotResponse {
    id: i64,
    name: Option<String>,
    kind: String,
    device: String,
    created_at: i64,
    /// §17: like the head, an e2e snapshot carries `manifest_enc` (base64
    /// of the encrypted manifest blob) instead of `manifest`.
    e2e: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_enc: Option<String>,
}

async fn get_snapshot(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path((id, sid)): Path<(String, i64)>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Reader)?;
        let Some(snap) = db.get_snapshot(&id, sid)? else {
            return Err(ApiError::NotFound(format!(
                "workspace {id:?} has no snapshot {sid}"
            )));
        };
        let (manifest, manifest_enc) = if ws.e2e {
            // §24 envelope in storage, bare manifest_enc on the wire
            // (pre-§24 rows are already bare).
            (None, Some(e2e_wire_manifest(&snap.manifest)))
        } else {
            // Stored bytes were validated on write; embed them verbatim.
            let manifest =
                RawValue::from_string(snap.manifest).map_err(|e| ApiError::Internal(e.into()))?;
            (Some(manifest), None)
        };
        Ok(Json(SnapshotResponse {
            id: snap.id,
            name: snap.name,
            kind: snap.kind,
            device: snap.device,
            created_at: snap.created_at,
            e2e: ws.e2e,
            manifest,
            manifest_enc,
        }))
    })
    .await
}

// --- lease state machine ----------------------------------------------------

#[derive(Deserialize)]
struct AcquireRequest {
    device_id: String,
}

#[derive(Serialize)]
struct AcquireResponse {
    generation: i64,
    expires_at: i64,
}

async fn lease_acquire(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<AcquireRequest>,
) -> Result<Json<AcquireResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        require_role(&db, &id, &principal, Role::Writer)?;
        check_device(&req.device_id)?;
        let now = unix_now();
        let expires_at = now + state.lease_ttl_secs;
        match db.get_lease(&id)? {
            // No lease: grant at generation 1.
            None => {
                db.put_lease(&id, &req.device_id, 1, expires_at)?;
                Ok(Json(AcquireResponse {
                    generation: 1,
                    expires_at,
                }))
            }
            // Expired lease: steal succeeds and the generation bump fences the
            // previous holder.
            Some(lease) if now >= lease.expires_at => {
                let generation = lease.generation + 1;
                db.put_lease(&id, &req.device_id, generation, expires_at)?;
                Ok(Json(AcquireResponse {
                    generation,
                    expires_at,
                }))
            }
            // The current holder re-acquiring refreshes without a bump.
            Some(lease) if lease.holder == req.device_id => {
                db.put_lease(&id, &req.device_id, lease.generation, expires_at)?;
                Ok(Json(AcquireResponse {
                    generation: lease.generation,
                    expires_at,
                }))
            }
            Some(lease) => Err(ApiError::Conflict(
                json!({ "holder": lease.holder, "expires_at": lease.expires_at }),
            )),
        }
    })
    .await
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    device_id: String,
    generation: i64,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    expires_at: i64,
}

async fn lease_heartbeat(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        require_role(&db, &id, &principal, Role::Writer)?;
        check_device(&req.device_id)?;
        match db.get_lease(&id)? {
            // Expiry is terminal for a generation, exactly as in
            // acquire: a lapsed lease cannot be revived by heartbeat,
            // only re-acquired (with a generation bump fencing the stale
            // holder).
            Some(lease)
                if lease.holder == req.device_id
                    && lease.generation == req.generation
                    && unix_now() < lease.expires_at =>
            {
                let expires_at = unix_now() + state.lease_ttl_secs;
                db.put_lease(&id, &lease.holder, lease.generation, expires_at)?;
                Ok(Json(HeartbeatResponse { expires_at }))
            }
            _ => Err(ApiError::Fenced(
                "heartbeat fenced: not the lease holder or stale generation".to_string(),
            )),
        }
    })
    .await
}

#[derive(Deserialize)]
struct TransferRequest {
    device_id: String,
    #[allow(dead_code)] // carried by the contract; the decision is §11-pinned
    generation: i64,
    base_seq: i64,
}

#[derive(Serialize)]
struct TransferResponse {
    generation: i64,
}

async fn lease_transfer(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<TransferRequest>,
) -> Result<Json<TransferResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        require_role(&db, &id, &principal, Role::Writer)?;
        check_device(&req.device_id)?;
        // The requester must be synced to the current head so a handoff cannot
        // silently drop the writer's latest state.
        let head_seq = db.current_head(&id)?.map(|h| h.seq).unwrap_or(0);
        if req.base_seq != head_seq {
            return Err(ApiError::Conflict(json!({ "current_seq": head_seq })));
        }
        let now = unix_now();
        match db.get_lease(&id)? {
            // A valid lease held by another device requires `force`.
            Some(lease) if lease.holder != req.device_id && now < lease.expires_at => {
                Err(ApiError::Conflict(
                    json!({ "holder": lease.holder, "expires_at": lease.expires_at }),
                ))
            }
            // Already theirs: refresh without a generation bump.
            Some(lease) if lease.holder == req.device_id => {
                db.put_lease(
                    &id,
                    &lease.holder,
                    lease.generation,
                    now + state.lease_ttl_secs,
                )?;
                Ok(Json(TransferResponse {
                    generation: lease.generation,
                }))
            }
            // Expired (or no) lease: hand over, bumping the generation to fence
            // the old writer.
            lease => {
                let generation = lease.map(|l| l.generation + 1).unwrap_or(1);
                db.put_lease(&id, &req.device_id, generation, now + state.lease_ttl_secs)?;
                Ok(Json(TransferResponse { generation }))
            }
        }
    })
    .await
}

#[derive(Deserialize)]
struct ForceRequest {
    device_id: String,
}

#[derive(Serialize)]
struct ForceResponse {
    generation: i64,
}

async fn lease_force(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<ForceRequest>,
) -> Result<Json<ForceResponse>, ApiError> {
    block(move || {
        let db = lock_db(&state)?;
        let ws = require_role(&db, &id, &principal, Role::Writer)?;
        check_device(&req.device_id)?;
        let lease = db.get_lease(&id)?;
        // §12: an overwritten head is never lost — before revoking, record a
        // checkpoint snapshot of the current head, credited to the outgoing
        // holder. Skip when there is nothing new to preserve: the forcer
        // already holds the lease (their head is their own state), or the
        // newest checkpoint already matches this head. The checkpoint insert
        // also runs §14 time-based retention (see `Db::insert_snapshot`).
        if let Some(head) = db.current_head(&id)? {
            let forcer_holds = lease
                .as_ref()
                .is_some_and(|l| l.holder == req.device_id && unix_now() < l.expires_at);
            let already_captured = db
                .latest_checkpoint_manifest(&id)?
                .is_some_and(|m| m == head.manifest);
            if !forcer_holds && !already_captured {
                let outgoing = lease
                    .as_ref()
                    .map(|l| l.holder.as_str())
                    .unwrap_or("unknown");
                // On an e2e workspace the head text is the §24 envelope
                // (encrypted manifest + chunk_hashes): it checkpoints
                // verbatim, and its chunk refs were already written by the
                // head commit (refs are additive-only here, so nothing is
                // lost by not re-deriving them — and §24's GC rebuild
                // re-derives them from the envelope if drift ever occurs).
                let refs = if ws.e2e {
                    std::collections::HashSet::new()
                } else {
                    let manifest: Manifest = serde_json::from_str(&head.manifest)
                        .map_err(|e| ApiError::Internal(e.into()))?;
                    chunk_hashes(&manifest)
                };
                db.insert_snapshot(
                    &id,
                    crate::db::NewSnapshot {
                        name: None,
                        kind: "checkpoint",
                        device: outgoing,
                        created_at: unix_now(),
                        manifest: &head.manifest,
                        refs: &refs,
                    },
                )?;
            }
        }
        // Force always succeeds; the generation bump revokes and fences whoever
        // held the lease before (§11 documents the stranded-changes risk for
        // state that was never synced to the head).
        let generation = lease.map(|l| l.generation + 1).unwrap_or(1);
        db.put_lease(
            &id,
            &req.device_id,
            generation,
            unix_now() + state.lease_ttl_secs,
        )?;
        Ok(Json(ForceResponse { generation }))
    })
    .await
}

// --- WebSocket fan-out (§14, catch-up §21) --------------------------------

#[derive(Deserialize)]
struct WsQuery {
    workspace: String,
}

/// `GET /v1/ws?workspace=<id>`: upgrade to a WebSocket and stream the
/// workspace's `head_changed` hints. Same bearer auth (router middleware)
/// and the same reader-role gate as every other workspace route — no role
/// is the existence-hiding 404. The role check runs before the upgrade
/// (and re-runs periodically on the live connection, so a revoked
/// subscriber is dropped); the fan-out channel is created lazily on first
/// subscription. The upgrade is answered with the §21 `head_now` catch-up
/// (the current head seq) before any streamed hint.
async fn ws_subscribe(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let id = query.workspace;
    let (rx, head_seq) = block({
        let state = state.clone();
        let id = id.clone();
        let principal = principal.clone();
        move || {
            let db = lock_db(&state)?;
            let ws = require_role(&db, &id, &principal, Role::Reader)?;
            // §21: the catch-up seq is read in this same blocking section
            // as the role check, and AFTER subscribing: with the receiver
            // already registered there is no window where a commit is both
            // unhinted and unreported by `head_now`.
            let rx = state.subscribe_head(&id);
            let head_seq = db.current_head(&ws.id)?.map(|h| h.seq).unwrap_or(0);
            Ok((rx, head_seq))
        }
    })
    .await?;
    Ok(ws.on_upgrade(move |socket| ws_fanout(socket, state, id, principal, rx, head_seq)))
}

/// Pump `head_changed` hints to one subscriber, starting with the §21
/// `head_now` catch-up (the head seq at subscribe time) so a subscriber
/// that (re)connects after a commit converges immediately. The socket is
/// read as well as written: reading is what lets axum answer protocol
/// Pings with Pongs, and it is how a client Close (or a dead TCP
/// connection) is noticed — inbound data messages are discarded. A lagging
/// receiver no longer drops hints silently: it gets a polite Close, and
/// the client's reconnect catches it up via the fresh `head_now` (§21).
/// The reader role is re-checked every `ws_recheck_secs`: a revoked
/// subscriber gets a polite Close instead of streaming hints indefinitely
/// (§14).
async fn ws_fanout(
    mut socket: WebSocket,
    state: AppState,
    workspace: String,
    principal: Principal,
    mut rx: Receiver<String>,
    head_seq: i64,
) {
    // §21: the catch-up goes FIRST — ahead of the select loop, so it
    // precedes every post-connect broadcast. A failed send means the
    // subscriber is already gone; nothing else to do.
    if socket
        .send(Message::Text(crate::head_now_message(&workspace, head_seq).into()))
        .await
        .is_err()
    {
        return;
    }
    let mut recheck = tokio::time::interval(Duration::from_secs(state.ws_recheck_secs.max(1)));
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately; the role was checked at upgrade.
    recheck.tick().await;
    loop {
        tokio::select! {
            hint = rx.recv() => {
                let hint = match hint {
                    Ok(hint) => hint,
                    // §21: the receiver fell behind and hints were silently
                    // dropped. Ending the subscription turns silent loss
                    // into a reconnect, and the reconnect's `head_now`
                    // catches the subscriber up — exactly what the client's
                    // keepalive already does for a dead connection.
                    Err(RecvError::Lagged(_)) => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    Err(RecvError::Closed) => break,
                };
                if socket.send(Message::Text(hint.into())).await.is_err() {
                    break;
                }
            }
            inbound = socket.recv() => match inbound {
                // Clean Close, dead connection, or a socket error: the
                // subscriber is gone — end the task and drop the receiver.
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                // Ping/Pong/text from a mirror: nothing to do (axum's
                // automatic Pong is queued by the read itself).
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                let check = block({
                    let state = state.clone();
                    let workspace = workspace.clone();
                    let principal = principal.clone();
                    move || {
                        let db = lock_db(&state)?;
                        require_role(&db, &workspace, &principal, Role::Reader)?;
                        Ok(())
                    }
                })
                .await;
                match check {
                    Ok(()) => {}
                    // Revoked or re-attached elsewhere: close and end.
                    Err(ApiError::Forbidden(_)) | Err(ApiError::NotFound(_)) => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    // A transient internal failure (DB error, panicked
                    // blocking task) is NOT a revocation: keep the
                    // subscriber and re-check next tick — the role_on
                    // principle that a transient failure must never look
                    // like "no role" applies here too.
                    Err(_) => {}
                }
            }
        }
    }
}
