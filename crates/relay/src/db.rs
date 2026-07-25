//! Relay metadata: workspace registry, head log (§11), snapshots
//! (§12), users/teams/memberships (§13), and the §17/§19 E2E envelope
//! state (user key bundles, per-member wrapped workspace keys). No
//! migrations framework — `CREATE TABLE IF NOT EXISTS` plus idempotent
//! column migrations at open (§19 user bundles, §28 team `sync_env`);
//! §13 rebuilds the schema and pre-M4 data dirs are dev-stage (delete on
//! upgrade).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

/// A workspace row (§13): `owner` is the creating user's name (`None` =
/// pre-M4 or admin-created, treated as admin-owned), `team_id` the single
/// attached team, if any. `e2e` is the §17 end-to-end-encryption flag,
/// set once at create and immutable.
pub(crate) struct Workspace {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) owner: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) e2e: bool,
}

/// A team row. `sync_env` is the §28 per-team `.env` kill switch: TRUE by
/// default (the product promise is that `.env*` syncs); a team owner can
/// forbid it, and the relay then rejects plaintext commits containing
/// `.env*` paths in this team's workspaces.
pub(crate) struct Team {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) sync_env: bool,
}

/// A user's registered key material (§19): the §17 X25519 pubkey plus the
/// nullable ed25519 identity and bundle signature (NULL together on legacy
/// pubkey-only rows and never-enrolled users).
pub(crate) struct KeyBundle {
    pub(crate) pubkey: Option<String>,
    pub(crate) ed_pubkey: Option<String>,
    pub(crate) key_sig: Option<String>,
}

/// A team member row with their registered key material (§17/§19), if any.
pub(crate) struct MemberRow {
    pub(crate) user_name: String,
    pub(crate) role: String,
    pub(crate) pubkey: Option<String>,
    pub(crate) ed_pubkey: Option<String>,
    pub(crate) key_sig: Option<String>,
}

/// Why `create_workspace` refused the insert.
pub(crate) enum CreateWorkspaceOutcome {
    Created,
    /// The workspace id is taken.
    IdConflict,
    /// Another workspace already holds this name in this team (§13:
    /// workspace names are unique within a team).
    NameConflict,
}

/// Why `attach_team` refused the update.
pub(crate) enum AttachOutcome {
    Attached,
    /// Another workspace already holds this workspace's name in the team.
    NameConflict,
}

/// A head log entry: seq, BLAKE3 hex of the manifest bytes, and the exact
/// manifest JSON as submitted (returned verbatim by `GET /head`).
pub(crate) struct Head {
    pub(crate) seq: i64,
    pub(crate) hash: String,
    pub(crate) manifest: String,
}

/// A snapshot row (§12): an immutable manifest plus metadata. `kind` is
/// `named` (CLI-made); `checkpoint` rows exist only in data dirs written
/// by pre-§32 relays, which made them on lease force.
pub(crate) struct Snapshot {
    pub(crate) id: i64,
    pub(crate) name: Option<String>,
    pub(crate) kind: String,
    pub(crate) device: String,
    pub(crate) created_at: i64,
    pub(crate) manifest: String,
}

/// Snapshot metadata for listings (§12): everything but the manifest
/// body, which can be tens of MiB per row and is never needed for a
/// metadata-only list.
pub(crate) struct SnapshotMeta {
    pub(crate) id: i64,
    pub(crate) name: Option<String>,
    pub(crate) kind: String,
    pub(crate) device: String,
    pub(crate) created_at: i64,
}

pub(crate) struct Db {
    conn: Connection,
}

/// How many head log rows to keep per workspace (see `insert_head`).
const HEAD_KEEP: i64 = 50;

/// §19: every users table gains the bundle columns, however old the data
/// dir. Fresh DBs have them from CREATE TABLE above; pre-§19 dirs are
/// ALTERed here. Idempotent (PRAGMA table_info gates each ALTER), and
/// legacy rows simply keep NULL in the new columns.
fn migrate_users_table(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(users)")?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    for (column, ddl) in [
        ("ed_pubkey", "ALTER TABLE users ADD COLUMN ed_pubkey TEXT"),
        ("key_sig", "ALTER TABLE users ADD COLUMN key_sig TEXT"),
    ] {
        if !columns.iter().any(|c| c == column) {
            conn.execute_batch(ddl)?;
        }
    }
    Ok(())
}

/// §28: every teams table gains the `sync_env` kill switch, however old the
/// data dir. Fresh DBs have it from CREATE TABLE above; pre-§28 dirs are
/// ALTERed here. Idempotent (PRAGMA table_info gates the ALTER, same
/// pattern as §19's users migration), and existing teams land on the
/// DEFAULT 1 — they keep the product promise (`.env*` syncs) unless an
/// owner explicitly forbids it.
fn migrate_teams_table(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(teams)")?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    if !columns.iter().any(|c| c == "sync_env") {
        conn.execute_batch("ALTER TABLE teams ADD COLUMN sync_env INTEGER NOT NULL DEFAULT 1")?;
    }
    Ok(())
}

/// §14 checkpoint retention windows, in seconds: keep all of the last
/// hour, then the newest per hour for 24h, then the newest per day for
/// 7 days.
const HOUR_SECS: i64 = 3600;
const DAY_SECS: i64 = 24 * HOUR_SECS;
const CHECKPOINT_KEEP_SECS: i64 = 7 * DAY_SECS;

/// §14 checkpoint retention as a pure, unit-testable decision: given
/// `now` and a workspace's checkpoint snapshots as `(id, created_at)`
/// pairs, return the ids to delete. Everything from the last hour is
/// kept; then the newest checkpoint per trailing hour for 24h; then the
/// newest per trailing day for 7 days; the rest is pruned. Buckets are
/// age-relative (`now` is the inserting checkpoint's own timestamp); ties
/// on `created_at` keep the higher id (the later insert). Named snapshots
/// are never in the input and so can never be pruned.
pub(crate) fn checkpoints_to_prune(now: i64, checkpoints: &[(i64, i64)]) -> Vec<i64> {
    // The newest (created_at, id) seen so far per (tier, bucket) window.
    let mut newest: std::collections::HashMap<(i64, i64), (i64, i64)> = Default::default();
    let mut prune = Vec::new();
    for &(id, created_at) in checkpoints {
        let age = now - created_at;
        if age < HOUR_SECS {
            continue; // the last hour: kept unconditionally
        }
        if age >= CHECKPOINT_KEEP_SECS {
            prune.push(id); // past 7 days: always pruned
            continue;
        }
        let bucket = if age < DAY_SECS {
            (1, age / HOUR_SECS) // hourly tier
        } else {
            (2, age / DAY_SECS) // daily tier
        };
        match newest.get_mut(&bucket) {
            Some(best) if *best >= (created_at, id) => prune.push(id),
            Some(best) => {
                prune.push(best.1);
                *best = (created_at, id);
            }
            None => {
                newest.insert(bucket, (created_at, id));
            }
        }
    }
    // Sorted so the decision is deterministic for tests and the DELETE
    // loop alike.
    prune.sort_unstable();
    prune
}

/// Everything a snapshot row carries besides its workspace id (see
/// `insert_snapshot`).
pub(crate) struct NewSnapshot<'a> {
    pub(crate) name: Option<&'a str>,
    pub(crate) kind: &'a str,
    pub(crate) device: &'a str,
    pub(crate) created_at: i64,
    pub(crate) manifest: &'a str,
    pub(crate) refs: &'a std::collections::HashSet<String>,
}

impl Db {
    /// Run `f` inside an immediate transaction (this connection lives
    /// behind one mutex, so transactions never nest or interleave).
    fn with_tx<T>(&self, f: impl FnOnce() -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match f() {
            Ok(v) => {
                if let Err(e) = self.conn.execute_batch("COMMIT") {
                    // A failed COMMIT can leave the transaction OPEN
                    // (SQLITE_BUSY does not auto-rollback): without a
                    // rollback every later BEGIN on this one shared
                    // connection fails with "cannot start a transaction
                    // within a transaction" — all commits 500 forever.
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
    pub(crate) fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // §22: WAL + synchronous=NORMAL — the per-commit fsync leaves the
        // request path. A crash can now only ROLL BACK recently committed
        // transactions (bounded by WAL checkpointing), never corrupt the
        // database. Rollback is safe here because every class of relay
        // state is re-executable or loudly comparable: chunk refs
        // re-insert unconditionally on re-upload, put_head CASes on
        // base_seq and every idle check compares seq AND hash (§32: that
        // CAS is the only concurrency control), and a rolled-back
        // snapshot 404s at restore —
        // DESIGN.md §22, "Why rollback is safe here".
        //
        // `journal_mode=WAL` is a getter: it RETURNS the mode now in
        // effect as a row, so query_row (execute_batch would silently
        // discard it). An in-memory connection answers "memory" — it
        // cannot WAL, and with no file there is no crash window to argue
        // about, so that result is tolerated without failing.
        let _journal_mode: String =
            conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute("PRAGMA synchronous=NORMAL", [])?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                name TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                created_at INTEGER,
                -- One X25519 public key per user (§17), 64 lowercase hex,
                -- self-registered via PUT /v1/users/:name/key; NULL until then.
                pubkey TEXT,
                -- §19: the user's ed25519 identity (64 lowercase hex) and
                -- its signature (128 lowercase hex) over the bundle
                -- statement for this name. NULL together on legacy
                -- pubkey-only rows and never-enrolled users.
                ed_pubkey TEXT,
                key_sig TEXT
            );
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                created_at INTEGER,
                -- §28: per-team `.env` kill switch. 1 (the default) keeps
                -- the product promise that `.env*` files sync; 0 forbids
                -- them in every workspace attached to this team. Set at
                -- create or via PUT /v1/teams/:id/policy (team-owner only).
                sync_env INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS team_members (
                team_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (team_id, user_name)
            );
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner TEXT,
                team_id TEXT,
                -- §17: end-to-end encrypted workspace. Set once at create
                -- (e2e: true) and immutable — plaintext and e2e heads are
                -- rejected on the wrong workspace type with a 409.
                e2e INTEGER NOT NULL DEFAULT 0
            );
            -- Workspace names are unique within a team (§13); NULL team_ids
            -- are distinct, so unattached workspaces are unconstrained.
            CREATE UNIQUE INDEX IF NOT EXISTS workspaces_team_name
                ON workspaces (team_id, name);
            CREATE TABLE IF NOT EXISTS heads (
                workspace_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                hash TEXT NOT NULL,
                manifest TEXT NOT NULL,
                PRIMARY KEY (workspace_id, seq)
            );
            -- §32 retired leases: pre-§32 data dirs keep an orphaned
            -- `leases` table that is never read again (no migration).
            CREATE TABLE IF NOT EXISTS snapshots (
                workspace_id TEXT NOT NULL,
                id INTEGER NOT NULL,
                name TEXT,
                kind TEXT NOT NULL,
                device TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                manifest TEXT NOT NULL,
                PRIMARY KEY (workspace_id, id)
            );
            -- Which workspaces reference which chunks (§13): the pool is
            -- global, but content visibility is not.
            CREATE TABLE IF NOT EXISTS chunk_refs (
                workspace_id TEXT NOT NULL,
                hash TEXT NOT NULL,
                PRIMARY KEY (workspace_id, hash)
            );
            -- Visibility checks look up by hash first (§13): keep them
            -- off the full-table scan.
            CREATE INDEX IF NOT EXISTS chunk_refs_hash ON chunk_refs (hash, workspace_id);
            -- §17: the workspace key wrapped to each member's public key.
            -- The relay stores opaque blobs only (hex of the sealed-box
            -- wrap); it never sees the workspace key itself.
            CREATE TABLE IF NOT EXISTS wrapped_keys (
                workspace_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                blob TEXT NOT NULL,
                PRIMARY KEY (workspace_id, user_name)
            );",
        )?;
        migrate_users_table(&conn)?;
        migrate_teams_table(&conn)?;
        Ok(Self { conn })
    }

    // --- users (§13) ------------------------------------------------------

    /// Returns false when the user name is taken.
    pub(crate) fn create_user(
        &self,
        name: &str,
        token: &str,
        created_at: i64,
    ) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO users (name, token, created_at) VALUES (?1, ?2, ?3)",
            params![name, token, created_at],
        )?;
        Ok(n > 0)
    }

    pub(crate) fn user_exists(&self, name: &str) -> rusqlite::Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Every (name, token digest) pair, for the auth middleware's token
    /// scan. Only BLAKE3 digests are stored, never plaintext tokens (§13).
    pub(crate) fn user_token_digests(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, token FROM users ORDER BY name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// (name, created_at) for all users, name-ordered.
    pub(crate) fn list_users(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, created_at FROM users ORDER BY name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Register (or replace) a user's signed key bundle (§19): the pubkey
    /// column keeps its §17 meaning (one X25519 key per user; existing
    /// reads keep working) and the signature halves land alongside it —
    /// verified route-side before this write. Returns false when the user
    /// does not exist.
    pub(crate) fn set_user_key_bundle(
        &self,
        name: &str,
        x25519_hex: &str,
        ed25519_hex: &str,
        sig_hex: &str,
    ) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "UPDATE users SET pubkey = ?2, ed_pubkey = ?3, key_sig = ?4 WHERE name = ?1",
            params![name, x25519_hex, ed25519_hex, sig_hex],
        )?;
        Ok(n > 0)
    }

    /// The user's registered key bundle (§19): outer `None` = no such
    /// user; a NULL ed_pubkey/key_sig pair on a non-NULL pubkey is a
    /// legacy pre-§19 row.
    pub(crate) fn user_key_bundle(&self, name: &str) -> rusqlite::Result<Option<KeyBundle>> {
        self.conn
            .query_row(
                "SELECT pubkey, ed_pubkey, key_sig FROM users WHERE name = ?1",
                params![name],
                |row| {
                    Ok(KeyBundle {
                        pubkey: row.get(0)?,
                        ed_pubkey: row.get(1)?,
                        key_sig: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    // --- teams (§13) ------------------------------------------------------

    /// Returns false when the team name is taken. `sync_env` is the §28
    /// `.env` policy (true = `.env*` files sync, the product promise).
    pub(crate) fn create_team(
        &self,
        id: &str,
        name: &str,
        created_at: i64,
        sync_env: bool,
    ) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO teams (id, name, created_at, sync_env) VALUES (?1, ?2, ?3, ?4)",
            params![id, name, created_at, sync_env],
        )?;
        Ok(n > 0)
    }

    /// Create a team and seat its first owner atomically: a failed owner
    /// insert must not strand an ownerless team on its unique name —
    /// member management is owner-gated, so such a team could never
    /// recover. Returns false when the team name is taken.
    pub(crate) fn create_team_with_owner(
        &self,
        id: &str,
        name: &str,
        created_at: i64,
        owner: &str,
        sync_env: bool,
    ) -> rusqlite::Result<bool> {
        self.with_tx(|| {
            let created = self.create_team(id, name, created_at, sync_env)?;
            if created {
                self.add_member(id, owner, "owner")?;
            }
            Ok(created)
        })
    }

    /// Test-only fault injection for `create_team_with_owner`: fail right
    /// after the team insert, as a SQLite error in `add_member` would.
    #[cfg(test)]
    pub(crate) fn create_team_with_owner_fault(
        &self,
        id: &str,
        name: &str,
        created_at: i64,
        owner: &str,
    ) -> rusqlite::Result<bool> {
        self.with_tx(|| {
            let created = self.create_team(id, name, created_at, true)?;
            if created {
                self.add_member(id, owner, "owner")?;
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(created)
        })
    }

    pub(crate) fn get_team(&self, id: &str) -> rusqlite::Result<Option<Team>> {
        self.conn
            .query_row(
                "SELECT id, name, sync_env FROM teams WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Team {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        sync_env: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    pub(crate) fn get_team_by_name(&self, name: &str) -> rusqlite::Result<Option<Team>> {
        self.conn
            .query_row(
                "SELECT id, name, sync_env FROM teams WHERE name = ?1",
                params![name],
                |row| {
                    Ok(Team {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        sync_env: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    /// All teams, name-ordered (the admin's view).
    pub(crate) fn list_teams(&self) -> rusqlite::Result<Vec<Team>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, sync_env FROM teams ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(Team {
                id: row.get(0)?,
                name: row.get(1)?,
                sync_env: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// The teams one user belongs to, name-ordered.
    pub(crate) fn list_teams_for_user(&self, user_name: &str) -> rusqlite::Result<Vec<Team>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.id, t.name, t.sync_env FROM teams t
             JOIN team_members m ON m.team_id = t.id
             WHERE m.user_name = ?1 ORDER BY t.name",
        )?;
        let rows = stmt.query_map(params![user_name], |row| {
            Ok(Team {
                id: row.get(0)?,
                name: row.get(1)?,
                sync_env: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// Set a team's §28 `.env` policy; returns false when no such team
    /// exists (the route 404s). The owner gate lives at the route, like
    /// every other team-owner operation.
    pub(crate) fn set_team_sync_env(&self, id: &str, sync_env: bool) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "UPDATE teams SET sync_env = ?2 WHERE id = ?1",
            params![id, sync_env],
        )?;
        Ok(n > 0)
    }

    /// The §28 policy of the team a workspace is attached to, as
    /// `(team_name, sync_env)` — `None` for an unattached workspace (no
    /// policy lives anywhere; the kill switch does not apply). One join
    /// next to commit validation so a forbidding team 409s `.env*`
    /// manifests without a second round trip.
    pub(crate) fn workspace_team_env_policy(
        &self,
        workspace_id: &str,
    ) -> rusqlite::Result<Option<(String, bool)>> {
        self.conn
            .query_row(
                "SELECT t.name, t.sync_env FROM teams t
                 JOIN workspaces w ON w.team_id = t.id
                 WHERE w.id = ?1",
                params![workspace_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
    }

    /// Add a member, or update their role when already a member.
    pub(crate) fn add_member(
        &self,
        team_id: &str,
        user_name: &str,
        role: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO team_members (team_id, user_name, role) VALUES (?1, ?2, ?3)
             ON CONFLICT (team_id, user_name) DO UPDATE SET role = excluded.role",
            params![team_id, user_name, role],
        )?;
        Ok(())
    }

    /// Remove a member from a team (§20). Returns whether a membership row
    /// actually existed — the route is idempotent either way, but the CLI
    /// prints "removed" vs "was not a member" from the difference. On an
    /// actual removal, the departed user's wrapped-key rows in EVERY
    /// workspace attached to this team die in the same transaction: their
    /// `keys/me` ends with the membership itself, not at the next writer
    /// watch (§20). The crypto cutoff (key rotation) still waits for the
    /// writer's next watch-start pass.
    pub(crate) fn remove_member(&self, team_id: &str, user_name: &str) -> rusqlite::Result<bool> {
        self.with_tx(|| {
            let removed = self.conn.execute(
                "DELETE FROM team_members WHERE team_id = ?1 AND user_name = ?2",
                params![team_id, user_name],
            )?;
            if removed > 0 {
                self.conn.execute(
                    "DELETE FROM wrapped_keys WHERE user_name = ?1
                     AND workspace_id IN (SELECT id FROM workspaces WHERE team_id = ?2)",
                    params![user_name, team_id],
                )?;
            }
            Ok(removed > 0)
        })
    }

    /// The number of owners in a team — the last-owner guard (§20): the
    /// remove route refuses to take a team's last remaining owner, or the
    /// team would be left unmanageable.
    pub(crate) fn owner_count(&self, team_id: &str) -> rusqlite::Result<usize> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM team_members WHERE team_id = ?1 AND role = 'owner'",
            params![team_id],
            |row| row.get(0),
        )
    }

    /// The user's role in the team, if they are a member.
    pub(crate) fn member_role(
        &self,
        team_id: &str,
        user_name: &str,
    ) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT role FROM team_members WHERE team_id = ?1 AND user_name = ?2",
                params![team_id, user_name],
                |row| row.get(0),
            )
            .optional()
    }

    /// Every member with their registered key material, name-ordered
    /// (§17: the writer wraps the workspace key for members with a key;
    /// §19: only to signed, pin-matching bundles).
    pub(crate) fn list_members(&self, team_id: &str) -> rusqlite::Result<Vec<MemberRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.user_name, m.role, u.pubkey, u.ed_pubkey, u.key_sig FROM team_members m
             LEFT JOIN users u ON u.name = m.user_name
             WHERE m.team_id = ?1 ORDER BY m.user_name",
        )?;
        let rows = stmt.query_map(params![team_id], |row| {
            Ok(MemberRow {
                user_name: row.get(0)?,
                role: row.get(1)?,
                pubkey: row.get(2)?,
                ed_pubkey: row.get(3)?,
                key_sig: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    // --- workspaces ---------------------------------------------------------

    /// Insert a workspace. The id is the primary key; the name must be
    /// unique within the target team (§13). Both conflicts are reported
    /// distinctly so the route can explain which one fired. The DB lives
    /// behind one mutex, so check-then-insert here is race-free. `e2e` is
    /// written once here and never updated (§17: immutable).
    pub(crate) fn create_workspace(
        &self,
        id: &str,
        name: &str,
        owner: Option<&str>,
        team_id: Option<&str>,
        e2e: bool,
    ) -> rusqlite::Result<CreateWorkspaceOutcome> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO workspaces (id, name, owner, team_id, e2e) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, owner, team_id, e2e],
        )?;
        if n > 0 {
            return Ok(CreateWorkspaceOutcome::Created);
        }
        if self.get_workspace(id)?.is_some() {
            return Ok(CreateWorkspaceOutcome::IdConflict);
        }
        Ok(CreateWorkspaceOutcome::NameConflict)
    }

    pub(crate) fn get_workspace(&self, id: &str) -> rusqlite::Result<Option<Workspace>> {
        self.conn
            .query_row(
                "SELECT id, name, owner, team_id, e2e FROM workspaces WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Workspace {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        owner: row.get(2)?,
                        team_id: row.get(3)?,
                        e2e: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    /// The workspace with this name attached to this team (§13 name
    /// resolution for `team/name`).
    pub(crate) fn find_workspace_in_team(
        &self,
        team_id: &str,
        name: &str,
    ) -> rusqlite::Result<Option<Workspace>> {
        self.conn
            .query_row(
                "SELECT id, name, owner, team_id, e2e FROM workspaces
                 WHERE team_id = ?1 AND name = ?2",
                params![team_id, name],
                |row| {
                    Ok(Workspace {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        owner: row.get(2)?,
                        team_id: row.get(3)?,
                        e2e: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    /// Attach a workspace to a team (re-attach moves it; a workspace has at
    /// most one team). Refuses when the name is already taken in the team.
    pub(crate) fn attach_team(&self, id: &str, team_id: &str) -> rusqlite::Result<AttachOutcome> {
        let taken: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM workspaces
                 WHERE team_id = ?2 AND id != ?1
                   AND name = (SELECT name FROM workspaces WHERE id = ?1)",
                params![id, team_id],
                |row| row.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return Ok(AttachOutcome::NameConflict);
        }
        self.conn.execute(
            "UPDATE workspaces SET team_id = ?2 WHERE id = ?1",
            params![id, team_id],
        )?;
        Ok(AttachOutcome::Attached)
    }

    /// Newest head log entry, if any.
    pub(crate) fn current_head(&self, workspace_id: &str) -> rusqlite::Result<Option<Head>> {
        self.conn
            .query_row(
                "SELECT seq, hash, manifest FROM heads
                 WHERE workspace_id = ?1 ORDER BY seq DESC LIMIT 1",
                params![workspace_id],
                |row| {
                    Ok(Head {
                        seq: row.get(0)?,
                        hash: row.get(1)?,
                        manifest: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    pub(crate) fn insert_head(
        &self,
        workspace_id: &str,
        seq: i64,
        hash: &str,
        manifest: &str,
        refs: &std::collections::HashSet<String>,
    ) -> rusqlite::Result<()> {
        // Head row and its chunk-visibility refs commit together: a crash
        // between them would leave a head no team reader could ever fetch
        // (deduped chunks have no put_chunk-time ref here).
        self.with_tx(|| {
            self.conn.execute(
                "INSERT INTO heads (workspace_id, seq, hash, manifest) VALUES (?1, ?2, ?3, ?4)",
                params![workspace_id, seq, hash, manifest],
            )?;
            // Retention: keep only the newest HEAD_KEEP rows per workspace —
            // full manifests make the log grow unboundedly otherwise, and
            // nothing reads older rows today. M3 snapshots must pin the rows
            // they reference before this pruning may apply to them.
            self.conn.execute(
                "DELETE FROM heads WHERE workspace_id = ?1 AND seq NOT IN (
                    SELECT seq FROM heads WHERE workspace_id = ?1
                    ORDER BY seq DESC LIMIT ?2
                )",
                params![workspace_id, HEAD_KEEP],
            )?;
            let mut stmt = self
                .conn
                .prepare("INSERT OR IGNORE INTO chunk_refs (workspace_id, hash) VALUES (?1, ?2)")?;
            for h in refs {
                stmt.execute(params![workspace_id, h])?;
            }
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn head_count(&self, workspace_id: &str) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM heads WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get(0),
        )
    }

    /// Append a snapshot; returns its per-workspace incrementing id (§12).
    /// The relay holds one DB behind a mutex, so the id read-then-write
    /// here is race-free. Snapshot row and chunk-visibility refs commit
    /// together (same crash-safety reason as `insert_head`). Checkpoint
    /// inserts also run §14 time-based retention in the same transaction:
    /// metadata-only, named snapshots never selected, chunk pool untouched.
    pub(crate) fn insert_snapshot(
        &self,
        workspace_id: &str,
        snapshot: NewSnapshot<'_>,
    ) -> rusqlite::Result<i64> {
        self.with_tx(|| {
            let id: i64 = self.conn.query_row(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM snapshots WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )?;
            self.conn.execute(
                "INSERT INTO snapshots (workspace_id, id, name, kind, device, created_at, manifest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    workspace_id,
                    id,
                    snapshot.name,
                    snapshot.kind,
                    snapshot.device,
                    snapshot.created_at,
                    snapshot.manifest
                ],
            )?;
            let mut stmt = self
                .conn
                .prepare("INSERT OR IGNORE INTO chunk_refs (workspace_id, hash) VALUES (?1, ?2)")?;
            for h in snapshot.refs {
                stmt.execute(params![workspace_id, h])?;
            }
            // §14 retention runs at insert time only (no timer): on every
            // checkpoint insert, prune this workspace's checkpoints. The
            // inserting checkpoint's own timestamp is the bucketing `now`,
            // which also guarantees it survives its own prune.
            if snapshot.kind == "checkpoint" {
                let mut select = self.conn.prepare(
                    "SELECT id, created_at FROM snapshots
                     WHERE workspace_id = ?1 AND kind = 'checkpoint'",
                )?;
                let checkpoints = select
                    .query_map(params![workspace_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<(i64, i64)>>>()?;
                let mut delete = self
                    .conn
                    .prepare("DELETE FROM snapshots WHERE workspace_id = ?1 AND id = ?2")?;
                for doomed in checkpoints_to_prune(snapshot.created_at, &checkpoints) {
                    delete.execute(params![workspace_id, doomed])?;
                }
            }
            Ok(id)
        })
    }

    /// Record that a workspace's state references these chunks (written at
    /// head/snapshot commits; the read side of cross-tenant pool
    /// isolation, §13).
    pub(crate) fn insert_chunk_refs(
        &self,
        workspace_id: &str,
        hashes: &std::collections::HashSet<String>,
    ) -> rusqlite::Result<()> {
        let mut stmt = self
            .conn
            .prepare("INSERT OR IGNORE INTO chunk_refs (workspace_id, hash) VALUES (?1, ?2)")?;
        for hash in hashes {
            stmt.execute(params![workspace_id, hash])?;
        }
        Ok(())
    }

    // --- §24 pool GC ------------------------------------------------------

    /// Every workspace with its e2e flag — the GC's live-set parse flavor
    /// (plaintext manifests parse as JSON; e2e rows as the §24 envelope).
    pub(crate) fn list_workspaces_for_gc(&self) -> rusqlite::Result<Vec<(String, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, e2e FROM workspaces ORDER BY id")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// The `manifest` column of every RETAINED head row of a workspace.
    /// Retention is applied at insert (`insert_head`), so every row
    /// present is by definition retained.
    pub(crate) fn retained_head_manifests(
        &self,
        workspace_id: &str,
    ) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest FROM heads WHERE workspace_id = ?1")?;
        let rows = stmt.query_map(params![workspace_id], |row| row.get(0))?;
        rows.collect()
    }

    /// The `manifest` column of every retained snapshot row of a
    /// workspace, any kind (named snapshots are never pruned; checkpoint
    /// pruning happens at insert, so presence = retained here too).
    pub(crate) fn snapshot_manifests(&self, workspace_id: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest FROM snapshots WHERE workspace_id = ?1")?;
        let rows = stmt.query_map(params![workspace_id], |row| row.get(0))?;
        rows.collect()
    }

    /// §24 refs rebuild, ONE transaction for every workspace: after it,
    /// `chunk_refs` holds exactly the given live sets — unjustified rows
    /// deleted (the actual GC), missing justified rows re-inserted
    /// (self-healing for refs drift: a §22 WAL rollback that lost refs
    /// rows, or an e2e force-checkpoint that commits no refs of its
    /// own). A workspace mapped to an empty set loses all its refs. A
    /// workspace ABSENT from the map is not touched at all (the GC's
    /// conservative skip arm). Returns the number of rows deleted.
    pub(crate) fn gc_rebuild_refs(
        &self,
        live: &std::collections::BTreeMap<String, std::collections::HashSet<String>>,
    ) -> rusqlite::Result<usize> {
        self.with_tx(|| {
            let mut select = self
                .conn
                .prepare("SELECT hash FROM chunk_refs WHERE workspace_id = ?1")?;
            let mut delete = self
                .conn
                .prepare("DELETE FROM chunk_refs WHERE workspace_id = ?1 AND hash = ?2")?;
            let mut insert = self
                .conn
                .prepare("INSERT OR IGNORE INTO chunk_refs (workspace_id, hash) VALUES (?1, ?2)")?;
            let mut deleted = 0usize;
            for (ws, keep) in live {
                let existing: std::collections::HashSet<String> = select
                    .query_map(params![ws], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                for hash in existing.difference(keep) {
                    delete.execute(params![ws, hash])?;
                    deleted += 1;
                }
                for hash in keep {
                    insert.execute(params![ws, hash])?;
                }
            }
            Ok(deleted)
        })
    }

    /// Does ANY workspace reference this chunk? The §24 blob sweep's
    /// collect test (indexed by `chunk_refs_hash`).
    pub(crate) fn hash_has_refs(&self, hash: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM chunk_refs WHERE hash = ?1)",
            params![hash],
            |row| row.get(0),
        )
    }

    /// Is this chunk referenced by at least one workspace the user can
    /// read? The chunk pool is global, but content visibility is not.
    pub(crate) fn chunk_visible_to(&self, hash: &str, user_name: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM chunk_refs cr
                JOIN workspaces w ON w.id = cr.workspace_id
                LEFT JOIN team_members tm
                    ON tm.team_id = w.team_id AND tm.user_name = ?2
                WHERE cr.hash = ?1 AND (w.owner = ?2 OR tm.user_name = ?2)
            )",
            params![hash, user_name],
            |row| row.get(0),
        )
    }

    /// All snapshots of a workspace, newest first — metadata only: a
    /// manifest can be tens of MiB, and retained checkpoints plus
    /// unlimited named snapshots would make the full-body list read
    /// allocate hundreds of MiB under the DB mutex.
    pub(crate) fn list_snapshots(&self, workspace_id: &str) -> rusqlite::Result<Vec<SnapshotMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, kind, device, created_at FROM snapshots
             WHERE workspace_id = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt.query_map(params![workspace_id], |row| {
            Ok(SnapshotMeta {
                id: row.get(0)?,
                name: row.get(1)?,
                kind: row.get(2)?,
                device: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub(crate) fn get_snapshot(
        &self,
        workspace_id: &str,
        id: i64,
    ) -> rusqlite::Result<Option<Snapshot>> {
        self.conn
            .query_row(
                "SELECT id, name, kind, device, created_at, manifest FROM snapshots
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id, id],
                |row| {
                    Ok(Snapshot {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        kind: row.get(2)?,
                        device: row.get(3)?,
                        created_at: row.get(4)?,
                        manifest: row.get(5)?,
                    })
                },
            )
            .optional()
    }

    // --- wrapped keys (§17) -------------------------------------------------

    /// Store (or replace) the workspace key wrapped to a member's public
    /// key. The blob is opaque to the relay — hex of the sealed-box wrap.
    pub(crate) fn put_wrapped_key(
        &self,
        workspace_id: &str,
        user_name: &str,
        blob: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO wrapped_keys (workspace_id, user_name, blob) VALUES (?1, ?2, ?3)
             ON CONFLICT (workspace_id, user_name) DO UPDATE SET blob = excluded.blob",
            params![workspace_id, user_name, blob],
        )?;
        Ok(())
    }

    /// The workspace key wrapped for this user, if the writer wrapped one.
    pub(crate) fn get_wrapped_key(
        &self,
        workspace_id: &str,
        user_name: &str,
    ) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT blob FROM wrapped_keys WHERE workspace_id = ?1 AND user_name = ?2",
                params![workspace_id, user_name],
                |row| row.get(0),
            )
            .optional()
    }

    /// Delete the wrapped key stored for a user (§20). Idempotent: a wrap
    /// that was never stored (or is already gone) is not an error — the
    /// postcondition "no wrap for this user" holds either way.
    pub(crate) fn delete_wrapped_key(
        &self,
        workspace_id: &str,
        user_name: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM wrapped_keys WHERE workspace_id = ?1 AND user_name = ?2",
            params![workspace_id, user_name],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §20: wrapped-key rows delete idempotently — removing a member's
    /// wrap twice, or one that never existed, is a success either way.
    #[test]
    fn wrapped_keys_delete_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("relay.db")).unwrap();
        db.put_wrapped_key("ws-1", "alice", "deadbeef").unwrap();
        assert_eq!(
            db.get_wrapped_key("ws-1", "alice").unwrap().as_deref(),
            Some("deadbeef")
        );
        db.delete_wrapped_key("ws-1", "alice").unwrap();
        assert_eq!(db.get_wrapped_key("ws-1", "alice").unwrap(), None);
        // Deleting again, deleting a never-wrapped user, and deleting on
        // another workspace are all fine — and touch nothing else.
        db.delete_wrapped_key("ws-1", "alice").unwrap();
        db.delete_wrapped_key("ws-1", "bob").unwrap();
        db.put_wrapped_key("ws-2", "alice", "cafe").unwrap();
        db.delete_wrapped_key("ws-1", "alice").unwrap();
        assert_eq!(
            db.get_wrapped_key("ws-2", "alice").unwrap().as_deref(),
            Some("cafe"),
            "deletes are scoped to (workspace, user)"
        );
    }

    /// §20: member removal reports whether a row existed, and cascades to
    /// the departed user's wrapped keys across every workspace attached to
    /// the team — and ONLY those: wraps on other teams' or unattached
    /// workspaces, and other members' wraps, survive.
    #[test]
    fn remove_member_cascades_wrapped_keys_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("relay.db")).unwrap();
        db.create_team_with_owner("t1", "acme", 1, "alice", true)
            .unwrap();
        db.create_team_with_owner("t2", "other", 1, "alice", true)
            .unwrap();
        db.add_member("t1", "bob", "reader").unwrap();
        db.add_member("t2", "bob", "reader").unwrap();
        // Two workspaces on t1, one on t2, one unattached.
        db.create_workspace("w1", "one", Some("alice"), Some("t1"), true)
            .unwrap();
        db.create_workspace("w2", "two", Some("alice"), Some("t1"), true)
            .unwrap();
        db.create_workspace("w3", "three", Some("alice"), Some("t2"), true)
            .unwrap();
        db.create_workspace("w4", "four", Some("alice"), None, true)
            .unwrap();
        for ws in ["w1", "w2", "w3", "w4"] {
            db.put_wrapped_key(ws, "bob", "blob").unwrap();
        }
        db.put_wrapped_key("w1", "alice", "blob").unwrap();

        // Removing a NON-member is a no-op that reports false and
        // cascades nothing.
        assert!(!db.remove_member("t1", "carol").unwrap());
        for ws in ["w1", "w2", "w3", "w4"] {
            assert!(db.get_wrapped_key(ws, "bob").unwrap().is_some());
        }

        // The actual removal: true, and bob's wraps die on BOTH t1
        // workspaces — but not on t2's or the unattached one, and alice's
        // wrap is untouched. Bob's t2 MEMBERSHIP survives too.
        assert!(db.remove_member("t1", "bob").unwrap());
        assert_eq!(db.get_wrapped_key("w1", "bob").unwrap(), None);
        assert_eq!(db.get_wrapped_key("w2", "bob").unwrap(), None);
        assert!(db.get_wrapped_key("w3", "bob").unwrap().is_some());
        assert!(db.get_wrapped_key("w4", "bob").unwrap().is_some());
        assert!(db.get_wrapped_key("w1", "alice").unwrap().is_some());
        assert_eq!(db.member_role("t2", "bob").unwrap().as_deref(), Some("reader"));
        // Idempotent: the second removal reports false.
        assert!(!db.remove_member("t1", "bob").unwrap());

        // The owner counter the route's last-owner guard reads.
        assert_eq!(db.owner_count("t1").unwrap(), 1);
        db.add_member("t1", "carol", "owner").unwrap();
        assert_eq!(db.owner_count("t1").unwrap(), 2);
    }

    /// §19: a pre-§19 data dir (a users table without the bundle columns)
    /// gains them at open, its legacy rows survive untouched, and bundle
    /// writes/reads work against the migrated table.
    #[test]
    fn users_table_migration_adds_bundle_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            // Hand-create the OLD schema: pubkey only, no ed_pubkey/key_sig.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (
                    name TEXT PRIMARY KEY,
                    token TEXT UNIQUE NOT NULL,
                    created_at INTEGER,
                    pubkey TEXT
                );
                INSERT INTO users (name, token, created_at, pubkey)
                    VALUES ('legacy', 'tokdigest', 1, 'aa');",
            )
            .unwrap();
        }

        // The normal open path migrates: the legacy row keeps its pubkey
        // with NULL bundle halves...
        let db = Db::open(&path).unwrap();
        let bundle = db.user_key_bundle("legacy").unwrap().unwrap();
        assert_eq!(bundle.pubkey.as_deref(), Some("aa"), "legacy row intact");
        assert_eq!(bundle.ed_pubkey, None);
        assert_eq!(bundle.key_sig, None);

        // ...and bundle writes/reads work on the migrated table.
        assert!(db.set_user_key_bundle("legacy", "bb", "cc", "dd").unwrap());
        let bundle = db.user_key_bundle("legacy").unwrap().unwrap();
        assert_eq!(bundle.pubkey.as_deref(), Some("bb"));
        assert_eq!(bundle.ed_pubkey.as_deref(), Some("cc"));
        assert_eq!(bundle.key_sig.as_deref(), Some("dd"));

        // Re-opening is a no-op (the migration is idempotent).
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.user_key_bundle("legacy")
                .unwrap()
                .unwrap()
                .ed_pubkey
                .as_deref(),
            Some("cc")
        );
    }

    /// §28: a pre-§28 data dir (a teams table without `sync_env`) gains
    /// the column at open, and existing teams land on the DEFAULT true —
    /// the kill switch never retroactively changes what a team syncs.
    #[test]
    fn teams_table_migration_defaults_sync_env_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            // Hand-create the OLD schema: no sync_env column.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE teams (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    created_at INTEGER
                );
                INSERT INTO teams (id, name, created_at) VALUES ('t1', 'legacy', 1);",
            )
            .unwrap();
        }

        // The normal open path migrates: the legacy team keeps its row and
        // reads back sync_env = true (the product promise)...
        let db = Db::open(&path).unwrap();
        let team = db.get_team("t1").unwrap().unwrap();
        assert_eq!(team.name, "legacy");
        assert!(team.sync_env, "existing teams keep the .env promise");

        // ...the policy setter works on the migrated table...
        assert!(db.set_team_sync_env("t1", false).unwrap());
        assert!(!db.get_team("t1").unwrap().unwrap().sync_env);
        assert!(
            !db.set_team_sync_env("nope", false).unwrap(),
            "unknown team reports false so the route can 404"
        );

        // ...and re-opening is a no-op (the migration is idempotent).
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(!db.get_team("t1").unwrap().unwrap().sync_env);

        // A fresh create on a migrated table carries the flag explicitly.
        db.create_team_with_owner("t2", "new", 2, "alice", false)
            .unwrap();
        assert!(!db.get_team("t2").unwrap().unwrap().sync_env);
    }

    /// §22: a file-backed open lands WAL + synchronous=NORMAL (the two
    /// pragmas that take the per-commit fsync off the request path), and
    /// a row committed before close survives a reopen — a crash can only
    /// roll back recent committed transactions, never lose durable state
    /// or corrupt the file.
    #[test]
    fn open_sets_wal_and_synchronous_normal_and_data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            let db = Db::open(&path).unwrap();
            let journal_mode: String = db
                .conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(journal_mode, "wal");
            let synchronous: i64 = db
                .conn
                .query_row("PRAGMA synchronous", [], |row| row.get(0))
                .unwrap();
            assert_eq!(synchronous, 1, "1 = NORMAL");
            db.create_workspace("ws-1", "one", Some("alice"), None, false)
                .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let ws = db.get_workspace("ws-1").unwrap().unwrap();
        assert_eq!(ws.name, "one");
        assert_eq!(ws.owner.as_deref(), Some("alice"));
    }

    /// with_tx's COMMIT-failure arm: a failed COMMIT leaves the
    /// transaction OPEN (SQLITE_BUSY does not auto-rollback), and without
    /// the rollback every later BEGIN on this one shared connection would
    /// fail — all commits 500 forever. The fault is injected with
    /// rollback-journal lock semantics: a reader's SHARED lock lets our
    /// BEGIN IMMEDIATE through (RESERVED is compatible with SHARED) but
    /// blocks the COMMIT-time upgrade to EXCLUSIVE. Under §22's WAL that
    /// failure can no longer be manufactured cross-connection (readers
    /// never block writers), so the test connection is switched back to
    /// DELETE for the injection. The arm still matters under WAL — COMMIT
    /// can fail there too (SQLITE_FULL, SQLITE_IOERR) and must never
    /// wedge the shared connection. (Lives here, not in tests.rs: the
    /// journal-mode switch needs the private `conn`.)
    #[test]
    fn failed_commit_rolls_back_so_the_shared_connection_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let db = Db::open(&path).unwrap();
        db.create_workspace("ws2", "w2", Some("alice"), None, false)
            .unwrap();
        // Rollback-journal mode for the fault injection (see above).
        let mode: String = db
            .conn
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "delete");

        // A second connection holding a SHARED read lock.
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN DEFERRED").unwrap();
        blocker
            .query_row("SELECT count(*) FROM workspaces", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();

        let refs: std::collections::HashSet<String> =
            ["h9".to_string()].into_iter().collect();
        assert!(
            db.insert_head("ws2", 1, "hash1", "{}", &refs).is_err(),
            "COMMIT must fail while the reader holds its lock"
        );

        // Release the reader: the shared connection must NOT be wedged in
        // the dead transaction — the next with_tx succeeds.
        blocker.execute_batch("ROLLBACK").unwrap();
        db.insert_head("ws2", 1, "hash1", "{}", &refs)
            .expect("the connection recovers after a failed COMMIT");
        assert!(db.chunk_visible_to("h9", "alice").unwrap());
    }
}
