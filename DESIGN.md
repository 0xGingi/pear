# pear — Design Doc

Status: draft v0.1
Audience: us, before any code exists.

## 1. What this is

Dropbox for developers. Your entire working context — uncommitted changes,
local branches, stashes, environment, local data — follows you across
machines, and can be handed to a teammate as a link.

Explicitly not a cloud IDE. Compute stays local; state moves. Gitpod,
Codespaces, and Coder all answered this problem by moving the workspace into
a container in their cloud. This product bets developers don't want that —
they want their own machine, their own editor, their own GPU — and the thing
that should move is *state*.

## 2. Principles

1. **Sync state, never system.** The environment (toolchain, packages,
   editor extensions) is *declared* in a manifest and rebuilt on each
   machine. Only unreproducible state — files you haven't committed, data
   you haven't exported — ever crosses the wire.
2. **One writer at a time.** Every workspace has exactly one active writer,
   enforced by a lease. No CRDTs, no OT, no live multi-writer merge. This is
   the decision that keeps the hard distributed-systems problem out of the
   product.
3. **Adopt, don't invent.** Nix flakes / devcontainer.json for environments,
   S3 for chunk storage, git stays git. Our surface area is sync, snapshots,
   and leasing — nothing else.
4. **Local-first.** Everything works offline. Sync catches up when the
   network does.

## 3. Core concepts

- **Workspace** — a project directory under pear management. Has an ID,
  an owner, a content log, and a head. The unit of sync.
- **Lease** — a single-writer token for a workspace, held by one device at a
  time. Heartbeat-based, transferable, force-takable (with consequences, see
  §5).
- **Snapshot** — an immutable, content-addressed point-in-time capture of a
  workspace's files plus metadata. The unit of history, sharing, and
  recovery.
- **Manifest** — the environment declaration that already lives in the repo
  (`flake.nix` or `.devcontainer/devcontainer.json`), plus a small
  `pear.toml` for sync-specific behavior. We do not invent a new env
  format.

## 4. What syncs vs. what rebuilds

| Thing | Behavior | Why |
|---|---|---|
| Worktree files (incl. uncommitted changes) | **Sync** | The core value. |
| `.git/` (branches, stash, unpushed commits) | **Sync** | Single-writer makes this safe; applied last during updates (§5). |
| `.env*` and local config | **Sync (deliberate default)** | "Environment follows me" includes secrets; encrypted in transit and at rest. Overridable in `pear.toml`. |
| `node_modules/`, `target/`, `dist/`, build outputs | **Never sync** | Reproducible; respect `.gitignore` plus a built-in exclude list. |
| Toolchain, packages, editor extensions | **Rebuild from manifest** | Declared, not synced. |
| Local database contents | **State providers** (post-MVP) | Snapshot-time dump/restore hooks, e.g. `pg_dump`. Never live-sync a data dir — that corrupts. |
| Running processes | **Record command only** | On clone/handoff, offer to restart what was running. No CRIU, no process checkpointing. |

## 5. Sync and conflict model

### Lease lifecycle

- The device holding the lease is the **writer**; all other devices are
  **read-only mirrors** that apply the writer's changes as they arrive.
- `pear checkout <workspace>` on device B: B must be synced to head, then
  the server transfers the lease. A's final state is checkpointed as a
  snapshot first. A becomes a mirror.
- Writer goes offline mid-work: mirrors keep their last-consistent state.
  Another device can `pear checkout --force`. The old writer's lease is
  revoked; if it later reconnects with unsynced changes, those become a
  **divergent snapshot** the user can diff and restore from manually. Forks
  are explicit, never silently merged.
- Lease heartbeats (30s) keep a crashed laptop from holding a workspace
  hostage; expiry is 5 minutes.

### Conflict policy

There are no file-level conflicts by construction — only one writer exists.
The failure modes are (a) force-takeover forks, handled as divergent
snapshots above, and (b) partial application of a sync batch on a mirror,
handled by staged application below. Dropbox's last-writer-wins-with-
conflict-copies model is *not* used; for code and `.git`, silent conflict
copies are worse than an explicit fork.

### Apply protocol (mirrors)

1. Stage incoming chunks into `.pear/staging/`.
2. Apply as a batch: deletes → writes → renames, fsync, then update the
   local manifest pointer.
3. `.git/` paths are applied **last**, after the worktree is consistent, so
   an interrupted apply leaves at worst a stale-but-valid repo, never a
   half-written one. Recovery path if it ever does break: restore from the
   last checkpoint snapshot (they're immutable and content-addressed).

### Ignore rules

Respect `.gitignore` by default, *except* `.env*`-style files, which sync.
Both directions overridable per-workspace in `pear.toml`.

## 6. Snapshots and team flows

### Format

- Files are split with content-defined chunking (FastCDC, ~1 MiB average),
  hashed with BLAKE3, deduplicated across snapshots and across the whole
  workspace's history. Content-addressed store, same model as restic.
- A snapshot = a manifest tree (path → chunk hashes, mode, mtime) + metadata:
  workspace ID, device, timestamp, message, manifest hash, git HEAD.
- Two kinds: **named** (`pear snapshot -m "before refactor"`, kept
  forever) and **checkpoints** (automatic: on lease release, on force
  takeover, hourly while dirty; rolling retention — hourly for a day, daily
  for a week).

### Sharing

Sharing = granting read access to an immutable snapshot. `pear share`
returns a link. The recipient runs `pear clone <link>` and gets the exact
file state, then the environment rebuilds from the manifest. Clones are new
workspaces (forked lineage), not mirrors — the sharer's workspace is
untouched.

### The three team flows this enables

1. **Onboarding in minutes** — `pear clone acme/api` on a fresh laptop:
   files appear, environment builds, done. Replaces the wiki page of setup
   steps.
2. **Bug repro** — "tests fail on my machine" → `pear snapshot` → link →
   teammate clones the *exact* state, unpushed branch and all.
3. **Pairing / handoff** — lease transfer moves the live workspace to a
   teammate's machine mid-problem.

## 7. Security model

Threat model: the sync server is semi-trusted infrastructure; teams are
sending each other proprietary code and `.env` files.

- Device identity: each device has an ed25519 keypair, enrolled per user.
- v1 (honest trade-off): TLS in transit, per-workspace AES-256 keys held by
  the server, encryption at rest. This is early-Dropbox's model and it makes
  sharing and search simple. We state it plainly in the docs rather than
  pretending otherwise.
- Designed for E2E from day one: the chunk and snapshot formats carry an
  encryption envelope, so moving to client-side keys (workspace key wrapped
  to each member's public key, snapshot sharing = re-wrapping) is an
  upgrade, not a migration. Target: v1.1.
- Known metadata leakage even under E2E later: workspace sizes, chunk
  counts, timing. Acceptable; documented.

## 8. Architecture

- **`peard`** — per-machine daemon: filesystem watcher (FSEvents /
  inotify), debounce, chunker, sync client, lease holder, apply engine.
  Plain directories on disk; **no FUSE, no virtual filesystem** — that path
  is how sync products die.
- **`pear`** — CLI control surface (`init`, `clone`, `checkout`,
  `snapshot`, `share`, `status`, `log`).
- **Relay server** — auth, user/team registry, lease coordination, snapshot
  metadata (Postgres), chunk store (S3-compatible). Sync events fan out to
  mirrors over WebSocket; chunks flow device → S3 → mirrors, presigned.
- **Offline** — the daemon queues operations locally and pushes on
  reconnect; mirrors simply apply the backlog in order.
- **Implementation** — Rust throughout: `peard`, `pear`, and the relay
  (axum). Client and server share crates for the protocol: chunk format,
  manifest schema, encryption envelope. Chosen over TS/Bun for watcher
  reliability at scale, daemon memory footprint, static-binary
  distribution, and native-speed chunking/hashing.

Rough sync flow: watcher fires → debounce (500ms) → chunk new/changed files
→ upload missing chunks → commit new manifest as head → server notifies
mirrors → mirrors stage and apply per §5.

## 9. MVP scope

**In:** `init` + continuous file sync on one device; multi-device mirrors +
lease handoff; named snapshots; `share`/`clone`; macOS + Linux (both
verified: full suite green on APFS and on x86_64 Linux); single-tenant
cloud hosted by us.

**Out (explicit non-goals for v1):** live multi-writer collab, FUSE/virtual
files, process checkpointing, database state providers, GUI, Windows, full
E2E, self-hosting.

Milestones, in dependency order:

1. M1 — local sync loop: watch → chunk → upload → apply on a second directory.
2. M2 — multi-device + lease + handoff.
3. M3 — snapshots, share links, clone-from-snapshot.
4. M4 — teams: membership, ACLs (owner / writer / reader), onboarding flow.

## 10. Risks and open questions

- **`.git` sync edge cases.** Single-writer + apply-last + snapshots bounds
  the damage, but the recovery UX (`git fsck` horror stories from Dropbox
  users) needs real testing before teams trust it.
- **Force-takeover forks.** The divergent-snapshot UX has to be excellent or
  users will lose uncommitted work once and never trust the product again.
- **`.env` sync-by-default.** Decided: stays. It *is* the product's promise;
  the mitigation for security teams is a per-team kill switch, not a
  different default.
- **Monorepos.** Initial clone time and watcher load at 500k+ files are
  measured in §15 (50k/5k synthetic trees): the double walk is noise
  (0.5s of a 25.7s cold cycle) and stays — the `ignore` crate's
  override layer provably cannot compose whitelist-over-gitignore
  (evidence pinned in `crates/core/tests/perf.rs`). The real cold-clone
  bottleneck is the sink phase below.
- **Sink-phase fsync cost — RESOLVED (§18 + §25).** Was the measured
  clone bottleneck (~6ms/chunk up, ~12ms/chunk down at 5k). Client-side
  batched flush (§18) plus directory-sync flush (§25) and relay-side
  commit-point flush + WAL (§22) brought the 5k e2e clone from 92.9s
  to 42.9-53.2s; durability semantics are pinned in those sections.
- **Built-in excludes are name-based — RESOLVED (§14).** A *tracked*
  directory named `build`/`dist`/`target`/`node_modules` was silently
  skipped; `pear.toml` per-workspace include/exclude (§14) is the
  override, with precedence `exclude > include > built-in > gitignore`.
  (Raised by M1 autoreview.)
- **Symlinked ancestors in the target (resolved in M2).** Apply rejects
  any destination whose ancestors below the target include a symlink
  (`ensure_real_ancestors`); a network manifest can no longer write or
  delete outside the mirror tree. (Raised by M1 autoreview; fixed when
  manifests became network input.)
- **Relay handlers block on the async runtime — RESOLVED (§14).** All
  rusqlite queries and store I/O moved into `spawn_blocking` behind the
  one DB mutex (§14 hardening batch).
- **Lost-response + edit race (M3).** If a head commit's response is lost
  and the user edits before the retry, the writer wedges behind its own
  commit. `pear mirror` would then overwrite the newer local edit; only
  `--force` preserves it. M3's divergent snapshots are the real fix; the
  resume-refusal message now spells out both remedies' consequences.
- **Name.** Decided: **pear** ("devbox" collides with Jetify's Devbox, a
  Nix-based dev-environment tool). Personal project: no
  trademark/collision sweep is planned.
- **Trust model — RESOLVED (§17, hardened §19/§20).** E2E encryption is
  live: AES-256-GCM convergent chunks + encrypted manifests, X25519
  wrapped keyrings, ed25519 signed device keys with writer-side pinning,
  and key generations that cut removed members off future content.
  Server-held-keys workspaces remain supported as the non-E2E flavor.

## 11. M2 implementation contract

M2 = multi-device mirrors + lease handoff (§9). Deliverables: `pear-relay`
(server binary) and relay client flows in `pear-core` + `pear` CLI. The
`peard` daemon/IPC split is deferred — M2 runs foreground `pear watch`
(writer) and `pear mirror` (mirror).

### Deviations from §8 (reversible; seams preserved)

- Relay stores chunks on server-local disk in one global content-addressed
  pool (reuses `LocalStore`); S3-presigned flow arrives with scale, behind
  the same `ChunkSink`/`ChunkSource` seam.
- Relay metadata in SQLite (rusqlite); Postgres arrives with teams.
- Auth: one shared bearer token (`PEAR_TOKEN`); device keypairs + the E2E
  envelope stay on the §7 roadmap.
- Mirror updates: 2s polling; WebSocket fan-out deferred.
- Lease transfer requires the current lease to be expired or held by the
  requester (the common closed-laptop case); everything else is `force`,
  which revokes and fences via generation bump. Divergent-snapshot capture
  on force takeover arrives with M3 snapshots — until then, force-taken
  workspaces may strand the old writer's unsynced changes (documented risk).
- TLS: dev/localhost; production termination deferred.

### HTTP API (JSON unless noted; `Authorization: Bearer <token>` required on all)

- `POST /v1/workspaces` `{ id, name }` → 201 `{ id }`; 409 if id exists.
  The id is the client-generated workspace id from `pear init`.
- `GET /v1/workspaces/:id` → 200 `{ id, name, head_seq, head_hash, lease }`
  where `lease` is `{ holder, generation, expires_at }` or null.
- `PUT /v1/workspaces/:id/chunks/:hash` (binary body) → 200; idempotent;
  `:hash` must be 64 lowercase hex.
- `GET /v1/workspaces/:id/chunks/:hash` → 200 binary; 404.
- `POST /v1/workspaces/:id/chunks/missing` `{ hashes: [..] }` → 200
  `{ missing: [..] }`. Batch presence check (global pool).
- `GET /v1/workspaces/:id/head` → 200 `{ seq, hash, manifest }`; 404 if
  none. `manifest` is the pear-core `Manifest` JSON document.
- `PUT /v1/workspaces/:id/head` `{ base_seq, manifest }` + headers
  `X-Pear-Device`, `X-Pear-Generation` → 200 `{ seq, hash }`;
  409 `{ current_seq }` on CAS conflict; 403 when the lease is held by
  another device, the generation is stale, or the lease expired (fencing).
  `hash` = BLAKE3 hex of the manifest JSON bytes. Server must
  `manifest::validate` every submitted manifest — the trust boundary
  exists here too.
- `POST /v1/workspaces/:id/lease/acquire` `{ device_id }` → 200
  `{ generation, expires_at }`. Succeeds immediately for the current
  holder or an expired lease (generation bumps on a steal); 409
  `{ holder, expires_at }` while another device holds a valid lease.
- `POST /v1/workspaces/:id/lease/heartbeat` `{ device_id, generation }` →
  200 `{ expires_at }`; 403 if not holder or stale generation.
- `POST /v1/workspaces/:id/lease/transfer` `{ device_id, generation,
  base_seq }` → 200 `{ generation }`; 409 unless the requester is synced
  to the current head (`base_seq == head_seq`) AND the current lease is
  expired or already theirs.
- `POST /v1/workspaces/:id/lease/force` `{ device_id }` → 200
  `{ generation }`. Always succeeds; bumps generation.
- Lease TTL: 300s (configurable via `--lease-ttl-secs`); writers heartbeat
  every 30s.

### Writer flow — `pear watch <path> --relay <url>`

1. `pear init` locally (existing), `POST /workspaces` (idempotent), lease
   acquire. Device id defaults to hostname, overridable via `--device`.
2. Heartbeat every 30s; on 403 exit loudly — the lease is lost.
3. On start the writer resumes only from the head it actually knows (its
   last committed/applied seq, `.pear/remote.json`); a device behind the
   relay head is refused (run `pear mirror` first). Takeover is explicit:
   `pear watch --relay --force` revokes the lease and makes this tree the
   head. Only `force` may strand changes.
4. Each sync cycle: scan → chunk (M1 logic, shared) → ONE batched
   presence check for all reusable chunks → `PUT` missing chunks →
   `PUT /head` with `base_seq` = last committed seq and lease headers.
   409/403 is fatal: the writer no longer owns the head.

### Mirror flow — `pear mirror <path> --workspace <id> --relay <url>`

1. Local init with the *remote* workspace id (`init_workspace` takes an
   optional explicit id).
2. Poll `GET /head` every 2s; unchanged seq → idle.
3. On change: diff remote manifest vs local → `chunks/missing` → GET
   missing chunks into the local `.pear/store` → apply (M1 engine,
   untouched) → write local manifest.

### Crate/server shapes (pinned for parallel work)

- `pear-relay` = library + thin binary. Library exposes:
  `pub async fn serve(addr: std::net::SocketAddr, token: &str, data_dir: &std::path::Path, lease_ttl_secs: u64) -> anyhow::Result<()>`
- HTTP client in `pear-core` (module `relay`), blocking (ureq 3), with
  typed errors for fenced (403) and conflict (409). `ChunkSink` gains a
  batch presence default method so the writer flow never does per-chunk
  HTTP calls; `LocalStore` uses the default (per-chunk `has`).

## 12. M3 implementation contract

M3 = snapshots, share links, clone-from-snapshot (§9). A snapshot is an
immutable manifest plus metadata stored on the relay; chunks stay in the
global content-addressed pool. Deviations from §6 (reversible):

- No time-based checkpoint retention yet (keep-all at dev scale);
  checkpoints fire on `lease/force` only — the lease-release checkpoint is
  redundant with the synced-to-head transfer rule.
- "Share a link" = the raw `--workspace`/`--snapshot` ids; signed URLs
  arrive with teams.
- Snapshot kinds: `named` (CLI-made) and `checkpoint` (relay-made on
  force). A "divergent snapshot" is a `named` snapshot taken of unsynced
  local state — the mechanism is the same.

### Relay API additions (auth on all routes; JSON)

- `POST /v1/workspaces/:id/snapshots` `{ name, device, manifest }` → 201
  `{ id, created_at }`. `name` may be null. The manifest gets the same
  validation as `PUT /head` (parse, path safety, workspace-id match,
  chunk-hash format, chunk presence) minus fencing/CAS. 404 on unknown
  workspace.
- `GET /v1/workspaces/:id/snapshots` → 200
  `{ snapshots: [{ id, name, kind, device, created_at }] }`, newest first.
- `GET /v1/workspaces/:id/snapshots/:sid` → 200
  `{ id, name, kind, device, created_at, manifest }`; 404.
- Snapshot ids are per-workspace incrementing integers.
- On `lease/force`: if a head exists, the relay records a checkpoint of it
  first (`kind: "checkpoint"`, `device`: the outgoing holder) — an
  overwritten head is never lost. Repeat forces skip duplicates (forcer
  already holds, or the newest checkpoint already matches the head).

### CLI

- `pear snapshot <path> [-m msg] --relay <url>` — scan → chunk → upload
  missing (the writer pipeline), then POST. Works on any pear workspace,
  head-synced or not — this is how unsynced state is preserved (the
  divergent-snapshot answer to force takeovers and the lost-response
  wedge).
- `pear snapshots <path> --relay <url>` — list snapshots of the local
  workspace.
- `pear clone <path> --workspace <id> --snapshot <sid> --relay <url>` —
  fetch the snapshot, fetch missing chunks, apply into a fresh directory
  with a NEW random workspace id (forked lineage per §6; writes
  `.pear/origin.json` recording the source workspace + snapshot). Clone
  never registers, mirrors, or pushes.
- The writer resume-refusal message also points at `pear snapshot` as the
  preserve-first option.

## 13. M4 implementation contract

M4 = teams: membership, ACLs (owner / writer / reader), the onboarding
flow (§9). This replaces the single shared bearer token with per-user
identity; device keypairs and the E2E envelope stay on the §7 roadmap
(v1.1), as does TLS termination.

### Auth model

- The relay bootstrap token (`PEAR_TOKEN` / `--token`) becomes the
  **admin** credential: it may create/list users and acts as an implicit
  owner on every workspace.
- `POST /v1/users` `{ name }` (admin only) → 201 `{ name, token }`. The
  token is shown once; only its BLAKE3 digest is stored. `GET /v1/users`
  (admin only) → list.
- Every other request authenticates as a user via
  `Authorization: Bearer <user-token>` (or the admin token).
- Workspace-scoped routes return **404** when the requester has no role
  on the workspace (don't leak existence) and **403** when they have a
  role but it is insufficient. One documented exception: `POST
  /v1/workspaces` itself is 201-vs-404 asymmetric — accepted because ids
  are 128-bit random and unguessable, and a fake-201 would break
  idempotent registration.
- The chunk pool stays global for dedup, but content visibility follows
  `chunk_refs` (written at every head/snapshot commit *and at
  `put_chunk` — uploading the bytes is the proof of knowledge): a chunk
  is served — and presence-answered — only when some workspace the
  caller can read references it. Manifest validation likewise requires
  visibility, not mere presence. Non-visible chunks report "missing" (a
  re-upload dedupes in the store), so the pool cannot be used as a
  cross-tenant presence oracle.

### Teams and roles

- A team has members; each membership carries one role: `owner`,
  `writer`, `reader`. The team's creator is its first owner.
- A workspace may be attached to at most one team (M4 simplification).
  A user's effective role on a workspace: workspace creator → owner;
  else their role in the attached team; else none.
- Capability matrix (writer includes reader, owner includes writer):

  | action | reader | writer | owner |
  |---|---|---|---|
  | mirror/pull, read head/chunks/snapshots | ✓ | ✓ | ✓ |
  | push chunks/head, lease ops, snapshot create | — | ✓ | ✓ |
  | attach workspace to a team | — | — | ✓ (and team owner/writer) |
  | team member management | — | — | team owner |

### API additions (JSON; existing routes gain the role checks above)

- `POST /v1/users`, `GET /v1/users` (admin).
- `POST /v1/teams` `{ name }` → 201 `{ id, name }` (any user; caller
  becomes owner). `GET /v1/teams` → teams the requester belongs to
  (admin: all).
- `POST /v1/teams/:id/members` `{ user, role }` → 200 (team owner only;
  target user must exist). `GET /v1/teams/:id/members` → members
  (members only).
- `POST /v1/workspaces/:id/team` `{ team_id }` → 200 (workspace owner
  who is also owner/writer in the team).
- `GET /v1/teams/:team/workspaces/:name` → workspace info (reader+ on
  the workspace) — name resolution for `acme/api`.
- `POST /v1/workspaces` accepts an optional `team_id` (attach at
  create, same rule). Workspace names are unique within a team.

### CLI

- `pear user create <name> --relay <url>` (admin token) — prints the
  new user's token once.
- `pear team create <team> --relay <url>`; `pear team add <team>
  --user <name> --role owner|writer|reader --relay <url>`;
  `pear team members <team> --relay <url>`.
- `pear share <path> --team <team> --relay <url>` — attach the local
  workspace to a team (workspace owner).
- `pear watch --relay [--team <team>]` — attach at register.
- `pear clone <path> --workspace <ref> --relay <url> [--snapshot sid]`
  where `ref` is a hex id or `team/name`: with `--snapshot`, the M3
  fork-clone; without it, **mirror the head once** (init with the
  shared id, `pull_once`) — the onboarding command.

### The onboarding flow this enables

1. Operator: `pear user create jane` → jane's token.
2. Owner: `pear team create acme`; `pear team add acme --user jane
   --role writer`; `pear watch ~/src/api --relay --team acme`.
3. Jane: `pear clone ~/api --workspace acme/api --relay` — files in
   minutes, no wiki page.

### Deviations / notes

- Schema is rebuilt for users/teams/owner columns; pre-M4 relay data
  dirs are dev-stage and should be deleted on upgrade (no migration).
- Pre-M4 workspaces (no owner) are treated as admin-owned.
- Signed share URLs, multiple teams per workspace, and device keypairs
  stay deferred.

## 14. Hardening batch contract (spawn_blocking, pear.toml, retention, WS)

Four deferred items from §10/§12. None change the trust model; wire-format
changes are limited to the one new WS route noted below.

### Relay: blocking I/O off the async runtime

- No rusqlite calls or chunk-store I/O in async handler bodies. Handlers
  delegate every DB/store touch to `tokio::task::spawn_blocking` (one
  shared helper), keeping the `Mutex<Db>` inside the blocking closure.
- Semantics unchanged: same routes, status codes, and transactional
  guarantees (head/snapshot commit + `chunk_refs` stay one transaction).
  This is a scheduling fix only — observable behavior identical.

### `pear.toml` per-workspace exclude override

- Optional `pear.toml` at the workspace root (syncs as a normal worktree
  file, so all devices share it; changes take effect on the next scan
  cycle):

  ```toml
  [sync]
  include = ["build", "tools/dist"]   # re-include paths the built-in
                                      # name list would exclude
  exclude = ["fixtures/node_modules"] # additional excludes
  ```

- Entries are root-relative path prefixes: plain component-wise prefix
  match on the normalized relative path (`build` matches `build/**` but
  not `rebuild/**`).
- Precedence: user `exclude` > user `include` > built-in name excludes
  (`node_modules`/`target`/`dist`/`build`/…) > gitignore (with the §5
  `.env*`/`.git` exception unchanged).
- Unparseable `pear.toml`: warn once per scan cycle and sync as if the
  file were absent — a config typo must never wedge the sync loop.

### Checkpoint time-based retention

- On every checkpoint insert (currently only `lease/force`), the relay
  prunes `kind = "checkpoint"` snapshots of that workspace: keep all from
  the last hour; then the newest per hour for 24h; then the newest per
  day for 7 days; delete the rest. Named snapshots are never pruned.
- Pruning is metadata-only — the chunk pool is untouched (chunks may
  still be referenced by other snapshots/heads; there is no GC).
- No background timer: retention runs at insert time only, keeping it
  deterministic and testable.

### WebSocket fan-out for mirrors

- `GET /v1/ws?workspace=<id>` (same bearer auth; reader role required,
  same 404-hides-existence rule) upgrades to a WebSocket. On every
  successful `PUT /head` the relay sends
  `{ "type": "head_changed", "workspace": id, "seq": n }` to every
  connection subscribed to that workspace. No other message types; the
  message is a hint, not correctness.
- Live connections re-check the reader role every 60s; a revoked
  subscriber's socket is closed, so revocation is promptly effective
  (hints carry only seq numbers, but that is still an activity signal).
- `pear mirror` keeps its pull logic untouched. It spawns a WS listener
  (blocking `tungstenite` in a thread); a `head_changed` message triggers
  an immediate pull cycle. Fallback: while the WS is disconnected the
  mirror polls every 2s exactly as today; while connected it still polls
  every 30s as a dropped-message safety net.
- Non-goals: no chunk transfer over WS, no presence protocol, no
  replay/backlog — a mirror that missed messages catches up via the poll.

## 15. Monorepo perf contract (measure first, then targeted fixes)

§10 flags initial-clone time, watcher load at 500k+ files, and the
double tree walk as unmeasured risks. This milestone measures them on
synthetic trees and fixes only what the numbers indict. No sync
semantics change; scan output must stay bit-identical.

### Measurement harness

- `crates/core/tests/perf.rs`, all tests `#[ignore]` (run explicitly
  via `cargo test -p pear-core --test perf -- --ignored --nocapture`);
  never part of the default suite.
- Synthetic tree generator (deterministic seed): N files across a
  realistic dir fan-out, mixed sizes (many small source files, some
  multi-MB blobs), a `.git/` with realistic internals, `.env*` files,
  and `node_modules/`+`target/` trees that must be excluded.
- Baselines, measured 2026-07-22 on the reference machine (Apple M4,
  macOS/APFS, debug build, deterministic seed 0x5eed5eed5eed5eed) —
  macOS/APFS reference points, not SLAs. Reproduce with
  `cargo test -p pear-core --test perf -- --ignored --nocapture`.

  | # | baseline | tree shape (deterministic) | wall time |
  |---|----------|----------------------------|-----------|
  | 1 | cold `scan` + chunk (the double walk + per-file fastcdc/BLAKE3, no sink — see note) | 50,149 scannable files / 249.4 MB across 52 dirs: 50,000 worktree files (49,994 × 1-8 KB source-like + 6 × 3 MiB blobs), 131 `.git` files, 16 `.env*` (some gitignored), `.gitignore`, README; plus 900 excluded files (`node_modules`/`target`) and 2 gitignored files that must stay out | scan 0.54 s + chunk 25.17 s = **25.71 s** (50,160 chunks out) |
  | 2 | steady-state cycle, one small file changed (real `sync_cycle`, warm cache) | same 50k tree | **2.24 s** (1 file, 1 chunk) |
  | 3 | no-op cycle (real `sync_cycle`) | same 50k tree | **2.11 s** |
  | 4 | e2e initial clone over a real local relay (`push_cycle` + `pull_once`) | 5,145 scannable files / 25.1 MB (5,000 worktree files + same garnish) | push 30.45 s (5,137 chunks up), pull 62.47 s (5,137 chunks down), **total 92.93 s** |

  Re-measured after the single-walk attempt below (`scan.rs` untouched
  — double walk kept; deterministic tree shapes byte-identical):
  [1] 0.44 + 22.11 = 22.55 s, [2] 2.17 s, [3] 2.15 s,
  [4] 32.44 + 72.77 = 105.21 s — unchanged within run-to-run noise
  (the e2e pull leg varies ±15 %).

  Re-measured 2026-07-23 in RELEASE mode (`[profile.release]
  lto = "thin"`, §26) after §18/§22/§23/§25:
  [1] 0.24 + 12.80 = **13.04 s**, [2] **0.52 s**, [3] **0.47 s**,
  [4] push 18.58 s + pull 18.96 s = **37.54 s** — debug-mode §25
  numbers were 20.37 + 22.55 = 42.92 s; steady-state cycles dropped
  ~5× from the original debug baselines.

  Why baseline 1 has no sink phase: a sink-inclusive cold cycle fsyncs
  twice per file (`LocalStore::put` + apply staging; `F_FULLFSYNC`
  costs ~2 ms on this volume, ~3.6 ms on the boot volume — measured).
  At 50k files that is ~100k serial flushes (3.5+ min), far outside
  the harness's ~60 s target, so baseline 1 measures the
  contract-literal "scan + chunk". The steady-state cycles (2/3) write
  no chunks, so they run the real pipeline unmodified (the writer/
  mirror state is fixture-seeded from baseline 1's chunk pass), and
  baseline 4 carries the real fsync-inclusive end-to-end cost at 5k:
  ≈6 ms/chunk up, ≈12 ms/chunk down — dominated by per-chunk flushes
  and per-request SQLite transactions on the relay. Whole-suite wall
  time is ~140 s on this machine — over the ~60 s target; the
  contract-pinned scales (50k files, 5k e2e) and per-file flush costs
  leave no room to shave it on this hardware, and the numbers above
  show exactly where it goes.
- Numbers are macOS/APFS reference points (Apple Silicon), not SLAs.

### The one pre-approved fix: single-walk scan

- Every cycle currently walks the tree twice (the second pass picks up
  `.env*`/`.git` with ignore rules off). Replace with ONE walk using the
  `ignore` crate's override/whitelist layer to force-include `.env*` and
  `.git` paths while respecting gitignore otherwise, IF exact current
  semantics can be preserved (including §14 `pear.toml` precedence and
  the `excluded` field's contents).
- Guardrail outcome: exact composition is IMPOSSIBLE with the
  `ignore` crate's override layer (0.4.31, per Cargo.lock), so the
  double walk stays and the fixture-tree equality test is moot.
  Evidence, pinned as the re-runnable `override_layer_probe` test in
  `crates/core/tests/perf.rs`: per `src/overrides.rs`, once at least
  one whitelist glob exists, every unmatched *file* is reported
  `Ignore` (`mat.is_none() && num_whitelists > 0 && !is_dir`;
  unmatched dirs still descend), and per `src/dir.rs` any override
  match — whitelist or ignore — returns before gitignore is ever
  consulted. Measured outcomes on a fixture tree: whitelisting
  `.env*` + `.git` + `.git/**` yields exactly those paths and drops
  every ordinary file (`README.md`, `src/main.rs`); a blacklist-only
  override (`!*.log`) defers non-matches to gitignore but cannot
  force-include anything; whitelisting `**` to compensate bypasses
  gitignore entirely (ignored files are walked). The needed third
  mode — "whitelist these patterns, defer everything else to
  gitignore" — does not exist, so the `.env*`/`.git`/`include` pass
  with ignore rules off stays.
- Anything further (parallel hashing, stat caching, chunked-tree
  manifests) requires the baseline numbers to justify it first — no
  speculative optimization.

## 16. `peard` daemon contract (process supervisor over existing loops)

§8 calls for a per-machine daemon; M2 deferred it to foreground
`pear watch`/`pear mirror`. This milestone makes the daemon real as a
**process supervisor only**: every sync/lease/apply semantic stays in
the existing watch/mirror loops, unchanged.

### Shape

- Second binary `peard` in `crates/cli` (`[[bin]]`), sharing pear-core.
  Runs in the foreground by default (supervision/auto-start is the
  user's init system, not ours); `--daemonize` explicitly out of scope.
- IPC: unix socket at `$PEAR_HOME/daemon.sock` (`$PEAR_HOME` defaults
  to `~/.pear`). Directory and socket 0700/same-uid; the CLI refuses a
  socket with wrong ownership/permissions. No TCP, no auth tokens on
  the socket — same-uid local trust.
- Protocol: newline-delimited JSON, one request → one response.
  Requests: `add_watch { path, relay, device, force, team }`,
  `add_mirror { path, workspace, relay }`, `list`, `remove { path }`,
  `status { path? }`, `shutdown`. Unknown request → error response.
- Registration carries the bearer token; the daemon holds tokens in
  memory only and never writes them to disk (including logs and status
  responses — tokens are never echoed).

### Semantics

- One OS thread per registered workspace, running the existing watch or
  mirror loop as-is. A wedged/failed loop is reported in `status` with
  its error; other workspaces are unaffected.
- `pear watch --daemon …` / `pear mirror --daemon …` register with the
  running daemon instead of running foreground (error if no daemon is
  up — no implicit spawn). `pear status` queries the daemon;
  `pear daemon stop` shuts it down cleanly (loops finish their current
  cycle, leases simply expire — no special release).
- Daemon state is the registration list only, persisted as
  `$PEAR_HOME/daemon.json` (paths + args, **no tokens**); on restart the
  daemon re-registers the list but refuses to resume workspaces without
  a token re-supplied via the environment (`PEAR_TOKEN`).
- Foreground `pear watch`/`pear mirror` without `--daemon` remain
  exactly as today. Two writers on one workspace remain impossible by
  the lease, daemon or not.
- Windows is out of scope; the socket code is unix-only (`#[cfg(unix)]`).

## 17. TLS + E2E encryption contract (phase 1)

§7 promised TLS in transit and an E2E upgrade carried by the existing
envelope seam. This lands both, scoped to what is shippable and honest;
the residual risks are listed at the end and are part of the contract.

### TLS

- `pear-relay --tls-cert <pem> --tls-key <pem>` serves HTTPS directly
  (rustls; no proxy required). Absent flags → plain HTTP for dev,
  unchanged.
- Clients (`pear watch/mirror/clone/…`) verify against system roots;
  `--tls-ca-cert <pem>` / `PEAR_TLS_CA` adds a private CA for
  self-signed deployments. **No skip-verify flag** — we do not ship
  that footgun. Applies uniformly to ureq and the tungstenite WS
  listener (wss). (Implementation note: ureq's `RootCerts` is
  exclusive, so a supplied CA *replaces* the system roots rather than
  extending them — curl `--cacert` semantics, documented in the flag
  help.)
- Tests generate certs at runtime (rcgen, dev-dependency); no PEM or
  key material is ever committed to the repo.

### E2E content encryption

- Cipher suite: AES-256-GCM (chunks and manifest), X25519 (via
  curve25519-dalek MontgomeryPoint) + HKDF-SHA256 sealed-box-style
  wrapping (workspace key → member), BLAKE3 content hashing unchanged
  — but now over **ciphertext**. (§17 originally named
  XChaCha20-Poly1305; this build environment has no crates.io access
  and the local registry carries `aes-gcm` but not
  `chacha20poly1305`. Both are sound AEADs, and the convergent-nonce
  scheme below makes GCM's nonce-reuse hazard inapplicable.) HKDF is
  implemented over `sha2` (the `hkdf`/`hmac` crates are likewise
  unavailable), pinned against RFC 5869 vectors.
- Chunks use **convergent encryption**: nonce = first 24 bytes of
  keyed-BLAKE3(workspace_key, plaintext). Identical plaintext under one
  workspace key dedupes exactly as today (the restic model in §6
  survives); the trade-off — content-equality is visible within the
  workspace — is accepted and documented here.
- The manifest is encrypted as one blob for E2E workspaces. Server-side
  manifest validation is impossible there, so: head/snapshot commits
  carry the encrypted manifest plus a plaintext `chunk_hashes` list
  (hashes of ciphertext — the server learns nothing it didn't already
  know from uploads); the relay maintains `chunk_refs` and fencing/CAS
  from that list exactly as before. Full manifest validation becomes a
  **client-side MUST** before any apply (mirrors already treat network
  manifests as hostile; this formalizes it).
- A workspace is E2E iff created with `e2e: true` (immutable).
  Plaintext head on an E2E workspace or vice versa → 409.

### Keys

- One X25519 keypair per user (per installation in phase 1), generated
  by `pear user keygen`; private key at `~/.pear/keys/<name>.x25519`
  mode 0600, public key registered via `POST /v1/users/:name/key`
  (self only). Moving an identity between machines is a manual
  export/import, like an SSH key.
- The workspace key (32B random) is generated client-side at first E2E
  push/init, stored locally at `.pear/workspace_key` mode 0600 (the
  `.pear` dir never syncs), and wrapped to each member's public key.
  Relay stores wrapped blobs only:
  `PUT /v1/workspaces/:id/keys/:user` (workspace writer/owner; body is
  the wrapped blob) and `GET /v1/workspaces/:id/keys/me`.
- Onboarding (`pear clone` on an E2E workspace) fetches the wrapped
  key, unwraps locally, and proceeds — the operator flow from §13
  gains no extra step.

### Accepted residual risks (contractual, not bugs)

- **TOFU on public keys** — RETIRED by §19 (signed device keys +
  writer-side identity pinning; first-sight pinning remains TOFU at
  the identity level, documented there).
- **No re-key on member removal** — RETIRED by §20 (key generations;
  removal cuts off future content, history stays readable to current
  members).
- **Metadata leakage** (unchanged from §7, now plus): chunk counts,
  sizes, timing, seq numbers; equality of chunk contents within a
  workspace. Paths and contents are encrypted.
- Server-held-keys workspaces (non-E2E) remain supported exactly as
  before; E2E is opt-in per workspace.

### §17 implementation notes (as built)

- Wire encodings: pubkeys are 64 lowercase hex; wrapped-key blobs are
  184 lowercase hex (92 bytes: ephemeral pub 32 ‖ nonce 12 ‖ wrapped
  key 32 ‖ tag 16); `manifest_enc` is base64 of `nonce 12 ‖ ct ‖ tag`
  over the manifest JSON. Head/snapshot flavor mixing is refused with
  409 `kind: "e2e_mismatch"`; `e2e_mismatch` joins `id_conflict` and
  `name_conflict` on workspace create.
- `GET /v1/teams/:id/members` carries a nullable `pubkey` per member;
  key registration is `PUT /v1/users/:name/key` (self only, replacing
  is allowed).
- Wrap-maintenance (wrapping the workspace key to every team member
  with a registered pubkey) runs at `pear watch --e2e` startup and at
  `pear share`. A member added later gains access at the next writer
  watch start or share; before that, their clone gets the actionable
  "ask the writer to push/re-wrap" error. The writer's local store
  keeps plaintext chunks (plaintext-hash keyed); mirrors keep
  ciphertext chunks and decrypt at apply through a verifying adapter.
- `pear clone`/`mirror` take `--name` for the enrolling identity.
  A failed e2e clone (no keygen'd identity, no wrapped key) leaves no
  filesystem side effects — retry is never blocked.
- HKDF is implemented over `sha2` (no `hkdf`/`hmac` crates in this
  environment) and pinned against RFC 5869 vectors; X25519 known-answer
  coverage is RFC 7748 §5.2.

## 18. Batched-fsync durability contract (client sync paths)

§15's baselines isolated the e2e clone cost: ≈12 ms/chunk down —
dominated by per-chunk `LocalStore::put` fsyncs plus two fsyncs per
applied file — and ≈6 ms/chunk up, dominated by relay-side puts and
per-request SQLite transactions. This milestone removes per-unit fsync
from the CLIENT sync paths in favor of group flushes at phase
boundaries, without weakening the post-commit durability story.

Scope line: relay-side batching (deferred pool puts, SQLite group
commit) is NOT in this section. It changes the network durability ack
(a PUT 200 there means durable today) and needs a `chunk_refs` heal
path for torn pool blobs; it waits for a later section with §18's
re-measured numbers to justify it. The relay's store stays eager.

### Terms

- Flush point: a point in a sync cycle where every write issued so far
  is made durable as a group — fsync each pending file, then fsync
  each touched directory. Same `fsync(2)`/`File::sync_all` semantics
  as today; only WHEN they are issued changes.
- Commit point: unchanged — the atomic manifest write
  (`manifest::write_file_atomic`: tmp + fsync + rename + dir fsync).
  The apply batch is durable only once the manifest pointer moves, and
  every group flush lands BEFORE its commit point.

### Chunk store (`LocalStore`)

- Two modes. `open` (eager, unchanged): fsync per `put` — the relay's
  pool keeps this. `open_deferred` (client sync paths): `put` is tmp
  write + rename with the open fd queued; when 64 puts are pending the
  queue flushes itself; `flush()` fsyncs every queued chunk file, then
  every touched shard directory.
- Flush points (all client-side):
  - mirror pull (`pull_inner`): after the fetch loop, before apply.
  - local sync (`sync_cycle`): after the scan/chunk pass, before apply.
  - e2e writer's local plaintext store: inside `E2eUploader::flush`.
- Content addressing becomes a VERIFIED invariant on read and write,
  not just on the wire:
  - `put` refuses bytes that do not BLAKE3-hash to the claimed hash
    (InvalidData; nothing is written).
  - `get` re-hashes and, on mismatch, deletes the chunk and returns
    NotFound — a torn post-crash chunk (dirent without data) heals
    itself: the next cycle re-fetches or re-chunks it. `has` stays a
    cheap existence check and never hashes.
- A failed flush keeps the un-fsynced remainder queued so the next
  flush retries it. Deferred mode never changes put/get error
  semantics, only fsync timing.

### Apply (file assembly)

- `apply` stages + renames all files without per-file fsync, then
  group-flushes every written file (reopen + fsync; a file that
  vanished in between is skipped) and the parent directory of every
  written OR DELETED file (deletes gain directory durability for the
  first time), then commits the manifest. Order: writes → group flush
  → manifest commit.
- Staging temporaries need no fsync: a crash can only resurrect a tmp
  name (cleaned by `clean_staging`) or lose a dest rename (rewritten
  next cycle from the still-old manifest).

### Crash matrix (power loss; every row recovers with no operator action)

| crash point | observable state | recovery |
|---|---|---|
| before chunk flush | chunk absent, or torn (dirent persisted, data lost) | absent: re-fetched/re-put next cycle; torn: verify-on-get deletes it, the following cycle re-fetches (two-cycle heal — `has` skips re-fetch until the first `get` detects it) |
| after chunk flush, before apply flush | chunk dirents durable (§25: flush fsyncs shard dirs only); a very recent chunk's DATA can still be torn after power loss | same verify-on-get heal — the name IS the hash, so torn data is detected, never trusted; staging temps cleaned by `clean_staging` |
| after apply flush, before manifest commit | new files durable, manifest still old | next cycle redoes the same writes (idempotent) |
| after manifest commit | fully durable (flush preceded commit) | — |

Loss window vs eager mode: up to 64 unflushed chunks or one apply
batch — always recoverable, because the source of truth (relay pool /
writer tree) is untouched by the window. No new permanent-loss mode is
introduced on any filesystem, including ones with no write-ordering
guarantee: that is exactly what verify-on-get covers.

### Explicitly unchanged

- Manifest, `remote.json`, and source-manifest writes stay eager
  atomic commits.
- Relay pool puts stay eager (network ack semantics); chunk
  visibility, `chunks/missing`, and GET contracts are untouched. The
  relay's GET does gain the store's verify-on-get: a torn pool blob
  now 404s instead of serving bad bytes the mirror's wire check would
  reject anyway — same stuck-workspace outcome, louder signal, and
  healing it is part of the deferred-relay section, not this one.
- No config knobs: the mode is chosen by the callsite, not the user.

### §18 implementation notes (as built)

- `LocalStore::open_deferred` queues `(shard_dir, File)` under a Mutex;
  64 pending puts self-flush (lock dropped first). `flush` drains under
  the lock, fsyncs outside it — files then deduped shard dirs — and
  requeues the un-fsynced remainder ahead of newer puts on error.
  `put`/`get` verify BLAKE3 content addressing on write and read
  (`get` self-heals: delete + NotFound); `has` never hashes. The
  relay's pool keeps `open` (eager): a chunk PUT 200 remains a
  durability ack. The relay's PUT route already verified
  body-hashes-to-name (routes.rs, with a regression test).
- Flush points: `sync_cycle` after the chunk pass, `pull_inner` after
  the fetch loop, `E2eUploader::flush` after the relay-buffer flush.
  `apply` records written dest paths + written/deleted parent dirs and
  group-flushes them (reopen + fsync; NotFound skipped) immediately
  before the manifest commit, which stays the sole commit point.
- Re-measured 2026-07-23, same machine/seed as §15 (suite + clippy
  green: 234 passed macOS AND x86_64 Linux/ext4):
  [1] 0.43 + 24.24 = 24.67 s, [2] 2.56 s, [3] 2.55 s (all unchanged —
  the sink was never in these paths),
  [4] push 31.58 s + pull 42.38 s = **73.96 s** (from 92.93 s;
  the pull leg −32 %, 12 → ≈8 ms/chunk).
- The remaining e2e cost is exactly what the scope line left behind:
  relay-side eager pool puts + per-request SQLite transactions (the
  31.6 s push leg) and per-chunk GET round trips + relay read path
  (the 42.4 s pull leg). Relay-side batching is the next measured perf
  candidate and still needs the `chunk_refs` heal path from the scope
  line before it can be contracted.

## 19. Signed device keys contract (retiring TOFU at the key registry)

§17's accepted residual risk: the key registry is trust-on-first-use —
`PUT /users/:name/key` accepts a replacement pubkey from any bearer of
the user's token, and the semi-trusted relay (§7) can substitute a
member's pubkey outright. Wrap-maintenance then wraps the workspace
key to the attacker's key, silently. This milestone binds each
encryption key to a long-term ed25519 identity with a signature, and
pins identities writer-side (the SSH known_hosts model), so
substitution becomes a loud failure instead of a silent wrap.

### Identity and bundle

- A user identity is a pair of keypairs: the existing X25519
  encryption key (`~/.pear/keys/<name>.x25519`) and a new long-term
  ed25519 signing key (`<name>.ed25519`, 32-byte seed, 0600,
  zeroized/redacted like the X25519 half). The ed25519 public key IS
  the identity; its full hex is the fingerprint `pear user id` prints.
- A signed key bundle is `{x25519, ed25519, sig}` (all lowercase hex;
  sig 64 bytes): sig = Ed25519Sign(`"pear device key v1\0"` ‖ name ‖
  x25519_pub_raw32). Domain-separated, and it binds the user NAME so a
  bundle cannot be replayed for another user.
- ed25519-dalek `=3.0.0-pre.6` from the offline registry, pinned
  against RFC 8032 §7.1 vectors in tests; keys come from
  `rand::random` seeds via `from_bytes` (no rand_core trait plumbing).

### Relay registry changes

- `PUT /v1/users/:name/key` takes the bundle, not a bare pubkey. The
  relay verifies the signature against the enclosed ed25519 key over
  the canonical statement for `:name` before storing (400 otherwise).
  The relay enforces bundle WELL-FORMEDNESS — never bundle AUTHENTICITY
  (that is the writer-side pin's job). Unsigned registrations
  (`{pubkey}` alone) are rejected (400): new keys are signed or
  nothing. Self-only and replacement-allowed are unchanged.
- The users table gains nullable `ed_pubkey` and `key_sig` columns
  (idempotent migration: PRAGMA table_info + ALTER TABLE; legacy rows
  keep `pubkey` only). `GET /v1/users/:name/key` and
  `GET /v1/teams/:id/members` carry the new nullable fields.
- `GET /users/:name/key` now returns the bundle to any authenticated
  user (today it hides non-self keys as null): pubkeys are public by
  design and teammates/`pear trust` need to read them.
- Legacy grandfathering: a pre-§19 `pubkey` row keeps working for
  READS (existing wraps still unwrap — the X25519 key never moved)
  but is never wrapped to again (below).

### Writer-side verification + identity pinning

- `$PEAR_HOME/known_keys` (0600, atomic write): JSON map user →
  ed25519 fingerprint, pinned at the first VERIFIED wrap for that
  user, global across workspaces — one identity per user, exactly the
  known_hosts model.
- Wrap-maintenance (watch startup, `pear share`) classifies each team
  member and reports the buckets:
  - no bundle (legacy pubkey-only) → `unsigned`: skipped ("re-run
    `pear user keygen` to sign your key"); never wrapped to.
  - bad signature → `bad_sig`: skipped and reported as a SECURITY
    event (possible relay/key tampering); never wrapped to.
  - valid bundle, ed25519 ≠ pinned → `pin_changed`: skipped ("identity
    changed since first wrap; if expected, run `pear trust <user>`").
  - valid bundle + pin match or first sight → wrapped; first-sight
    pins, and the CLI prints newly pinned fingerprints (an invitation
    to compare them out-of-band).
  The pass itself always succeeds: one bad member never blocks the
  rest.
- `pear trust <user> --relay <url>`: fetch the user's current bundle,
  verify its signature, re-pin. Explicit and operator-visible — a pin
  is never updated implicitly on mismatch.

### CLI and key files

- `pear user keygen`: creates only MISSING components (never
  overwrites; an existing `.x25519` is signed as-is, so old wraps
  still unwrap), then registers the signed bundle. Idempotent.
- `pear user id --name <name>`: print the ed25519 fingerprint (full
  hex) from the local key — the out-of-band comparison aid.
- `pear user export`/`import` move the FULL identity (both files); a
  legacy 32-byte export imports as x25519-only and gains the ed25519
  half at the next keygen.

### Mirror side: unchanged, and why that is safe

A relay can forge a WRAP blob directly (wrap its own key to a member's
real pubkey), but the forgery self-limits to a loud head-decrypt
failure: the head is encrypted under the writer's real workspace key,
which the relay cannot re-encrypt. No silent plaintext exposure via
forged wraps; wrap signatures stay out of scope.

### Accepted residual risks (contractual, not bugs)

- First-sight pinning is still TOFU at the IDENTITY level: a relay
  that substitutes a whole bundle before the writer's first wrap wins
  that pin. Closed out-of-band with `pear user id` fingerprints (the
  CLI prints newly pinned ones precisely to enable this).
- `known_keys` is per-device: each new writer device pins at its first
  wrap there.
- Legacy unsigned members receive no new wraps until they re-keygen —
  intentional hardening, not a regression.

### §19 implementation notes (as built)

- `crypto::EdKeypair` mirrors `UserKeypair` hygiene (seed zeroized on
  drop, Debug redacted, 0600 files); `bundle_statement` =
  `b"pear device key v1\0" ‖ name ‖ x25519_pub_raw32`; `ed_verify`
  uses dalek's `verify_strict` (rejects small-order keys and
  non-canonical signatures) and never panics on hostile input.
  RFC 8032 §7.1 TEST 1 and TEST 3 are pinned in tests and pass.
- Relay: `users` gains `ed_pubkey`/`key_sig` via idempotent
  PRAGMA+ALTER migration at open (with an old-schema test); the PUT
  route verifies the bundle over `:name` before storing, and
  `{pubkey}`-only bodies get a 400 pointing at `pear user keygen`.
  Non-self GET needed no access delta — §17 already served pubkeys to
  any authenticated user; the change is the bundle fields.
- Writer side: pure `classify_member` (NoKey/Unsigned/BadSig/
  PinChanged/Wrap{first_sight}) verifies the signature BEFORE the pin
  check — nothing unverified is ever pinned. `$PEAR_HOME/known_keys`
  is 0600 JSON `{user: ed25519_hex}`, atomic-written; a corrupt file
  is a loud error, never a silent reset. Newly pinned fingerprints are
  printed by watch/share with a compare-out-of-band hint; `bad_sig`
  prints as a SECURITY WARNING.
- `pear user keygen` signs an existing `.x25519` as-is (old wraps keep
  unwrapping) and a fresh `.x25519` under an existing `.ed25519` keeps
  the identity — and every pin — stable across X25519 rotation.
  `pear user id` prints the fingerprint; `pear trust <user>` re-pins
  after re-verifying; `pear user export`/`import` move the full
  identity (128 hex = x25519‖ed25519, 64 hex legacy x-only).
- Malformed bundle fields classify as `bad_sig` (a bundle that cannot
  decode cannot verify). Verified: 248 passed + clippy clean on macOS
  and x86_64 Linux; live smoke covered keygen idempotence, export →
  import fingerprint equality across homes, and pin_changed → trust →
  wrapped on a real relay.

## 20. Key generations contract (re-key on member removal)

§17's accepted residual risk: a removed team member keeps the
workspace key forever and can decrypt everything FUTURE pushes
produce. This milestone adds key generations so removal cuts off
future content, while keeping the two properties a sync tool needs:
no full re-upload on rotation, and no history loss for current
members. Content a member legitimately had while enrolled is NOT
re-protected — they could have copied it then; only content written
after the removal is.

### Generations

- The workspace key becomes a KEYRING: `{generation: key}` (gen 1 =
  the pre-§20 single key; a legacy `.pear/workspace_key` file or a
  32-byte legacy wrap blob migrates to `{1: key}` on load — no
  operator action). Local keyring: `.pear/workspace_keys` (0600 JSON).
- New/changed files are chunked under the NEWEST generation; unchanged
  files keep their existing ciphertext chunk hashes via the ordinary
  scan-cache reuse — so a rotation re-uploads nothing but the next
  real edits. Dedupe within a generation is exactly §17's convergent
  encryption; across generations the same plaintext has different
  ciphertext, which is fine because only post-rotation edits use the
  new generation.
- Readers decrypt with the whole keyring, trying newest → oldest:
  the AEAD tag disambiguates (keyrings stay small — one entry per
  removal in the workspace's history). Chunks, manifest envelopes,
  and snapshot envelopes all ride this; no on-disk or wire format
  gains a generation field.
- Wrap payloads become the serialized keyring (one sealed box per
  member, all generations included): a member always receives the
  full history. `wrap_key`/`unwrap_key` generalize from `[u8; 32]`
  to arbitrary payloads; a 32-byte plaintext unwraps as the legacy
  `{1: key}` keyring. The relay's wrapped-key blob validation relaxes
  from fixed-length to "hex, plausible length".

### Rotation triggers

- Member removal is a real operation, not a DB edit:
  `DELETE /v1/teams/:id/members/:user` (CLI `pear team remove <team>
  <user>`), team-owner gated, idempotent 204. Removing the LAST owner
  is refused (a team must keep an owner); leaving a team yourself is
  allowed. Removal deletes the departed member's wrapped-key rows in
  every workspace attached to that team — their `keys/me` dies with
  the membership, not at the next writer watch. The crypto cutoff
  (new generation) still waits for the writer's rotation pass below.
- Automatic, at `pear watch --e2e` startup, AFTER the lease is owned
  and before the first push: wrap-maintenance compares the current
  team member set against the set it last wrapped for (recorded in
  `.pear/`). A member who VANISHED since the last wrap means: rotate
  to a new generation, delete the departed member's wrapped-key rows
  (new `DELETE /v1/workspaces/:id/keys/:user`, same role gate as the
  PUT), then wrap the new keyring to the current set. A pure addition
  never rotates — new members get the full keyring.
- Manual: `pear rekey <path>` forces a rotation + re-wrap for the
  current team (compromise response, operator-initiated).
- Between a removal and the next writer watch start nothing new can
  be pushed (only the writer pushes, and the writer rotates before
  pushing), so the removal window has no silent exposure.
- Re-admitting a removed member wraps them the full CURRENT keyring:
  re-admission restores full history, including generations created
  while they were away. That is a policy choice, documented here.

### Explicitly unchanged

- Chunk/manifest wire formats, convergent nonces, head CAS/fencing,
  relay pool semantics, and §19's bundle verification all ride
  unchanged. The relay learns nothing new except the DELETE route and
  the relaxed blob length.
- Removed members keep whatever they already fetched (their cached
  keyring decrypts it — by design). Relay auth (team membership) is
  what cuts off their access to anything else.

### §20 implementation notes (as built)

- `Keyring` = `BTreeMap<u32, [u8; 32]>` (gen 1 = legacy), zeroize-on
  drop, redacted Debug; `.pear/workspace_keys` is 0600 JSON
  `{gen: key_hex}`; loaders prefer it over legacy `.pear/workspace_key`
  and store rewrites/removes the legacy file. Gen 0, empty maps,
  non-hex, and non-32-byte keys are load-time errors.
- Wrap payload = the keyring JSON inside the §17 sealed box (one box
  per member, full history); a 32-byte unwrap plaintext decodes as
  legacy `{1: key}`. `wrap_key`/`unwrap_key` take arbitrary bytes;
  the relay bounds blobs at 60..=65536 raw bytes (was fixed 184 hex).
- `rotation_maintenance(client, root, keyring, known_keys, force)`
  runs at watch startup AFTER the lease, before the first push:
  vanished member → rotate → delete departed wraps → §19 wrap →
  persist `.pear/wrapped_members.json` (0600, atomic). The record is
  the actually-WRAPPED set, so members skipped for bad/missing keys
  never cause spurious rotations. `pear rekey` forces the same pass.
- Member removal: `DELETE /v1/teams/:id/members/:user` (owner-gated,
  self-leave allowed, last-owner 409, idempotent 204) cascades the
  departed user's wrapped-key rows across the team's workspaces in the
  same transaction — `keys/me` dies with the membership, proven by a
  re-add resurrection test. CLI: `pear team remove <team> --user <u>`.
- The e2e removal story drives the real route: removal → watch-start
  rotation to gen 2 → push uploads exactly the edited file's chunks
  (no full re-upload — unchanged files reuse cached ciphertext hashes)
  → the departed member's stale ring fails the new head while old
  content still decrypts (by design) → a new member unwraps the
  two-generation ring and reads everything.
- Verified: 265 passed + clippy clean on macOS; Linux run alongside.
  (Pre-existing flakes seen under parallel load only: the lease-TTL
  and watch-disappears tests; both pass isolated and in final runs.)

## 21. WebSocket catch-up contract (head_now + reconnect)

§14's fan-out is strictly one-shot: the mirror's listener connects
once, and any blip (sleep, roam, relay restart) permanently demotes
that mirror to the 2s fallback poll; a (re)connecting subscriber
learns only about FUTURE commits; and a lagging broadcast receiver has
hints silently dropped (`RecvError::Lagged => continue`). All three
are the same problem: the feed has no catch-up. Because `head_changed`
hints are cumulative state (seq N), not a log of deltas, "replay"
degenerates to telling the subscriber the current head — no buffer,
no hello message, no per-event state.

### Protocol

- On WS subscribe (after the bearer + reader-role check, at upgrade
  time), the relay sends `{"type":"head_now","workspace":id,"seq":n}`
  FIRST — `n` = the workspaces row's current head seq (0 = no head),
  read in the same blocking section as the role check. Then hints
  stream as today. Additive: old relays never send it, new clients
  cope; old clients ignore unknown message types.
- A lagging broadcast receiver no longer has hints silently dropped:
  the relay sends a polite Close and ends the task. The client's
  reconnect (below) then catches up via `head_now`. Silent loss
  becomes a reconnect, which is exactly what the keepalive already
  does for a dead connection.
- The client feed gains a reconnect loop: on listener exit, respawn
  with backoff 1s ×2 per consecutive failure, capped at 30s, reset to
  1s after a connection stayed up at least 90s (2× the keepalive).
  Each reconnect is productive (head_now), so the §14 "no reconnect
  storm" objection is answered by the backoff, not by giving up
  forever.

### Mirror changes

- The feed listener parses `head_now` into the same seq channel as
  `head_changed`: any hint is "pull now", and the pull's own
  seq+hash idle check makes a nothing-changed wake-up one cheap
  `get_workspace` call. No new client-side state.
- The live-feed safety-net poll relaxes from 30s to 5 minutes: its
  only remaining job is catching a hint lost to a relay bug, since
  keepalive (45s), reconnect+head_now, and the 60s role re-check
  cover every realistic loss path. The 2s feed-down poll is unchanged
  — it is the correctness floor, not a safety net.

### Explicitly unchanged

- Pull correctness never depends on any of this (§14: hints are not
  correctness); `remote.json` idle checks stay the gate; the role
  re-check and the bearer/role upgrade gate are untouched; the relay
  stores nothing new.

### §21 implementation notes (as built)

- `ws_subscribe` subscribes BEFORE reading the head seq (same blocking
  section): a commit landing between the two is then either hinted or
  reported by `head_now`, never neither. `ws_fanout` sends
  `{"type":"head_now","workspace":id,"seq":n}` as the first frame;
  `Lagged` now Closes the subscriber instead of silently dropping
  hints. Lag-close is documented but untestable without heroics (the
  eager fan-out drain + TCP buffers absorb far more than the 8-slot
  channel) — channel-level lag semantics stay pinned by the existing
  broadcast test.
- Client: the feed thread is a supervisor — one mpsc channel for all
  connection generations (sender cloned per attempt), `connected`
  flips per attempt, backoff 1s ×2 cap 30s reset after a 90s-stable
  connection (sleeps the CURRENT delay, then computes the next —
  the first reconnect really waits 1s). `FeedExit::Orphaned` (the
  mirror dropped its receiver) stops the loop instead of spinning
  reconnects forever. `parse_head_hint` folds `head_now` into the
  same u64 seq channel; unknown types still ignored.
- Mirror: live-feed safety poll 30s → 5 min; the 2s feed-down poll is
  untouched. E2E proof: a mirror connecting AFTER a commit converges
  in seconds via head_now (`recv_timeout(5s)` vs the 5-minute poll).
- Verified: 271 passed + clippy clean on macOS and x86_64 Linux.

## 22. Relay-side batched durability contract

§18 left the up-leg at ≈6 ms/chunk: one pool fsync + one SQLite commit
fsync per chunk PUT on the relay. This milestone removes both from the
request path. The ack-semantics change is documented below, and the
recovery argument rides §18's verified content addressing plus the
seq-AND-hash comparisons the protocol already makes everywhere — no
new heal machinery is needed, and none may be added beyond what this
section lists.

### What changes

- The relay's pool store opens DEFERRED (`open_deferred`, §18) and is
  flushed AT COMMIT POINTS: `put_head` and `insert_snapshot` flush the
  pool inside their blocking sections, before the head/snapshot row
  commits (a 5 s backstop tick covers stray puts; the 64-pending
  self-flush bounds bursts). Rationale: a chunk only needs durability
  once a head or snapshot REFERENCES it — an accepted-but-never-
  referenced chunk is unreferenced garbage whose loss costs nothing —
  and a continuous timer flush (tried first) measurably REGRESSED the
  push leg on APFS: its F_FULLFSYNC bursts saturated the disk and
  stalled in-flight PUTs, while doing zero fsyncs during the upload
  stream plus one burst at commit does not. The ack semantics are
  therefore precise rather than approximate: a chunk referenced by a
  committed head/snapshot is PRESENT (sharpened by §25: dir-durable —
  a rare very-recent-blob tear after power loss is always caught by
  verify-on-get and heals by re-upload, never silently wrong); an
  accepted chunk awaiting reference has no guarantee at all. Crash
  window = "since the last commit point", and the matrix below covers
  it.
- SQLite at open: `PRAGMA journal_mode=WAL` + `PRAGMA
  synchronous=NORMAL`. A crash can only ROLL BACK recent committed
  transactions (bounded by checkpointing), never corrupt the database.

### Why rollback is safe here (the contract's core argument)

Every class of relay state is either re-executable or loudly
comparable, so a rollback/torn write surfaces as repair or a loud
mismatch — never as silent divergence:

- Chunk state heals by re-execution: `chunks/missing` ANDs
  refs-visibility with blob existence; `PUT /chunks` re-inserts the
  refs row unconditionally even when the blob dedupes; and §18's
  verify-on-get turns a torn blob into delete → 404 → "missing" →
  re-upload. Worst case is one loud "cannot converge" window on
  mirrors until the writer's next push repairs the pool (§11's
  flush-before-commit gate).
- Heads fork loudly, never silently: put_head CASes on base_seq, and
  every idle check compares seq AND hash (§11). A rolled-back head
  commit trips the writer guard's "silent head rewind" refusal
  (operator decision required); a same-seq-different-content head is
  caught by every mirror's remote.json hash compare.
- Lease safety rests on head CAS, not on lease durability: a
  rolled-back lease can produce a loud fencing, never two writers
  committing the same seq with the same content.
- Snapshots: a rolled-back committed snapshot 404s loudly at restore;
  re-running the snapshot heals.

### Explicitly unchanged

- Client code, wire shapes, role gates, and the §18 client flush
  points are untouched (client-visible transfer batching is §23).
- The relay keeps per-request validation (hash format, size cap,
  body-hashes-to-name, refs insert) exactly as today — only WHEN the
  fsyncs happen changes.

### §22 implementation notes (as built)

- Pool store is `open_deferred`; the flusher task's tick is a 5 s
  backstop for stray puts — the real durability driver is AT COMMIT
  POINTS: `put_head` and `create_snapshot` call `store.flush()` inside
  their blocking sections after all validation/CAS and before the row
  commits (flush error → 500, the commit never references unflushed
  chunks; §18's requeue makes the retry re-flush). A `put_head`/
  snapshot commit leaves the deferred queue empty (test-pinned).
- SQLite: `journal_mode=WAL` + `synchronous=NORMAL` at open (the
  getter-mode pragma via query_row; in-memory tolerated). The one
  journal-coupled test (COMMIT-failure injection) now forces
  journal_mode=DELETE for its fault case — WAL readers never block
  writers, so the scenario otherwise can't happen.
- The 200 ms timer-flush design was REPLACED on measurement (perf [4]:
  31.6 s pre-§22 → 39.1/35.8 s with it — continuous F_FULLFSYNC
  bursts saturated APFS and stalled in-flight PUTs). Commit-point
  flush alone did not recover it either (the 64-pending self-flush
  still ran inline in `put`): the fsync COUNT, not placement, was the
  bound — which is what §25 then cut. Final numbers in §25's notes.

## 23. Batched chunk transfer contract

After §18 + §22 the remaining e2e clone cost is per-chunk HTTP round
trips: thousands of single-chunk GETs on the down-leg and PUTs on the
up-leg. This milestone adds batched transfer endpoints in both
directions; presence checks were already batched (`chunks/missing`),
so after this no sync path makes per-chunk HTTP calls.

### Frame format (defined once in pear-core)

- Binary, count-prefixed, ordered: `u32 count` (little-endian), then
  per entry: 64 bytes ASCII hex hash ‖ `u64 blob_len` (LE) ‖ blob.
- Caps, enforced by BOTH sides: `put_many` accepts at most 256
  entries AND at most 32 MiB of decoded blobs per request (the writer
  knows sizes and splits transparently). `get_many` accepts at most
  128 hashes per request — the mirror cannot know blob sizes before
  downloading, so the response is bounded structurally by
  128 × MAX_CHUNK_SIZE instead. Encoders split transparently;
  decoders reject oversize frames with an error, never a panic
  (truncated frames, bogus counts, absurd lengths are hostile input).

### Endpoints (same auth + role gates as the single-chunk routes)

- `POST /v1/workspaces/:id/chunks/get_many` — JSON body
  `{hashes: [...]}` → 200 octet-stream frame in the request order.
  Reader role; per-chunk visibility exactly like `GET /chunks/:hash`.
  A hash the caller may not read fails the WHOLE request with a 404
  naming it: callers always pre-check via `chunks/missing`, so this
  only fires on a heal-delete race, and failing loud lets the next
  cycle re-plan.
- `POST /v1/workspaces/:id/chunks/put_many` — octet-stream frame →
  JSON `{results: [{hash, status}]}`, status ∈ `"stored" |
  "present" | "error"`. Writer role. Each entry gets the single-PUT
  validation (hash format, size cap, body-hashes-to-name, refs
  insert); a bad entry fails only THAT entry — the writer's
  BatchUploader keeps failed chunks buffered per-chunk, and an
  all-or-nothing batch would wedge its buffer on one deterministic
  failure. `"present"` (dedupe) still re-inserts the refs row, same
  as the single PUT under §22.
- The single-chunk routes stay (compat and small transfers).

### Client changes

- `BatchUploader::flush` uploads via `put_many` in ≤256-entry/32 MiB
  sub-batches; per-chunk statuses preserve the keep-failed-buffered
  contract exactly.
- The mirror fetch loop downloads via `get_many` in the same
  sub-batches; every chunk is still BLAKE3-verified on receipt (the
  per-chunk wire check does not move), lands in the deferred store,
  and the §18 flush point is unchanged.
- E2E rides unchanged: ciphertext chunks are opaque bytes to all of
  this.

## 24. Garbage collection contract (pool + local stores)

`chunk_refs` is insert-only since §13: head retention keeps
`HEAD_KEEP` rows and §14 prunes checkpoints, but nothing ever deletes
a refs row or a blob, so the relay pool and every mirror's store grow
monotonically. §20 key rotations accelerate this (a generation of
ciphertext per rotation). This milestone adds mark-and-sweep GC on
both sides, pinned so it can never collect anything reachable from
current state or from an in-flight push.

### Relay pool GC

- Live set, rebuilt per workspace: the chunk lists of the RETAINED
  head rows (`HEAD_KEEP`) plus every retained snapshot/checkpoint row,
  parsed from the `manifest` column exactly as commit-time validation
  does (plaintext: files→chunks; e2e: the chunk_hashes envelope).
  `chunk_refs` is REBUILT to exactly this set (unjustified rows
  deleted) — self-healing for any refs drift, not just GC.
- Blobs with zero refs rows afterwards are deleted, EXCEPT any with an
  mtime younger than 10 minutes: that grace window covers a push
  between chunk-upload and head-commit (refs are earned at commit).
- Cadence: a relay background task, first run one hour after boot and
  hourly thereafter, logging scanned/refs-deleted/blobs-deleted/bytes.
  v1 runs the whole sweep under the one DB mutex — an hourly
  seconds-scale stall at monorepo sizes beats a lock-free race.
- GC never changes visibility semantics: a chunk referenced by any
  current head, snapshot, or retained checkpoint keeps all its refs
  rows, so `chunk_visible_to` is invariant under GC.

### Local store GC (mirror + M1 target stores)

- After every SUCCESSFUL apply (`pull_inner`, `sync_cycle`), sweep the
  store: delete chunk files whose hash is not in the just-applied
  manifest's chunk set. A failed apply never sweeps. `.tmp-*` files
  are skipped (`sweep_tmp` owns them), staging is untouched
  (`clean_staging` owns it).
- The e2e writer's plaintext local store is EXEMPT: no manifest
  references its plaintext hashes, so its pin set is undefined. It
  only ever holds chunks of files the worktree had; the documented
  manual remedy is deleting `.pear/store` (content re-chunks on
  demand). Plain (non-e2e) writers have no local store at all.

### §24 implementation notes (as built)

- Relay `gc.rs::run_pool_gc(db, store, grace)`: the live set is parsed
  from retained head rows + all snapshot rows via ONE shared
  `stored_row_chunks` helper (plaintext arm reuses the commit path's
  own chunk extraction — zero parse drift); `chunk_refs` is rebuilt
  to exactly the live set in a single transaction (which also
  INSERTs missing justified refs — heals §22 rollback refs loss);
  blobs with no refs anywhere and mtime older than the 10-minute
  grace are unlinked. A workspace with ANY unparseable row is skipped
  conservatively (`workspaces_skipped` in the hourly log line): GC
  never collects what it can't understand, and such rows age out of
  retention on their own. Timer: `interval_at(boot + 1h)`, hourly,
  `spawn_blocking` under the one DB mutex.
- Required schema fix found while building: e2e heads/snapshots
  stored only bare base64 `manifest_enc` — their chunk list lived
  ONLY as refs rows, so a refs rebuild was impossible. The `manifest`
  column now stores `{"chunk_hashes": [...], "manifest_enc": "..."}`
  (sorted/deduped hashes); GET routes unwrap it, legacy bare-base64
  rows read back verbatim and are GC-skipped until they age out. The
  wire protocol is unchanged; two test assertions that pinned
  `head.hash == blake3(manifest)` now hash the envelope (documented).
- Local stores: `LocalStore::sweep_unreferenced(keep)` (strict
  64-hex names, `.tmp-*` skipped, warn-not-fail — GC never breaks
  convergence), called from `pull_inner` (only when the pull changed
  something or fetched chunks, after the commit) and `sync_cycle`;
  the e2e writer's plaintext store is exempt per the contract.
- Verified: 298 passed + clippy clean on macOS.
## 25. Directory-sync flush contract (cutting the fsync count 20×)

Measurement after §22/§23 (perf [4], repeated runs): the e2e legs are
bounded by fsync COUNT, not fsync placement. Per-file F_FULLFSYNC is
~2 ms each on the reference volume with no group-commit sharing, so
5137 deferred chunks ≈ 10 s of inline self-flush bursts per leg
(§18's threshold self-flush runs inside `put`), regardless of whether
a timer, a commit point, or the request path schedules them. The only
remaining lever is fewer fsyncs, and content addressing makes it
safe: the chunk's name IS its hash, so torn data can never masquerade
as good data.

### What changes

- `LocalStore`'s deferred `flush` fsyncs the touched SHARD DIRECTORIES
  ONLY — no per-file fsyncs for chunk blobs. After any flush: a
  chunk's dirent is durable; a very recent chunk's DATA may still be
  torn by power loss. Every chunk read path already re-hashes (§18
  verify-on-get is mandatory in `LocalStore::get`), so a torn blob is
  deleted + reported NotFound and heals by re-fetch/re-upload —
  exactly the "torn" arm §18's crash matrix already had, now extended
  past the flush point. This applies to ALL chunk stores: mirror
  stores, M1 target stores, the e2e writer's plaintext store, and the
  relay pool.
- The apply-side group flush (assembled WORKTREE files) keeps
  per-file fsyncs: user files are not content-addressed, nothing
  re-hashes them on read, and a silently torn worktree file is
  unacceptable. Only the chunk-store flush changes.
- §22's ack semantics sharpen: a chunk referenced by a committed
  head/snapshot is PRESENT; in the rare power-loss case a very recent
  blob can be detectably torn (never silently wrong), and the §22
  re-execution argument (verify-on-get → missing → re-upload) heals
  it. A stuck-until-a-writer-pushes window after relay power loss is
  possible and loud, never silent.
- The deferred queue no longer holds open fds (only shard-dir paths),
  so the fd-pressure motivation for the 64 threshold is gone; 64 stays
  as the loss-window bound.

### §25 implementation notes (as built)

- The deferred queue is `Vec<PathBuf>` of shard dirs, one entry per
  put (dedupe at flush, not at push — so the 64 threshold keeps its
  §18 meaning of "64 unflushed CHUNKS" and the loss window stays a
  chunk-count bound). `flush_batch` fsyncs each queued dir once and
  nothing else; the drain-outside-lock + requeue-on-error contract is
  unchanged, as is every flush POINT (§18 client phases, §22 commit
  points) and the `flush()` API.
- Re-measured 2026-07-23 on the reference machine ([1] = 20.68 s,
  machine comparable to its fastest historical runs), two consecutive
  runs: perf [4] = push 20.37 / 29.61 s, pull 22.55 / 23.54 s —
  totals **42.9-53.2 s** (from 92.93 s at §15, 73.96 s after §18,
  ~80 s after §22+§23). The pull leg is consistently −45 % vs the
  pre-§22 42.4 s; the push leg is below pre-§22's 31.6 s in both
  runs (its ±20 % spread tracks the machine's background load). The
  §22 regression is gone and the fsync-count diagnosis is confirmed:
  the pull leg's remaining fsync block is apply's per-file fsyncs,
  deliberately kept (worktree files are not content-addressed).
- Verified: 299 passed + clippy clean; the relay's §22 commit-point
  drain test and all §18 deferred-mode tests pass unchanged in
  semantics (the queue counts puts 1:1 across shards).

## 26. Hygiene batch (flakes, release profile, stale risks)

- The two pre-existing parallel-load flakes are fixed as TEST timing,
  not product bugs: `handoff_after_lease_lapse_fences_old_writer` now
  uses a 5 s TTL (the relay tracks expiry in whole seconds, so a 1 s
  TTL had an effective lifetime in (0, 1] depending on where in the
  second the acquire landed) with a heartbeat-before-push helper —
  the expiry is still a real sleep past the TTL, and the handoff
  assertion strengthened to exactly-one-generation-bump;
  `watch_exits_when_source_disappears` now synchronizes on cycle
  completion (the on_cycle callback fires after the trailing manifest
  write) instead of file visibility. Both reproduced under load
  (1/30, 6/40) and then ran clean 25/25 and 30/30 under the same
  induced load.
- `[profile.release] lto = "thin"` added; perf baselines re-measured
  in release mode (recorded in §15's baseline block).
- §10's stale risk bullets (sink-phase fsync, name-based excludes,
  blocking relay handlers, trust model) now point at their resolving
  sections.

## 27. 500k watcher-load measurement contract

§10's monorepo risk was measured only at 50k/5k (§15). This milestone
extends the perf harness to a 500k-file tree and MEASURES — no fixes
unless the numbers indict something (§15's discipline). All runs in
release mode (§26); numbers are reference points, not SLAs.

- A 500k-file synthetic tree from the §15 generator (same
  deterministic shape, scaled: ~500k files / ~2.5 GB).
- Measure and record: cold scan + chunk (linearity vs the 50k
  baseline); steady-state no-op cycle (the per-cycle manifest load
  parses the full JSON — watch its cost at 500k entries); watcher
  registration wall time and RSS after registering the tree; a
  mass-edit event (touch 10k files, git-checkout-style) — event
  handling and convergence time; manifest.json size at 500k entries.
- Verdict rule: anything within ~linear of the 50k baselines is a
  pass and is documented, not fixed; superlinear growth or
  pathological memory is what justifies follow-up work.

### §27 implementation notes (as built)

- `crates/core/tests/perf.rs::watcher_load_500k` (`#[ignore]`d;
  persistent tree under `$CARGO_TARGET_TMPDIR/perf27/` with a
  scale+seed reuse marker). Measured 2026-07-23, RELEASE build, solo
  run, fresh 500,149-file / 2.32 GB tree (seed 0x…5eca):
  - [27.1] cold scan+chunk: scan 15.71 s + chunk 276.49 s = **292.20 s**
    (500,163 chunks out) — vs the 50k release baseline 13.04 s:
    ~22× for 10× the files; the scan alone is ~3× slower PER FILE
    than at 50k (warm-cache effects at 2.3 GB suspected, no code
    pathology identified).
  - [27.2] no-op `sync_cycle`: **33.92 s** — scan dominates, plus the
    500k-entry BTreeMap rebuild, the ~500k-stat `has_many` presence
    pass, and the 120 MB manifest write. Cycle cost matters only when
    events fire (the writer loop is event-driven; an idle watch costs
    nothing), but every git operation at 500k costs a ~34 s coalesced
    cycle.
  - [27.3] manifest.json = **120.8 MB** at 500,149 entries;
    `manifest::load` ≈ 0.29 s warm — the per-cycle parse is NOT a
    bottleneck.
  - [27.4] watcher registration: **0.03 s**, RSS delta ≈ 0 — FSEvents
    watches the whole tree in one registration; no fd/memory issue at
    500k.
  - [27.5] 10,000-file mass-edit burst: 10,006 events received,
    coalesced into ONE `sync_cycle`, converged in **56.41 s**
    (re-chunk + upload + apply with per-file fsyncs — the honest
    real-path cost).
- Verdict: registration, memory, event handling, and manifest parse
  all pass. The 500k CYCLE cost (~34 s no-op / ~56 s for a 10k-file
  burst) is the documented limitation; candidates if it needs to
  move: profile the scan's per-file cost at 500k, incremental
  manifests (avoid the full BTreeMap rebuild + 120 MB rewrite), and a
  cheaper presence index than 500k stats. None are scheduled —
  measure-first says the current shape is usable, not pathological.

## 28. `.env` per-team kill switch contract

§10 decided `.env` syncs by default (it is the product's promise) and
named the mitigation for security teams: a per-team kill switch, not
a different default. This milestone builds the switch.

- A team gains a `sync_env` policy (boolean, default TRUE — the
  default is the product promise). Set at `pear team create --no-env`
  or changed later by a team owner via
  `PUT /v1/teams/:id/policy {sync_env}`; surfaced in team info
  responses.
- Relay-side enforcement (plaintext workspaces): head and snapshot
  commit validation rejects any manifest containing a `.env*` path
  when the workspace's team forbids it — a clear 409 naming the
  policy. Even an old/misconfigured client cannot push `.env` into a
  protected team. E2E workspaces are exempt from relay enforcement by
  construction: the relay cannot see encrypted paths.
- Client-side enforcement (all flavors, and the ONLY line for e2e):
  at `pear watch` startup the writer fetches the team policy; a
  forbidden team REFUSES to watch with an actionable error ("team X
  forbids .env sync — remove the .env files or ask a team owner to
  lift the policy"). Refusing beats silently excluding: a file the
  user expects synced must never silently stop syncing.
- Mirrors need nothing: a policy-compliant head simply contains no
  `.env` paths.
- Workspaces without an attached team are unaffected (the policy
  lives on teams).

### §28 implementation notes (as built)

- `teams.sync_env INTEGER NOT NULL DEFAULT 1` via the §19-style
  idempotent migration; surfaced on create/list/policy responses.
  `PUT /v1/teams/:id/policy {sync_env}` is team-owner gated; CLI:
  `pear team create --no-env` and `pear team policy <team> --env
  on|off`.
- Relay enforcement: `validate_submitted_manifest` (shared by
  put_head + create_snapshot) 409s `.env*` paths with
  `kind: "sync_env"` when the workspace's team forbids; e2e heads
  never reach it (exempt by construction). The client maps
  `sync_env` 409s to `RelayError::Fatal` (no infinite retry).
- Client enforcement: the writer pins the policy at watch startup
  (`get_workspace().team_id` → team list) on a `RelayClient` field
  (zero churn at the ~60 push_cycle call sites); a cycle whose
  captured set contains an `is_dotenv` path fails as
  `PushError::Client` (fatal to the loop) naming team + paths +
  remedy. The definition is the scanner's own `is_dotenv` (final
  path component starts with `.env`, case-sensitive) — kill switch ≡
  product promise, exactly.
- Verified: 309 passed + clippy clean at landing.

## 29. Real-git recovery UX tests contract

§10's `.git` risk: recovery UX "needs real testing before teams trust
it". This milestone tests with REAL git repositories (the suites so
far use synthetic `.git` trees). Tests skip cleanly when no `git`
binary is on PATH.

- Round trip: a real repo (init, commits on two branches, a merge,
  tags) pushed via pear and cloned via pear passes `git fsck
  --strict` and `git status` clean on the mirror; `git checkout` of
  the other branch works on the mirror.
- Live edit loop: commit on the writer side, watch it converge on
  the mirror, `git log` agrees; then commit on the MIRROR's repo
  back (role semantics: a mirror's own git operations must not wedge
  the next apply — .git writes are ordered last per the apply
  protocol).
- Force-takeover fork: two writers diverge; the takeover path offers
  the divergent snapshot, and the snapshot clone contains the
  stranded work (nothing silently lost).

### §29 implementation notes (as built)

- `crates/relay/tests/git_ux.rs` (3 tests, skip cleanly without a
  `git` binary; all git calls run with isolated global/system config
  and per-repo identity). No production code changed; no real bugs
  found.
- `real_git_round_trip`: byte-identical `.git` after push+pull,
  `git fsck --strict` clean, status clean, branch checkout works,
  tags and log match — including repo-local `.git/config`
  round-tripping.
- `real_git_live_edit_loop_with_mirror_side_commit`: writer commits
  converge on the mirror; a MIRROR-SIDE commit between cycles does
  not wedge apply (manifest-diff-driven, `.git` writes ordered last)
  and survives as a dangling-but-recoverable object; its worktree
  file stays as an untracked file — nothing silently lost.
- `real_git_force_takeover_fork_preserves_stranded_work`: takeover
  checkpoints the pre-fork head, the stranded writer is fenced with
  the `pear snapshot` remedy in the message, and the divergent
  snapshot clones out fsck-clean with the stranded work as HEAD.
- Verified: 312 passed at landing (312/0/3 with §27's harness test
  ignored), clippy clean.

## 30. get_many byte-budget splitting (refinement of §23)

§23's get_many cap was count-only (128 hashes), so a blob-heavy
workspace could pull a 128 × 4 MiB response. A file's chunks
partition it exactly, so the manifest's per-file `size` is the exact
byte cost of a chunk group — the fetch loop splits by a byte budget
instead of hoping chunks are small. The wire is unchanged.

### §30 implementation notes (as built)

- `plan_fetch_batches` (pure, sync.rs): first-fit over FILES, each
  file's chunks an atomic group costing exactly `entry.size`; a batch
  closes at 128 hashes OR `GET_MANY_TARGET_BYTES = 32 MiB` (chunk_frame
  caps block); an oversized single file rides alone. `pull_inner`
  downloads one `get_chunks` per planned batch; the ≤128 wire cap
  stays as the client's safety net. E2E sizes are plaintext while
  wire bytes are ciphertext (+ small AEAD overhead) — immaterial
  against the target; the 128-hash structural cap still bounds any
  response.
- The §23-era "512 MiB worst case" comment now describes reality:
  batches are byte-budgeted by manifest knowledge; the structural
  bound (128 × 4 MiB) is unreachable from the real fetch loop.
- Integration test pins first-fit exactly (8 × 4 MiB = one
  full-budget batch), multiple batches for blob-heavy pulls, and
  byte/hash caps per request; counters and convergence unchanged.
- Verified: 319 passed + clippy clean at landing.

### §23 implementation notes (as built)

- `pear_core::chunk_frame`: one shared codec — `u32 count` (LE), then
  per entry `64B hex hash ‖ u64 blob_len (LE) ‖ blob`. `decode` is
  total on hostile input (pre-allocation capped at
  `min(count, remaining/72)`; absurd lengths are fast small errors).
  Caps live next to the codec so both sides enforce the same numbers:
  `PUT_MANY_MAX_ENTRIES=256`, `PUT_MANY_MAX_BYTES=32 MiB`,
  `GET_MANY_MAX_HASHES=128`. MAX_CHUNK_SIZE is 4 MiB, so a get_many
  response is structurally bounded at 128 × 4 MiB = 512 MiB worst
  case — honest but pathological (blob-heavy workspaces); typical
  batches are a few hundred KB.
- Routes: `put_many` validates each entry exactly like the single PUT
  (bad entries get their own `"error"` + reason, never fail the
  batch; store I/O errors fail the request, same as the single PUT)
  and re-inserts refs for stored AND deduped chunks. `get_many` fails
  the whole request 404 naming the first invisible/absent hash.
  Single-chunk routes stay (snapshot restore still uses them).
- `ChunkSink::put_many` default loops `put` (LocalStore/test sinks
  keep today's semantics); the RelayClient override rides the batched
  endpoint. `BatchUploader::flush` sends each flush as ONE put_many:
  per-entry errors keep only those chunks buffered; a whole-call
  error re-buffers everything unconfirmed (the no-suppression
  invariant is preserved). `pull_inner` downloads via `get_chunks`;
  the per-chunk BLAKE3 wire-verify and the §18 flush point are
  unmoved. A core integration test pins ZERO single-chunk PUT/GET
  calls across a full push+pull round trip.
- Verified: suite + clippy green (285 passed at landing) on macOS;
  perf re-measure folded into §22's final numbers below.

## 31. Removing the e2e writer's vestigial plaintext store

§17 gave the e2e writer a local plaintext chunk store
(`<source>/.pear/store`, keyed by plaintext hash) "for its own
dedupe". In the code as built nothing ever READS it: upload dedupe
runs on ciphertext hashes against the relay (`has_many`), unchanged
files ride the scan cache, and `E2eUploader.local` is write-only
(`put` whose result is discarded, plus a flush). It costs disk on
every push, grows without bound (§24 had to exempt it because no
manifest pins its keys), and its presence implies a backup that does
not exist. This milestone removes it.

- `E2eUploader` loses the local store: no writes, no flush, no
  `source` parameter — the writer flow keeps only the ciphertext
  path through `BatchUploader`.
- Existing on-disk stores from earlier versions are NOT deleted by
  pear (a sync tool never deletes user files unprompted); the
  documented remedy is deleting `<source>/.pear/store` by hand —
  nothing references it after this change.
- §24's exemption note is retired with the store itself; mirror and
  M1 target stores keep their manifest-pinned sweeps unchanged.

### §31 implementation notes (as built)

- `E2eUploader` lost the `local` field, the per-chunk `local.put`,
  the `local.flush`, and the `source` parameter; the writer flow is
  ciphertext-only through `BatchUploader`. Call sites (push_inner,
  snapshot push, §20 rotation tests) updated; the rotation tests'
  generation assertions are unchanged.
- The mock-relay round-trip test now asserts the writer's
  `.pear/store` does NOT exist after a push — ciphertext only on the
  relay, plaintext only in the worktree. No test had the store as its
  only subject; none were deleted.
- §24's exemption comment retired with the store; the e2e.rs module
  header needed no edit (its store mentions were already mirror-side).
- Pre-existing on-disk stores are not deleted by code; manual removal
  of `<source>/.pear/store` is safe (nothing references it).
- Verified: 319 passed + clippy clean at landing.

