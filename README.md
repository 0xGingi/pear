# pear

Your working context, everywhere. `pear` is a file-sync tool for
developers — think "Dropbox, but for dev folders": it syncs your
workspace between machines, **including the files other tools
deliberately drop** — `.env*` files sync by default, and `.git`
directories sync so a clone on another machine is a real,
`git fsck`-clean repository.

## What it does

- **One-way sync, two roles.** A *writer* device owns a workspace's
  head and pushes changes to a relay; *mirror* devices pull and apply
  them. A single-writer lease with fencing makes split-brain
  impossible; handoff between devices is explicit (`pear checkout`).
- **Content-addressed chunk storage.** Files are cut into chunks
  (fastcdc, BLAKE3-addressed), deduped globally on the relay, and
  transferred in batches — only what the other side is missing ever
  crosses the wire.
- **Instant-ish mirrors.** Mirrors follow a WebSocket feed for
  sub-second convergence and fall back to polling when it's down.
- **Snapshots.** Preserve any local tree on the relay — the escape
  hatch before a mirror/force decision can strand work. Clone a
  snapshot out as a new, forked workspace anytime.
- **Teams.** Users, teams, and owner/writer/reader roles on the
  relay; workspaces attach to teams.
- **Optional end-to-end encryption** per workspace: AES-256-GCM
  chunks and manifests, X25519-wrapped keyrings, ed25519 signed
  device keys with SSH-style identity pinning, and key generations
  that cut removed members off future content without re-uploading
  the world.
- **TLS** on the relay with private-CA support (no skip-verify mode
  anywhere).
- **`peard`** — a small daemon that supervises watch/mirror loops for
  you (unix-socket control, no tokens on disk).
- **Durability-engineered.** Crash-safe stores with verified content
  addressing, group fsync at commit points, hourly relay GC — a
  corrupted chunk is always detected and self-heals.

## Build

```sh
cargo build --release
```

Three binaries: `pear` (the CLI), `pear-relay` (the server), `peard`
(the daemon), all under `target/release/`.

## Quickstart

### Local sync (no relay)

```sh
pear init ~/proj
pear watch ~/proj ~/proj-backup      # initial sync, then keep converged
```

### Multi-device via a relay

```sh
# On the relay host:
pear-relay --addr 0.0.0.0:7700 --token "$ADMIN_TOKEN" --data-dir /var/pear

# Writer device:
export PEAR_TOKEN="$ADMIN_TOKEN"     # or a per-user token, see Teams
pear watch ~/proj --relay http://relay:7700

# Another device — one-time clone, then follow:
pear clone ~/proj --workspace <hex-id> --relay http://relay:7700
pear mirror ~/proj --workspace <hex-id> --relay http://relay:7700
```

(`pear clone` also accepts a `team/name` ref; `pear mirror` wants the
hex id.)

The writer holds the lease and pushes on change; mirrors get a
WebSocket hint and converge immediately (2s poll while the feed is
down). Moving the writer role to another device is explicit:
`pear checkout`.

### Teams

```sh
# Admin creates users (prints each user's token once):
pear user create --relay $R --token "$ADMIN_TOKEN" alice

# Alice, on her devices:
export PEAR_TOKEN="$ALICE_TOKEN"
pear team create dev --relay $R
pear team add dev --user bob --role reader --relay $R
pear watch ~/proj --relay $R --team dev          # attach at register
pear share ~/proj --team dev --relay $R          # (re)share later
```

`bob` mirrors with his own token: `pear clone ~/proj --workspace
dev/proj --relay $R`, then follows with
`pear mirror ~/proj --workspace <hex-id> --relay $R` (clone resolves
`team/name` for you; mirror takes the hex id).

### End-to-end encrypted workspaces

```sh
# Everyone, once per device:
pear user keygen --name alice --relay $R   # signs + registers your key bundle

# Writer:
pear watch ~/proj --relay $R --team dev --e2e

# Teammate onboarding (after the writer's next watch start or share):
pear clone ~/proj --workspace dev/proj --relay $R --name bob
```

The relay stores only ciphertext. Identity fingerprints print with
`pear user id` — compare them out-of-band the first time (the model
is SSH-style first-sight pinning; `pear trust bob` re-pins after a
legitimate re-keygen). Removing a member
(`pear team remove dev --user bob`) cuts off future content at the
writer's next watch start via key rotation; `pear rekey` forces a
rotation by hand.

### Snapshots

```sh
pear snapshot ~/proj --relay $R -m "before the big rebase"
pear snapshots ~/proj --relay $R
pear clone ~/proj-2 --workspace dev/proj --snapshot <id> --relay $R
```

## What syncs and what doesn't

- Files only. Symlinks, fifos, and non-UTF-8 names are skipped
  (loudly, per cycle). Empty directories are not tracked.
- `.env*` files sync **by default** — that's the product's promise.
  A team can forbid them: `pear team policy dev --env off` (relay
  rejects plaintext `.env*` commits; writers refuse to watch trees
  that capture them).
- `.git` syncs; the apply protocol writes `.git` last so a mirror is
  never a half-written repo (recovery: the tree is fsck-clean in the
  test suite's real-git scenarios).
- Built-in excludes: `node_modules`, `target`, `build`, `dist`, and
  the like, plus your `.gitignore`. Override per workspace in
  `pear.toml`:

  ```toml
  [sync]
  include = ["target/important"]   # re-include under a built-in exclude
  exclude = ["secrets/local"]      # prune extra paths
  ```

  Precedence: `exclude` > `include` > built-in > gitignore.

- `.pear/` itself never syncs (metadata, chunk store, keyring).

## CLI reference (abridged)

| command | what it does |
|---|---|
| `pear init <dir>` | initialize a workspace |
| `pear sync <src> <dst>` | one local sync cycle |
| `pear watch <src> [dst] [--relay R] [--team T] [--e2e] [--force] [--daemon]` | local watch, or writer mode against a relay |
| `pear mirror <path> --workspace W --relay R [--name N] [--daemon]` | follow a workspace |
| `pear clone <path> --workspace W --relay R [--snapshot id] [--name N]` | one-shot clone (head or snapshot fork) |
| `pear checkout` | move the writer lease to this device |
| `pear snapshot / snapshots` | preserve / list snapshots |
| `pear share` | (re)share the workspace to its team, re-wrap keys |
| `pear status` / `pear daemon stop` | query / stop `peard` |
| `pear user create / keygen / id / export / import` | users and device identity |
| `pear team create / add / remove / members / policy` | teams, roles, `.env` policy |
| `pear trust <user>` | re-pin an identity fingerprint (after out-of-band verify) |
| `pear rekey` | force a workspace key rotation |

Common flags: `--token` (or `PEAR_TOKEN`), `--tls-ca-cert` (or
`PEAR_TLS_CA` — replaces the root set for self-signed deployments;
there is no skip-verify mode). Relay TLS: `pear-relay --tls-cert
fullchain.pem --tls-key key.pem`.

## The daemon

`peard` runs in the foreground and supervises watch/mirror loops, one
OS thread per workspace. Point your init system at it; register work
with `pear watch ... --daemon` / `pear mirror ... --daemon`; inspect
with `pear status`; stop with `pear daemon stop`. Tokens live in
memory only; state is `$PEAR_HOME/daemon.json` (no secrets) plus a
same-uid unix socket at `$PEAR_HOME/daemon.sock`.

## Security model (the short version)

- All relay routes need a bearer token; per-user tokens with
  team-based roles; an admin token manages users.
- E2E workspaces: the relay is semi-trusted — it stores opaque
  chunks, encrypted manifests, and wrapped-key blobs, but never a
  plaintext byte or the workspace key. Chunk *metadata* (counts,
  sizes, timing) is visible to it; that's documented, not hidden.
- Device identity: ed25519 signing key + X25519 encryption key per
  user, the former signing the latter. Writers pin fingerprints on
  first wrap and refuse silent changes.
- Content integrity is structural: every chunk is BLAKE3-verified on
  write, on fetch, and on every read, so a torn or tampered byte is
  always detected and re-fetched — never applied.

## Development

```sh
cargo test --workspace                  # the suite
cargo clippy --workspace --all-targets  # lint gate (0 warnings)
cargo test --release -p pear-core --test perf -- --ignored --nocapture   # perf baselines (not in the default suite)
```

Layout: `crates/core` (scan/chunk/store/sync/crypto/e2e),
`crates/relay` (axum server, SQLite, chunk pool, WS fan-out, GC),
`crates/cli` (`pear` + `peard`). DESIGN.md is the contract of record:
every milestone §11–§31 has a pinned contract and as-built notes,
including the perf baselines (5k e2e clone ≈ 37s release; 500k-file
watcher-load numbers and the current cycle-cost caveat in §27).
