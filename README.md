# pear

Your working context, everywhere.

`pear` syncs a development folder between machines and between
teammates — like Dropbox, but built for dev folders, so it syncs the
files general-purpose tools deliberately drop: `.env*` files sync by
default, and `.git` syncs so the copy on another machine is a real,
`git fsck`-clean repository, unpushed branches and all.

There is no "sync now" button and no baton to pass. You run one
command, once, per machine — after that, every save on any machine
shows up on every other one, usually in under a second.

```sh
pear join ~/proj --relay http://relay:7700
```

Personal project. macOS and Linux are verified; Windows is out of
scope. The living spec is [DESIGN.md](DESIGN.md) — every contract and
its as-built notes, §1–§32.

## Quickstart

Build (three binaries land in `target/release/`: `pear` the CLI,
`pear-relay` the server, `peard` the daemon):

```sh
cargo build --release
```

Run a relay somewhere all your machines can reach:

```sh
pear-relay --addr 0.0.0.0:7700 --token "$ADMIN_TOKEN" --data-dir /var/pear
```

Then, on your first device:

```sh
export PEAR_TOKEN="$ADMIN_TOKEN"     # or a per-user token, see Teams
pear join ~/proj --relay http://relay:7700
```

And on every other device, the same command into an empty directory:

```sh
pear join ~/proj --workspace <hex-id> --relay http://relay:7700
```

That's the whole setup. `join` registers the folder with the `peard`
daemon (starting it if needed) and returns. From then on everything
is automatic: local edits go up, everyone else's come down, no
commands, no handoff, on every device at once. `pear status` shows
what each loop is doing.

No relay handy? `pear watch ~/proj ~/proj-backup` keeps two local
directories converged with the same engine.

## How sync works

Every device runs the same *converge* loop, continuously and
concurrently — there are no distinguished "writer" or "primary"
machines. A cycle is triggered by a local file event, by a WebSocket
hint that someone else pushed, or by a fallback poll, and it does one
thing: three-way merge **your last synced state**, **your disk right
now**, and **the current shared head**, then apply and publish the
result. The relay accepts a publication only if it saw the head you
merged against (compare-and-swap); if someone beat you to it, the
loop re-merges against their result and tries again. The merge is
deterministic, so every device lands on the byte-identical tree.

Conflict handling falls out of the merge:

- Edits to different files just both land — the common case is
  invisible.
- An edit beats a delete, in both directions. Deleting a file someone
  is actively working on brings it back rather than eating their work.
- Two devices editing the *same* file concurrently: the newer save
  wins the filename, and the loser is preserved right beside it as
  `name (conflict from <device> <time>).ext`, synced to everyone. A
  converge never loses a byte of anyone's data.

Files travel as content-defined chunks (fastcdc, BLAKE3-addressed),
deduplicated across the whole relay — only chunks the other side is
missing ever cross the wire. Applies are staged and crash-safe:
verified content addressing, group fsync at commit points, `.git`
written last so an interrupted apply leaves a stale-but-valid repo,
never a half-written one.

## Teams

```sh
# Admin creates users (prints each user's token once):
pear user create --relay $R --token "$ADMIN_TOKEN" alice

# Alice, on her devices:
export PEAR_TOKEN="$ALICE_TOKEN"
pear team create dev --relay $R
pear team add dev --user bob --role writer --relay $R
pear join ~/proj --relay $R --team dev            # attach at register
pear share ~/proj --team dev --relay $R           # (re)share later
```

Bob joins with his own token — `pear join ~/proj --workspace <hex-id>
--relay $R` — and both of them now write. Roles are owner / writer /
reader: a `reader` runs the same `join` and converges read-only.
`pear clone` (which resolves a `team/name` ref) is still the one-shot
"just give me the files".

## End-to-end encryption (optional, per workspace)

```sh
# Everyone, once per device:
pear user keygen --name alice --relay $R   # signs + registers your key bundle

# First device:
pear join ~/proj --relay $R --team dev --e2e

# Teammate onboarding (after a writer's next join/share wraps for them):
pear join ~/proj --workspace <hex-id> --relay $R --name bob
```

The relay stores only ciphertext: AES-256-GCM chunks and manifests,
X25519-wrapped keyrings, ed25519-signed device keys. Identity is
SSH-style first-sight pinning — compare `pear user id` fingerprints
out-of-band the first time; `pear trust bob` re-pins after a
legitimate re-keygen. Removing a member cuts them off from future
content via key rotation at the next converge start (`pear rekey`
forces one by hand), without re-uploading the world. Rotations merge
the relay's copy of your wrapped keyring first, so two devices
rotating at once extend one keyring instead of forking it.

## Snapshots

The escape hatch before any risky decision — preserve any local tree
on the relay, forever, and fork it back out anytime:

```sh
pear snapshot ~/proj --relay $R -m "before the big rebase"
pear snapshots ~/proj --relay $R
pear clone ~/proj-2 --workspace dev/proj --snapshot <id> --relay $R
```

## What syncs and what doesn't

- Files only. Symlinks, fifos, and non-UTF-8 names are skipped
  (loudly, per cycle). Empty directories are not tracked.
- `.env*` files sync **by default** — that's the product's promise.
  A team can forbid them: `pear team policy dev --env off` (the relay
  rejects plaintext `.env*` commits; devices refuse to converge trees
  that capture them).
- `.git` syncs. When two devices move the same ref, the losing side
  is *not* copied into `.git` (an invalid refname would break
  `git fsck`): its bytes go to `.pear/conflicts/<path> (conflict
  from …)` on that device, and both repos stay fsck-clean with the
  losing commit dangling-but-recoverable.
- Built-in excludes: `node_modules`, `target`, `build`, `dist`, and
  the like, plus your `.gitignore`. Override per workspace in
  `pear.toml`:

  ```toml
  [sync]
  include = ["target/important"]   # re-include under a built-in exclude
  exclude = ["secrets/local"]      # prune extra paths
  ```

  Precedence: `exclude` > `include` > built-in > gitignore.

- `.pear/` itself never syncs (metadata, chunk store, keyring, local
  conflict copies).

## CLI reference (abridged)

| command | what it does |
|---|---|
| `pear join <dir> --relay R [--workspace ID] [--team T] [--e2e] [--device D] [--name N]` | start converging this directory — the one-time setup |
| `pear init <dir>` | initialize a workspace (`join` does it for you) |
| `pear sync <src> <dst>` | one local sync cycle |
| `pear sync <dir> --relay R […]` | foreground converge loop (debug/CI) |
| `pear watch <src> <dst> [--daemon]` | local watch between two directories |
| `pear mirror <path> --workspace W --relay R [--name N] [--daemon]` | follow a workspace read-only |
| `pear clone <path> --workspace W --relay R [--snapshot id] [--name N]` | one-shot clone (head or snapshot fork) |
| `pear snapshot / snapshots` | preserve / list snapshots |
| `pear share` | (re)share the workspace to its team, re-wrap keys |
| `pear status` / `pear daemon stop` | query / stop `peard` |
| `pear user create / keygen / id / export / import` | users and device identity |
| `pear team create / add / remove / members / policy` | teams, roles, `.env` policy |
| `pear trust <user>` | re-pin an identity fingerprint (after out-of-band verify) |
| `pear rekey [--name N]` | force a workspace key rotation |

Common flags: `--token` (or `PEAR_TOKEN`), `--tls-ca-cert` (or
`PEAR_TLS_CA` — replaces the root set for self-signed deployments;
there is no skip-verify mode). Relay TLS: `pear-relay --tls-cert
fullchain.pem --tls-key key.pem`.

## The daemon

`peard` runs in the foreground and supervises converge/mirror/watch
loops, one OS thread per workspace. `pear join` starts it for you;
point your init system at it if you prefer. Inspect with
`pear status`, stop with `pear daemon stop`. Tokens live in memory
only; state is `$PEAR_HOME/daemon.json` (no secrets) plus a same-uid
unix socket at `$PEAR_HOME/daemon.sock`.

## Security model (the short version)

- All relay routes need a bearer token; per-user tokens with
  team-based roles; an admin token manages users.
- E2E workspaces: the relay is semi-trusted — it stores opaque
  chunks, encrypted manifests, and wrapped-key blobs, but never a
  plaintext byte or the workspace key. Chunk *metadata* (counts,
  sizes, timing) is visible to it; that's documented, not hidden.
- Device identity: ed25519 signing key + X25519 encryption key per
  user, the former signing the latter. Devices pin fingerprints on
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

Layout: `crates/core` (scan/chunk/store/sync/merge/converge/crypto/e2e),
`crates/relay` (axum server, SQLite, chunk pool, WS fan-out, GC),
`crates/cli` (`pear` + `peard`). DESIGN.md is the contract of record:
every milestone §11–§32 has a pinned contract and as-built notes,
including the perf baselines (5k e2e clone ≈ 37s release; 500k-file
watcher-load numbers and the current cycle-cost caveat in §27).

## Caveats

- Personal project: no support channel, no Windows, no promises.
- Conflict resolution is last-writer-wins by mtime plus a conflict
  copy — not a semantic merge. Two people editing the same file at
  the same second get one winner and one clearly named loser file.
- Under end-to-end encryption, identical files written by two devices
  do not dedup against each other (chunks are addressed by
  ciphertext).
- Very large trees (500k+ files) work — measured in §27 — but each
  change-triggered cycle costs tens of seconds there.
