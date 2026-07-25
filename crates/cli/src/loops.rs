//! The converge/watch/mirror loop bodies, shared by the foreground `pear`
//! CLI and the `peard` daemon's per-workspace threads (§16). The only seam
//! is [`LoopControl`], which tells a loop how to report a fatal condition
//! and when to wind down.
//!
//! §32: the writer path is [`converge`] — one bidirectional loop per
//! Writer device, no leases, driven by FS events + relay head hints +
//! a poll fallback, all funneling into `converge_once`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pear_core::converge::ConvergeReport;
use pear_core::relay::{RelayClient, RelayError};
use pear_core::sync::{CycleReport, PullReport, PushError};

/// Mirrors and converge loops poll the head every 2s while the WebSocket
/// feed is down (§11/§14/§32).
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// With a live WebSocket feed the poll relaxes to a 5-minute safety net
/// (§21): its only remaining job is catching a hint lost to a relay bug —
/// keepalive (45s), reconnect+head_now, and the 60s role re-check cover
/// every realistic loss path. The 2s feed-down poll above is unchanged:
/// it is the correctness floor, not a safety net.
const POLL_INTERVAL_WS: Duration = Duration::from_secs(300);

/// Exit code when a loop hits a condition it can never recover from
/// (auth/role revoked, a deterministic relay rejection).
const EXIT_FATAL: i32 = 3;

/// Supervision seam for a running sync loop (§16).
///
/// The foreground CLI uses [`LoopControl::foreground`]: the stop flag is
/// never set and a fatal (auth/deterministic) condition prints and exits
/// with `EXIT_FATAL`. A `peard` worker uses [`LoopControl::worker`]:
/// `remove`/`shutdown` set the stop flag, a fatal condition is recorded
/// for `status` instead of killing the daemon, and the loop goes inert
/// rather than sync again.
pub struct LoopControl {
    stop: AtomicBool,
    in_cycle: AtomicBool,
    error: Mutex<Option<String>>,
    head_seq: AtomicU64,
    exit_on_fatal: bool,
}

impl LoopControl {
    pub fn foreground() -> Arc<Self> {
        Self::new(true)
    }

    pub fn worker() -> Arc<Self> {
        Self::new(false)
    }

    fn new(exit_on_fatal: bool) -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
            in_cycle: AtomicBool::new(false),
            error: Mutex::new(None),
            head_seq: AtomicU64::new(0),
            exit_on_fatal,
        })
    }

    /// Ask the loop to wind down at its next cycle boundary (`remove`,
    /// `shutdown`). §32: nothing is held relay-side, so there is nothing
    /// to release.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// The last converged (writer) or applied (mirror) head seq, for
    /// `status` — and the companion thread's filter for head hints that
    /// only echo our own commit. 0 = none known yet.
    pub fn set_head_seq(&self, seq: u64) {
        self.head_seq.store(seq, Ordering::SeqCst);
    }

    pub fn head_seq(&self) -> u64 {
        self.head_seq.load(Ordering::SeqCst)
    }

    /// The terminal error of a wedged/failed loop, if any (first one wins —
    /// it is the root cause; later noise would hide it).
    pub fn record_error(&self, message: String) {
        let mut slot = self.error.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(message);
        }
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// A fatal (auth/deterministic) condition. Foreground: print and exit
    /// with `EXIT_FATAL`. Daemon worker: record it for `status`; the
    /// caller then goes inert via [`Self::park_if_done`].
    fn fatal(&self, message: String) {
        if self.exit_on_fatal {
            eprintln!("pear: {message}");
            std::process::exit(EXIT_FATAL);
        }
        self.record_error(message);
    }

    /// Park forever once the loop is done (removed, or a fatal error was
    /// recorded) so a daemon worker never syncs again. The foreground never
    /// parks: it either exits on fatal or was never stopped. A parked
    /// thread holds nothing but its stack; daemon shutdown does not wait
    /// on it.
    pub fn park_if_done(&self) {
        if self.exit_on_fatal || (!self.stopped() && self.error().is_none()) {
            return;
        }
        loop {
            std::thread::park();
        }
    }

    /// Mark a sync cycle in flight until the guard drops; `peard` shutdown
    /// drains these so loops finish their current cycle (§16).
    pub fn enter_cycle(&self) -> CycleGuard<'_> {
        self.in_cycle.store(true, Ordering::SeqCst);
        CycleGuard(self)
    }

    pub fn in_cycle(&self) -> bool {
        self.in_cycle.load(Ordering::SeqCst)
    }
}

/// Clears the in-flight mark of [`LoopControl::enter_cycle`] on drop.
pub struct CycleGuard<'a>(&'a LoopControl);

impl Drop for CycleGuard<'_> {
    fn drop(&mut self) {
        self.0.in_cycle.store(false, Ordering::SeqCst);
    }
}

/// Local-mode watch: initial sync, then watch SOURCE and keep TARGET
/// converged after each debounced batch of changes. Shared by foreground
/// `pear watch SOURCE TARGET` and daemon-registered local watches (§16).
pub fn watch_local(
    source: &Path,
    target: &Path,
    control: &Arc<LoopControl>,
    on_cycle: impl FnMut(&CycleReport),
) -> Result<()> {
    pear_core::watch::watch_loop_with(
        source,
        |src| {
            control.park_if_done();
            let _cycle = control.enter_cycle();
            pear_core::sync::sync_cycle(src, target)
        },
        on_cycle,
    )
}

/// §32 converge flow: init, idempotent workspace create (+ team attach),
/// the §28 `.env` policy learn/pin, the §17/§19/§20 e2e key pass, then one
/// bidirectional converge per trigger — forever.
///
/// Three triggers funnel into the same `converge_once` (§32): local
/// filesystem events (the existing 500ms-quiet / 2s-cap debounce), relay
/// `head_changed` hints over the §14 WebSocket feed, and a poll fallback
/// (2s with the feed down, 5 minutes with it live). The last two are
/// driven by the companion thread below, which kicks the watch loop
/// through [`pear_core::watch::watch_loop_with_kicks`].
///
/// There is no lease and no fencing: `put_head`'s CAS on `base_seq` is the
/// whole of the concurrency control, and `converge_once` re-merges against
/// the winning head on a 409 internally. A 409 that escapes it (the bounded
/// retry exhausted) is RETRYABLE, not fatal — another writer is simply
/// publishing faster than this device can merge, and the next trigger tries
/// again.
///
/// `workspace` adopts an existing relay workspace (`--workspace ID`, the
/// join-into-an-empty-directory case); without it the workspace id is the
/// local one, created on the relay if new. With `team`, the workspace is
/// attached to the team at register (§13). With `e2e`, a new workspace is
/// registered end-to-end encrypted (§17). `name` is the local identity
/// used to unwrap an existing e2e workspace's key (§17), needed only when
/// joining one this device has never held the key for.
/// `tls_ca_cert` is the §17 private-CA PEM for the relay's TLS, if any.
///
/// §32 reader fallback: if the relay answers 403 to a converge push, this
/// device has no Writer role. It says so once and degrades to the
/// read-only mirror loop for the rest of the run instead of dying.
#[allow(clippy::too_many_arguments)]
pub fn converge(
    source: &Path,
    relay: &str,
    token: &str,
    workspace: Option<&str>,
    device: Option<String>,
    team: Option<String>,
    e2e: bool,
    name: Option<&str>,
    tls_ca_cert: Option<&Path>,
    control: &Arc<LoopControl>,
    mut on_cycle: impl FnMut(&ConvergeReport),
) -> Result<()> {
    let device = device.unwrap_or_else(hostname);
    let tls_ca = resolve_tls_ca(tls_ca_cert)?;
    // `--workspace ID` adopts the relay's id (join into an empty dir);
    // otherwise the local `.pear` id is authoritative and gets created
    // relay-side below. `init_workspace` refuses to re-target an existing
    // workspace, so a mismatch is loud here rather than mid-converge.
    let (meta, _) = pear_core::init_workspace(source, workspace)?;
    let client = RelayClient::with_tls_ca(relay, token, &meta.id, &device, tls_ca.as_deref())?;
    let ws = register_workspace(&client, source, &meta.id, team.as_deref(), e2e)?;
    learn_env_policy(&client)?;

    // §17+§19+§20: the e2e key pass runs BEFORE the first converge. A
    // device that already holds the ring uses it; one joining a workspace
    // it has never held the key for fetches its own wrap and unwraps it
    // with the `name` identity (§17); a freshly created workspace mints
    // one. Rotation-maintenance then drops departed members' wraps (§20)
    // and re-wraps the ring to the current team (§19) — merging the
    // relay's copy of our own wrap in before it mints anything (§32).
    let e2e_keyring = if ws.e2e {
        let keys = crate::daemon::pear_home()?.join("keys");
        let mut keyring = match pear_core::e2e::load_workspace_keyring(source)? {
            Some(keyring) => keyring,
            None if ws.existed => {
                pear_core::e2e::workspace_key_for_reader(source, &client, &keys, name)?
            }
            None => pear_core::e2e::load_or_create_workspace_keyring(source)?,
        };
        let known_keys = crate::daemon::pear_home()?.join("known_keys");
        let rotation = pear_core::e2e::rotation_maintenance(
            &client,
            source,
            &mut keyring,
            &known_keys,
            &keys,
            name,
            false,
        )?;
        print_rotation_report(&rotation);
        Some(keyring)
    } else {
        None
    };

    println!(
        "converging {} <-> {} (workspace {}, device {device}, ctrl-c to stop)",
        source.display(),
        relay,
        meta.id
    );

    // Triggers 2 and 3 (§32): head hints and the poll fallback. Teardown
    // is by channel: when the watch loop below returns it drops its
    // receiver, the forwarder's next send fails and it exits, which drops
    // this thread's kick receiver, which ends this thread at its next
    // wakeup. Nothing here outlives the loop by more than one poll.
    let (kick_tx, kick_rx) = std::sync::mpsc::channel::<()>();
    spawn_head_watcher(&client, control, kick_tx);

    // Set once a 403 proves this device is a reader: the loop stops
    // converging and finishes the run as a mirror (§32).
    let mut demoted = false;
    let outcome = pear_core::watch::watch_loop_with_kicks(
        source,
        Some(kick_rx),
        |src| {
            control.park_if_done();
            let _cycle = control.enter_cycle();
            match pear_core::converge::converge_once(src, &client, &device, e2e_keyring.as_ref()) {
                Ok(report) => {
                    control.set_head_seq(report.head_seq);
                    Ok(report)
                }
                // §32: this device is not a Writer. Say so once and fall
                // back to the read-only mirror loop.
                Err(PushError::Forbidden(why)) => {
                    demoted = true;
                    println!(
                        "pear: the relay refuses writes from this device (403: {why}); \
                         continuing as a read-only mirror"
                    );
                    Err(anyhow::Error::new(pear_core::watch::StopWatching(
                        anyhow::anyhow!("no writer role on workspace {}", client.workspace_id()),
                    )))
                }
                Err(e @ PushError::Client(_)) => {
                    control.fatal(format!("fatal converge error — {e}; exiting."));
                    control.park_if_done();
                    unreachable!(
                        "fatal() exits the foreground; park_if_done() parks daemon workers"
                    )
                }
                // A CAS conflict that outlived converge_once's own bounded
                // retry is transient: the next trigger merges again.
                Err(e @ PushError::HeadConflict { .. }) => Err(anyhow::Error::new(e)),
                Err(PushError::Other(e)) => Err(e),
            }
        },
        |report: &ConvergeReport| on_cycle(report),
    );
    if demoted {
        return mirror(
            source,
            &meta.id,
            relay,
            token,
            name,
            tls_ca_cert,
            control,
            print_pull_report,
        );
    }
    outcome
}

/// What `register_workspace` learned about the relay-side workspace.
struct WorkspaceFacts {
    /// §17: end-to-end encrypted (immutable, set at create).
    e2e: bool,
    /// The workspace was already registered before this loop started —
    /// i.e. this is a join, not a create.
    existed: bool,
}

/// Idempotent relay-side registration (§13/§17), shared by every converge
/// start. An already-registered workspace is adopted with its recorded
/// flavor; only a new one is created, and `--e2e` on an existing PLAIN
/// workspace is an operator error, not a silent downgrade.
fn register_workspace(
    client: &RelayClient,
    source: &Path,
    id: &str,
    team: Option<&str>,
    e2e: bool,
) -> Result<WorkspaceFacts> {
    // Attach at register: the team name resolves to an id passed along
    // with the idempotent create (a 409 keeps whatever the workspace
    // already has — registration happened earlier).
    let team_id = match team {
        Some(name) => Some(find_team(client, name)?.id),
        None => None,
    };
    let existing = match client.get_workspace() {
        Ok(ws) => Some(ws),
        Err(RelayError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let ws_e2e = match &existing {
        Some(ws) => {
            if e2e && !ws.e2e {
                bail!(
                    "workspace {id} is already registered WITHOUT end-to-end encryption; \
                     the flavor is immutable (§17) — drop --e2e or use a new workspace"
                );
            }
            ws.e2e
        }
        None => {
            if e2e {
                client.create_workspace_e2e(&workspace_name(source), team_id.as_deref())?;
            } else {
                client.create_workspace_with_team(&workspace_name(source), team_id.as_deref())?;
            }
            e2e
        }
    };
    if let (Some(name), Some(team_id)) = (team, &team_id) {
        // Attach explicitly only when needed: the relay's attach route is
        // owner-gated, and a team writer resuming an already-attached
        // workspace must not be refused by a redundant call.
        if client.get_workspace()?.team_id.as_deref() == Some(team_id.as_str()) {
            println!("workspace {id} is attached to team {name}");
        } else {
            // Attachment is an owner concern, not a prerequisite for
            // writing the head: a failed attach (a non-owner writer, a
            // name conflict) warns and continues.
            match client.attach_team(team_id) {
                Ok(()) => println!("workspace {id} registered in team {name}"),
                Err(e) => eprintln!(
                    "pear: could not attach workspace to team {name} ({e}); \
                     continuing un-attached — the workspace owner can run `pear share --team {name}`"
                ),
            }
        }
    }
    Ok(WorkspaceFacts {
        e2e: ws_e2e,
        existed: existing.is_some(),
    })
}

/// §28: learn the attached team's `.env` policy BEFORE the first converge
/// and pin it on the client — a forbidding team makes any cycle whose scan
/// captures `.env*` files refuse loudly (fatal), the ONLY line for e2e and
/// the early line for plaintext (the relay 409s too). A team the device
/// cannot see in its own list (e.g. not a member) yields no policy here —
/// the relay's 409 stays the backstop for plaintext.
fn learn_env_policy(client: &RelayClient) -> Result<()> {
    let Some(team_id) = client.get_workspace()?.team_id else {
        return Ok(());
    };
    if let Some(t) = client
        .list_teams()?
        .into_iter()
        .find(|t| t.id == team_id && !t.sync_env)
    {
        println!(
            "team {} forbids .env sync — this loop stops if .env* files appear",
            t.name
        );
        client.set_env_sync_policy(Some(t.name));
    }
    Ok(())
}

/// §32 triggers (b) and (c) for the converge loop: a companion thread that
/// waits on the §14 head feed and kicks a converge on every hint, or on the
/// poll timeout when no hint arrives (2s with the feed down — the
/// correctness floor; 5 minutes with it live — a relay-bug safety net,
/// §21). A relay without the `/ws` route leaves the feed absent and the
/// thread degenerates into the 2s poll, exactly as a mirror does.
///
/// Hints whose seq is not ahead of what this device has already converged
/// are dropped: the relay fans a commit out to every subscriber INCLUDING
/// its author, and re-converging on the echo of our own push would double
/// the work of every cycle for nothing.
fn spawn_head_watcher(client: &RelayClient, control: &Arc<LoopControl>, kick: pear_core::watch::Kick) {
    let client = client.clone();
    let control = control.clone();
    std::thread::spawn(move || {
        let feed = client.head_changes();
        loop {
            if control.stopped() {
                return;
            }
            match &feed {
                Some(feed) => {
                    let interval = if feed.connected() {
                        POLL_INTERVAL_WS
                    } else {
                        POLL_INTERVAL
                    };
                    // A hint at or behind our own converged head is an
                    // echo of our own commit: nothing new to merge
                    // against, so keep waiting instead of converging.
                    if let Ok(seq) = feed.recv_timeout(interval) {
                        if seq <= control.head_seq() {
                            continue;
                        }
                    }
                }
                None => std::thread::sleep(POLL_INTERVAL),
            }
            if kick.send(()).is_err() {
                // The converge loop is gone: so is this thread.
                return;
            }
        }
    });
}

/// Mirror flow (§11/§14/§21): init with the remote workspace id, then apply
/// the writer's changes — immediately on a WebSocket head hint (`head_now`
/// on (re)connect, then `head_changed` per commit), otherwise on the poll
/// tick (5 minutes while the feed is live as a relay-bug safety net, 2s
/// when it is not — the correctness floor). Idle cycles stay quiet.
/// `tls_ca_cert` is the §17 private-CA PEM for the relay's TLS, if any.
/// On an e2e workspace the keyring (§20) is resolved once at startup
/// (§17): local file, else fetched and unwrapped with the `name`
/// identity's keypair.
#[allow(clippy::too_many_arguments)]
pub fn mirror(
    path: &Path,
    workspace: &str,
    relay: &str,
    token: &str,
    name: Option<&str>,
    tls_ca_cert: Option<&Path>,
    control: &Arc<LoopControl>,
    mut on_cycle: impl FnMut(&PullReport),
) -> Result<()> {
    // Verify the workspace exists BEFORE initializing the directory: a
    // typo'd id must not strand a wrong-id `.pear` here.
    let tls_ca = resolve_tls_ca(tls_ca_cert)?;
    let client = RelayClient::with_tls_ca(relay, token, workspace, &hostname(), tls_ca.as_deref())?;
    let ws = client.get_workspace().map_err(|e| match e {
        RelayError::NotFound(_) => anyhow::anyhow!(
            "relay has no workspace {workspace}; check the id, or create it with `pear join --relay <url>` on a writer"
        ),
        other => anyhow::Error::new(other),
    })?;
    // Same guard as the clone paths: never apply into a non-empty
    // directory that is not already this workspace's mirror (a resume
    // with a matching id or init's re-target refusal covers those cases).
    if pear_core::load_workspace(path)?.is_none()
        && path.exists()
        && std::fs::read_dir(path)?.next().is_some()
    {
        bail!(
            "{} is not empty; mirror needs a fresh directory",
            path.display()
        );
    }
    let (meta, _) = pear_core::init_workspace(path, Some(workspace))?;
    // §17: an e2e workspace needs its keyring. The writer wraps for team
    // members at ITS loop start / share — a mirror that starts before
    // its wrap exists must not die permanently: log and retry on the
    // poll interval until the wrap (or the identity keypair) appears.
    let e2e_keyring = if ws.e2e {
        let keys = crate::daemon::pear_home()?.join("keys");
        loop {
            match pear_core::e2e::workspace_key_for_reader(path, &client, &keys, name) {
                Ok(keyring) => break Some(keyring),
                Err(e) => {
                    if control.stopped() {
                        return Ok(());
                    }
                    eprintln!(
                        "pear: e2e workspace key not available yet ({e:#}); \
                         retrying — a writer may need to re-run `pear join --e2e` \
                         or `pear share`, or you `pear user keygen`"
                    );
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }
    } else {
        None
    };
    println!(
        "mirroring workspace {} into {} from {} (ctrl-c to stop)",
        meta.id,
        path.display(),
        relay
    );
    // §14/§21: follow the relay's head feed. A relay without the /ws
    // route leaves the feed disconnected and the loop polls every 2s,
    // exactly as before; a dropped connection now respawns with backoff,
    // and each reconnect's head_now drives a pull right away.
    let feed = client.head_changes();
    loop {
        if control.stopped() {
            return Ok(());
        }
        if let Some(feed) = &feed {
            // Drain only BEFORE the pull: everything queued at this point
            // is covered by the pull that immediately follows. Hints that
            // arrive DURING the pull must stay queued so the wait below
            // wakes on them at once — draining after the pull would defer
            // a mid-pull commit to the 5-minute safety-net poll.
            feed.drain();
        }
        let _cycle = control.enter_cycle();
        let pulled = match &e2e_keyring {
            Some(keyring) => pear_core::sync::pull_once_e2e(path, &client, keyring),
            None => pear_core::sync::pull_once(path, &client),
        };
        match pulled {
            Ok(report) => {
                control.set_head_seq(report.head_seq);
                on_cycle(&report);
            }
            Err(e) => {
                // Deterministic failures (bad token, lost role or
                // workspace) will never succeed: exit like the writer
                // does on losing the head (foreground) or record and
                // return (daemon worker), instead of retrying forever.
                let fatal = matches!(
                    e.downcast_ref::<RelayError>(),
                    Some(RelayError::Http {
                        status: 401 | 403,
                        ..
                    }) | Some(RelayError::NotFound(_))
                        | Some(RelayError::Fatal(_))
                );
                if fatal {
                    control.fatal(format!("mirror cannot continue — {e:#}; exiting."));
                    return Ok(());
                }
                eprintln!("pear: pull failed, will retry: {e:#}");
            }
        }
        drop(_cycle);
        match &feed {
            Some(feed) => {
                let interval = if feed.connected() {
                    POLL_INTERVAL_WS
                } else {
                    POLL_INTERVAL
                };
                // A head hint (§21 head_now / §14 head_changed) wakes the
                // wait early: pull now instead of at the next poll tick.
                let _ = feed.recv_timeout(interval);
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// The id of the caller-visible team named `name` (team commands take the
/// name; the relay API addresses teams by id).
pub fn find_team(client: &RelayClient, name: &str) -> Result<pear_core::relay::TeamInfo> {
    client
        .list_teams()?
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no team {name:?} visible to you — create it with `pear team create {name}` or ask a team owner to add you"
            )
        })
}

/// The PEM bytes of `--tls-ca-cert` / `PEAR_TLS_CA` (§17), if given.
/// Shared by the foreground CLI and the daemon's worker threads so a
/// missing/unreadable CA file fails the same way on both paths.
pub fn resolve_tls_ca(path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    path.map(|p| std::fs::read(p).with_context(|| format!("read TLS CA cert {}", p.display())))
        .transpose()
}

pub fn hostname() -> String {
    whoami::fallible::hostname().unwrap_or_else(|_| "unknown-device".to_string())
}

pub fn workspace_name(source: &Path) -> String {
    source
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "workspace".to_string())
}

pub fn print_report(r: &CycleReport) {
    let mut line = format!(
        "sync: {} written, {} deleted, {} chunks uploaded ({})",
        r.written.len(),
        r.deleted.len(),
        r.chunks_uploaded,
        human_bytes(r.bytes_uploaded)
    );
    if !r.written.is_empty() {
        line.push_str(&format!("; wrote {}", r.written.join(", ")));
    }
    if !r.deleted.is_empty() {
        line.push_str(&format!("; removed {}", r.deleted.join(", ")));
    }
    println!("{line}");
}

/// One line per converge (§32): what came down, what went up, and any
/// conflict copies — the last of those is the line a user must never miss.
pub fn print_converge_report(r: &ConvergeReport) {
    if !r.pushed
        && r.written.is_empty()
        && r.deleted.is_empty()
        && r.conflict_copies.is_empty()
    {
        return;
    }
    let mut line = format!(
        "converge: seq {}; {} written, {} deleted, {} chunks up ({}), {} chunks down ({})",
        r.head_seq,
        r.written.len(),
        r.deleted.len(),
        r.chunks_uploaded,
        human_bytes(r.bytes_uploaded),
        r.chunks_fetched,
        human_bytes(r.bytes_fetched)
    );
    if !r.written.is_empty() {
        line.push_str(&format!("; wrote {}", r.written.join(", ")));
    }
    if !r.deleted.is_empty() {
        line.push_str(&format!("; removed {}", r.deleted.join(", ")));
    }
    println!("{line}");
    if !r.conflict_copies.is_empty() {
        println!(
            "conflict: both sides changed the same file — your version is kept as {}",
            r.conflict_copies.join(", ")
        );
    }
}

/// The §20 lines of a rotation-maintenance pass (rotation + departures),
/// then the ordinary §19 wrap report — shared by converge startup and
/// `pear rekey`.
pub fn print_rotation_report(r: &pear_core::e2e::RotationReport) {
    // §32 merge-before-rotate, when it had something to say.
    if !r.merged_from_relay.is_empty() {
        println!(
            "adopted key generation(s) {} from the relay before rotating",
            r.merged_from_relay
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(why) = &r.merge_skipped {
        println!("rotating on the local keyring alone: {why}");
    }
    if r.rotated {
        println!(
            "rotated the workspace keyring to generation {}",
            r.generation
        );
    }
    if !r.departed.is_empty() {
        println!(
            "members removed since the last wrap (their wrapped keys are deleted): {}",
            r.departed.join(", ")
        );
    }
    print_wrap_report(&r.wrap);
}

/// One line per wrap-maintenance outcome (§17/§19), shared by
/// `pear share` and converge startup. `bad_sig` and `pin_changed` print as
/// warnings, not errors: the pass itself succeeded; those members were
/// simply never wrapped to.
pub fn print_wrap_report(wrap: &pear_core::e2e::WrapReport) {
    if !wrap.wrapped.is_empty() {
        println!("wrapped the workspace keyring for: {}", wrap.wrapped.join(", "));
    }
    if !wrap.skipped.is_empty() {
        println!(
            "skipped members with no registered key (they gain access after `pear user keygen` + your next converge/share): {}",
            wrap.skipped.join(", ")
        );
    }
    if !wrap.unsigned.is_empty() {
        println!(
            "skipped members with an unsigned legacy key (they must re-run `pear user keygen` to sign it; never wrapped to): {}",
            wrap.unsigned.join(", ")
        );
    }
    if !wrap.pin_changed.is_empty() {
        println!(
            "WARNING: identity changed since first wrap — NOT wrapped to (if expected, verify out-of-band, then run `pear trust <user>`): {}",
            wrap.pin_changed.join(", ")
        );
    }
    if !wrap.bad_sig.is_empty() {
        println!(
            "SECURITY WARNING: bad key-bundle signature — NOT wrapped to (possible relay/key tampering): {}",
            wrap.bad_sig.join(", ")
        );
    }
    if !wrap.newly_pinned.is_empty() {
        for (user, fingerprint) in &wrap.newly_pinned {
            println!("pinned new identity for {user}: {fingerprint}");
        }
        println!(
            "compare these fingerprints with their owners out-of-band (`pear user id`) — a wrong pin means the relay substituted a bundle"
        );
    }
}

pub fn print_pull_report(r: &PullReport) {
    // Idle polls (head seq unchanged, nothing applied) stay quiet.
    if !r.changed {
        return;
    }
    let mut line = format!(
        "pull: seq {}; {} written, {} deleted, {} chunks fetched ({})",
        r.head_seq,
        r.written.len(),
        r.deleted.len(),
        r.chunks_fetched,
        human_bytes(r.bytes_fetched)
    );
    if !r.written.is_empty() {
        line.push_str(&format!("; wrote {}", r.written.join(", ")));
    }
    if !r.deleted.is_empty() {
        line.push_str(&format!("; removed {}", r.deleted.join(", ")));
    }
    println!("{line}");
}

pub fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}
