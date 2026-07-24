//! The watch/mirror loop bodies, shared by the foreground `pear` CLI and
//! the `peard` daemon's per-workspace threads (§16). Semantics are the
//! pre-daemon ones, unchanged: the only seam is [`LoopControl`], which
//! tells a loop how to report a fatal condition and when to wind down.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pear_core::relay::{RelayClient, RelayError};
use pear_core::sync::{CycleReport, PullReport, PushError, PushReport};

/// Writers heartbeat the lease every 30s (§11).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Mirrors poll the head every 2s while the WebSocket feed is down (§11/§14).
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// With a live WebSocket feed the poll relaxes to a 5-minute safety net
/// (§21): its only remaining job is catching a hint lost to a relay bug —
/// keepalive (45s), reconnect+head_now, and the 60s role re-check cover
/// every realistic loss path. The 2s feed-down poll above is unchanged:
/// it is the correctness floor, not a safety net.
const POLL_INTERVAL_WS: Duration = Duration::from_secs(300);

/// Exit code when this device loses the lease / head ownership mid-watch.
const EXIT_LOST_LEASE: i32 = 3;

/// Supervision seam for a running sync loop (§16).
///
/// The foreground CLI uses [`LoopControl::foreground`]: the stop flag is
/// never set and a fatal (fencing/auth) condition prints and exits with
/// `EXIT_LOST_LEASE` — byte-for-byte the pre-daemon behavior. A `peard`
/// worker uses [`LoopControl::worker`]: `remove`/`shutdown` set the stop
/// flag, a fatal condition is recorded for `status` instead of killing the
/// daemon, and the loop goes inert rather than sync again.
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
    /// `shutdown`). Leases are left to expire — no special release (§16).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// The last committed (writer) or applied (mirror) head seq, for
    /// `status`. 0 = none known yet.
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

    /// A fatal (fencing/auth) condition. Foreground: print and exit with
    /// `EXIT_LOST_LEASE`, the pre-daemon behavior. Daemon worker: record it
    /// for `status`; the caller then goes inert via [`Self::park_if_done`].
    fn fatal(&self, message: String) {
        if self.exit_on_fatal {
            eprintln!("pear: {message}");
            std::process::exit(EXIT_LOST_LEASE);
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

/// Writer flow (§11): init, idempotent workspace create, lease acquire,
/// heartbeat thread, then push every watch cycle. Losing the lease or the
/// head is fatal — the foreground exits rather than push into someone
/// else's generation; a daemon worker records the error and goes inert.
/// With `team`, the workspace is attached to the team at register (§13).
/// With `e2e`, the workspace is registered end-to-end encrypted (§17):
/// the keyring (§20) is loaded or created at `.pear/workspace_keys` and,
/// AFTER the lease is owned and BEFORE the first push, rotation-maintenance
/// runs — a team member who VANISHED since the last recorded wrap rotates
/// the keyring and loses their wrap row (§20), then every member whose
/// signed bundle verifies and matches the known_keys pin gets the
/// (possibly rotated) keyring wrapped to them (§19).
/// `tls_ca_cert` is the §17 private-CA PEM for the relay's TLS, if any.
#[allow(clippy::too_many_arguments)]
pub fn watch_writer(
    source: &Path,
    relay: &str,
    token: &str,
    device: Option<String>,
    force: bool,
    team: Option<String>,
    e2e: bool,
    tls_ca_cert: Option<&Path>,
    control: &Arc<LoopControl>,
    on_cycle: impl FnMut(&PushReport),
) -> Result<()> {
    let device = device.unwrap_or_else(hostname);
    let tls_ca = resolve_tls_ca(tls_ca_cert)?;
    let (meta, _) = pear_core::init_workspace(source, None)?;
    let client = RelayClient::with_tls_ca(relay, token, &meta.id, &device, tls_ca.as_deref())?;
    // Attach at register: the team name resolves to an id passed along
    // with the idempotent create (a 409 keeps whatever the workspace
    // already has — registration happened earlier).
    let team_id = match &team {
        Some(name) => Some(find_team(&client, name)?.id),
        None => None,
    };
    // §17: e2e registration is immutable relay-side — a workspace already
    // registered under the other flavor 409s (`e2e_mismatch`) here.
    if e2e {
        client.create_workspace_e2e(&workspace_name(source), team_id.as_deref())?;
    } else {
        client.create_workspace_with_team(&workspace_name(source), team_id.as_deref())?;
    }
    if let (Some(name), Some(team_id)) = (&team, &team_id) {
        // Attach explicitly only when needed: the relay's attach route is
        // owner-gated, and a team writer resuming an already-attached
        // workspace must not be fenced out by a redundant call.
        if client.get_workspace()?.team_id.as_deref() == Some(team_id.as_str()) {
            println!("writer: workspace {} is attached to team {name}", meta.id);
        } else {
            // Attachment is an owner concern, not a prerequisite for
            // writing the head: a failed attach (a non-owner writer, a
            // name conflict) warns and continues.
            match client.attach_team(team_id) {
                Ok(()) => println!("writer: workspace {} registered in team {name}", meta.id),
                Err(e) => eprintln!(
                    "pear: could not attach workspace to team {name} ({e}); \
                     continuing un-attached — the workspace owner can run `pear share --team {name}`"
                ),
            }
        }
    }
    // §28: learn the attached team's `.env` policy BEFORE the first push
    // and pin it on the client — a forbidding team makes any cycle whose
    // scan captures `.env*` files refuse loudly (fatal), the ONLY line
    // for e2e and the early line for plaintext (the relay 409s too).
    // Read-only calls, before the lease is touched: a refusing watch must
    // never steal a lease. A team the writer cannot see in its own list
    // (e.g. not a member) yields no policy here — the relay's 409 stays
    // the backstop for plaintext.
    if let Some(team_id) = client.get_workspace()?.team_id {
        if let Some(t) = client
            .list_teams()?
            .into_iter()
            .find(|t| t.id == team_id && !t.sync_env)
        {
            println!(
                "writer: team {} forbids .env sync — this watch stops if .env* files appear",
                t.name
            );
            client.set_env_sync_policy(Some(t.name));
        }
    }
    // The resume-safety check runs BEFORE touching the lease: acquire
    // steals an expired lease, and a resume we then refuse would have
    // fenced the sleeping writer for nothing.
    let mut base_seq = pear_core::sync::writer_base_seq(source, &client, force)?;
    // Takeover is explicit: --force revokes the current lease (and can
    // strand the old writer's unsynced changes); otherwise acquire.
    let generation = if force {
        client.force()?
    } else {
        client.acquire()?
    };
    println!(
        "writer: workspace {}, device {device}, lease generation {generation}",
        meta.id
    );
    control.set_head_seq(base_seq);

    // §17+§19+§20: the e2e key pass runs with the lease owned and BEFORE
    // the first push — only the lease holder may re-key, and between a
    // member removal and this pass nothing new can be pushed, so the
    // removal window has no silent exposure. Rotation-maintenance first
    // (§20): a team member who VANISHED since the last recorded wrap
    // rotates the keyring and loses their wrap row; a pure addition never
    // rotates. The ordinary §19 wrap pass inside it then wraps the
    // (possibly rotated) keyring to the current team.
    let e2e_keyring = if e2e {
        let mut keyring = pear_core::e2e::load_or_create_workspace_keyring(source)?;
        let known_keys = crate::daemon::pear_home()?.join("known_keys");
        let rotation =
            pear_core::e2e::rotation_maintenance(&client, source, &mut keyring, &known_keys, false)?;
        print_rotation_report(&rotation);
        Some(keyring)
    } else {
        None
    };

    // Heartbeat keeps a crashed laptop from holding the workspace hostage;
    // a 403 means this device has been fenced — die loudly (foreground) or
    // go inert with the error recorded (daemon worker).
    let heartbeat_client = client.clone();
    let heartbeat_control = control.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(HEARTBEAT_INTERVAL);
        if heartbeat_control.stopped() {
            return;
        }
        match heartbeat_client.heartbeat() {
            Ok(()) => {}
            Err(RelayError::Fenced(why)) => {
                heartbeat_control.fatal(format!(
                    "LEASE LOST — fenced ({why}); another device owns the workspace. Exiting."
                ));
                return;
            }
            Err(RelayError::Http { status, body }) if matches!(status, 401 | 403) => {
                heartbeat_control.fatal(format!(
                    "heartbeat rejected (HTTP {status}): {body}. Token or role revoked? Exiting."
                ));
                return;
            }
            Err(e) => eprintln!("pear: heartbeat failed, will retry: {e}"),
        }
    });

    println!(
        "watching {} -> {} (head seq {base_seq}, ctrl-c to stop)",
        source.display(),
        relay
    );
    // The first cycle after a forced takeover commits unconditionally:
    // "this tree becomes the head", even when unchanged locally. The flag
    // is consumed only once a cycle succeeds — a transient failure must
    // not quietly drop the takeover.
    let mut takeover = force;
    pear_core::watch::watch_loop_with(
        source,
        |src| {
            control.park_if_done();
            let _cycle = control.enter_cycle();
            let pushed = match &e2e_keyring {
                Some(keyring) => {
                    pear_core::sync::push_cycle_e2e(src, &client, base_seq, takeover, keyring)
                }
                None => pear_core::sync::push_cycle(src, &client, base_seq, takeover),
            };
            match pushed {
                Ok(report) => {
                    takeover = false;
                    base_seq = report.head_seq;
                    control.set_head_seq(report.head_seq);
                    Ok(report)
                }
                Err(
                    e @ (PushError::Fenced(_)
                    | PushError::HeadConflict { .. }
                    | PushError::Client(_)),
                ) => {
                    control.fatal(format!("fatal push error — {e}; exiting."));
                    // The foreground never gets here (fatal exited); a
                    // daemon worker parks instead of pushing again.
                    control.park_if_done();
                    unreachable!(
                        "fatal() exits the foreground; park_if_done() parks daemon workers"
                    )
                }
                Err(PushError::Other(e)) => Err(e),
            }
        },
        on_cycle,
    )
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
            "relay has no workspace {workspace}; check the id, or create it with `pear watch --relay` on the writer"
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
    // members at ITS watch start / share — a mirror that starts before
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
                         retrying — the writer may need to re-run `pear watch --e2e` \
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

pub fn print_push_report(r: &PushReport) {
    if !r.committed {
        println!("push: no changes (seq {})", r.head_seq);
        return;
    }
    let mut line = format!(
        "push: seq {}; {} added, {} changed, {} deleted, {} chunks uploaded ({})",
        r.head_seq,
        r.added.len(),
        r.changed.len(),
        r.deleted.len(),
        r.chunks_uploaded,
        human_bytes(r.bytes_uploaded)
    );
    let mut wrote = r.added.clone();
    wrote.extend(r.changed.iter().cloned());
    if !wrote.is_empty() {
        line.push_str(&format!("; wrote {}", wrote.join(", ")));
    }
    if !r.deleted.is_empty() {
        line.push_str(&format!("; removed {}", r.deleted.join(", ")));
    }
    println!("{line}");
}

/// The §20 lines of a rotation-maintenance pass (rotation + departures),
/// then the ordinary §19 wrap report — shared by watch startup and
/// `pear rekey`.
pub fn print_rotation_report(r: &pear_core::e2e::RotationReport) {
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
/// `pear share` and watch startup. `bad_sig` and `pin_changed` print as
/// warnings, not errors: the pass itself succeeded; those members were
/// simply never wrapped to.
pub fn print_wrap_report(wrap: &pear_core::e2e::WrapReport) {
    if !wrap.wrapped.is_empty() {
        println!("wrapped the workspace keyring for: {}", wrap.wrapped.join(", "));
    }
    if !wrap.skipped.is_empty() {
        println!(
            "skipped members with no registered key (they gain access after `pear user keygen` + your next watch/share): {}",
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
