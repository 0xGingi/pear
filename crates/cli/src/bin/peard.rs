//! `peard` — the pear daemon (§16): a process supervisor over the existing
//! watch/mirror loops. It runs in the foreground (supervision is the
//! user's init system), serves newline-delimited JSON on
//! `$PEAR_HOME/daemon.sock`, and keeps one OS thread per registered
//! workspace running the same loop bodies the foreground CLI uses.
//!
//! Tokens arrive with `add_*` requests and are held in memory only —
//! `daemon.json` (the registration list) has no token field, and neither
//! logs nor status responses echo one.

// Shared with the `pear` binary via path includes; each binary uses part
// of the daemon module (client vs server side), hence the allow.
#[allow(dead_code, unused_imports)]
#[path = "../daemon.rs"]
mod daemon;
#[allow(dead_code)]
#[path = "../loops.rs"]
mod loops;

fn main() -> anyhow::Result<()> {
    server::run()
}

#[cfg(unix)]
mod server {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context, Result};
    use serde_json::{json, Value};

    use super::daemon::{self, EntryInfo, Registration, Request, Response};
    use super::loops::{self, LoopControl};

    /// Longest shutdown waits for in-flight cycles before exiting anyway:
    /// "loops finish their current cycle" (§16), but a wedged push must not
    /// hold the process forever.
    const SHUTDOWN_DRAIN: Duration = Duration::from_secs(60);

    /// A registered workspace: its persisted args plus the control seam of
    /// its running (or failed) loop thread. The token is NOT here — it was
    /// moved into the thread closure and lives only there.
    struct Worker {
        registration: Registration,
        control: Arc<LoopControl>,
    }

    impl Worker {
        fn entry_info(&self) -> EntryInfo {
            self.registration.entry_info(&self.control)
        }
    }

    struct Registry {
        home: PathBuf,
        workers: HashMap<String, Worker>,
    }

    impl Registry {
        fn new(home: PathBuf) -> Self {
            Self {
                home,
                workers: HashMap::new(),
            }
        }

        /// `add_watch`: validate, spawn the loop thread, persist. A watch is
        /// either local (target) or a writer (relay); a writer needs a token.
        #[allow(clippy::too_many_arguments)]
        fn add_watch(
            &mut self,
            path: PathBuf,
            target: Option<PathBuf>,
            relay: Option<String>,
            token: Option<String>,
            device: Option<String>,
            force: bool,
            team: Option<String>,
            e2e: bool,
            tls_ca_cert: Option<PathBuf>,
        ) -> Result<EntryInfo> {
            let path = path
                .canonicalize()
                .with_context(|| format!("canonicalize {}", path.display()))?;
            match (&target, &relay) {
                (Some(_), Some(_)) => {
                    bail!("a watch takes either a target (local) or a relay (writer), not both")
                }
                (None, None) => bail!("a watch needs a target (local) or a relay (writer)"),
                _ => {}
            }
            if relay.is_some() && token.as_deref().is_none_or(str::is_empty) {
                bail!("a relay watch needs a bearer token");
            }
            let registration = Registration::Watch {
                path,
                target,
                relay,
                device,
                force,
                team,
                e2e,
                tls_ca_cert,
            };
            let worker = self.start(registration, token)?;
            self.persist()?;
            Ok(worker)
        }

        /// `add_mirror`: validate, spawn the pull loop, persist.
        fn add_mirror(
            &mut self,
            path: PathBuf,
            workspace: String,
            relay: String,
            token: String,
            name: Option<String>,
            tls_ca_cert: Option<PathBuf>,
        ) -> Result<EntryInfo> {
            let path = path
                .canonicalize()
                .with_context(|| format!("canonicalize {}", path.display()))?;
            if workspace.is_empty() {
                bail!("a mirror needs a workspace id");
            }
            if token.is_empty() {
                bail!("a mirror needs a bearer token");
            }
            let registration = Registration::Mirror {
                path,
                workspace,
                relay,
                name,
                tls_ca_cert,
            };
            let worker = self.start(registration, Some(token))?;
            self.persist()?;
            Ok(worker)
        }

        /// Register and spawn one workspace loop, refusing duplicates (two
        /// writers on one workspace stay impossible by the lease, but the
        /// same path twice in one daemon is always a mistake).
        fn start(
            &mut self,
            registration: Registration,
            token: Option<String>,
        ) -> Result<EntryInfo> {
            let key = registration.key();
            if self.workers.contains_key(&key) {
                bail!(
                    "{} is already registered; remove it first",
                    registration.path().display()
                );
            }
            let control = LoopControl::worker();
            spawn_worker(&registration, token, &control);
            let worker = Worker {
                registration,
                control,
            };
            let entry = worker.entry_info();
            self.workers.insert(key, worker);
            Ok(entry)
        }

        /// `remove`: stop the loop and drop the registration. The thread
        /// goes inert at its next cycle boundary and the lease is left to
        /// expire (§16).
        fn remove(&mut self, path: &Path) -> Result<()> {
            let key = key_of(path);
            let Some(worker) = self.workers.remove(&key) else {
                bail!("{} is not registered", path.display());
            };
            worker.control.stop();
            self.persist()?;
            Ok(())
        }

        /// `list` / `status`: live state of every (or one) registration.
        fn entries(&self, path: Option<&Path>) -> Value {
            let workers: Vec<&Worker> = match path {
                Some(path) => self.workers.get(&key_of(path)).into_iter().collect(),
                None => self.workers.values().collect(),
            };
            json!({
                "workspaces": workers.iter().map(|w| w.entry_info().to_json()).collect::<Vec<_>>(),
            })
        }

        /// Re-register the persisted list on startup (§16). Relay
        /// workspaces resume only when a token is re-supplied via
        /// `PEAR_TOKEN`; without one the entry stays registered and reports
        /// a clear status error instead of running.
        fn restore(&mut self) -> Result<()> {
            for registration in daemon::load_state(&self.home)? {
                if self.workers.contains_key(&registration.key()) {
                    continue;
                }
                let control = LoopControl::worker();
                if registration.needs_token() {
                    match env_token() {
                        Some(token) => spawn_worker(&registration, Some(token), &control),
                        None => control.record_error(
                            "not resumed: relay workspaces need a token — restart peard with \
                             PEAR_TOKEN set (tokens are held in memory only, never persisted)"
                                .to_string(),
                        ),
                    }
                } else {
                    spawn_worker(&registration, None, &control);
                }
                self.workers.insert(
                    registration.key(),
                    Worker {
                        registration,
                        control,
                    },
                );
            }
            Ok(())
        }

        /// `shutdown`: every loop winds down at its next cycle boundary;
        /// in-flight cycles finish, then the process exits. Leases are left
        /// to expire — no special release (§16).
        fn shutdown(&mut self) {
            let controls: Vec<Arc<LoopControl>> = self
                .workers
                .values()
                .map(|w| {
                    w.control.stop();
                    w.control.clone()
                })
                .collect();
            let deadline = Instant::now() + SHUTDOWN_DRAIN;
            loop {
                if controls.iter().all(|c| !c.in_cycle()) {
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!("peard: a sync cycle is still in flight; exiting anyway");
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        fn persist(&self) -> Result<()> {
            let registrations: Vec<Registration> = self
                .workers
                .values()
                .map(|w| w.registration.clone())
                .collect();
            daemon::save_state(&self.home, &registrations)
        }
    }

    /// One OS thread running the existing loop body for a registration
    /// (§16). A returned error is recorded for `status`; other workspaces
    /// are unaffected.
    fn spawn_worker(
        registration: &Registration,
        token: Option<String>,
        control: &Arc<LoopControl>,
    ) {
        let registration = registration.clone();
        let control = control.clone();
        std::thread::spawn(move || {
            let result = match &registration {
                Registration::Watch {
                    path,
                    target: Some(target),
                    ..
                } => loops::watch_local(path, target, &control, loops::print_report),
                Registration::Watch {
                    path,
                    relay: Some(relay),
                    device,
                    force,
                    team,
                    e2e,
                    tls_ca_cert,
                    ..
                } => loops::watch_writer(
                    path,
                    relay,
                    token.as_deref().unwrap_or(""),
                    device.clone(),
                    *force,
                    team.clone(),
                    *e2e,
                    tls_ca_cert.as_deref(),
                    &control,
                    loops::print_push_report,
                ),
                Registration::Mirror {
                    path,
                    workspace,
                    relay,
                    name,
                    tls_ca_cert,
                } => loops::mirror(
                    path,
                    workspace,
                    relay,
                    token.as_deref().unwrap_or(""),
                    name.as_deref(),
                    tls_ca_cert.as_deref(),
                    &control,
                    loops::print_pull_report,
                ),
                // Validated away at registration (a watch always has a
                // target or a relay); never reached.
                _ => Ok(()),
            };
            if let Err(e) = result {
                eprintln!(
                    "peard: {} loop exited with an error: {e:#}",
                    registration.path().display()
                );
                control.record_error(format!("{e:#}"));
            }
        });
    }

    /// The registry key for a client-supplied path: canonical when it
    /// exists, absolute otherwise (a removed workspace's path may be gone).
    fn key_of(path: &Path) -> String {
        path.canonicalize()
            .or_else(|_| std::path::absolute(path))
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned()
    }

    /// The token for resumed relay workspaces: `PEAR_TOKEN` from the
    /// daemon's own environment (§16).
    fn env_token() -> Option<String> {
        std::env::var("PEAR_TOKEN").ok().filter(|t| !t.is_empty())
    }

    fn lock(registry: &Arc<Mutex<Registry>>) -> MutexGuard<'_, Registry> {
        registry.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Create `$PEAR_HOME` 0700. The chmod also proves ownership: it fails
    /// for another user's directory.
    fn prepare_home(home: &Path) -> Result<()> {
        std::fs::create_dir_all(home).with_context(|| format!("create {}", home.display()))?;
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {} — owned by another user?", home.display()))?;
        Ok(())
    }

    /// Bind the socket 0700, replacing a stale one but refusing to start
    /// over a live daemon.
    fn bind_socket(home: &Path) -> Result<UnixListener> {
        let sock = daemon::socket_path(home);
        if sock.exists() {
            if UnixStream::connect(&sock).is_ok() {
                bail!("peard is already running ({} answers)", sock.display());
            }
            std::fs::remove_file(&sock)
                .with_context(|| format!("remove stale socket {}", sock.display()))?;
        }
        let listener =
            UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", sock.display()))?;
        Ok(listener)
    }

    /// One connection = one request line, one response line (§16). Parse
    /// failures and unknown requests get an error response, never a panic.
    fn handle(stream: UnixStream, registry: &Arc<Mutex<Registry>>) {
        if let Err(e) = serve_conn(stream, registry) {
            eprintln!("peard: connection failed: {e:#}");
        }
    }

    fn serve_conn(stream: UnixStream, registry: &Arc<Mutex<Registry>>) -> Result<()> {
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line)? == 0 {
            bail!("empty request");
        }
        let parsed = serde_json::from_str::<Value>(&line)
            .map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))
            .and_then(|doc| Request::from_json(&doc));
        let (response, shutdown) = match parsed {
            Ok(Request::Shutdown) => (Response::ok(json!({})), true),
            Ok(request) => (dispatch(request, registry), false),
            Err(e) => (Response::err(format!("bad request: {e:#}")), false),
        };
        let mut writer = stream.try_clone()?;
        writeln!(writer, "{}", response.to_json())?;
        writer.flush()?;
        if shutdown {
            lock(registry).shutdown();
            println!("peard: shutdown complete");
            std::process::exit(0);
        }
        Ok(())
    }

    fn dispatch(request: Request, registry: &Arc<Mutex<Registry>>) -> Response {
        let result = match request {
            Request::AddWatch {
                path,
                target,
                relay,
                token,
                device,
                force,
                team,
                e2e,
                tls_ca_cert,
            } => lock(registry)
                .add_watch(
                    path,
                    target,
                    relay,
                    token,
                    device,
                    force,
                    team,
                    e2e,
                    tls_ca_cert,
                )
                .map(|entry| entry.to_json()),
            Request::AddMirror {
                path,
                workspace,
                relay,
                token,
                name,
                tls_ca_cert,
            } => lock(registry)
                .add_mirror(path, workspace, relay, token, name, tls_ca_cert)
                .map(|entry| entry.to_json()),
            Request::List => Ok(lock(registry).entries(None)),
            Request::Remove { path } => lock(registry)
                .remove(&path)
                .map(|()| json!({ "removed": true })),
            Request::Status { path } => Ok(lock(registry).entries(path.as_deref())),
            Request::Shutdown => unreachable!("handled by serve_conn"),
        };
        match result {
            Ok(value) => Response::ok(value),
            Err(e) => Response::err(format!("{e:#}")),
        }
    }

    pub fn run() -> Result<()> {
        let home = daemon::pear_home()?;
        prepare_home(&home)?;
        let listener = bind_socket(&home)?;
        let registry = Arc::new(Mutex::new(Registry::new(home.clone())));
        lock(&registry).restore()?;
        println!(
            "peard: listening on {} ({} workspace(s) restored)",
            daemon::socket_path(&home).display(),
            lock(&registry).workers.len()
        );
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let registry = registry.clone();
                    std::thread::spawn(move || handle(stream, &registry));
                }
                Err(e) => eprintln!("peard: accept failed: {e}"),
            }
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod server {
    pub fn run() -> anyhow::Result<()> {
        anyhow::bail!("peard runs on unix only (§16)")
    }
}
