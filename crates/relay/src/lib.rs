//! pear relay server (DESIGN.md §11): bearer-token auth, the workspace
//! registry, a global content-addressed chunk pool, the head log with CAS,
//! the single-writer lease state machine (acquire / heartbeat / transfer /
//! force, TTL expiry, generation fencing on head writes), and the §14
//! WebSocket fan-out of `head_changed` hints to mirrors.
//!
//! §17: with `--tls-cert`/`--tls-key` the same API is served over HTTPS
//! directly (rustls, no proxy); absent those flags plain HTTP is unchanged.

mod db;
mod error;
mod gc;
mod routes;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use pear_core::store::LocalStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// Capacity of one workspace's `head_changed` fan-out channel (§14).
/// Small on purpose: the message is a hint, so a lagging subscriber is
/// not buffered for — it gets a polite Close and its client's reconnect
/// catches up via `head_now` (§21).
const HEAD_BROADCAST_CAPACITY: usize = 8;

/// §22: BACKSTOP interval for the pool flush task. Durability is not
/// driven by this tick — commit points flush the pool (`put_head`,
/// `create_snapshot`); this 5 s sweep only fsyncs stray puts that were
/// accepted but never referenced, so their un-fsynced dirents do not
/// linger forever (§25: the queue holds shard-dir paths, no open fds).
/// A continuous short-interval timer
/// (200 ms, tried first) measurably REGRESSED the push leg: its
/// F_FULLFSYNC bursts saturated APFS and stalled in-flight PUTs — zero
/// fsyncs during the upload stream plus one burst at commit does not
/// (DESIGN.md §22).
const POOL_BACKSTOP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// §24: pool GC cadence — first run one hour after boot (startup already
/// has `sweep_tmp` at store open; an immediate sweep only adds boot
/// latency), then hourly. The whole sweep runs under the one DB mutex:
/// an hourly seconds-scale stall at monorepo sizes beats a lock-free
/// race (§24).
const POOL_GC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);
/// §24: an unreferenced blob younger than this is NOT collected — it may
/// belong to a push between chunk-upload and head-commit (refs are
/// earned only at commit).
const POOL_GC_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

/// Shared relay state: the metadata DB, the global chunk pool, the lease
/// TTL that drives expiry and fencing, and the per-workspace fan-out
/// channels for `head_changed` hints (§14).
#[derive(Clone)]
pub(crate) struct AppState {
    token: Arc<str>,
    db: Arc<Mutex<db::Db>>,
    store: Arc<LocalStore>,
    lease_ttl_secs: i64,
    broadcasts: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
    /// Seconds between reader-role re-checks on live WS connections.
    ws_recheck_secs: u64,
}

impl AppState {
    fn new(token: &str, data_dir: &Path, lease_ttl_secs: u64) -> anyhow::Result<Self> {
        if token.is_empty() {
            anyhow::bail!(
                "relay token is empty: the relay would accept an empty bearer credential — set a non-empty token"
            );
        }
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        // One global content-addressed chunk pool for all workspaces.
        // §22: DEFERRED — a chunk PUT fsyncs nothing on the request path.
        // Durability lands AT COMMIT POINTS (`put_head`/`create_snapshot`
        // flush before the row commits); `spawn_pool_flusher`'s slow
        // backstop tick covers only stray never-referenced puts. The
        // precise ack semantics are documented on the flusher and the
        // PUT route.
        let store = LocalStore::open_deferred(data_dir)
            .with_context(|| format!("open chunk store in {}", data_dir.display()))?;
        let db = db::Db::open(&data_dir.join("relay.db")).context("open metadata database")?;
        let token: Arc<str> = token.into();
        Ok(Self {
            token,
            db: Arc::new(Mutex::new(db)),
            store: Arc::new(store),
            lease_ttl_secs: lease_ttl_secs as i64,
            broadcasts: Arc::new(Mutex::new(HashMap::new())),
            ws_recheck_secs: 60,
        })
    }

    /// Test hook: shorten the WS role re-check interval.
    #[cfg(test)]
    pub(crate) fn with_ws_recheck_secs(mut self, secs: u64) -> Self {
        self.ws_recheck_secs = secs;
        self
    }

    /// Subscribe to a workspace's `head_changed` hints, creating the
    /// fan-out channel lazily on first use (§14).
    pub(crate) fn subscribe_head(&self, workspace: &str) -> broadcast::Receiver<String> {
        let mut channels = self
            .broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        channels
            .entry(workspace.to_string())
            .or_insert_with(|| broadcast::channel(HEAD_BROADCAST_CAPACITY).0)
            .subscribe()
    }

    /// Fan a successful head commit out to the workspace's subscribers
    /// (§14): `{ "type": "head_changed", "workspace": id, "seq": n }`.
    /// The message is a hint, not correctness — a missing receiver or a
    /// lagging subscriber must never affect the commit, so the send
    /// result is deliberately ignored. A channel with no live receivers
    /// is dropped so the map stays bounded by live subscribers, not by
    /// every workspace ever watched.
    pub(crate) fn notify_head_changed(&self, workspace: &str, seq: i64) {
        let mut channels = self
            .broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = channels.get(workspace) {
            if tx.receiver_count() == 0 {
                channels.remove(workspace);
                return;
            }
            let hint = serde_json::json!({
                "type": "head_changed",
                "workspace": workspace,
                "seq": seq,
            });
            let _ = tx.send(hint.to_string());
        }
    }
}

/// The §21 catch-up message, sent as the FIRST frame after a WS upgrade
/// (before any streamed hint): `{ "type": "head_now", "workspace": id,
/// "seq": n }` with `n` the workspace's current head seq (0 = no head).
/// Hints are cumulative state, not a delta log, so "replay" degenerates to
/// reporting where the head is NOW — a (re)connecting subscriber learns
/// about commits that predated the subscription (or were lost to a
/// lag-close) with no buffer, no hello state, no per-event log.
pub(crate) fn head_now_message(workspace: &str, seq: i64) -> String {
    serde_json::json!({
        "type": "head_now",
        "workspace": workspace,
        "seq": seq,
    })
    .to_string()
}

/// Bind `addr` and serve the relay API until the process exits.
pub async fn serve(
    addr: std::net::SocketAddr,
    token: &str,
    data_dir: &std::path::Path,
    lease_ttl_secs: u64,
) -> anyhow::Result<()> {
    let state = AppState::new(token, data_dir, lease_ttl_secs)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    serve_listener(listener, state).await
}

/// Serve on an already-bound listener. Binding first lets tests learn the
/// ephemeral port before the accept loop starts.
pub(crate) async fn serve_listener(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    spawn_pool_flusher(&state.store);
    spawn_pool_gc(&state);
    axum::serve(listener, routes::router(state)).await?;
    Ok(())
}

/// §22 pool BACKSTOP flush driver, spawned next to the server. The
/// deferred pool store fsyncs nothing on `put`, and durability is
/// flushed AT COMMIT POINTS (`put_head`/`create_snapshot`, before the
/// row commits) — this task's slow [`POOL_BACKSTOP_INTERVAL`] tick only
/// sweeps stray accepted-but-never-referenced puts so their un-fsynced
/// dirents do not linger (§25: dir paths, no open fds). That makes the
/// §22 ack
/// semantics precise: a chunk REFERENCED BY A COMMITTED head/snapshot
/// is PRESENT (§25: dir-durable — a rare very-recent-blob tear after
/// power loss is always caught by verify-on-get and heals by
/// re-upload, never silently wrong); an accepted chunk awaiting
/// reference has no durability
/// guarantee at all (it is unreferenced garbage — its loss costs
/// nothing). Crash window = "since the last commit point", and
/// DESIGN.md §22's crash matrix shows it heals with no new machinery —
/// chunks/missing ANDs refs-visibility with blob existence, and §18's
/// verify-on-get turns a torn blob into delete → 404 → "missing" →
/// re-upload.
///
/// A failed flush is logged and retried next tick: `flush` itself
/// requeues the un-fsynced remainder ahead of newer puts (§18), and a
/// persistent failure surfaces on the request path anyway via the
/// 64-pending self-flush inside `put`. The fsyncs run in
/// `spawn_blocking` — blocking I/O stays off the runtime threads, the
/// same §14 rule as the request path's `block`.
fn spawn_pool_flusher(store: &Arc<LocalStore>) {
    let store = store.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POOL_BACKSTOP_INTERVAL);
        loop {
            tick.tick().await;
            let store = store.clone();
            match tokio::task::spawn_blocking(move || store.flush()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    eprintln!("pear-relay: chunk pool flush failed (retried next tick): {e}");
                }
                Err(e) => eprintln!("pear-relay: chunk pool flush panicked: {e}"),
            }
        }
    });
}

/// §24 pool garbage collector, spawned next to the server alongside the
/// flusher. The first run lands one hour after boot, then hourly
/// (`interval_at`: a plain `interval` fires immediately on creation).
/// Each tick runs the mark-and-sweep in `spawn_blocking` (blocking I/O
/// stays off the runtime threads, the same §14 rule as the request path)
/// and holds the one DB mutex for the whole sweep — v1's documented
/// trade: an hourly seconds-scale stall beats a lock-free race. The
/// report is logged every run; a failed sweep is logged and retried next
/// tick, never fatal.
fn spawn_pool_gc(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + POOL_GC_INTERVAL,
            POOL_GC_INTERVAL,
        );
        loop {
            tick.tick().await;
            let state = state.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                // One lock for the whole sweep (§24 v1): the live-set
                // reads, the refs rebuild, and every blob unlink see one
                // consistent DB. into_inner: a poisoned lock (some request
                // panicked holding it) must not disable GC forever.
                let db = state
                    .db
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                gc::run_pool_gc(&db, &state.store, POOL_GC_GRACE)
            })
            .await;
            match outcome {
                Ok(Ok(report)) => eprintln!("pear-relay: pool GC: {report}"),
                Ok(Err(e)) => eprintln!("pear-relay: pool GC failed (retried next tick): {e:#}"),
                Err(e) => eprintln!("pear-relay: pool GC panicked: {e}"),
            }
        }
    });
}

/// Serve on an already-bound listener, constructing state from the same
/// arguments as `serve`. Callers learn the port before the accept loop
/// starts — no bind-then-drop port race.
pub async fn serve_on(
    listener: TcpListener,
    token: &str,
    data_dir: &Path,
    lease_ttl_secs: u64,
) -> anyhow::Result<()> {
    let state = AppState::new(token, data_dir, lease_ttl_secs)?;
    serve_listener(listener, state).await
}

/// The relay's TLS identity (§17): a PEM cert chain and matching private
/// key, loaded and validated at startup so unreadable or mismatched key
/// material fails the process loudly instead of at the first handshake.
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<rustls::ServerConfig>,
}

impl ServerTls {
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("read TLS cert {}", cert_path.display()))?;
        let certs = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parse TLS cert {}", cert_path.display()))?;
        if certs.is_empty() {
            anyhow::bail!("no certificates in {}", cert_path.display());
        }
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("read TLS key {}", key_path.display()))?;
        let key = PrivateKeyDer::from_pem_slice(&key_pem)
            .with_context(|| format!("parse TLS key {}", key_path.display()))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("TLS cert/key do not match or are unusable")?;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// `serve` over HTTPS (§17): same router, TLS-terminated in-process.
pub async fn serve_tls(
    addr: std::net::SocketAddr,
    token: &str,
    data_dir: &Path,
    lease_ttl_secs: u64,
    tls: ServerTls,
) -> anyhow::Result<()> {
    let state = AppState::new(token, data_dir, lease_ttl_secs)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    serve_listener_tls(listener, state, &tls).await
}

/// `serve_on` over HTTPS (§17): the bind-first variant tests use to learn
/// the ephemeral port before the accept loop starts.
pub async fn serve_on_tls(
    listener: TcpListener,
    token: &str,
    data_dir: &Path,
    lease_ttl_secs: u64,
    tls: ServerTls,
) -> anyhow::Result<()> {
    let state = AppState::new(token, data_dir, lease_ttl_secs)?;
    serve_listener_tls(listener, state, &tls).await
}

/// TLS accept loop (§17): TCP accept → rustls handshake → the same axum
/// router over hyper's HTTP/1, one task per connection. `axum::serve`
/// cannot terminate TLS, so this mirrors its per-connection shape
/// (TowerToHyperService, upgrades on for the §14 WS route). A failed
/// handshake or a broken connection is logged and dropped without
/// disturbing the loop.
async fn serve_listener_tls(
    listener: TcpListener,
    state: AppState,
    tls: &ServerTls,
) -> anyhow::Result<()> {
    spawn_pool_flusher(&state.store);
    spawn_pool_gc(&state);
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.config.clone());
    let router = routes::router(state);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            let service = hyper_util::service::TowerToHyperService::new(router);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}
