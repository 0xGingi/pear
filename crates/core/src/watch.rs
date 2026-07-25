//! The filesystem watch machinery: a debounced notify loop that drives a
//! cycle closure, plus (§32) an optional external trigger channel so a
//! converge loop can also be woken by relay head hints and its poll
//! fallback.

use std::path::Path;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use notify::{Event, RecursiveMode, Watcher};

use crate::sync::{sync_cycle, CycleReport};

/// Quiet period after the last filesystem event before a sync cycle runs.
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// What woke the loop. Filesystem events are debounced (an editor writes a
/// file many times in a burst); an external kick is NOT — it is already a
/// coalesced signal from somewhere else (§32: a relay head hint or a poll
/// tick), and a remote change has no local write storm to wait out.
enum Trigger {
    Fs(notify::Result<Event>),
    External,
}

/// The sending half of a [`watch_loop_with_kicks`] trigger channel. Every
/// send asks for one cycle; sends that arrive while a cycle is running
/// coalesce into the single follow-up cycle after it.
pub type Kick = Sender<()>;

/// A cycle error that ENDS the loop instead of being retried on the timer.
/// Ordinary cycle failures are transient by assumption (editor rename
/// races, a flaky relay) and retry forever; a cycle that has decided the
/// loop can never succeed again wraps its error in this and the loop
/// returns it unchanged. §32 uses it for the reader demotion: a converge
/// that learns this device has no Writer role stops converging so the
/// caller can hand the run to the mirror loop.
#[derive(Debug)]
pub struct StopWatching(pub anyhow::Error);

impl std::fmt::Display for StopWatching {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for StopWatching {}

/// Watch `source` recursively and run a sync cycle into `target` after each
/// debounced batch of changes. `on_cycle` fires after every cycle, including
/// the initial one. Runs until the watcher dies (or Ctrl-C kills the process).
pub fn watch_loop<F: FnMut(&CycleReport)>(source: &Path, target: &Path, on_cycle: F) -> Result<()> {
    watch_loop_with(source, |src| sync_cycle(src, target), on_cycle)
}

/// The watch machinery generalized over the cycle it runs: local sync
/// passes `sync_cycle`, the §32 converge loop passes `converge_once`. The
/// closure receives the canonicalized source path; `on_cycle` fires after
/// every successful cycle, including the initial one.
pub fn watch_loop_with<C, R, F>(source: &Path, cycle: C, on_cycle: F) -> Result<()>
where
    C: FnMut(&Path) -> Result<R>,
    F: FnMut(&R),
{
    watch_loop_with_kicks(source, None, cycle, on_cycle)
}

/// [`watch_loop_with`] plus a second, non-filesystem trigger source (§32).
///
/// A converge loop is driven by three triggers that all funnel into the
/// same cycle: local FS events (debounced here as always), relay head
/// hints, and a poll fallback. The last two live in the caller's companion
/// thread, which sends `()` on `kicks` whenever it wants a converge; this
/// loop treats such a kick as an immediate cycle request — no debounce
/// window, because there is no local write burst to wait out.
///
/// Kicks that arrive while a cycle is running stay queued and produce
/// exactly one follow-up cycle (the channel is drained down to a single
/// pending request before each cycle), so a hint storm cannot make the
/// device converge in a tight loop.
pub fn watch_loop_with_kicks<C, R, F>(
    source: &Path,
    kicks: Option<Receiver<()>>,
    mut cycle: C,
    mut on_cycle: F,
) -> Result<()>
where
    C: FnMut(&Path) -> Result<R>,
    F: FnMut(&R),
{
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;

    let (tx, rx) = channel::<Trigger>();
    let fs_tx = tx.clone();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = fs_tx.send(Trigger::Fs(res));
    })?;
    watcher.watch(&source, RecursiveMode::Recursive)?;
    // Forward the caller's kicks into the one trigger channel, so the loop
    // below waits on a single receiver. The thread ends when the caller
    // drops its `Kick` sender; `tx` itself is kept alive by the watcher.
    if let Some(kicks) = kicks {
        std::thread::spawn(move || {
            while kicks.recv().is_ok() {
                if tx.send(Trigger::External).is_err() {
                    return;
                }
            }
        });
    }
    let pear_dir = source.join(".pear");

    // Initial convergence. The watcher is already live, so changes landing
    // during this cycle are queued and trigger a follow-up cycle: no gap.
    // A failure here is retried on the timer like any in-loop failure.
    let mut retry = match cycle(&source) {
        Ok(report) => {
            on_cycle(&report);
            false
        }
        Err(e) => match e.downcast::<StopWatching>() {
            Ok(stop) => return Err(stop.0),
            Err(e) => {
                eprintln!("pear: initial sync failed, will retry: {e:#}");
                true
            }
        },
    };
    loop {
        // A deleted source is not a transient error: the workspace is
        // gone, so exit loudly instead of failing every cycle forever
        // (a detached watcher must not spin against nonexistent paths).
        if !source.is_dir() {
            return Err(anyhow!(
                "source {} no longer exists; watcher exiting",
                source.display()
            ));
        }
        // After a failed cycle, retry on a timer even when the workspace
        // is quiet — a transient failure must not stall convergence until
        // the next edit (possibly forever).
        let first = if retry {
            match rx.recv_timeout(RETRY_AFTER) {
                Ok(ev) => Some(ev),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(anyhow!("watcher disconnected"));
                }
            }
        } else {
            Some(
                rx.recv()
                    .map_err(|_| anyhow!("watcher channel closed unexpectedly"))?,
            )
        };

        if let Some(Trigger::Fs(first)) = first {
            // Coalesce events until quiet, but cap the window: under
            // sustained fs activity (a build writing to `target/`) an
            // uncapped debounce would starve convergence forever.
            let window_start = Instant::now();
            let mut wanted = !is_pear_only(&first, &pear_dir);
            loop {
                match rx.recv_timeout(DEBOUNCE) {
                    Ok(Trigger::Fs(ev)) => wanted |= !is_pear_only(&ev, &pear_dir),
                    // An external kick inside the window is a real cycle
                    // request; it rides out the rest of the debounce
                    // rather than racing the in-flight write burst.
                    Ok(Trigger::External) => wanted = true,
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(anyhow!("watcher disconnected"));
                    }
                }
                if window_start.elapsed() >= MAX_COALESCE {
                    break;
                }
            }
            // Our own manifest write must not trigger another cycle.
            if !wanted {
                continue;
            }
        }
        // Every trigger already queued is covered by the cycle below: it
        // re-scans the tree and re-reads the head after this point.
        // Collapse them so a hint storm cannot spin the loop. Triggers
        // that arrive DURING the cycle stay queued and drive the
        // follow-up — that is the no-gap guarantee, and it is unchanged.
        while rx.try_recv().is_ok() {}

        // A transient cycle error (editor temp-then-rename races, a file
        // vanishing mid-scan, an unreadable file) must not kill the
        // watcher; it is retried on the next change or the retry timer,
        // whichever comes first.
        match cycle(&source) {
            Ok(report) => {
                on_cycle(&report);
                retry = false;
            }
            Err(e) => match e.downcast::<StopWatching>() {
                Ok(stop) => return Err(stop.0),
                Err(e) => {
                    eprintln!("pear: sync cycle failed, will retry: {e:#}");
                    retry = true;
                }
            },
        }
    }
}

/// Longest we keep coalescing events before running a cycle despite
/// ongoing fs activity.
const MAX_COALESCE: Duration = Duration::from_secs(2);

/// How long after a failed cycle we retry even without filesystem events:
/// a quiet workspace must not leave a transient failure unconverged.
#[cfg(not(test))]
const RETRY_AFTER: Duration = Duration::from_secs(5);
#[cfg(test)]
const RETRY_AFTER: Duration = Duration::from_millis(200);

fn is_pear_only(res: &notify::Result<Event>, pear_dir: &Path) -> bool {
    // Empty paths are rescan/overflow-style notifications ("you may have
    // missed changes") and must always trigger a cycle.
    matches!(res, Ok(ev) if !ev.paths.is_empty() && ev.paths.iter().all(|p| p.starts_with(pear_dir)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn event_with_paths(paths: Vec<PathBuf>) -> notify::Result<Event> {
        let mut ev = Event::new(notify::event::EventKind::Other);
        ev.paths = paths;
        Ok(ev)
    }

    #[test]
    fn empty_path_events_trigger_cycles() {
        let pear = Path::new("/ws/.pear");
        // Rescan/overflow notifications have no paths: never pear-only.
        assert!(!is_pear_only(&event_with_paths(vec![]), pear));
        // Events entirely under .pear are our own writes: skip them.
        assert!(is_pear_only(
            &event_with_paths(vec![pear.join("manifest.json")]),
            pear
        ));
        // Anything else triggers a cycle.
        assert!(!is_pear_only(
            &event_with_paths(vec![PathBuf::from("/ws/src/main.rs")]),
            pear
        ));
        // Errors trigger a cycle.
        assert!(!is_pear_only(&Err(notify::Error::generic("boom")), pear));
    }

    /// §32: a kick on the external channel runs a cycle with no
    /// filesystem event at all, and without waiting out the FS debounce.
    #[test]
    fn external_kicks_drive_cycles_without_filesystem_events() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().to_path_buf();
        let (kick_tx, kick_rx) = std::sync::mpsc::channel::<()>();
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let cycles = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = cycles.clone();
        std::thread::spawn(move || {
            let _ = watch_loop_with_kicks(
                &src,
                Some(kick_rx),
                move |_path| Ok(counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst)),
                move |report: &u32| {
                    let _ = tx_done.send(*report);
                },
            );
        });
        // The initial cycle, then one per kick — nothing ever touches the
        // watched directory.
        assert_eq!(rx_done.recv_timeout(Duration::from_secs(10)).unwrap(), 0);
        for expected in 1..=3 {
            kick_tx.send(()).unwrap();
            assert_eq!(
                rx_done.recv_timeout(Duration::from_secs(10)).unwrap(),
                expected,
                "a kick must drive a cycle with no fs event"
            );
        }
    }

    #[test]
    fn failed_cycles_retry_on_a_timer_without_events() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().to_path_buf();
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempts2 = attempts.clone();
        std::thread::spawn(move || {
            let _ = watch_loop_with(
                &src,
                move |_path| {
                    let n = attempts2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n < 2 {
                        Err(anyhow::anyhow!("injected transient failure"))
                    } else {
                        Ok(n)
                    }
                },
                move |report: &u32| {
                    let _ = tx_done.send(*report);
                },
            );
        });
        // No filesystem events at all: the retry timer must drive the
        // recovery on its own.
        let report = rx_done
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the failed cycle must be retried on the timer");
        assert_eq!(report, 2);
    }
}
