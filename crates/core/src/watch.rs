use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use notify::{Event, RecursiveMode, Watcher};

use crate::sync::{sync_cycle, CycleReport};

/// Quiet period after the last filesystem event before a sync cycle runs.
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// Watch `source` recursively and run a sync cycle into `target` after each
/// debounced batch of changes. `on_cycle` fires after every cycle, including
/// the initial one. Runs until the watcher dies (or Ctrl-C kills the process).
pub fn watch_loop<F: FnMut(&CycleReport)>(source: &Path, target: &Path, on_cycle: F) -> Result<()> {
    watch_loop_with(source, |src| sync_cycle(src, target), on_cycle)
}

/// The watch machinery generalized over the cycle it runs: local sync
/// passes `sync_cycle`, the relay writer passes `push_cycle`. The closure
/// receives the canonicalized source path; `on_cycle` fires after every
/// successful cycle, including the initial one.
pub fn watch_loop_with<C, R, F>(source: &Path, mut cycle: C, mut on_cycle: F) -> Result<()>
where
    C: FnMut(&Path) -> Result<R>,
    F: FnMut(&R),
{
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;
    watcher.watch(&source, RecursiveMode::Recursive)?;
    let pear_dir = source.join(".pear");

    // Initial convergence. The watcher is already live, so changes landing
    // during this cycle are queued and trigger a follow-up cycle: no gap.
    // A failure here is retried on the timer like any in-loop failure.
    let mut retry = match cycle(&source) {
        Ok(report) => {
            on_cycle(&report);
            false
        }
        Err(e) => {
            eprintln!("pear: initial sync failed, will retry: {e:#}");
            true
        }
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

        if let Some(first) = first {
            // Coalesce events until quiet, but cap the window: under
            // sustained fs activity (a build writing to `target/`) an
            // uncapped debounce would starve convergence forever.
            let window_start = Instant::now();
            let mut non_pear = !is_pear_only(&first, &pear_dir);
            loop {
                match rx.recv_timeout(DEBOUNCE) {
                    Ok(ev) => non_pear |= !is_pear_only(&ev, &pear_dir),
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
            if !non_pear {
                continue;
            }
        }

        // A transient cycle error (editor temp-then-rename races, a file
        // vanishing mid-scan, an unreadable file) must not kill the
        // watcher; it is retried on the next change or the retry timer,
        // whichever comes first.
        match cycle(&source) {
            Ok(report) => {
                on_cycle(&report);
                retry = false;
            }
            Err(e) => {
                eprintln!("pear: sync cycle failed, will retry: {e:#}");
                retry = true;
            }
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
