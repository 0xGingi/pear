use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use pear_core::watch::watch_loop;
use tempfile::tempdir;

#[test]
fn watch_converges_on_changes() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path().to_path_buf(), b_dir.path().to_path_buf());

    fs::write(a.join("seed.txt"), b"seed\n").unwrap();

    let (src, dst) = (a.clone(), b.clone());
    let watcher = thread::spawn(move || watch_loop(&src, &dst, |_| {}));
    drop(watcher); // detached on purpose; the test process outlives it

    wait_until("initial sync", || {
        fs::read(b.join("seed.txt")).is_ok_and(|c| c == b"seed\n")
    });

    fs::write(a.join("hello.txt"), b"hello one\n").unwrap();
    wait_until("new file appears", || {
        fs::read(b.join("hello.txt")).is_ok_and(|c| c == b"hello one\n")
    });

    // Different length: content must update even if mtimes were coarse.
    fs::write(a.join("hello.txt"), b"hello two, a bit longer\n").unwrap();
    wait_until("edit converges", || {
        fs::read(b.join("hello.txt")).is_ok_and(|c| c == b"hello two, a bit longer\n")
    });
}

fn wait_until<F: FnMut() -> bool>(what: &str, mut cond: F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn watch_survives_transient_cycle_error() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path().to_path_buf(), b_dir.path().to_path_buf());

    fs::write(a.join("seed.txt"), b"seed\n").unwrap();
    let (src, dst) = (a.clone(), b.clone());
    let watcher = thread::spawn(move || watch_loop(&src, &dst, |_| {}));
    drop(watcher); // detached on purpose; the test process outlives it

    wait_until("initial sync", || {
        fs::read(b.join("seed.txt")).is_ok_and(|c| c == b"seed\n")
    });

    fs::write(a.join("locked.txt"), b"v1\n").unwrap();
    wait_until("locked file synced", || {
        fs::read(b.join("locked.txt")).is_ok_and(|c| c == b"v1\n")
    });

    // Make the file unreadable-but-writable, then change it: the next cycle
    // fails mid-chunk, and the watcher must log and live on.
    set_mode(&a.join("locked.txt"), 0o222);
    // Root bypasses permission bits (container CI): the scenario does not
    // apply there.
    if fs::read(a.join("locked.txt")).is_ok() {
        return;
    }
    fs::write(a.join("locked.txt"), b"v2\n").unwrap();
    fs::write(a.join("during.txt"), b"during outage\n").unwrap();
    thread::sleep(Duration::from_millis(1500)); // let the failing cycle happen

    set_mode(&a.join("locked.txt"), 0o644);
    fs::write(a.join("after.txt"), b"after recovery\n").unwrap();
    wait_until("watch recovers and converges", || {
        fs::read(b.join("after.txt")).is_ok_and(|c| c == b"after recovery\n")
            && fs::read(b.join("during.txt")).is_ok_and(|c| c == b"during outage\n")
            && fs::read(b.join("locked.txt")).is_ok_and(|c| c == b"v2\n")
    });
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) {}

#[test]
fn watch_converges_under_sustained_activity() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path().to_path_buf(), b_dir.path().to_path_buf());

    fs::write(a.join("seed.txt"), b"seed\n").unwrap();
    let (src, dst) = (a.clone(), b.clone());
    let watcher = thread::spawn(move || watch_loop(&src, &dst, |_| {}));
    drop(watcher); // detached on purpose; the test process outlives it

    wait_until("initial sync", || {
        fs::read(b.join("seed.txt")).is_ok_and(|c| c == b"seed\n")
    });

    // Sustained event spam in an excluded directory, faster than the
    // debounce: an uncapped coalesce window would starve convergence
    // forever. Real changes must still land.
    let stop = Arc::new(AtomicBool::new(false));
    let spam_dir = a.join("target");
    fs::create_dir_all(&spam_dir).unwrap();
    let spam_stop = stop.clone();
    let spammer = thread::spawn(move || {
        let mut n = 0u64;
        while !spam_stop.load(Ordering::Relaxed) {
            if fs::write(spam_dir.join("spam.log"), format!("{n}\n")).is_err() {
                break;
            }
            n += 1;
            thread::sleep(Duration::from_millis(50));
        }
    });

    fs::write(a.join("real.txt"), b"real change\n").unwrap();
    wait_until("real change converges despite spam", || {
        fs::read(b.join("real.txt")).is_ok_and(|c| c == b"real change\n")
    });
    stop.store(true, Ordering::Relaxed);
    spammer.join().unwrap();
}

#[test]
fn watch_survives_failed_initial_cycle() {
    let a_dir = tempdir().unwrap();
    // Target inside source makes every cycle fail the containment check;
    // the watcher must log and stay alive instead of exiting at startup.
    let inner = a_dir.path().join("inner");
    fs::create_dir_all(&inner).unwrap();

    let (src, dst) = (a_dir.path().to_path_buf(), inner);
    let watcher = thread::spawn(move || watch_loop(&src, &dst, |_| {}));
    thread::sleep(Duration::from_millis(1500));
    assert!(
        !watcher.is_finished(),
        "watcher must survive a failed initial cycle"
    );
}

#[test]
fn watch_exits_when_source_disappears() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path().to_path_buf(), b_dir.path().to_path_buf());

    fs::write(a.join("seed.txt"), b"seed\n").unwrap();
    let (src, dst) = (a.clone(), b.clone());
    // Synchronize on the completed cycle, not on the synced file: a
    // cycle's last write is the SOURCE `.pear/manifest.json`, and
    // `on_cycle` fires only after it landed. Waiting for the file alone
    // races that trailing write.
    let (tx_cycle, rx_cycle) = std::sync::mpsc::channel();
    let watcher = thread::spawn(move || {
        watch_loop(&src, &dst, move |_| {
            let _ = tx_cycle.send(());
        })
    });

    rx_cycle
        .recv_timeout(Duration::from_secs(10))
        .expect("initial cycle must complete");
    assert!(
        fs::read(b.join("seed.txt")).is_ok_and(|c| c == b"seed\n"),
        "the initial cycle converged the seed file"
    );

    // A deleted workspace is not a transient error: the watcher exits
    // loudly instead of failing every cycle against nonexistent paths. A
    // queued event can still trigger one last debounced cycle whose
    // trailing manifest write lands mid-removal — the removal must win,
    // so tolerate the write and retry until the tree is gone.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::remove_dir_all(&a) {
            Ok(()) => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    && Instant::now() < deadline => {}
            Err(e) => panic!("failed to remove the source tree: {e}"),
        }
        thread::sleep(Duration::from_millis(50));
    }
    wait_until("the watcher to exit", || watcher.is_finished());
    let result = watcher.join().expect("watcher thread panicked");
    assert!(
        result.is_err(),
        "the watcher must exit when its source is gone"
    );
}
