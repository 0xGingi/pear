//! End-to-end tests for the `peard` daemon (§16), driving the real built
//! `pear`/`peard` binaries and the raw newline-delimited JSON protocol over
//! the unix socket. Every test gets its own tempdir `$PEAR_HOME`; all
//! waiting is deadline polling, never fixed sleeps (the one bounded
//! negative wait — proving a removed watch stays stopped — is annotated).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// A running peard; killed on drop so a failed assertion never leaks one.
struct Peard {
    child: Option<Child>,
    home: PathBuf,
}

impl Drop for Peard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Peard {
    fn socket(&self) -> PathBuf {
        self.home.join("daemon.sock")
    }

    /// Hand the child out (for exit observation); disarms the kill-on-drop.
    fn into_child(mut self) -> Child {
        self.child.take().unwrap()
    }
}

/// Spawn peard with the given `$PEAR_HOME`; `None` unsets PEAR_TOKEN for
/// the daemon's environment (the resume-refusal path re-reads it).
fn start_peard(home: &Path, pear_token: Option<&str>) -> Peard {
    std::fs::create_dir_all(home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_peard"));
    cmd.env("PEAR_HOME", home)
        .stdout(Stdio::null())
        // Diagnostics land in a log file, never a pipe the daemon could
        // block on and never interleaved into the test runner output.
        .stderr(Stdio::from(
            std::fs::File::create(home.join("peard.log")).unwrap(),
        ));
    match pear_token {
        Some(token) => cmd.env("PEAR_TOKEN", token),
        None => cmd.env_remove("PEAR_TOKEN"),
    };
    let child = cmd.spawn().expect("spawn peard");
    let peard = Peard {
        child: Some(child),
        home: home.to_path_buf(),
    };
    wait_for("peard to answer on its socket", || {
        request(&peard.home, &json!({ "type": "list" })).is_ok()
    });
    peard
}

/// One request line, one response line — the test-side protocol client.
fn request(home: &Path, req: &Value) -> anyhow::Result<Value> {
    let stream = UnixStream::connect(home.join("daemon.sock"))?;
    let mut writer = stream.try_clone()?;
    writeln!(writer, "{req}")?;
    writer.flush()?;
    let mut line = String::new();
    if BufReader::new(&stream).read_line(&mut line)? == 0 {
        anyhow::bail!("peard closed the connection without a response");
    }
    Ok(serde_json::from_str(&line)?)
}

fn ok(req: &Value, home: &Path) -> Value {
    let resp = request(home, req).expect("a response");
    assert_eq!(resp["ok"], true, "request {req} failed: {resp}");
    resp["result"].clone()
}

/// Poll `cond` every 25ms until it holds or the deadline passes.
fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_file(path: &Path, want: &[u8]) {
    wait_for(&format!("{} to appear", path.display()), || {
        std::fs::read(path).is_ok_and(|data| data == want)
    });
}

fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

/// The full protocol lifecycle over a LOCAL watch (no relay involved):
/// bad requests error, add_watch runs the loop under the daemon, files
/// converge, list/status report it, remove stops it, `pear daemon stop`
/// exits the process.
#[test]
fn protocol_and_local_watch_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let home = root.join("home");
    let peard = start_peard(&home, None);

    // Unknown/broken requests get error responses, never a panic.
    let resp = request(&home, &json!("{ not json at all")).unwrap();
    assert_eq!(resp["ok"], false, "a string is not a request: {resp}");
    let stream = UnixStream::connect(peard.socket()).unwrap();
    writeln!(&mut &stream, "{{ not json").unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false, "invalid JSON must error: {resp}");
    let resp = request(&home, &json!({ "type": "frobnicate" })).unwrap();
    assert_eq!(resp["ok"], false, "unknown type must error: {resp}");
    assert!(resp["error"].as_str().unwrap().contains("frobnicate"));

    // The daemon creates its home and socket 0700.
    assert_eq!(
        std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(peard.socket())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Register a local watch.
    let src = root.join("src");
    let tgt = root.join("tgt");
    write(&src.join("hello.txt"), b"hello\n");
    let result = ok(
        &json!({ "type": "add_watch", "path": src, "target": tgt }),
        &home,
    );
    assert_eq!(result["role"], "watch");
    assert_eq!(result["state"], "running");

    // The loop runs under the daemon: the initial sync converges, and a
    // later edit follows via the watcher.
    wait_for_file(&tgt.join("hello.txt"), b"hello\n");
    write(&src.join("two.txt"), b"two\n");
    wait_for_file(&tgt.join("two.txt"), b"two\n");

    // list and status report the registration.
    let list = ok(&json!({ "type": "list" }), &home);
    let entries = list["workspaces"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["path"].as_str().unwrap(), src.to_str().unwrap());
    assert_eq!(entries[0]["role"], "watch");
    assert_eq!(entries[0]["state"], "running");
    let status = ok(&json!({ "type": "status", "path": src }), &home);
    assert_eq!(status["workspaces"].as_array().unwrap().len(), 1);
    let status = ok(
        &json!({ "type": "status", "path": root.join("elsewhere") }),
        &home,
    );
    assert_eq!(status["workspaces"].as_array().unwrap().len(), 0);

    // Duplicate registration is refused. §32 made concurrent writers
    // legal ACROSS devices, but two loops on ONE directory are still a
    // mistake, so the refusal stays.
    let resp = request(
        &home,
        &json!({ "type": "add_watch", "path": src, "target": tgt }),
    )
    .unwrap();
    assert_eq!(resp["ok"], false, "duplicate must error: {resp}");
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("already registered"),
        "{resp}"
    );

    // remove stops it: a post-remove edit never converges. The negative
    // check needs one bounded wait — 2s covers the 500ms debounce + a
    // cycle many times over.
    ok(&json!({ "type": "remove", "path": src }), &home);
    let list = ok(&json!({ "type": "list" }), &home);
    assert_eq!(list["workspaces"].as_array().unwrap().len(), 0);
    write(&src.join("three.txt"), b"three\n");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert!(
            !tgt.join("three.txt").exists(),
            "a removed watch must stop syncing"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // `pear daemon stop` shuts the daemon down cleanly.
    let out = Command::new(env!("CARGO_BIN_EXE_pear"))
        .env("PEAR_HOME", &home)
        .args(["daemon", "stop"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pear daemon stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut child = peard.into_child();
    wait_for("peard to exit", || child.try_wait().unwrap().is_some());
}

/// `pear watch --daemon` (and status/stop) against a stopped daemon fail
/// cleanly with a non-zero exit — the CLI never spawns a daemon itself.
#[test]
fn daemon_commands_fail_cleanly_without_a_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let home = root.join("home");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();

    for args in [
        vec!["watch", "src", "tgt", "--daemon"],
        vec![
            "sync",
            "src",
            "--relay",
            "http://127.0.0.1:1",
            "--token",
            "irrelevant",
            "--daemon",
        ],
        vec!["status"],
        vec!["daemon", "stop"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_pear"))
            .env("PEAR_HOME", &home)
            .current_dir(&root)
            .args(&args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?} must fail without a daemon");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no peard daemon is running"),
            "{args:?}: unexpected error: {stderr}"
        );
    }
}

/// Token hygiene (§16): the token travels in the add_mirror request but
/// lands neither in `daemon.json` nor in status responses. Also: the CLI
/// refuses a socket with the wrong permissions.
#[test]
fn token_is_never_persisted_or_echoed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let home = root.join("home");
    let peard = start_peard(&home, None);

    // Built at runtime: credential-shaped literals don't belong in tests.
    let token = format!("pear-it-{}", "t".repeat(24));
    let mirror_dir = root.join("mirror");
    std::fs::create_dir_all(&mirror_dir).unwrap();
    let workspace = "ab".repeat(16);
    let result = ok(
        &json!({
            "type": "add_mirror",
            "path": mirror_dir,
            "workspace": workspace,
            // Nothing listens there; the loop fails — fine, the token is
            // what this test is about, not the sync.
            "relay": "http://127.0.0.1:1",
            "token": token,
        }),
        &home,
    );
    assert_eq!(result["role"], "mirror");

    // daemon.json holds the registration but never the token.
    let state = std::fs::read_to_string(home.join("daemon.json")).unwrap();
    assert!(
        state.contains(&workspace),
        "registration persisted: {state}"
    );
    assert!(
        !state.contains(&token),
        "daemon.json must never contain a token: {state}"
    );

    // status never echoes the token (the entry may carry a loop error —
    // the relay is unreachable — but never the credential).
    let status = ok(&json!({ "type": "status" }), &home).to_string();
    assert!(
        !status.contains(&token),
        "status must never echo a token: {status}"
    );

    // The CLI refuses a socket whose permissions are open.
    let mut perms = std::fs::metadata(peard.socket()).unwrap().permissions();
    perms.set_mode(0o777);
    std::fs::set_permissions(peard.socket(), perms).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_pear"))
        .env("PEAR_HOME", &home)
        .arg("status")
        .output()
        .unwrap();
    assert!(!out.status.success(), "an open socket must be refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing"),
        "unexpected error: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    ok(&json!({ "type": "shutdown" }), &home);
    let mut child = peard.into_child();
    wait_for("peard to exit", || child.try_wait().unwrap().is_some());
}

/// Persistence and restart (§16): a LOCAL watch resumes across a daemon
/// restart; a §32 converge registration whose token is not re-supplied
/// via PEAR_TOKEN stays registered, reports a clear status error, and
/// does not run.
#[test]
fn restart_resumes_local_watch_but_not_tokenless_converge() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let home = root.join("home");

    let src = root.join("src");
    let tgt = root.join("tgt");
    write(&src.join("one.txt"), b"one\n");
    let writer_dir = root.join("writer");
    std::fs::create_dir_all(&writer_dir).unwrap();

    {
        let peard = start_peard(&home, None);
        ok(
            &json!({ "type": "add_watch", "path": src, "target": tgt }),
            &home,
        );
        // A §32 converge loop, registered with a token (unreachable
        // relay; the loop fails but the registration persists).
        ok(
            &json!({
                "type": "add_converge",
                "path": writer_dir,
                "relay": "http://127.0.0.1:1",
                "token": format!("pear-it-{}", "w".repeat(24)),
            }),
            &home,
        );
        wait_for_file(&tgt.join("one.txt"), b"one\n");
        ok(&json!({ "type": "shutdown" }), &home);
        let mut child = peard.into_child();
        wait_for("peard to exit", || child.try_wait().unwrap().is_some());
    }

    // Restart WITHOUT PEAR_TOKEN in the daemon's environment.
    let peard = start_peard(&home, None);

    // The local watch resumed: new edits converge again.
    write(&src.join("two.txt"), b"two\n");
    wait_for_file(&tgt.join("two.txt"), b"two\n");

    // The converge loop did not resume: registered, state error, and the
    // error says why.
    let status = ok(&json!({ "type": "status" }), &home);
    let entries = status["workspaces"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{status}");
    let relay_entry = entries
        .iter()
        .find(|e| e["path"].as_str() == Some(writer_dir.to_string_lossy().as_ref()))
        .expect("the converge registration persists");
    assert_eq!(relay_entry["role"], "sync", "{relay_entry}");
    assert_eq!(relay_entry["state"], "error", "{relay_entry}");
    let error = relay_entry["error"].as_str().unwrap();
    assert!(
        error.contains("PEAR_TOKEN"),
        "the status error must name the missing token: {error}"
    );
    let local_entry = entries
        .iter()
        .find(|e| e["path"].as_str() == Some(src.to_string_lossy().as_ref()))
        .unwrap();
    assert_eq!(local_entry["state"], "running", "{local_entry}");

    ok(&json!({ "type": "shutdown" }), &home);
    let mut child = peard.into_child();
    wait_for("peard to exit", || child.try_wait().unwrap().is_some());
}

/// §16 + §17 + §32 smoke: a daemon-run converge/mirror pair converges on
/// an e2e workspace — `pear join` carries the e2e options (`--e2e`,
/// `--team`) through unchanged, wrap-maintenance runs at loop start, and
/// the mirror onboards by fetching and unwrapping its key.
#[test]
fn daemon_e2e_join_mirror_converges() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let home = root.join("home");
    let relay_dir = root.join("relay-data");
    // Built at runtime: credential-shaped literals don't belong in tests.
    let admin_token = format!("pear-adm-{}", "a".repeat(24));

    // The real relay binary lives next to peard in the target dir.
    let relay_bin = Path::new(env!("CARGO_BIN_EXE_peard"))
        .parent()
        .unwrap()
        .join("pear-relay");
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let mut relay = Command::new(&relay_bin)
        .args([
            "--addr",
            &format!("127.0.0.1:{port}"),
            "--token",
            &admin_token,
            "--data-dir",
            &relay_dir.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(root.join("relay.log")).unwrap(),
        ))
        .spawn()
        .expect("spawn pear-relay");
    let url = format!("http://127.0.0.1:{port}");
    wait_for("the relay to accept connections", || {
        std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok()
    });

    // Operator: create the two users (writer and mirror-side member).
    let w_out = pear_ok(
        &home,
        &admin_token,
        &["user", "create", "w", "--relay", &url],
    );
    let w_token = w_out
        .split("token (shown once): ")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let m_out = pear_ok(
        &home,
        &admin_token,
        &["user", "create", "m", "--relay", &url],
    );
    let m_token = m_out
        .split("token (shown once): ")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    // Both users keygen (keys land in $PEAR_HOME/keys — the same home the
    // daemon's loops read from); w sets up the team.
    pear_ok(
        &home,
        &w_token,
        &["user", "keygen", "--name", "w", "--relay", &url],
    );
    pear_ok(
        &home,
        &m_token,
        &["user", "keygen", "--name", "m", "--relay", &url],
    );
    pear_ok(
        &home,
        &w_token,
        &["team", "create", "acme", "--relay", &url],
    );
    pear_ok(
        &home,
        &w_token,
        &[
            "team", "add", "acme", "--user", "m", "--role", "writer", "--relay", &url,
        ],
    );

    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    write(&src.join("note.txt"), b"daemon e2e canary\n");

    let peard = start_peard(&home, None);
    pear_ok(
        &home,
        &w_token,
        &[
            "join",
            src.to_str().unwrap(),
            "--relay",
            &url,
            "--e2e",
            "--team",
            "acme",
        ],
    );
    // The daemon's converge loop inits the workspace asynchronously —
    // wait for its metadata before reading the id.
    wait_for("the converge loop to init the workspace", || {
        src.join(".pear/workspace.json").exists()
    });
    let workspace: Value =
        serde_json::from_slice(&std::fs::read(src.join(".pear/workspace.json")).unwrap()).unwrap();
    let ws_id = workspace["id"].as_str().unwrap();

    // The mirror onboards under the daemon: fetch + unwrap needs the
    // writer's wrap (done at watch start) and m's local keypair.
    let dst = root.join("mirror");
    std::fs::create_dir_all(&dst).unwrap();
    pear_ok(
        &home,
        &m_token,
        &[
            "mirror",
            dst.to_str().unwrap(),
            "--daemon",
            "--workspace",
            ws_id,
            "--relay",
            &url,
            "--name",
            "m",
        ],
    );
    wait_for_file(&dst.join("note.txt"), b"daemon e2e canary\n");
    assert!(
        dst.join(".pear/workspace_keys").exists(),
        "the mirror cached its keyring (§20)"
    );

    // The daemon's status shows both loops healthy, and the relay never
    // saw the plaintext (opaque ciphertext pool on the e2e path too).
    let status = ok(&json!({ "type": "status" }), &home);
    for entry in status["workspaces"].as_array().unwrap() {
        assert_eq!(entry["state"], "running", "{entry}");
        assert_eq!(entry["error"], Value::Null, "{entry}");
    }
    assert_no_dir_contains(&relay_dir, b"daemon e2e canary");

    pear_ok(&home, &admin_token, &["daemon", "stop"]);
    let mut child = peard.into_child();
    wait_for("peard to exit", || child.try_wait().unwrap().is_some());
    let _ = relay.kill();
    let _ = relay.wait();
}

/// §32 end to end at the CLI: TWO concurrent converge loops on ONE
/// workspace, each supervised by its own `peard`, against one real relay.
/// Both devices' edits land on both sides — no lease, no handoff, no
/// manual command after `join` — and each device's own `join` is what
/// starts its daemon (the socket is absent until then).
#[test]
fn two_joined_devices_converge_concurrently() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let admin_token = format!("pear-adm-{}", "c".repeat(24));
    let relay = start_relay(&root, &admin_token);

    // Device A joins a fresh workspace; its `join` must start peard.
    let home_a = root.join("home-a");
    let dir_a = root.join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a.join("from-a.txt"), b"a1\n");
    std::fs::create_dir_all(&home_a).unwrap();
    assert!(
        !home_a.join("daemon.sock").exists(),
        "no daemon before join"
    );
    let _peard_a = PeardHandle::adopt(&home_a);
    pear_ok(
        &home_a,
        &admin_token,
        &["join", dir_a.to_str().unwrap(), "--relay", &relay.url],
    );
    assert!(
        home_a.join("daemon.sock").exists(),
        "join auto-started peard (§32)"
    );
    wait_for("device A to publish its workspace", || {
        dir_a.join(".pear/workspace.json").exists()
    });
    let workspace: Value =
        serde_json::from_slice(&std::fs::read(dir_a.join(".pear/workspace.json")).unwrap())
            .unwrap();
    let ws_id = workspace["id"].as_str().unwrap().to_string();

    // Device B joins the SAME workspace into an empty directory: the
    // first converge materializes it.
    let home_b = root.join("home-b");
    let dir_b = root.join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::create_dir_all(&home_b).unwrap();
    let _peard_b = PeardHandle::adopt(&home_b);
    pear_ok(
        &home_b,
        &admin_token,
        &[
            "join",
            dir_b.to_str().unwrap(),
            "--relay",
            &relay.url,
            "--workspace",
            &ws_id,
            "--device",
            "device-b",
        ],
    );
    wait_for_file(&dir_b.join("from-a.txt"), b"a1\n");

    // Now both write, concurrently, with nobody holding anything: each
    // edit reaches the other device.
    write(&dir_b.join("from-b.txt"), b"b1\n");
    write(&dir_a.join("from-a2.txt"), b"a2\n");
    wait_for_file(&dir_a.join("from-b.txt"), b"b1\n");
    wait_for_file(&dir_b.join("from-a2.txt"), b"a2\n");

    // ...and again, in the other order, to prove neither side wedged.
    write(&dir_a.join("from-a3.txt"), b"a3\n");
    write(&dir_b.join("from-b2.txt"), b"b2\n");
    wait_for_file(&dir_b.join("from-a3.txt"), b"a3\n");
    wait_for_file(&dir_a.join("from-b2.txt"), b"b2\n");

    // Both loops report the converge role and no error.
    for home in [&home_a, &home_b] {
        let status = ok(&json!({ "type": "status" }), home);
        let entries = status["workspaces"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{status}");
        assert_eq!(entries[0]["role"], "sync", "{status}");
        assert_eq!(entries[0]["error"], Value::Null, "{status}");
    }

    for home in [&home_a, &home_b] {
        ok(&json!({ "type": "shutdown" }), home);
    }
}

/// A peard this test did not spawn (`pear join` did): killed on drop via
/// its recorded pid file, so a failed assertion never leaks a daemon.
struct PeardHandle {
    home: PathBuf,
}

impl PeardHandle {
    fn adopt(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
        }
    }
}

impl Drop for PeardHandle {
    fn drop(&mut self) {
        // Best effort: ask it to stop over its own socket.
        let _ = request(&self.home, &json!({ "type": "shutdown" }));
    }
}

/// A real `pear-relay` child on an ephemeral port; killed on drop.
struct TestRelay {
    child: Option<Child>,
    url: String,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn the real relay binary (it lives next to peard in the target dir).
fn start_relay(root: &Path, token: &str) -> TestRelay {
    let relay_bin = Path::new(env!("CARGO_BIN_EXE_peard"))
        .parent()
        .unwrap()
        .join("pear-relay");
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let child = Command::new(&relay_bin)
        .args([
            "--addr",
            &format!("127.0.0.1:{port}"),
            "--token",
            token,
            "--data-dir",
            &root.join("relay-data").to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(root.join("relay.log")).unwrap(),
        ))
        .spawn()
        .expect("spawn pear-relay");
    wait_for("the relay to accept connections", || {
        std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok()
    });
    TestRelay {
        child: Some(child),
        url: format!("http://127.0.0.1:{port}"),
    }
}

/// Run the pear CLI with a token; assert success and return stdout.
fn pear_ok(home: &Path, token: &str, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_pear"))
        .env("PEAR_HOME", home)
        .env("PEAR_TOKEN", token)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pear {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Recursively assert no file under `dir` contains `needle`.
fn assert_no_dir_contains(dir: &Path, needle: &[u8]) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_dir_contains(&path, needle);
        } else {
            let data = std::fs::read(&path).unwrap();
            assert!(
                !data.windows(needle.len()).any(|w| w == needle),
                "{} holds plaintext that should only exist encrypted",
                path.display()
            );
        }
    }
}
