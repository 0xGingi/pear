//! End-to-end: pear-core converge/writer/mirror flows against a real
//! pear-relay server (§11). Covers push/pull convergence (including `.env`
//! and `.git`) and the §32 multi-writer contract: two concurrent converge
//! loops against one relay, CAS conflicts, and conflict copies.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use pear_core::relay::{RelayClient, RelayError};
use pear_core::sync::{pull_once, push_cycle, PushError};

const TOKEN: &str = "e2e-token";

/// Spawn the relay on an ephemeral port; return its base URL.
async fn start_relay(data_dir: &Path) -> String {
    // Bind first and pass the listener: no bind-then-drop port race.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = data_dir.to_path_buf();
    tokio::spawn(async move {
        pear_relay::serve_on(listener, TOKEN, &dir)
            .await
            .expect("relay serve failed");
    });
    format!("http://{addr}")
}

/// Wait until the relay answers. Probe on a throwaway id: probing with
/// the test's real workspace id would register it under the name "probe"
/// before the test's own create (a trap `team_onboarding_flow` worked
/// around locally until now).
async fn wait_ready(url: &str) {
    let probe = RelayClient::new(
        url,
        TOKEN,
        &format!("wait-ready-{}", std::process::id()),
        "probe",
    );
    for _ in 0..100 {
        if probe.create_workspace("probe").is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay did not come up");
}

fn write(dir: &Path, rel: &str, data: &[u8]) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

/// Recursive rel-path -> bytes map of a workspace, excluding `.pear`.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".pear" {
            continue;
        }
        if path.is_dir() {
            for (rel, data) in tree(&path) {
                out.insert(format!("{name}/{rel}"), data);
            }
        } else {
            out.insert(name, std::fs::read(&path).unwrap());
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_push_mirror_pull_converges() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    // Writer dir A, including the files that define the product: `.env`
    // and `.git` contents sync.
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, ".git/HEAD", b"ref: refs/heads/main\n");
    write(&dir_a, "README.md", b"# demo\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();

    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert!(pushed.committed);
    assert_eq!(pushed.head_seq, 1);

    // Mirror dir B: init with the remote workspace id, pull -> converged.
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(
        std::fs::read(dir_b.join(".env")).unwrap(),
        b"SECRET=hunter2\n"
    );
    assert_eq!(
        std::fs::read(dir_b.join(".git/HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );

    // Edit -> push -> pull -> converged.
    write(&dir_a, "src/main.rs", b"fn main() { println!(\"hi\"); }\n");
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert!(pushed.committed);
    assert_eq!(pushed.head_seq, 2);
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // Delete -> push -> pull -> converged.
    std::fs::remove_file(dir_a.join("README.md")).unwrap();
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert_eq!(pushed.deleted, vec!["README.md".to_string()]);
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert_eq!(pulled.deleted, vec!["README.md".to_string()]);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // Seq unchanged: the mirror idles.
    assert!(!pull_once(&dir_b, &mirror).unwrap().changed);
}



/// M3 end-to-end (§12): snapshot -> clone (forked lineage, byte-identical
/// tree), all through the real client and relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_and_clone_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    // Writer pushes a tree, including `.env` and `.git` contents.
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, ".git/HEAD", b"ref: refs/heads/main\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // Named snapshot of the synced tree via the real client.
    let head_manifest = pear_core::manifest::load(&dir_a.join(".pear/manifest.json"))
        .unwrap()
        .unwrap();
    let commit = writer
        .create_snapshot(Some("release candidate"), &head_manifest)
        .unwrap();
    assert_eq!(commit.id, 1);

    // Clone it into a fresh directory: byte-identical tree, forked lineage,
    // provenance in origin.json.
    let cloner = RelayClient::new(&url, TOKEN, &meta.id, "device-c");
    let dir_b = tmp.path().join("b");
    let clone = pear_core::snapshot::clone_from_snapshot(&dir_b, &cloner, commit.id).unwrap();
    assert_ne!(clone.workspace_id, meta.id, "forked lineage");
    assert_eq!(clone.files_written, 3);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(
        std::fs::read(dir_b.join(".env")).unwrap(),
        b"SECRET=hunter2\n"
    );
    assert_eq!(
        std::fs::read(dir_b.join(".git/HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );
    let origin: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir_b.join(".pear/origin.json")).unwrap()).unwrap();
    assert_eq!(origin["workspace_id"].as_str().unwrap(), meta.id);
    assert_eq!(origin["snapshot_id"].as_u64().unwrap(), 1);
    assert_eq!(origin["name"].as_str().unwrap(), "release candidate");

    // `pear snapshot` on unsynced state: the full writer pipeline against
    // the real relay, without moving the head.
    write(&dir_a, "wip.txt", b"unsynced work\n");
    let snap = pear_core::snapshot::push_snapshot(&dir_a, &writer, Some("wip")).unwrap();
    assert_eq!(snap.id, 2);
    assert_eq!(writer.get_head().unwrap().unwrap().seq, 1, "head unmoved");

    // Both snapshots are listed newest-first, named, and attributed.
    let snapshots = writer.list_snapshots().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].kind, "named", "newest first");
    assert_eq!(snapshots[0].device, "device-a");
    assert_eq!(snapshots[0].name.as_deref(), Some("wip"));
    assert_eq!(snapshots[1].name.as_deref(), Some("release candidate"));

    // The head-synced snapshot preserves the head manifest exactly;
    // cloning IT yields the synced tree (no wip.txt).
    let released = writer.get_snapshot(snapshots[1].id).unwrap();
    assert_eq!(released.manifest, head_manifest);
    let dir_c = tmp.path().join("c");
    pear_core::snapshot::clone_from_snapshot(&dir_c, &cloner, snapshots[1].id).unwrap();
    assert!(!dir_c.join("wip.txt").exists());
    assert_eq!(
        std::fs::read(dir_c.join("src/main.rs")).unwrap(),
        b"fn main() {}\n"
    );
}

/// §32 reader fallback, at the trigger: a device with only the Reader
/// role converges into a typed `Forbidden`, which is what makes the
/// converge loop log once and degrade to a read-only mirror instead of
/// dying. A Writer on the same workspace converges normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_converge_is_forbidden_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;
    wait_ready(&url).await;

    let admin = RelayClient::unbound(&url, TOKEN, "operator");
    let owner_tok = admin.create_user("owner").unwrap().token;
    let rita_tok = admin.create_user("rita").unwrap().token;
    let owner_admin = RelayClient::unbound(&url, &owner_tok, "owner-laptop");
    let acme = owner_admin.create_team("acme").unwrap();
    owner_admin
        .team_add_member(&acme.id, "rita", "reader")
        .unwrap();

    // The owner converges a tree into a fresh team workspace.
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let owner = RelayClient::new(&url, &owner_tok, &meta.id, "owner-laptop");
    owner.create_workspace_with_team("api", Some(&acme.id)).unwrap();
    let report = pear_core::converge::converge_once(&dir_a, &owner, "owner-laptop", None).unwrap();
    assert!(report.pushed);

    // Rita reads the workspace fine, but converging it is Forbidden — the
    // one error the loop answers by becoming a mirror.
    let dir_r = tmp.path().join("rita");
    std::fs::create_dir_all(&dir_r).unwrap();
    pear_core::init_workspace(&dir_r, Some(&meta.id)).unwrap();
    let rita = RelayClient::new(&url, &rita_tok, &meta.id, "rita-laptop");
    assert!(rita.get_workspace().is_ok(), "a reader can read");
    write(&dir_r, "rita.txt", b"reader edit\n");
    let err = pear_core::converge::converge_once(&dir_r, &rita, "rita-laptop", None).unwrap_err();
    assert!(
        matches!(err, PushError::Forbidden(_)),
        "a reader's converge must be Forbidden (§32 mirror fallback), got {err:?}"
    );
    // The converge got as far as MATERIALIZING the remote side before the
    // relay refused her upload — a reader already ends up with the head
    // on disk — and her own edit is untouched.
    assert_eq!(std::fs::read(dir_r.join("f.txt")).unwrap(), b"v1\n");
    assert_eq!(
        std::fs::read(dir_r.join("rita.txt")).unwrap(),
        b"reader edit\n"
    );
    // ...and the read-only loop she falls back to picks up from there:
    // the next writer commit lands for her.
    write(&dir_a, "f.txt", b"v2\n");
    pear_core::converge::converge_once(&dir_a, &owner, "owner-laptop", None).unwrap();
    assert!(pull_once(&dir_r, &rita).unwrap().changed);
    assert_eq!(std::fs::read(dir_r.join("f.txt")).unwrap(), b"v2\n");
}

/// M4 end-to-end (§13): the onboarding flow against the real relay. Admin
/// creates users; the team owner creates team + workspace and pushes; a
/// teammate mirrors by `team/name` with her own token; a reader reads but
/// cannot push; a non-member cannot even see the workspace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_onboarding_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    // 1. Operator (admin token): create the users. Tokens come back once.
    let admin = RelayClient::unbound(&url, TOKEN, "operator");
    let owner_tok = admin.create_user("owner").unwrap().token;
    let jane_tok = admin.create_user("jane").unwrap().token;
    let rita_tok = admin.create_user("rita").unwrap().token;
    let nate_tok = admin.create_user("nate").unwrap().token;

    // 2. Owner: create team acme; jane is a writer, rita a reader. Nate
    // stays outside the team.
    let owner_admin = RelayClient::unbound(&url, &owner_tok, "owner-laptop");
    let acme = owner_admin.create_team("acme").unwrap();
    owner_admin
        .team_add_member(&acme.id, "jane", "writer")
        .unwrap();
    owner_admin
        .team_add_member(&acme.id, "rita", "reader")
        .unwrap();

    // Owner pushes the api workspace (attached at register), `.env`
    // included.
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, "README.md", b"# api\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    // Readiness probe on a throwaway id: probing with the real workspace id
    // would register it (name "probe", unattached) before the create below.
    wait_ready(&url).await;
    let owner = RelayClient::new(&url, &owner_tok, &meta.id, "owner-laptop");
    owner
        .create_workspace_with_team("api", Some(&acme.id))
        .unwrap();
    let pushed = push_cycle(&dir_a, &owner, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // 3. Jane onboards with HER token: resolve acme/api (she never sees
    // the workspace id), adopt it, pull once — byte-identical tree.
    let jane_admin = RelayClient::unbound(&url, &jane_tok, "jane-laptop");
    let resolved = jane_admin.resolve_workspace("acme", "api").unwrap();
    assert_eq!(resolved.id, meta.id);
    assert_eq!(resolved.head_seq, 1);
    let dir_j = tmp.path().join("jane");
    pear_core::init_workspace(&dir_j, Some(&resolved.id)).unwrap();
    let jane = RelayClient::new(&url, &jane_tok, &resolved.id, "jane-laptop");
    let pulled = pull_once(&dir_j, &jane).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_j));
    assert_eq!(
        std::fs::read(dir_j.join(".env")).unwrap(),
        b"SECRET=hunter2\n"
    );

    // 4. Rita (reader) resolves and mirrors fine...
    let rita_admin = RelayClient::unbound(&url, &rita_tok, "rita-laptop");
    let resolved_rita = rita_admin.resolve_workspace("acme", "api").unwrap();
    let dir_r = tmp.path().join("rita");
    pear_core::init_workspace(&dir_r, Some(&resolved_rita.id)).unwrap();
    let rita = RelayClient::new(&url, &rita_tok, &resolved_rita.id, "rita-laptop");
    let pulled = pull_once(&dir_r, &rita).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_r));
    // ...but cannot push: chunks, head, and snapshots are all 403.
    let data = b"reader write attempt";
    let hash = blake3::hash(data).to_hex().to_string();
    let err = rita.put_chunk(&hash, data).unwrap_err();
    assert!(
        matches!(err, RelayError::Http { status: 403, .. }),
        "reader put_chunk: {err:?}"
    );
    let manifest = pear_core::manifest::load(&dir_r.join(".pear/manifest.json"))
        .unwrap()
        .unwrap();
    let err = rita.put_head(1, &manifest).unwrap_err();
    assert!(
        matches!(err, RelayError::Http { status: 403, .. }),
        "reader put_head: {err:?}"
    );
    let err = rita.create_snapshot(None, &manifest).unwrap_err();
    assert!(
        matches!(err, RelayError::Http { status: 403, .. }),
        "reader create_snapshot: {err:?}"
    );

    // 5. Nate (no role) cannot even see the workspace: resolution and
    // direct reads are 404.
    let nate_admin = RelayClient::unbound(&url, &nate_tok, "nate-laptop");
    let err = nate_admin.resolve_workspace("acme", "api").unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "resolve: {err:?}");
    let nate = RelayClient::new(&url, &nate_tok, &meta.id, "nate-laptop");
    let err = nate.get_workspace().unwrap_err();
    assert!(
        matches!(err, RelayError::NotFound(_)),
        "get_workspace: {err:?}"
    );
}

/// §14 end-to-end: a mirror following the WebSocket `head_changed` feed
/// pulls immediately on a commit and converges; a listener that cannot
/// upgrade (bad token → 401, no role → 404) stays disconnected so the
/// mirror keeps pure polling. Also pins the §21 `head_now` catch-up that
/// opens the feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_mirror_converges_on_head_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // Mirror: initial convergence, then follow the WS feed.
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    let feed = mirror.head_changes().expect("http relay url");
    for _ in 0..100 {
        if feed.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(feed.connected(), "listener did not connect");

    // §21: the feed opens with the catch-up — the head that already
    // existed at subscribe time (seq 1, pulled above).
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_now catch-up for seq 1");
    assert_eq!(seq, 1);

    // The writer's next commit arrives over the feed; the mirror pulls
    // right away (what the mirror loop does on a hint) and converges.
    write(&dir_a, "f.txt", b"v2\n");
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert_eq!(pushed.head_seq, 2);
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_changed hint for seq 2");
    assert_eq!(seq, 2);
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // Fallback (§14): a listener that cannot connect gets no hints and
    // reports disconnected — the mirror simply keeps polling.
    let ghost = RelayClient::new(&url, "wrong-token", &meta.id, "device-c");
    let dead = ghost.head_changes().unwrap();
    assert!(!dead.connected());
    // Every attempt 401s at the handshake, so no hint ever arrives even
    // though the §21 supervisor keeps retrying in the background.
    assert!(dead.recv_timeout(Duration::from_secs(5)).is_err());
    assert!(!dead.connected());
}

/// §21 end-to-end: a mirror whose feed CONNECTS AFTER a commit still
/// converges promptly — the subscribe-time `head_now` reports the
/// existing head, so the wake-up arrives in milliseconds, far below the
/// 5-minute live-feed safety-net poll (which is what would have to drive
/// the pull if the catch-up did not exist).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_mirror_connecting_after_a_commit_converges_via_head_now() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();

    // Commit FIRST: nobody is subscribed yet, so no head_changed hint
    // could ever reach the mirror below.
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // The mirror connects only now. head_now must deliver seq 1 well
    // inside a 5s bound (the safety-net poll it replaces is 5 minutes).
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let feed = mirror.head_changes().expect("http relay url");
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_now catch-up for the pre-existing head");
    assert_eq!(seq, 1);

    // What the mirror loop does on a hint: pull now — and converge.
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
}

// --- §17 TLS ----------------------------------------------------------------

/// A self-signed cert+key pair generated at runtime by the `openssl` CLI
/// (rcgen is unavailable in the offline registry). PEM material lives only
/// in the tempdir — nothing is committed. `None` when `openssl` is not on
/// PATH: the §17 tests skip in that case.
struct TestCert {
    dir: tempfile::TempDir,
    cert_pem: Vec<u8>,
}

impl TestCert {
    fn cert_path(&self) -> std::path::PathBuf {
        self.dir.path().join("cert.pem")
    }

    fn key_path(&self) -> std::path::PathBuf {
        self.dir.path().join("key.pem")
    }

    fn server_tls(&self) -> pear_relay::ServerTls {
        pear_relay::ServerTls::from_pem_files(&self.cert_path(), &self.key_path()).unwrap()
    }
}

fn generate_test_cert() -> Option<TestCert> {
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("skipping: openssl not on PATH");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
        .arg("-keyout")
        .arg(dir.path().join("key.pem"))
        .arg("-out")
        .arg(dir.path().join("cert.pem"))
        .args(["-days", "1", "-subj", "/CN=localhost"])
        // webpki verifies the dialed name against SANs only (no CN
        // fallback) and the tests dial 127.0.0.1, so the IP SAN must
        // cover it. And OpenSSL 3 defaults -x509 to CA:TRUE, which
        // webpki refuses as an end-entity (CaUsedAsEndEntity) — the
        // cert must be a plain leaf that doubles as its own anchor.
        .arg("-addext")
        .arg("subjectAltName=DNS:localhost,IP:127.0.0.1")
        .arg("-addext")
        .arg("basicConstraints=critical,CA:FALSE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cert_pem = std::fs::read(dir.path().join("cert.pem")).unwrap();
    Some(TestCert { dir, cert_pem })
}

/// Spawn the relay over HTTPS (§17) on an ephemeral port; return its
/// `https://` base URL.
async fn start_relay_tls(
    data_dir: &Path,
    tls: pear_relay::ServerTls,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = data_dir.to_path_buf();
    tokio::spawn(async move {
        pear_relay::serve_on_tls(listener, TOKEN, &dir, tls)
            .await
            .expect("relay TLS serve failed");
    });
    format!("https://{addr}")
}

/// `wait_ready` for an HTTPS relay: the probe must carry the CA.
async fn wait_ready_tls(url: &str, ca_pem: &[u8]) {
    let probe = RelayClient::with_tls_ca(
        url,
        TOKEN,
        &format!("wait-ready-{}", std::process::id()),
        "probe",
        Some(ca_pem),
    )
    .unwrap();
    let mut last_err = None;
    for _ in 0..100 {
        match probe.create_workspace("probe") {
            Ok(()) => return,
            Err(e) => last_err = Some(format!("{e:?}")),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("TLS relay did not come up; last probe error: {last_err:?}");
}

/// §17: the full writer/mirror round trip over HTTPS — workspace create,
/// chunks and head — with `--tls-ca-cert` trusting the relay's
/// self-signed cert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_round_trip_with_private_ca() {
    let Some(cert) = generate_test_cert() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay_tls(&tmp.path().join("relay"), cert.server_tls()).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    wait_ready_tls(&url, &cert.cert_pem).await;
    let writer =
        RelayClient::with_tls_ca(&url, TOKEN, &meta.id, "device-a", Some(&cert.cert_pem)).unwrap();
    writer.create_workspace("a").unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror =
        RelayClient::with_tls_ca(&url, TOKEN, &meta.id, "device-b", Some(&cert.cert_pem)).unwrap();
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
}

/// §17: against the same live HTTPS relay, a client WITHOUT the CA must
/// fail certificate verification — no silent fallback to plaintext roots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_client_without_ca_fails_verification() {
    let Some(cert) = generate_test_cert() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay_tls(&tmp.path().join("relay"), cert.server_tls()).await;
    // Prove the failure below is verification, not a dead server.
    wait_ready_tls(&url, &cert.cert_pem).await;

    let client = RelayClient::new(&url, TOKEN, "ws-1", "device-a");
    let err = client
        .create_workspace("a")
        .expect_err("self-signed relay must not verify against default roots");
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains("cert") || msg.contains("tls"),
        "expected a TLS verification failure, got: {err:?}"
    );

    // The wss listener without the CA never connects either (§14 fallback
    // to pure polling, exactly like a refused connection).
    let feed = client.head_changes().unwrap();
    assert!(feed.recv_timeout(Duration::from_millis(500)).is_err());
    assert!(!feed.connected());
}

/// §17 + §14: the mirror's `head_changed` feed works over wss with a
/// private CA — the same hint delivery as the plain-HTTP ws test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wss_head_changed_over_tls() {
    let Some(cert) = generate_test_cert() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay_tls(&tmp.path().join("relay"), cert.server_tls()).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    wait_ready_tls(&url, &cert.cert_pem).await;
    let writer =
        RelayClient::with_tls_ca(&url, TOKEN, &meta.id, "device-a", Some(&cert.cert_pem)).unwrap();
    writer.create_workspace("a").unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // Mirror: initial convergence, then follow the wss feed.
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror =
        RelayClient::with_tls_ca(&url, TOKEN, &meta.id, "device-b", Some(&cert.cert_pem)).unwrap();
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    let feed = mirror.head_changes().expect("https relay url");
    for _ in 0..100 {
        if feed.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(feed.connected(), "wss listener did not connect");

    // §21: the wss feed also opens with the catch-up (seq 1, pulled above).
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_now catch-up over wss for seq 1");
    assert_eq!(seq, 1);

    write(&dir_a, "f.txt", b"v2\n");
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert_eq!(pushed.head_seq, 2);
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_changed hint over wss for seq 2");
    assert_eq!(seq, 2);
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
}

/// §17: key material is validated at startup — unreadable files, garbage
/// PEM, and a cert/key mismatch all fail before the relay binds.
#[test]
fn server_tls_rejects_bad_material() {
    let tmp = tempfile::tempdir().unwrap();
    let cert = tmp.path().join("cert.pem");
    let key = tmp.path().join("key.pem");
    std::fs::write(&cert, b"not a pem\n").unwrap();
    std::fs::write(&key, b"also not a pem\n").unwrap();
    assert!(pear_relay::ServerTls::from_pem_files(&cert, &key).is_err());
    // Missing files fail too.
    assert!(pear_relay::ServerTls::from_pem_files(&tmp.path().join("missing.pem"), &key).is_err());

    // A mismatched pair (cert from one generation, key from another) is
    // rejected at load, not at the first handshake.
    let Some(a) = generate_test_cert() else {
        return;
    };
    let Some(b) = generate_test_cert() else {
        return;
    };
    let err = pear_relay::ServerTls::from_pem_files(&a.cert_path(), &b.key_path());
    assert!(err.is_err(), "mismatched cert/key must fail to load");
}

/// §17: the CA PEM itself is validated at client construction — garbage
/// fails before any request goes out.
#[test]
fn client_rejects_bad_ca_pem() {
    let result = RelayClient::with_tls_ca(
        "https://127.0.0.1:1",
        TOKEN,
        "ws-1",
        "device-a",
        Some(b"definitely not a pem"),
    );
    let err = match result {
        Ok(_) => panic!("garbage CA PEM must be rejected"),
        Err(err) => err,
    };
    assert!(matches!(err, RelayError::Fatal(_)), "got {err:?}");
}

// --- §17 E2E content encryption -----------------------------------------------

/// A string that must never appear anywhere on the relay: not in the
/// chunk pool, not in the metadata DB, not in any head/snapshot body.
const CANARY: &[u8] = b"E2E-CANARY-9f3b7d-open-sesame";

/// Recursively assert no file under `dir` contains `needle`.
fn assert_no_file_contains(dir: &Path, needle: &[u8]) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_file_contains(&path, needle);
        } else {
            let data = std::fs::read(&path).unwrap();
            assert!(
                !data.windows(needle.len()).any(|window| window == needle),
                "{} contains plaintext that should only exist encrypted",
                path.display()
            );
        }
    }
}

/// §17: an e2e push uploads only ciphertext (the relay pool and the head
/// never contain a plaintext byte, convergent dedupe is preserved), and a
/// mirror holding the workspace key converges byte-identically. The e2e
/// snapshot + fork-clone path round-trips too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_push_pull_converges_and_relay_sees_only_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let relay_dir = tmp.path().join("relay");
    let url = start_relay(&relay_dir).await;

    // Writer dir A, with the canary in .env and two identical files
    // (convergent encryption must dedupe them).
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", CANARY);
    write(&dir_a, "f1.txt", b"shared content\n");
    write(&dir_a, "f2.txt", b"shared content\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace_e2e("a", None).unwrap();
    assert!(writer.get_workspace().unwrap().e2e, "registered as e2e");

    // The workspace keyring lives at .pear/workspace_keys, 0600.
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir_a.join(".pear/workspace_keys"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the workspace keyring is owner-only");
    }
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &writer, 0, false, &keyring).unwrap();
    assert!(pushed.committed);
    assert_eq!(pushed.head_seq, 1);
    assert_eq!(
        pushed.chunks_uploaded, 3,
        "convergent dedupe: f1/f2 share one ciphertext chunk"
    );

    // The relay's entire data dir holds no plaintext: not the chunk pool,
    // not the metadata DB.
    assert_no_file_contains(&relay_dir, CANARY);
    assert_no_file_contains(&relay_dir, b"fn main() {}\n");

    // The head is opaque: the wire serves manifest_enc, the stored row is
    // the §24 envelope (manifest_enc + chunk_hashes), and the decoded blob
    // is not plaintext either.
    let head = writer.get_head().unwrap().unwrap();
    assert!(head.e2e);
    let enc = head.manifest_enc.as_deref().unwrap();
    assert!(!enc.contains("main.rs"), "paths are encrypted too");
    let decoded = pear_core::crypto::base64_decode(enc).unwrap();
    assert!(
        !decoded.windows(CANARY.len()).any(|w| w == CANARY),
        "the encrypted manifest leaks no plaintext"
    );
    // ...but it decrypts to exactly the writer's manifest.
    let decrypted = pear_core::e2e::decrypt_manifest(&keyring, enc).unwrap();
    // hash = BLAKE3 of the stored envelope, recomputed from the decrypted
    // manifest's own chunk list (canonicalized: sorted, deduped — the
    // same order the relay's envelope stores).
    let stored_envelope = serde_json::json!({
        "chunk_hashes": pear_core::e2e::manifest_chunk_hashes(&decrypted),
        "manifest_enc": enc,
    })
    .to_string();
    assert_eq!(
        head.hash,
        blake3::hash(stored_envelope.as_bytes()).to_hex().to_string(),
        "hash is BLAKE3 of the stored §24 envelope"
    );
    assert_eq!(decrypted.files.len(), 4);
    assert!(decrypted.files.contains_key(".env"));

    // Mirror dir B with the keyring: byte-identical convergence.
    let dir_b = tmp.path().join("b");
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let pulled = pear_core::sync::pull_once_e2e(&dir_b, &mirror, &keyring).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(std::fs::read(dir_b.join(".env")).unwrap(), CANARY);

    // Edit -> push -> pull -> converged again; then the mirror idles.
    write(&dir_a, "src/main.rs", b"fn main() { println!(\"hi\"); }\n");
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &writer, 1, false, &keyring).unwrap();
    assert_eq!(pushed.head_seq, 2);
    assert!(
        pear_core::sync::pull_once_e2e(&dir_b, &mirror, &keyring)
            .unwrap()
            .changed
    );
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert!(
        !pear_core::sync::pull_once_e2e(&dir_b, &mirror, &keyring)
            .unwrap()
            .changed
    );

    // The e2e snapshot commits the encrypted manifest; the fork-clone
    // decrypts it byte-identically.
    let snap =
        pear_core::snapshot::push_snapshot_e2e(&dir_a, &writer, Some("sealed"), &keyring).unwrap();
    let fetched = writer.get_snapshot(snap.id).unwrap();
    assert!(fetched.e2e);
    assert!(fetched.manifest_enc.is_some());
    let dir_c = tmp.path().join("c");
    let cloner = RelayClient::new(&url, TOKEN, &meta.id, "device-c");
    let clone =
        pear_core::snapshot::clone_from_snapshot_e2e(&dir_c, &cloner, snap.id, &keyring).unwrap();
    assert_eq!(clone.files_written, 4);
    assert_eq!(tree(&dir_a), tree(&dir_c));
    // The clone cached the keyring it onboarded with.
    assert_eq!(
        pear_core::e2e::load_workspace_keyring(&dir_c).unwrap(),
        Some(keyring.clone())
    );
    // Still nothing plaintext anywhere on the relay.
    assert_no_file_contains(&relay_dir, CANARY);
}

/// §17 + §13 + §19: the full onboarding flow. Admin creates users; the
/// owner keygens (signed bundle), creates the team, pushes an e2e
/// workspace; a new member keygens, the writer re-wraps at its next watch
/// start, and the member clones (fetch + unwrap) and reads the files —
/// while a member without a wrap gets the actionable 404 and a non-member
/// sees nothing. A substituted identity fails LOUD (pin_changed), never
/// silently wrapped to, until an explicit re-pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_onboarding_flow_with_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;
    // The writer's identity pins (§19): one known_keys file per device,
    // here the writer laptop's.
    let known_keys = tmp.path().join("known_keys");

    // 1. Operator (admin): create the users.
    let admin = RelayClient::unbound(&url, TOKEN, "operator");
    let owner_tok = admin.create_user("owner").unwrap().token;
    let jane_tok = admin.create_user("jane").unwrap().token;
    let rita_tok = admin.create_user("rita").unwrap().token;

    // 2. Owner keygens (his private keys never leave his device) and the
    // relay now serves his signed bundle to anyone.
    let owner_keys = tmp.path().join("owner-keys");
    let owner_admin = RelayClient::unbound(&url, &owner_tok, "owner-laptop");
    put_bundle(&owner_admin, &owner_keys, "owner");
    let served = owner_admin.get_key("owner").unwrap();
    let owner_kp = pear_core::crypto::user_keypair_load_or_create(&owner_keys, "owner").unwrap();
    let owner_ed = pear_core::crypto::ed_keypair_load_or_create(&owner_keys, "owner").unwrap();
    assert_eq!(
        served.pubkey.as_deref(),
        Some(pear_core::crypto::hex_encode(&owner_kp.public).as_str())
    );
    assert_eq!(
        served.ed25519.as_deref(),
        Some(pear_core::crypto::hex_encode(&owner_ed.public).as_str())
    );
    assert!(served.sig.is_some(), "the bundle carries the signature");

    // 3. Owner creates acme (jane writer, rita reader) and pushes the e2e
    // workspace attached to it.
    let acme = owner_admin.create_team("acme").unwrap();
    owner_admin
        .team_add_member(&acme.id, "jane", "writer")
        .unwrap();
    owner_admin
        .team_add_member(&acme.id, "rita", "reader")
        .unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", CANARY);
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    wait_ready(&url).await;
    let owner = RelayClient::new(&url, &owner_tok, &meta.id, "owner-laptop");
    owner.create_workspace_e2e("api", Some(&acme.id)).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &owner, 0, false, &keyring).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // 4. Wrap-maintenance (what a converge loop runs at startup): jane
    // and rita have no keys yet, so only the owner is wrapped — and his
    // identity is pinned at first sight.
    let wrap = pear_core::e2e::wrap_maintenance(&owner, &keyring, &known_keys).unwrap();
    assert_eq!(wrap.wrapped, vec!["owner".to_string()]);
    assert_eq!(wrap.skipped.len(), 2, "jane and rita never keygenned");
    assert_eq!(
        wrap.newly_pinned,
        vec![(
            "owner".to_string(),
            pear_core::crypto::hex_encode(&owner_ed.public)
        )]
    );
    assert!(wrap.unsigned.is_empty() && wrap.bad_sig.is_empty() && wrap.pin_changed.is_empty());
    // The pin persisted: the next pass is a plain match, not a re-pin.
    let pins = pear_core::known_keys::load(&known_keys).unwrap();
    assert_eq!(pins.len(), 1);

    // Jane onboards too early: nothing is wrapped for her — the 404 path
    // says exactly what to do.
    let jane_keys = tmp.path().join("jane-keys");
    let jane_admin = RelayClient::unbound(&url, &jane_tok, "jane-laptop");
    put_bundle(&jane_admin, &jane_keys, "jane");
    let jane = RelayClient::new(&url, &jane_tok, &meta.id, "jane-laptop");
    let err = pear_core::e2e::workspace_key_for_reader(
        &tmp.path().join("jane-early"),
        &jane,
        &jane_keys,
        Some("jane"),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("no key is wrapped"), "{msg}");
    assert!(msg.contains("pear user keygen"), "{msg}");
    assert!(msg.contains("join --relay <url> --e2e"), "{msg}");

    // 5. The writer's next converge start (or `pear share`) re-wraps: jane is
    // in (pinned at first sight), rita still has no key.
    let wrap = pear_core::e2e::wrap_maintenance(&owner, &keyring, &known_keys).unwrap();
    assert!(wrap.wrapped.contains(&"jane".to_string()));
    assert_eq!(wrap.skipped, vec!["rita".to_string()]);
    assert_eq!(wrap.newly_pinned.len(), 1, "only jane is newly pinned");
    assert_eq!(wrap.newly_pinned[0].0, "jane");

    // The members list carries bundles so later wraps see them.
    let members = owner_admin.team_members(&acme.id).unwrap();
    let jane_member = members.iter().find(|m| m.user == "jane").unwrap();
    assert!(jane_member.pubkey.is_some());
    assert!(jane_member.ed25519.is_some() && jane_member.sig.is_some());

    // 6. Jane clones: resolve acme/api, fetch + unwrap her keyring, pull —
    // byte-identical tree, canary included. Her keypair never left her
    // device; the relay only ever saw the wrap blob.
    let resolved = jane_admin.resolve_workspace("acme", "api").unwrap();
    assert!(resolved.e2e, "resolution carries the e2e flag");
    let dir_j = tmp.path().join("jane");
    let jane_ring =
        pear_core::e2e::workspace_key_for_reader(&dir_j, &jane, &jane_keys, Some("jane")).unwrap();
    assert_eq!(jane_ring, keyring, "jane unwrapped the same keyring");
    let pulled = pear_core::sync::pull_once_e2e(&dir_j, &jane, &jane_ring).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_j));
    assert_eq!(std::fs::read(dir_j.join(".env")).unwrap(), CANARY);

    // A second device for jane reuses the cached keyring (no relay round
    // trip needed for the unwrap).
    assert_eq!(
        pear_core::e2e::load_workspace_keyring(&dir_j).unwrap(),
        Some(jane_ring.clone())
    );

    // Rita (reader) keygens, the writer re-wraps (e.g. after `pear
    // share`), and she mirrors too — but a stranger still sees nothing.
    let rita_keys = tmp.path().join("rita-keys");
    let rita_admin = RelayClient::unbound(&url, &rita_tok, "rita-laptop");
    put_bundle(&rita_admin, &rita_keys, "rita");
    let wrap = pear_core::e2e::wrap_maintenance(&owner, &keyring, &known_keys).unwrap();
    assert!(wrap.skipped.is_empty(), "everyone has a key now");
    assert_eq!(wrap.newly_pinned.len(), 1, "only rita is newly pinned");
    let rita = RelayClient::new(&url, &rita_tok, &meta.id, "rita-laptop");
    let dir_r = tmp.path().join("rita");
    let rita_ring =
        pear_core::e2e::workspace_key_for_reader(&dir_r, &rita, &rita_keys, Some("rita")).unwrap();
    assert!(
        pear_core::sync::pull_once_e2e(&dir_r, &rita, &rita_ring)
            .unwrap()
            .changed
    );
    assert_eq!(tree(&dir_a), tree(&dir_r));

    // A non-member cannot even see the workspace or ask for its keys.
    let nate_tok = admin.create_user("nate").unwrap().token;
    let nate = RelayClient::new(&url, &nate_tok, &meta.id, "nate-laptop");
    let err = nate.get_my_wrapped_key().unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "got {err:?}");
    let err = nate.get_workspace().unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "got {err:?}");

    // §19: jane's identity changes (a new ed25519 key signs a new bundle —
    // self-only replacement is allowed relay-side). The writer's pin says
    // otherwise: she is NOT wrapped to, and the pass reports pin_changed.
    std::fs::remove_file(jane_keys.join("jane.ed25519")).unwrap();
    put_bundle(&jane_admin, &jane_keys, "jane");
    let wrap = pear_core::e2e::wrap_maintenance(&owner, &keyring, &known_keys).unwrap();
    assert_eq!(wrap.pin_changed, vec!["jane".to_string()]);
    assert!(!wrap.wrapped.contains(&"jane".to_string()));
    assert!(wrap.bad_sig.is_empty(), "her bundle is valid — just changed");

    // `pear trust` re-pins explicitly (never implicit on mismatch), and
    // the next pass wraps to her again.
    let served = owner_admin.get_key("jane").unwrap();
    let mut pins = pear_core::known_keys::load(&known_keys).unwrap();
    pear_core::known_keys::pin(&mut pins, "jane", served.ed25519.as_deref().unwrap());
    pear_core::known_keys::save(&known_keys, &pins).unwrap();
    let wrap = pear_core::e2e::wrap_maintenance(&owner, &keyring, &known_keys).unwrap();
    assert!(wrap.wrapped.contains(&"jane".to_string()));
    assert!(wrap.pin_changed.is_empty() && wrap.newly_pinned.is_empty());
}

/// What `pear user keygen` does (§19): mint any missing identity halves in
/// `keys_dir`, sign the bundle statement for `name`, and PUT the signed
/// bundle to the relay.
fn put_bundle(client: &RelayClient, keys_dir: &Path, name: &str) {
    let x = pear_core::crypto::user_keypair_load_or_create(keys_dir, name).unwrap();
    let ed = pear_core::crypto::ed_keypair_load_or_create(keys_dir, name).unwrap();
    let sig = ed.sign(&pear_core::crypto::bundle_statement(name, &x.public));
    client
        .put_key_bundle(
            name,
            &pear_core::crypto::hex_encode(&x.public),
            &pear_core::crypto::hex_encode(&ed.public),
            &pear_core::crypto::hex_encode(&sig),
        )
        .unwrap();
}

/// §17: a tampered ciphertext chunk never reaches apply. Since §18 the
/// relay's pool store verifies on read: the tampered blob 404s (and
/// self-deletes) instead of serving bad bytes the mirror's wire check
/// would reject — same stuck-workspace outcome, louder signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tampered_ciphertext_chunk_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let relay_dir = tmp.path().join("relay");
    let url = start_relay(&relay_dir).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"honest content\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    pear_core::sync::push_cycle_e2e(&dir_a, &writer, 0, false, &keyring).unwrap();

    // Tamper with the one chunk in the relay's pool (flip a byte).
    let chunk_file = std::fs::read_dir(relay_dir.join("chunks"))
        .unwrap()
        .flat_map(|d| {
            std::fs::read_dir(d.unwrap().path())
                .unwrap()
                .map(|e| e.unwrap().path())
        })
        .find(|p| p.is_file())
        .expect("one chunk in the pool");
    let mut bytes = std::fs::read(&chunk_file).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&chunk_file, &bytes).unwrap();

    let dir_b = tmp.path().join("b");
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let err = pear_core::sync::pull_once_e2e(&dir_b, &mirror, &keyring).unwrap_err();
    let msg = format!("{err:#}");
    // §18: the relay's verify-on-get fires before the mirror's wire
    // check — the pool chunk fails verification, deletes itself, and
    // the GET 404s.
    assert!(
        msg.contains("not found"),
        "tampered ciphertext 404s at the relay (§18 verify-on-get): {msg}"
    );
    assert!(!chunk_file.exists(), "the bad pool chunk deleted itself");
    assert!(!dir_b.join("f.txt").exists(), "nothing was applied");
}

/// §17: the relay cannot validate an encrypted manifest, so the client
/// MUST: a hostile e2e manifest with `../x` fails after decryption,
/// before anything touches disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_hostile_manifest_fails_client_side_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;

    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    pear_core::sync::push_cycle_e2e(&dir_a, &writer, 0, false, &keyring).unwrap();

    // A compromised writer/relay commits a manifest escaping the tree
    // (encrypted, so the relay's validation never sees the path).
    let mut hostile = pear_core::manifest::Manifest::new(meta.id.clone());
    hostile.files.insert(
        "../x".to_string(),
        pear_core::manifest::FileEntry {
            size: 0,
            mode: 0o644,
            mtime_secs: 0,
            mtime_nanos: 0,
            chunks: vec![],
        },
    );
    let enc = pear_core::e2e::encrypt_manifest(&keyring, &hostile).unwrap();
    writer.put_head_e2e(1, &enc, &[]).unwrap();

    // The mirror decrypts, then refuses it — Fatal, and nothing applied.
    let dir_b = tmp.path().join("b");
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let err = pear_core::sync::pull_once_e2e(&dir_b, &mirror, &keyring).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "hostile manifest must be fatal, got {err:?}"
    );
    assert!(
        format!("{err:#}").contains("invalid manifest"),
        "the client-side MUST validation fired: {err:#}"
    );
    assert!(
        !tmp.path().join("x").exists(),
        "nothing may be written outside the mirror tree"
    );
}

// --- §20 key generations (re-key on member removal) ----------------------------

/// The number of chunk files in the relay's content-addressed pool
/// (`chunks/<shard>/<hash>`) — the no-full-re-upload witness.
fn count_pool_chunks(relay_dir: &Path) -> usize {
    let mut count = 0;
    for shard in std::fs::read_dir(relay_dir.join("chunks")).unwrap() {
        let shard = shard.unwrap().path();
        if shard.is_dir() {
            count += std::fs::read_dir(&shard)
                .unwrap()
                .filter(|e| e.as_ref().unwrap().path().is_file())
                .count();
        }
    }
    count
}

/// Bump the writer's scan-cache timestamp so the next push can reuse
/// unchanged files' chunk lists without waiting out CACHE_SETTLE_SECS
/// (the production settle window is 2s of mtime age; the test compresses
/// it by post-dating the recorded scan time).
fn postdate_scan_cache(writer_dir: &Path) {
    let path = writer_dir.join(".pear/manifest.json");
    let mut manifest = pear_core::manifest::load(&path).unwrap().unwrap();
    manifest.scanned_at_secs += 60;
    pear_core::manifest::write_atomic(&path, &manifest).unwrap();
}

/// §20: the full member-removal story. Alice (writer) + bob; bob mirrors;
/// bob is removed from the team via the real route (his wrap rows die
/// with the membership, immediately); the next watch-start rotation pass
/// still rotates the keyring and re-deletes bob's wrap (a 204 no-op);
/// alice's edit then pushes under the new generation — bob's stale ring
/// cannot decrypt the new head, while carol, joining later, onboards onto
/// the full ring and reads old and new alike. Nothing but the edited
/// file's chunks re-uploads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_member_removal_rotates_and_cuts_off_future_content() {
    let tmp = tempfile::tempdir().unwrap();
    let relay_dir = tmp.path().join("relay");
    let url = start_relay(&relay_dir).await;
    // The writer's identity pins (§19), per-device as ever.
    let known_keys = tmp.path().join("known_keys");

    // Users + signed bundles (§19 onboarding, unchanged).
    let admin = RelayClient::unbound(&url, TOKEN, "operator");
    let alice_tok = admin.create_user("alice").unwrap().token;
    let bob_tok = admin.create_user("bob").unwrap().token;
    let carol_tok = admin.create_user("carol").unwrap().token;
    let alice_keys = tmp.path().join("alice-keys");
    let alice_admin = RelayClient::unbound(&url, &alice_tok, "alice-laptop");
    put_bundle(&alice_admin, &alice_keys, "alice");
    let bob_keys = tmp.path().join("bob-keys");
    let bob_admin = RelayClient::unbound(&url, &bob_tok, "bob-laptop");
    put_bundle(&bob_admin, &bob_keys, "bob");

    // Team acme (alice owner, bob reader) with the e2e workspace attached;
    // alice pushes v1 at generation 1.
    let acme = alice_admin.create_team("acme").unwrap();
    alice_admin
        .team_add_member(&acme.id, "bob", "reader")
        .unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "keep.txt", b"stays the same\n");
    write(&dir_a, "edit.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    wait_ready(&url).await;
    let alice = RelayClient::new(&url, &alice_tok, &meta.id, "alice-laptop");
    alice.create_workspace_e2e("api", Some(&acme.id)).unwrap();
    let mut keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    assert_eq!(keyring.newest().0, 1, "a fresh workspace starts at generation 1");
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &alice, 0, false, &keyring).unwrap();
    let base_seq = pushed.head_seq;
    let chunks_after_v1 = count_pool_chunks(&relay_dir);

    // The watch-start pass (§20): no record yet, so nothing rotates; alice
    // and bob are wrapped and the wrapped set is recorded.
    let pass =
        pear_core::e2e::rotation_maintenance(
            &alice,
            &dir_a,
            &mut keyring,
            &known_keys,
            &alice_keys,
            Some("alice"),
            false,
        )
        .unwrap();
    assert!(!pass.rotated, "no record yet: the first pass never rotates");
    assert_eq!(keyring.newest().0, 1);
    let mut wrapped = pass.wrap.wrapped.clone();
    wrapped.sort();
    assert_eq!(wrapped, vec!["alice".to_string(), "bob".to_string()]);
    let recorded = pear_core::e2e::load_wrapped_members(&dir_a).unwrap().unwrap();
    assert_eq!(
        recorded,
        ["alice", "bob"].into_iter().map(String::from).collect(),
        "the wrapped member set persisted"
    );

    // Bob mirrors: he unwraps the full (generation-1) ring and converges.
    let bob = RelayClient::new(&url, &bob_tok, &meta.id, "bob-laptop");
    let dir_b = tmp.path().join("b");
    let bob_ring =
        pear_core::e2e::workspace_key_for_reader(&dir_b, &bob, &bob_keys, Some("bob")).unwrap();
    assert_eq!(bob_ring, keyring, "bob received the generation-1 ring");
    assert!(
        pear_core::sync::pull_once_e2e(&dir_b, &bob, &bob_ring)
            .unwrap()
            .changed
    );
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // Bob leaves the team: a real operation now (§20) — the route behind
    // `pear team remove`, team-owner gated. His wrapped-key rows die WITH
    // the membership, immediately and before any writer pass: keys/me
    // 404s at once. (The crypto cutoff — the rotation — is the writer's
    // next watch-start pass below.)
    alice_admin.team_remove_member(&acme.id, "bob").unwrap();
    let err = bob.get_my_wrapped_key().unwrap_err();
    assert!(
        matches!(err, RelayError::NotFound(_)),
        "bob's keys/me died with the membership, before any rotation: {err:?}"
    );
    // The next watch-start pass still sees him VANISHED against the
    // recorded wrap set: rotate to generation 2, delete his wrap row
    // (already gone — the relay's DELETE is idempotent), re-wrap the rest.
    write(&dir_a, "edit.txt", b"v2 after bob left\n");
    postdate_scan_cache(&dir_a);
    let pass =
        pear_core::e2e::rotation_maintenance(
            &alice,
            &dir_a,
            &mut keyring,
            &known_keys,
            &alice_keys,
            Some("alice"),
            false,
        )
        .unwrap();
    assert!(pass.rotated, "a vanished member rotates");
    assert_eq!(pass.departed, vec!["bob".to_string()]);
    assert_eq!(keyring.newest().0, 2);
    assert_eq!(pass.wrap.wrapped, vec!["alice".to_string()]);
    // The rotation persisted the new ring 0600 before touching the relay.
    assert_eq!(
        pear_core::e2e::load_workspace_keyring(&dir_a).unwrap(),
        Some(keyring.clone())
    );
    // Bob's wrap row is gone (the removal cascade took it; the pass's
    // delete was a no-op), and re-deleting stays a 204 no-op — idempotent,
    // so a retried pass converges.
    let err = bob.get_my_wrapped_key().unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "got {err:?}");
    alice.delete_wrapped_key("bob").unwrap();
    let recorded = pear_core::e2e::load_wrapped_members(&dir_a).unwrap().unwrap();
    assert_eq!(recorded, ["alice".to_string()].into_iter().collect());

    // The push after rotation uploads ONLY the edited file's new chunks —
    // §20's central property: no full re-upload.
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &alice, base_seq, false, &keyring).unwrap();
    assert_eq!(
        pushed.chunks_uploaded, 1,
        "only edit.txt's new-generation chunk uploaded"
    );
    assert_eq!(
        count_pool_chunks(&relay_dir),
        chunks_after_v1 + 1,
        "the pool grew by exactly the edited file's chunks"
    );

    // Bob's stale generation-1 ring cannot decrypt the new head (the
    // crypto cutoff — relay auth already hides the workspace from him).
    let head = alice.get_head().unwrap().unwrap();
    let enc = head.manifest_enc.as_deref().unwrap();
    assert!(
        pear_core::e2e::decrypt_manifest(&bob_ring, enc).is_err(),
        "bob's stale ring fails on the post-removal head"
    );
    assert!(
        pear_core::e2e::decrypt_manifest(&keyring, enc).is_ok(),
        "the full ring reads the new head"
    );
    let err = bob.get_workspace().unwrap_err();
    assert!(
        matches!(err, RelayError::NotFound(_)),
        "team removal is the relay-auth cutoff: {err:?}"
    );
    // ...while the content bob legitimately had still decrypts under his
    // ring (§20: history is NOT re-protected — he could have copied it).
    {
        use pear_core::store::ChunkSource;
        let bob_store = pear_core::store::LocalStore::open(dir_b.join(".pear/store")).unwrap();
        let bob_manifest =
            pear_core::manifest::load(&dir_b.join(".pear/manifest.json")).unwrap().unwrap();
        let source = pear_core::e2e::DecryptingSource {
            inner: &bob_store,
            keyring: &bob_ring,
        };
        let plain = source.get(&bob_manifest.files["keep.txt"].chunks[0]).unwrap();
        assert_eq!(plain, b"stays the same\n");
    }

    // Carol joins: an ADDITION never rotates. She unwraps the full ring —
    // both generations — and reads old (gen-1) and new (gen-2) content.
    let carol_keys = tmp.path().join("carol-keys");
    let carol_admin = RelayClient::unbound(&url, &carol_tok, "carol-laptop");
    put_bundle(&carol_admin, &carol_keys, "carol");
    alice_admin
        .team_add_member(&acme.id, "carol", "reader")
        .unwrap();
    let pass =
        pear_core::e2e::rotation_maintenance(
            &alice,
            &dir_a,
            &mut keyring,
            &known_keys,
            &alice_keys,
            Some("alice"),
            false,
        )
        .unwrap();
    assert!(!pass.rotated, "a pure addition never rotates");
    assert_eq!(keyring.newest().0, 2);
    let mut wrapped = pass.wrap.wrapped.clone();
    wrapped.sort();
    assert_eq!(wrapped, vec!["alice".to_string(), "carol".to_string()]);

    let carol = RelayClient::new(&url, &carol_tok, &meta.id, "carol-laptop");
    let dir_c = tmp.path().join("c");
    let carol_ring =
        pear_core::e2e::workspace_key_for_reader(&dir_c, &carol, &carol_keys, Some("carol"))
            .unwrap();
    assert_eq!(
        carol_ring, keyring,
        "carol received the full two-generation ring"
    );
    assert!(
        pear_core::sync::pull_once_e2e(&dir_c, &carol, &carol_ring)
            .unwrap()
            .changed
    );
    assert_eq!(
        tree(&dir_a),
        tree(&dir_c),
        "carol reads the pre-rotation and post-rotation content alike"
    );
    assert_eq!(
        std::fs::read(dir_c.join("edit.txt")).unwrap(),
        b"v2 after bob left\n"
    );
}

/// §32 merge-before-rotate: two writer devices of the SAME user fork the
/// keyring's generation numbering — device A holds {1, 2a} while the
/// relay's copy of alice's wrap holds {1, 2b, 3} — and A's next rotation
/// must first union the relay's ring in (relay wins generation 2, gen 3
/// is adopted) and only then mint generation 4. Without the merge A would
/// mint 3 with a third key and strand the content sealed under the other
/// branch's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_merges_the_relays_wrapped_keyring_before_minting() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay")).await;
    // Pins are per-device: A and A2 keep their own (§19).
    let known_keys = tmp.path().join("known_keys-a");
    let known_keys_a2 = tmp.path().join("known_keys-a2");

    let admin = RelayClient::unbound(&url, TOKEN, "operator");
    let alice_tok = admin.create_user("alice").unwrap().token;
    let bob_tok = admin.create_user("bob").unwrap().token;
    let alice_keys = tmp.path().join("alice-keys");
    let alice_admin = RelayClient::unbound(&url, &alice_tok, "alice-laptop");
    put_bundle(&alice_admin, &alice_keys, "alice");
    let bob_keys = tmp.path().join("bob-keys");
    put_bundle(
        &RelayClient::unbound(&url, &bob_tok, "bob-laptop"),
        &bob_keys,
        "bob",
    );
    let acme = alice_admin.create_team("acme").unwrap();
    alice_admin
        .team_add_member(&acme.id, "bob", "reader")
        .unwrap();

    // Device A: the e2e workspace at generation 1, wrapped to alice+bob.
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    wait_ready(&url).await;
    let alice = RelayClient::new(&url, &alice_tok, &meta.id, "alice-laptop");
    alice.create_workspace_e2e("api", Some(&acme.id)).unwrap();
    let mut ring_a = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    pear_core::sync::push_cycle_e2e(&dir_a, &alice, 0, false, &ring_a).unwrap();
    let pass = pear_core::e2e::rotation_maintenance(
        &alice,
        &dir_a,
        &mut ring_a,
        &known_keys,
        &alice_keys,
        Some("alice"),
        false,
    )
    .unwrap();
    assert!(!pass.rotated, "the first pass has no record to compare");

    // Alice's SECOND device onboards from its wrap, rotates twice (say, a
    // `pear rekey` and a member removal it saw), and re-wraps: the relay's
    // copy of alice's ring is now {1, 2b, 3}.
    let dir_a2 = tmp.path().join("a2");
    let alice2 = RelayClient::new(&url, &alice_tok, &meta.id, "alice-desktop");
    let mut ring_a2 =
        pear_core::e2e::workspace_key_for_reader(&dir_a2, &alice2, &alice_keys, Some("alice"))
            .unwrap();
    assert_eq!(ring_a2.newest().0, 1, "A2 onboarded onto generation 1");
    ring_a2.rotate();
    let sealed_2b =
        pear_core::crypto::encrypt_chunk(ring_a2.newest().1, b"sealed by A2 under generation 2");
    ring_a2.rotate();
    assert_eq!(ring_a2.newest().0, 3);
    pear_core::e2e::wrap_maintenance(&alice2, &ring_a2, &known_keys_a2).unwrap();

    // Device A never saw any of it and forks generation 2 with its own key.
    ring_a.rotate();
    let sealed_2a =
        pear_core::crypto::encrypt_chunk(ring_a.newest().1, b"sealed by A under generation 2");
    pear_core::e2e::store_workspace_keyring(&dir_a, &ring_a).unwrap();
    assert_eq!(ring_a.newest().0, 2, "A's ring is {{1, 2a}}");

    // Bob leaves, so A's next pass rotates — merging first.
    alice_admin.team_remove_member(&acme.id, "bob").unwrap();
    let pass = pear_core::e2e::rotation_maintenance(
        &alice,
        &dir_a,
        &mut ring_a,
        &known_keys,
        &alice_keys,
        Some("alice"),
        false,
    )
    .unwrap();
    assert!(pass.rotated);
    assert_eq!(pass.departed, vec!["bob".to_string()]);
    assert_eq!(
        pass.merged_from_relay,
        vec![2, 3],
        "generation 2 replaced by the relay's, generation 3 adopted"
    );
    assert_eq!(pass.merge_skipped, None);
    assert_eq!(
        pass.generation, 4,
        "the mint is max(known generation) + 1, not local-max + 1"
    );
    // The relay's branch of generation 2 is what A holds now; its own is
    // gone (§32: the relay's copy is canonical).
    assert!(
        ring_a
            .decrypt("chunk", |k| pear_core::crypto::decrypt_chunk(k, &sealed_2b))
            .is_ok(),
        "A adopted the relay's generation-2 key"
    );
    assert!(
        ring_a
            .decrypt("chunk", |k| pear_core::crypto::decrypt_chunk(k, &sealed_2a))
            .is_err(),
        "A's forked generation-2 key lost"
    );
    // The merged-then-rotated ring is what landed on disk, and what the
    // relay now wraps for alice.
    assert_eq!(
        pear_core::e2e::load_workspace_keyring(&dir_a).unwrap(),
        Some(ring_a.clone())
    );
    let wrapped_now =
        pear_core::e2e::fetch_and_unwrap_workspace_key(&alice, &alice_keys, Some("alice")).unwrap();
    assert_eq!(wrapped_now, ring_a);

    // With no wrap on the relay yet (a first writer) — or no local
    // identity to unwrap one with — the pass rotates the local ring and
    // says so, rather than failing.
    let dir_s = tmp.path().join("solo");
    std::fs::create_dir_all(&dir_s).unwrap();
    let (smeta, _) = pear_core::init_workspace(&dir_s, None).unwrap();
    let solo = RelayClient::new(&url, &alice_tok, &smeta.id, "alice-laptop");
    solo.create_workspace_e2e("solo", Some(&acme.id)).unwrap();
    let mut ring_s = pear_core::e2e::load_or_create_workspace_keyring(&dir_s).unwrap();
    let pass = pear_core::e2e::rotation_maintenance(
        &solo,
        &dir_s,
        &mut ring_s,
        &known_keys,
        &alice_keys,
        Some("alice"),
        true,
    )
    .unwrap();
    assert_eq!(pass.generation, 2, "the local ring rotated anyway");
    assert!(pass.merged_from_relay.is_empty());
    assert!(
        pass.merge_skipped
            .as_deref()
            .unwrap_or_default()
            .contains("no keyring is wrapped"),
        "{:?}",
        pass.merge_skipped
    );
    let pass = pear_core::e2e::rotation_maintenance(
        &solo,
        &dir_s,
        &mut ring_s,
        &known_keys,
        &alice_keys,
        None,
        true,
    )
    .unwrap();
    assert_eq!(pass.generation, 3);
    assert!(
        pass.merge_skipped
            .as_deref()
            .unwrap_or_default()
            .contains("--name"),
        "{:?}",
        pass.merge_skipped
    );
}
