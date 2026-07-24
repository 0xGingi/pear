//! §29 real-git recovery UX tests: §10's `.git` risk ("recovery UX needs
//! real testing before teams trust it") exercised with REAL git repositories
//! — driven by the real `git` binary (init, commits on two branches, a
//! merge, an annotated tag, fsck, checkout) — on top of the real relay and
//! the real pear-core writer/mirror flows, exactly like `e2e.rs` does with
//! synthetic `.git` trees. Every test skips cleanly (early return, not a
//! failure) when no `git` binary is on PATH. No network beyond the local
//! relay.
//!
//! Git is always run with `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` pointed
//! at an empty file, so the host's config (aliases, `status.showUntrackedFiles`,
//! gpgsign, default branch) can never leak into an assertion; identity is
//! set per-repo (`user.email`/`user.name`) and the default branch via
//! `-c init.defaultBranch=main` at init. Repo-local config is itself synced
//! content (`.git/config` round-trips like any other file), which the
//! mirror-side commit in test 2 relies on — and asserts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pear_core::relay::RelayClient;
use pear_core::sync::{pull_once, push_cycle, PushError};

const TOKEN: &str = "e2e-token";

// --- relay fixture (same shape as e2e.rs) -------------------------------------

/// Spawn the relay on an ephemeral port; return its base URL.
async fn start_relay(data_dir: &Path, lease_ttl_secs: u64) -> String {
    // Bind first and pass the listener: no bind-then-drop port race.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = data_dir.to_path_buf();
    tokio::spawn(async move {
        pear_relay::serve_on(listener, TOKEN, &dir, lease_ttl_secs)
            .await
            .expect("relay serve failed");
    });
    format!("http://{addr}")
}

/// Wait until the relay answers. Probe on a throwaway id: probing with the
/// test's real workspace id would register it under the name "probe" before
/// the test's own create.
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
fn tree(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
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

// --- git fixture ----------------------------------------------------------------

/// Every test's entry gate: no `git` on PATH -> skip cleanly (§29).
fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A handle for running git commands inside one repository with the host's
/// global/system git config neutralized (`empty_config` is a real empty
/// file in the test's tempdir — portable, unlike `/dev/null`). All output
/// is captured; mutating commands run with quiet flags.
struct Repo {
    dir: PathBuf,
    empty_config: PathBuf,
}

impl Repo {
    /// `git init` a REAL repo in `dir` with a pinned default branch and a
    /// per-repo identity (never the host's).
    fn init(dir: &Path, empty_config: &Path) -> Self {
        std::fs::create_dir_all(dir).unwrap();
        let repo = Self {
            dir: dir.to_path_buf(),
            empty_config: empty_config.to_path_buf(),
        };
        repo.run(&["-c", "init.defaultBranch=main", "init", "-q"]);
        repo.run(&["config", "user.email", "pear-test@example.invalid"]);
        repo.run(&["config", "user.name", "Pear Test"]);
        repo.run(&["config", "commit.gpgsign", "false"]);
        repo.run(&["config", "tag.gpgsign", "false"]);
        repo
    }

    /// Attach to a repository that arrived via pear (mirror pull / snapshot
    /// clone). Identity is NOT set here: `.git/config` is synced content, so
    /// the writer's per-repo identity is already in place — one of the §29
    /// facts under test.
    fn attach(dir: &Path, empty_config: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            empty_config: empty_config.to_path_buf(),
        }
    }

    /// Run git, assert success, return trimmed stdout.
    fn run(&self, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&self.dir)
            .env("GIT_CONFIG_GLOBAL", &self.empty_config)
            .env("GIT_CONFIG_SYSTEM", &self.empty_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            // A pear test harness never provides these, but a poisoned
            // caller environment must not redirect git elsewhere.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {} failed in {}\nstdout: {}\nstderr: {}",
            args.join(" "),
            self.dir.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim_end().to_string()
    }

    /// Write `rel`, stage it, and commit quietly.
    fn commit_file(&self, rel: &str, data: &[u8], message: &str) {
        write(&self.dir, rel, data);
        self.run(&["add", "-A", "--", rel]);
        self.run(&["commit", "-q", "-m", message]);
    }

    fn head(&self) -> String {
        self.run(&["rev-parse", "HEAD"])
    }

    fn log_oneline(&self) -> String {
        self.run(&["log", "--oneline"])
    }

    fn status_porcelain(&self) -> String {
        self.run(&["status", "--porcelain"])
    }

    /// `git fsck --strict` must pass (exit 0); the assertion is in `run`.
    fn fsck_strict(&self) {
        self.run(&["fsck", "--strict", "--no-progress"]);
    }
}

// --- §29 tests ------------------------------------------------------------------

/// §29 round trip: a real repo (init, commits on two branches, a merge, an
/// annotated tag) pushed via pear and pulled by a mirror passes
/// `git fsck --strict` and `git status` clean on the mirror, `git log`
/// matches the writer's, and `git checkout` of the other branch works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_git_round_trip() {
    if !git_available() {
        eprintln!("skipping: git not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay"), 300).await;
    let git_cfg = tmp.path().join("empty-gitconfig");
    std::fs::write(&git_cfg, b"").unwrap();

    // The writer's real repo: several commits on main, a second branch with
    // commits, a merge back (the sides diverge first: different files, no
    // conflict), and an annotated tag. `.pear/` is gitignored exactly the
    // way a real user's repo ignores pear's metadata dir (pear itself never
    // scans it, but git would show it untracked) — and the `.gitignore`
    // syncs with everything else, so mirrors inherit the ignore.
    let dir_a = tmp.path().join("a");
    let a = Repo::init(&dir_a, &git_cfg);
    a.commit_file(".gitignore", b".pear/\n", "ignore pear metadata");
    a.commit_file("README.md", b"# demo\n", "initial commit");
    a.commit_file("src/main.rs", b"fn main() {}\n", "add main");
    a.run(&["checkout", "-q", "-b", "feature"]);
    a.commit_file("src/feature.rs", b"pub fn f() -> u8 { 1 }\n", "feature work 1");
    a.commit_file("src/feature.rs", b"pub fn f() -> u8 { 2 }\n", "feature work 2");
    a.run(&["checkout", "-q", "main"]);
    a.commit_file("CHANGELOG.md", b"# changelog\n", "main work");
    a.run(&["merge", "-q", "--no-edit", "feature"]);
    a.run(&["tag", "-a", "v1.0", "-m", "release v1.0"]);
    let writer_head = a.head();
    let writer_log = a.log_oneline();
    let writer_feature_tip = a.run(&["rev-parse", "feature"]);
    let writer_tag = a.run(&["rev-parse", "v1.0"]);

    // Push the repo through pear (writer flow -> real relay).
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();
    writer.acquire().unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    // Pull it on a second dir via pear (mirror flow).
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);

    // Byte-identical trees, `.git` and all — checked BEFORE any git command
    // runs on the mirror (`git status` legitimately refreshes the synced
    // index's stat cache in place, which would end byte-identity).
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // The mirror's repo is a healthy, usable repository.
    let b = Repo::attach(&dir_b, &git_cfg);
    b.fsck_strict();
    assert_eq!(b.status_porcelain(), "", "mirror worktree must be clean");
    assert_eq!(b.head(), writer_head, "mirror HEAD matches the writer's");
    assert_eq!(b.log_oneline(), writer_log, "mirror log matches the writer's");
    assert_eq!(b.run(&["rev-parse", "v1.0"]), writer_tag, "the tag came over");

    // `git checkout` of the other branch works on the mirror.
    b.run(&["checkout", "-q", "feature"]);
    assert_eq!(b.head(), writer_feature_tip);
    assert_eq!(
        b.status_porcelain(),
        "",
        "clean after cross-branch checkout"
    );
    b.fsck_strict();
}

/// §29 live edit loop: with a converged pair, a new writer-side commit
/// converges on the mirror (`git log` agrees, status clean). Then a commit
/// on the MIRROR's own repo (mirrors are read-mostly, but local git ops
/// happen) must not wedge the next apply: `.git` writes are ordered last
/// per the apply protocol, and the apply diff is manifest-vs-manifest, so
/// the mirror's between-cycles `.git` changes are simply overwritten where
/// the writer moved them and left alone where it did not.
///
/// What actually happens (pinned by assertion, per the task's "document
/// what actually happens"): the apply resets the mirror's `main` ref and
/// HEAD to the writer's new tip — the mirror-side commit leaves no ref
/// behind (its reflog entries live in `.git/logs/*`, which the apply
/// overwrites with the writer's versions) — but its objects stay in
/// `.git/objects` (pear only deletes files its manifests track), so the
/// work is dangling-but-recoverable, and `git fsck --strict` stays clean
/// (dangling objects are normal git state, not corruption). The file the
/// mirror committed stays on disk as an untracked file. Nothing is
/// silently lost; the pear-level answer for preserving mirror-side state
/// with a ref is §12 snapshots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_git_live_edit_loop_with_mirror_side_commit() {
    if !git_available() {
        eprintln!("skipping: git not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay"), 300).await;
    let git_cfg = tmp.path().join("empty-gitconfig");
    std::fs::write(&git_cfg, b"").unwrap();

    // A converged writer/mirror pair over a real repo (with the realistic
    // `.pear/` gitignore — see the round-trip test).
    let dir_a = tmp.path().join("a");
    let a = Repo::init(&dir_a, &git_cfg);
    a.commit_file(".gitignore", b".pear/\n", "ignore pear metadata");
    a.commit_file("README.md", b"# demo\n", "initial commit");
    a.commit_file("src/main.rs", b"fn main() {}\n", "add main");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let writer = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    writer.create_workspace("a").unwrap();
    writer.acquire().unwrap();
    let pushed = push_cycle(&dir_a, &writer, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let mirror = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    let b = Repo::attach(&dir_b, &git_cfg);
    assert_eq!(b.head(), a.head());

    // Live edit 1: a new commit on the writer side converges on the mirror.
    a.commit_file("src/main.rs", b"fn main() { println!(\"v2\"); }\n", "writer: iteration 2");
    let writer_v2 = a.head();
    let writer_v2_log = a.log_oneline();
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert_eq!(pushed.head_seq, 2);
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);
    assert_eq!(b.head(), writer_v2, "mirror HEAD tracks the writer's commit");
    assert_eq!(b.log_oneline(), writer_v2_log, "git log agrees");
    assert_eq!(b.status_porcelain(), "", "mirror worktree clean after apply");
    b.fsck_strict();

    // The mirror commits on its OWN repo (on main, the checked-out branch).
    // Identity comes from the synced `.git/config` — repo-local config is
    // synced content, exactly like real usage after a pear clone.
    assert_eq!(
        b.run(&["config", "user.email"]),
        "pear-test@example.invalid",
        "the writer's repo-local identity synced with .git/config"
    );
    b.commit_file("mirror-note.txt", b"local investigation\n", "mirror: local note");
    let mirror_commit = b.head();
    assert_ne!(mirror_commit, writer_v2);

    // The writer keeps working; its next cycle + the mirror's next pull is
    // the apply that must not wedge on the mirror's between-cycles `.git`
    // changes.
    a.commit_file("src/main.rs", b"fn main() { println!(\"v3\"); }\n", "writer: iteration 3");
    let writer_v3 = a.head();
    let pushed = push_cycle(&dir_a, &writer, pushed.head_seq, false).unwrap();
    assert_eq!(pushed.head_seq, 3);
    assert!(pull_once(&dir_b, &mirror).unwrap().changed);

    // The apply converged: HEAD and the whole ref/object state the writer
    // owns match the writer exactly, and the pear manifests agree file for
    // file.
    assert_eq!(b.head(), writer_v3, "apply resets the mirror's main to the writer's tip");
    assert_eq!(b.log_oneline(), a.log_oneline());
    let a_manifest = pear_core::manifest::load(&dir_a.join(".pear/manifest.json"))
        .unwrap()
        .unwrap();
    let b_manifest = pear_core::manifest::load(&dir_b.join(".pear/manifest.json"))
        .unwrap()
        .unwrap();
    assert_eq!(
        a_manifest.files, b_manifest.files,
        "converged: the pear manifests agree file for file"
    );
    assert!(
        !pull_once(&dir_b, &mirror).unwrap().changed,
        "the next pull idles: fully converged"
    );

    // fsck stays clean, and the mirror-side commit is dangling but NOT lost:
    // its objects survived the apply (pear deletes only manifest-tracked
    // files), its worktree file stays as the mirror's untracked own.
    b.fsck_strict();
    assert_eq!(
        b.run(&["cat-file", "-t", &mirror_commit]),
        "commit",
        "the mirror-side commit object survived the apply"
    );
    assert_eq!(
        b.status_porcelain(),
        "?? mirror-note.txt",
        "the mirror's local file is untracked-but-present; nothing else dirty"
    );
    assert_eq!(
        std::fs::read(dir_b.join("mirror-note.txt")).unwrap(),
        b"local investigation\n"
    );
}

/// §29 force-takeover fork: two writers on one workspace diverge offline
/// (both commit different work). The second forces the head (`pear watch
/// --relay --force` semantics: `writer_base_seq(.., force)` -> `force()` ->
/// takeover `push_cycle`, the same calls the CLI makes). The contract
/// (§5/§11/§12): the relay checkpoints the overwritten head at force time,
/// the stranded side's resume is refused with `pear snapshot` as the
/// preserve-first remedy, its push is fenced, and the divergent snapshot it
/// makes preserves the stranded tree — a clone from it contains the
/// stranded git work, fsck-clean. Nothing is silently lost on either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_git_force_takeover_fork_preserves_stranded_work() {
    if !git_available() {
        eprintln!("skipping: git not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let url = start_relay(&tmp.path().join("relay"), 300).await;
    let git_cfg = tmp.path().join("empty-gitconfig");
    std::fs::write(&git_cfg, b"").unwrap();

    // Device A writes a real repo and pushes it; device B mirrors it.
    let dir_a = tmp.path().join("a");
    let a = Repo::init(&dir_a, &git_cfg);
    a.commit_file(".gitignore", b".pear/\n", "ignore pear metadata");
    a.commit_file("README.md", b"# demo\n", "initial commit");
    a.commit_file("src/main.rs", b"fn main() {}\n", "add main");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let device_a = RelayClient::new(&url, TOKEN, &meta.id, "device-a");
    wait_ready(&url).await;
    device_a.create_workspace("a").unwrap();
    device_a.acquire().unwrap();
    let pushed = push_cycle(&dir_a, &device_a, 0, false).unwrap();
    assert_eq!(pushed.head_seq, 1);

    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let device_b = RelayClient::new(&url, TOKEN, &meta.id, "device-b");
    assert!(pull_once(&dir_b, &device_b).unwrap().changed);
    let b = Repo::attach(&dir_b, &git_cfg);
    assert_eq!(b.head(), a.head(), "B starts converged");

    // Both sides commit DIFFERENT work "offline" (no push in between). A
    // also has an uncommitted file — unsynced state beyond the git commit.
    a.commit_file("stranded.rs", b"pub fn stranded() {}\n", "a: stranded work");
    let a_stranded = a.head();
    write(&dir_a, "unsynced.txt", b"a was here, never pushed\n");
    b.commit_file("b-work.rs", b"pub fn b_work() {}\n", "b: takeover work");
    let b_head = b.head();

    // B force-takes the workspace (the CLI's `pear watch --relay --force`
    // sequence) and makes its tree the head.
    let base = pear_core::sync::writer_base_seq(&dir_b, &device_b, true).unwrap();
    assert_eq!(base, 1);
    device_b.force().unwrap();
    let pushed = push_cycle(&dir_b, &device_b, base, true).unwrap();
    assert_eq!(pushed.head_seq, 2, "B's tree is the new head");

    // The relay checkpointed the overwritten head first (§12): kind
    // "checkpoint", recorded under the outgoing holder, and it is the
    // PRE-fork tree (none of B's post-fork work).
    let snapshots = device_a.list_snapshots().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].kind, "checkpoint");
    assert_eq!(snapshots[0].device, "device-a");
    let checkpoint = device_a.get_snapshot(snapshots[0].id).unwrap();
    assert!(checkpoint.manifest.files.contains_key(".git/HEAD"));
    assert!(
        !checkpoint.manifest.files.contains_key("b-work.rs"),
        "the checkpoint is the pre-fork head"
    );

    // A reconnects with its unsynced work: resume is refused and the
    // refusal OFFERS the divergent-snapshot remedy (§11's preserve-first);
    // its push is fenced (stale generation).
    let err = pear_core::sync::writer_base_seq(&dir_a, &device_a, false).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("pear snapshot"),
        "the stranded side is offered the preserve-first remedy: {msg}"
    );
    let err = push_cycle(&dir_a, &device_a, base, false).unwrap_err();
    assert!(matches!(err, PushError::Fenced(_)), "got {err:?}");

    // A makes the divergent snapshot (§12: a `named` snapshot of unsynced
    // local state; snapshots have no fencing/CAS, so the stranded device
    // can always preserve). The head does not move.
    let snap = pear_core::snapshot::push_snapshot(&dir_a, &device_a, Some("a-stranded")).unwrap();
    assert_eq!(device_a.get_head().unwrap().unwrap().seq, 2);
    let snapshots = device_a.list_snapshots().unwrap();
    assert_eq!(snapshots[0].id, snap.id);
    assert_eq!(snapshots[0].kind, "named");
    assert_eq!(snapshots[0].name.as_deref(), Some("a-stranded"));

    // A clone from that snapshot contains the stranded work — the git
    // commit (recoverable, fsck-clean repo) AND the uncommitted file.
    let dir_c = tmp.path().join("c");
    let cloner = RelayClient::new(&url, TOKEN, &meta.id, "device-c");
    pear_core::snapshot::clone_from_snapshot(&dir_c, &cloner, snap.id).unwrap();
    let c = Repo::attach(&dir_c, &git_cfg);
    c.fsck_strict();
    assert_eq!(c.head(), a_stranded, "the stranded commit is HEAD in the clone");
    assert!(
        c.log_oneline().contains("a: stranded work"),
        "the stranded work is in the clone's history"
    );
    assert_eq!(
        std::fs::read(dir_c.join("unsynced.txt")).unwrap(),
        b"a was here, never pushed\n",
        "even the uncommitted stranded state is preserved"
    );
    assert_eq!(c.status_porcelain(), "?? unsynced.txt");
    assert!(
        !dir_c.join("b-work.rs").exists(),
        "the fork is real: B's work is not in A's snapshot"
    );

    // The fork's winner is fully usable: a fresh mirror converges on B's
    // tree, repo healthy, A's stranded file absent (it lives only in the
    // divergent snapshot — explicit, never silently merged, per §5).
    let dir_d = tmp.path().join("d");
    pear_core::init_workspace(&dir_d, Some(&meta.id)).unwrap();
    let device_d = RelayClient::new(&url, TOKEN, &meta.id, "device-d");
    assert!(pull_once(&dir_d, &device_d).unwrap().changed);
    let d = Repo::attach(&dir_d, &git_cfg);
    d.fsck_strict();
    assert_eq!(d.head(), b_head);
    assert_eq!(d.status_porcelain(), "");
    assert!(dir_d.join("b-work.rs").exists());
    assert!(!dir_d.join("stranded.rs").exists());
}
