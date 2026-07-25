//! §15 measurement harness: deterministic synthetic monorepo trees driven
//! through the real writer pipeline (scan -> chunk -> manifest) and a real
//! local relay. Every test here is `#[ignore]`d: they compile but never run
//! in the default suite. Run explicitly:
//!
//! ```sh
//! cargo test -p pear-core --test perf -- --ignored --nocapture
//! ```
//!
//! Numbers are macOS/APFS reference points (recorded in DESIGN.md §15), not
//! SLAs. Trees are deterministic (fixed-seed LCG) and live in auto-cleaned
//! tempdirs under `CARGO_TARGET_TMPDIR` when set (target/tmp — the project
//! volume's F_FULLFSYNC is measurably faster than the boot volume's, and
//! the sink-side baselines fsync per chunk).
//!
//! Budget note: a sink-inclusive cold cycle fsyncs twice per file
//! (`LocalStore::put` + apply staging), ~2 ms/file on this volume — at 50k
//! files that alone is minutes, outside the harness's ~60s budget. So
//! baseline 1 measures the contract-literal "cold scan + chunk" (the real
//! walker + the real `chunk_file` chunker, no sink), and the writer/mirror
//! state for the steady-state baselines is fixture-seeded from the same
//! chunk pass (plain writes, no fsync) — the measured cycles then run the
//! unmodified `sync_cycle` pipeline. The fsync-inclusive end-to-end cost is
//! measured for real at the 5k scale (baseline 4).
//!
//! §27 adds the 500k watcher-load measurement (`watcher_load_500k` below):
//! same discipline at ~10× scale, on a persistent reuse-if-present tree —
//! see its doc comment for how to run the full measurement.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use notify::{RecursiveMode, Watcher};
use pear_core::manifest::{self, FileEntry, Manifest};
use pear_core::relay::RelayClient;
use pear_core::scan::ScanOutcome;
use pear_core::sync::{pull_once, push_cycle, sync_cycle};

const TOKEN: &str = "perf-harness-token";
const SEED: u64 = 0x5eed_5eed_5eed_5eed;

// ---------- deterministic content ----------

/// A tiny deterministic PRNG: the harness must not add a `rand` dev-dep,
/// and tree shapes must be reproducible run over run.
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn hex(&mut self, digits: usize) -> String {
        let mut out = String::with_capacity(digits);
        while out.len() < digits {
            out.push_str(&format!("{:016x}", self.next_u64()));
        }
        out.truncate(digits);
        out
    }
}

/// Source-like line templates. `{i}` is the line number, `{h}` fresh hex.
const TEMPLATES: &[&str] = &[
    "fn worker_{i}(state: &mut State) -> Result<()> { state.tick(0x{h}); Ok(()) }\n",
    "let metric_{i} = registry.gauge(\"pear.fixture.{h}\").observe({i} as f64);\n",
    "if let Some(entry) = cache.lookup(0x{h}) { entry.touch({i}); }\n",
    "tracing::debug!(iteration = {i}, \"fixture line 0x{h}\");\n",
    "struct Record{i} { id: u64, tag: u64, payload: Vec<u8> } // 0x{h}\n",
    "impl Widget { fn render_{i}(&self) -> String { format!(\"0x{h}\") } }\n",
    "for chunk in batch.iter().take({i}) { sink.feed(0x{h}, chunk); }\n",
    "let digest_{i} = blake3::hash(&buf[0x{h} % buf.len()]);\n",
];

/// The shared pool of source-like text that file bodies are sliced from.
/// Each file still gets a unique header, so whole-file chunk hashes stay
/// distinct (fastcdc's 256 KiB minimum makes small files one chunk each).
fn source_pool(rng: &mut Lcg) -> Vec<u8> {
    let mut pool = String::with_capacity(64 * 1024 + 256);
    let mut i = 0u32;
    while pool.len() < 64 * 1024 {
        let line = TEMPLATES[rng.below(TEMPLATES.len() as u64) as usize];
        pool.push_str(
            &line
                .replace("{i}", &i.to_string())
                .replace("{h}", &rng.hex(8)),
        );
        i += 1;
    }
    pool.into_bytes()
}

fn source_content(rng: &mut Lcg, pool: &[u8], rel: &str, target: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(target + 96);
    let header = format!(
        "// {rel} — synthetic pear perf fixture\n// 0x{}\n",
        rng.hex(16)
    );
    out.extend_from_slice(header.as_bytes());
    while out.len() < target {
        let start = rng.below(pool.len() as u64) as usize;
        let n = (target - out.len()).min(pool.len() - start);
        out.extend_from_slice(&pool[start..start + n]);
    }
    out
}

/// Random-ish bytes for blobs and `.git/index`. `:` is mapped to NUL so
/// synthetic contents can never spell a `key:value` credential pattern.
fn noise_bytes(rng: &mut Lcg, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    for chunk in buf.chunks_mut(8) {
        let bytes = rng.next_u64().to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bytes[..len]);
    }
    for b in buf.iter_mut() {
        if *b == b':' {
            *b = 0;
        }
    }
    buf
}

fn env_content(rng: &mut Lcg) -> Vec<u8> {
    format!(
        "PEAR_FIXTURE=1\nVALUE_{:04x}={}\nVALUE_{:04x}={}\n",
        rng.below(0x1_0000),
        rng.hex(16),
        rng.below(0x1_0000),
        rng.hex(16)
    )
    .into_bytes()
}

fn git_log(rng: &mut Lcg, head: &str) -> Vec<u8> {
    let zero = "0".repeat(40);
    format!(
        "{zero} {head} Fixture <f@example.com> 1700000000 +0000\tcommit (initial): fixture\n\
         {head} {h2} Fixture <f@example.com> 1700000100 +0000\tcommit: more fixture\n",
        h2 = rng.hex(40)
    )
    .into_bytes()
}

// ---------- tree generation ----------

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct GenStats {
    dirs: usize,
    scannable_files: usize,
    scannable_bytes: u64,
    excluded_files: usize,
    gitignored_files: usize,
}

fn write_at(root: &Path, rel: &str, data: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

fn put_scannable(root: &Path, rel: &str, data: &[u8], stats: &mut GenStats) {
    write_at(root, rel, data);
    stats.scannable_files += 1;
    stats.scannable_bytes += data.len() as u64;
}

/// Build a deterministic workspace tree of `total_work_files` worktree
/// files (mostly 1-8 KB source-like files plus a few multi-MB blobs)
/// across ~50 leaf dirs, with a plausible `.git/`, `.env*` files (some
/// gitignored), a `.gitignore`, and `node_modules/`+`target/` trees that
/// must stay excluded.
fn gen_tree(root: &Path, total_work_files: usize, seed: u64) -> GenStats {
    let mut rng = Lcg(seed);
    let mut stats = GenStats::default();
    let pool = source_pool(&mut rng);

    let pkgs = (total_work_files / 2_000).max(5);
    let subs = pkgs * 2; // pkg-XX/src + pkg-XX/tests
    let (blobs, blob_bytes) = if total_work_files >= 10_000 {
        (6, 3 * 1024 * 1024)
    } else {
        (1, 2 * 1024 * 1024)
    };
    let src_files = total_work_files - blobs;
    for i in 0..src_files {
        let slot = i % subs;
        let sub = if slot.is_multiple_of(2) {
            "src"
        } else {
            "tests"
        };
        let rel = format!("pkg-{:02}/{sub}/f{:04}.rs", slot / 2, i / subs);
        let target = 1_024 + rng.below(7_168) as usize;
        let data = source_content(&mut rng, &pool, &rel, target);
        put_scannable(root, &rel, &data, &mut stats);
    }
    for i in 0..blobs {
        let data = noise_bytes(&mut rng, blob_bytes);
        put_scannable(root, &format!("assets/blob-{i}.bin"), &data, &mut stats);
    }
    stats.dirs = subs + 2; // pkg subdirs + assets/ + root

    // A plausible .git: pass 2 owns it, and `.git/logs/` must sync even
    // though the root .gitignore ignores a worktree `logs/` directory.
    let head = rng.hex(40);
    let support: Vec<(String, Vec<u8>)> =
        vec![
        (".git/HEAD".into(), b"ref: refs/heads/main\n".to_vec()),
        (
            ".git/config".into(),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tlogallrefupdates = true\n"
                .to_vec(),
        ),
        (".git/description".into(), b"pear perf fixture repo\n".to_vec()),
        (
            ".git/packed-refs".into(),
            format!("# pack-refs with: peeled fully-peeled sorted\n{head} refs/heads/main\n")
                .into_bytes(),
        ),
        (".git/refs/heads/main".into(), format!("{head}\n").into_bytes()),
        (
            ".git/refs/heads/perf-x".into(),
            format!("{}\n", rng.hex(40)).into_bytes(),
        ),
        (".git/logs/HEAD".into(), git_log(&mut rng, &head)),
        (".git/logs/refs/heads/main".into(), git_log(&mut rng, &head)),
        (
            ".git/info/exclude".into(),
            b"# git ls-files --others --exclude-from=.git/info/exclude\n*.swp\n".to_vec(),
        ),
        (
            ".git/hooks/applypatch-msg.sample".into(),
            b"#!/bin/sh\n# sample hook\n".to_vec(),
        ),
        (".git/index".into(), noise_bytes(&mut rng, 1024)),
    ];
    for (rel, data) in support {
        put_scannable(root, &rel, &data, &mut stats);
    }
    for _ in 0..120 {
        let rel = format!(".git/objects/{}/{}", rng.hex(2), rng.hex(38));
        let size = 200 + rng.below(200) as usize;
        let data = noise_bytes(&mut rng, size);
        put_scannable(root, &rel, &data, &mut stats);
    }

    // `.env*` files sync even when gitignored (§5).
    let env = env_content(&mut rng);
    put_scannable(root, ".env", &env, &mut stats);
    put_scannable(root, ".env.local", &env, &mut stats); // gitignored
    for p in 0..pkgs.min(8) {
        put_scannable(root, &format!("pkg-{p:02}/.env"), &env, &mut stats);
    }
    for p in 0..pkgs.min(6) {
        let rel = format!("pkg-{p:02}/tests/.env.test");
        put_scannable(root, &rel, &env, &mut stats); // gitignored
    }

    // Root noise: `.gitignore` itself syncs; the files it ignores must not.
    put_scannable(
        root,
        ".gitignore",
        b"*.log\nlogs/\n.env.local\n.env.test\n",
        &mut stats,
    );
    put_scannable(root, "README.md", b"# pear perf fixture\n", &mut stats);
    write_at(root, "logs/app.log", b"noise\n");
    write_at(root, "debug.log", b"noise\n");
    stats.gitignored_files += 2;

    // Excluded trees: never synced, pruned by the built-in name list.
    for d in 0..10 {
        for f in 0..60 {
            let name = if f == 0 {
                "index.js".to_string()
            } else {
                format!("lib/part-{f:02}.js")
            };
            let body = format!("module.exports = {{ dep: {d}, part: 0x{} }};\n", rng.hex(6));
            write_at(
                root,
                &format!("node_modules/dep-{d:02}/{name}"),
                body.as_bytes(),
            );
            stats.excluded_files += 1;
        }
    }
    for i in 0..300 {
        let data = noise_bytes(&mut rng, 1024);
        write_at(root, &format!("target/debug/obj-{i:04}.o"), &data);
        stats.excluded_files += 1;
    }

    stats
}

// ---------- helpers ----------

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Tempdirs live under CARGO_TARGET_TMPDIR (target/tmp, on the project
/// volume) when cargo sets it: F_FULLFSYNC is measurably faster there than
/// on the boot volume, and the sink-side baselines fsync per chunk. Falls
/// back to the system temp dir when the binary runs outside cargo.
fn base_tempdir() -> tempfile::TempDir {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_TMPDIR") {
        std::fs::create_dir_all(&dir).unwrap();
        return tempfile::tempdir_in(dir).unwrap();
    }
    tempfile::tempdir().unwrap()
}

/// The scan must find exactly the generated scannable set, keep gitignored
/// noise out, and report the built-in excludes.
fn sanity_check(out: &ScanOutcome, stats: &GenStats) {
    assert_eq!(out.files.len(), stats.scannable_files);
    let paths: std::collections::BTreeSet<&str> =
        out.files.iter().map(|f| f.rel_path.as_str()).collect();
    for want in [
        ".env",
        ".env.local",
        ".git/HEAD",
        ".git/logs/HEAD",
        ".gitignore",
    ] {
        assert!(paths.contains(want), "scan must include {want}");
    }
    for noise in ["logs/app.log", "debug.log"] {
        assert!(
            !paths.contains(noise),
            "gitignored noise must stay out: {noise}"
        );
    }
    assert!(
        !paths
            .iter()
            .any(|p| p.starts_with("node_modules/") || p.starts_with("target/")),
        "built-in excludes must stay out"
    );
    for dir in ["node_modules", "target"] {
        assert!(
            out.excluded.iter().any(|p| p == dir),
            "excluded list must report {dir}"
        );
    }
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

/// Wait until the relay answers. Probe on a throwaway id so the test's own
/// workspace id stays unregistered (same pattern as the relay e2e tests).
fn wait_ready(url: &str) {
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
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("relay did not come up");
}

/// Chunk every scanned file with the writer's real chunker
/// (`chunk::chunk_file`), writing each chunk into `store_chunks` using the
/// LocalStore layout (`chunks/<hash[..2]>/<hash>`, plain writes — the
/// fixture must not pay per-chunk fsync, see the budget note above).
/// Returns the manifest file map and chunk/byte totals.
fn chunk_all(
    ws: &Path,
    scanned: &ScanOutcome,
    store_chunks: &Path,
) -> (BTreeMap<String, FileEntry>, usize, u64) {
    let mut files = BTreeMap::new();
    let mut chunk_count = 0usize;
    let mut chunk_bytes = 0u64;
    for f in &scanned.files {
        let mut hashes = Vec::new();
        for c in pear_core::chunk::chunk_file(&ws.join(&f.rel_path)).unwrap() {
            let c = c.unwrap();
            let dest = store_chunks.join(&c.hash[..2]).join(&c.hash);
            if !dest.exists() {
                std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                std::fs::write(&dest, &c.data).unwrap();
                chunk_bytes += c.data.len() as u64;
            }
            std::hint::black_box(&c.hash);
            hashes.push(c.hash);
            chunk_count += 1;
        }
        files.insert(
            f.rel_path.clone(),
            FileEntry {
                size: f.size,
                mode: f.mode,
                mtime_secs: f.mtime_secs,
                mtime_nanos: f.mtime_nanos,
                chunks: hashes,
            },
        );
    }
    (files, chunk_count, chunk_bytes)
}

// ---------- baselines ----------

/// §15 baselines 1-4. One test, run serially, so timings never overlap.
#[test]
#[ignore]
fn monorepo_baselines() {
    println!("== pear perf harness (debug build, seed {SEED:#x}) ==");
    let tmp = base_tempdir();

    // ----- 50k-file tree -----
    let ws = tmp.path().join("ws50k");
    std::fs::create_dir_all(&ws).unwrap();
    let t = Instant::now();
    let stats = gen_tree(&ws, 50_000, SEED);
    println!(
        "[gen] 50k tree: {} scannable files ({} bytes) across {} dirs, \
         {} excluded files, {} gitignored files — {}",
        stats.scannable_files,
        stats.scannable_bytes,
        stats.dirs,
        stats.excluded_files,
        stats.gitignored_files,
        secs(t.elapsed())
    );

    // Let mtimes settle past the chunk-cache granularity
    // (CACHE_SETTLE_SECS = 2s in sync.rs) so steady-state cycles reuse
    // chunks exactly like a real long-lived writer.
    std::thread::sleep(Duration::from_millis(2500));

    // (1) Cold scan + chunk of the 50k tree: the real double walk, then the
    // real per-file chunker. The chunk pass simultaneously fixture-seeds the
    // mirror's store (same bytes a cold cycle would have put there).
    let (meta, _) = pear_core::init_workspace(&ws, None).unwrap();
    let mirror = tmp.path().join("mirror50k");
    let store_chunks = mirror.join(".pear").join("store").join("chunks");

    let t = Instant::now();
    let scanned = pear_core::scan::scan(&ws).unwrap();
    let scan_t = t.elapsed();
    sanity_check(&scanned, &stats);

    let t = Instant::now();
    let (files, chunks, chunk_bytes) = chunk_all(&ws, &scanned, &store_chunks);
    let chunk_t = t.elapsed();

    // Fixture-seed the writer/mirror pair to the state a completed cold
    // cycle would leave: identical manifests on both sides, store populated.
    let manifest = Manifest {
        version: pear_core::FORMAT_VERSION,
        workspace_id: meta.id.clone(),
        scanned_at_secs: now_secs(),
        files,
    };
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(ws.join(".pear").join("manifest.json"), &manifest_json).unwrap();
    std::fs::create_dir_all(mirror.join(".pear")).unwrap();
    std::fs::write(mirror.join(".pear").join("manifest.json"), &manifest_json).unwrap();

    // (3) No-op cycle on the real pipeline, run before the edit.
    let t = Instant::now();
    let noop = sync_cycle(&ws, &mirror).unwrap();
    let noop_t = t.elapsed();
    assert!(noop.written.is_empty() && noop.deleted.is_empty());

    // (2) Steady-state cycle: one small file changed.
    let changed_rel = "pkg-00/src/f0000.rs";
    let mut body = std::fs::read(ws.join(changed_rel)).unwrap();
    body.extend_from_slice(b"// one more line\n");
    std::fs::write(ws.join(changed_rel), body).unwrap();
    let t = Instant::now();
    let steady = sync_cycle(&ws, &mirror).unwrap();
    let steady_t = t.elapsed();
    assert_eq!(steady.written, vec![changed_rel.to_string()]);

    println!(
        "[1] cold scan+chunk, 50k tree: scan {scan} + chunk {chunk} = {total} \
         ({files} files, {bytes} bytes in, {chunks} chunks/{cbytes} bytes out; \
         sink fsync excluded — see [4])",
        scan = secs(scan_t),
        chunk = secs(chunk_t),
        total = secs(scan_t + chunk_t),
        files = stats.scannable_files,
        bytes = stats.scannable_bytes,
        chunks = chunks,
        cbytes = chunk_bytes,
    );
    println!(
        "[2] steady-state cycle (one small file changed): {t} ({} file written, {} chunk uploaded)",
        steady.written.len(),
        steady.chunks_uploaded,
        t = secs(steady_t),
    );
    println!("[3] no-op cycle: {}", secs(noop_t));

    // ----- (4) end-to-end initial clone over a real local relay, 5k -----
    let writer = tmp.path().join("w5k");
    std::fs::create_dir_all(&writer).unwrap();
    let t = Instant::now();
    let stats5 = gen_tree(&writer, 5_000, SEED ^ 0x5);
    println!(
        "[gen] 5k tree: {} scannable files ({} bytes) — {}",
        stats5.scannable_files,
        stats5.scannable_bytes,
        secs(t.elapsed())
    );

    // The relay is async; host it on its own runtime (pear-core itself
    // stays synchronous). Same spawn pattern as crates/relay/tests/e2e.rs.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener =
        rt.block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().unwrap();
    let data_dir = tmp.path().join("relay-data");
    rt.spawn(async move {
        pear_relay::serve_on(listener, TOKEN, &data_dir)
            .await
            .expect("relay serve failed");
    });
    let url = format!("http://{addr}");
    wait_ready(&url);

    // Writer: init, register, push the whole tree.
    let (meta, _) = pear_core::init_workspace(&writer, None).unwrap();
    let w = RelayClient::new(&url, TOKEN, &meta.id, "device-w");
    w.create_workspace("perf5k").unwrap();
    let t = Instant::now();
    let pushed = push_cycle(&writer, &w, 0, false).unwrap();
    let push_t = t.elapsed();
    assert!(pushed.committed);

    // Mirror: init with the shared id, pull the whole tree.
    let mirror5 = tmp.path().join("m5k");
    pear_core::init_workspace(&mirror5, Some(&meta.id)).unwrap();
    let m = RelayClient::new(&url, TOKEN, &meta.id, "device-m");
    let t = Instant::now();
    let pulled = pull_once(&mirror5, &m).unwrap();
    let pull_t = t.elapsed();
    assert!(pulled.changed);

    // Print before asserting: timings must survive a convergence failure.
    println!(
        "[4] e2e initial clone over local relay, 5k tree: writer push {push} \
         ({pc} chunks, {pb} bytes up), mirror pull {pull} ({fc} chunks, {fb} bytes down); \
         total {total}",
        push = secs(push_t),
        pc = pushed.chunks_uploaded,
        pb = pushed.bytes_uploaded,
        pull = secs(pull_t),
        fc = pulled.chunks_fetched,
        fb = pulled.bytes_fetched,
        total = secs(push_t + pull_t),
    );

    // Converged = the synced set matches byte-for-byte. The writer tree
    // also holds gitignored noise and the excluded node_modules/target
    // trees, which must NOT cross to the mirror.
    let synced = pear_core::scan::scan(&writer).unwrap();
    let wtree = tree(&writer);
    let mtree = tree(&mirror5);
    assert_eq!(
        mtree.len(),
        synced.files.len(),
        "mirror must hold exactly the synced set"
    );
    for f in &synced.files {
        assert_eq!(
            wtree.get(&f.rel_path),
            mtree.get(&f.rel_path),
            "mirror content mismatch at {}",
            f.rel_path
        );
    }
}

// ---------- §27 500k watcher-load measurement ----------

/// Default worktree-file count for the §27 tree: with the §15 garnish that
/// lands at ~500k scannable files / ~2.5 GB. Overridable via
/// `PEAR_PERF_SCALE` for reduced-scale harness validation.
const SCALE_27: usize = 500_000;
/// The 500k tree gets its own seed so its shape is independent of the §15
/// 50k/5k trees (which stay byte-identical: `gen_tree` is untouched).
const SEED_27: u64 = SEED ^ 0x27;
/// §27's mass-edit burst: a git-checkout-style mtime bump of 10k files.
const MASS_EDIT_FILES: usize = 10_000;

/// Written next to a generated tree so later runs can reuse it: at 500k,
/// generation takes minutes and ~2.5 GB, and the §15 harness's auto-cleaned
/// tempdirs would pay that on every run.
#[derive(serde::Serialize, serde::Deserialize)]
struct GenMarker {
    scale: usize,
    seed: u64,
    stats: GenStats,
}

/// Persistent dir for the §27 artifacts: under CARGO_TARGET_TMPDIR
/// (target/tmp) when cargo sets it — same volume rationale as
/// `base_tempdir`. NOT auto-cleaned; delete it to force regeneration.
fn perf27_dir() -> PathBuf {
    let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("perf27");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Generate the §27 tree, or reuse an existing one whose marker matches
/// `scale`/`seed`. The returned Option is the generation wall time — None
/// when the tree was reused.
fn gen_or_reuse(scale: usize, seed: u64) -> (PathBuf, GenStats, Option<Duration>) {
    let base = perf27_dir();
    let ws = base.join(format!("ws-{scale}"));
    let marker_path = base.join(format!("ws-{scale}.gen.json"));
    let marker = std::fs::read(&marker_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<GenMarker>(&bytes).ok())
        .filter(|m| m.scale == scale && m.seed == seed);
    if ws.is_dir() {
        if let Some(marker) = marker {
            return (ws, marker.stats, None);
        }
        // Interrupted generation or stale params: wipe and regenerate.
        std::fs::remove_dir_all(&ws).unwrap();
    }
    std::fs::create_dir_all(&ws).unwrap();
    let t = Instant::now();
    let stats = gen_tree(&ws, scale, seed);
    let gen_t = t.elapsed();
    let marker = GenMarker { scale, seed, stats };
    std::fs::write(&marker_path, serde_json::to_vec_pretty(&marker).unwrap()).unwrap();
    (ws, marker.stats, Some(gen_t))
}

/// Best-effort RSS of this process in bytes via `ps -o rss= -p <pid>`
/// (reported in KiB on both macOS and Linux). None when `ps` fails or its
/// output does not parse — RSS reporting must never fail the measurement.
fn rss_bytes() -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
        .map(|kib| kib * 1024)
}

fn mib(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => (b / 1048576).to_string(),
        None => "n/a".to_string(),
    }
}

/// §27 500k watcher-load measurement (DESIGN.md §27): the §15 baselines'
/// methodology at ~500k scannable files / ~2.5 GB — cold scan + chunk,
/// steady-state no-op cycle, manifest.json size + per-cycle parse cost,
/// recursive watcher registration wall time + RSS delta, and a 10k-file
/// mass-edit (git-checkout-style mtime bump) converged through the real
/// `watch_loop`/`sync_cycle` path. Numbers are reference points, not SLAs;
/// the verdict rule (linear vs 50k) is DESIGN.md §27's, not this test's.
///
/// Full measurement (release mode per §26; run solo via the name filter so
/// timings never overlap the other perf tests):
///
/// ```sh
/// cargo test --release -p pear-core --test perf -- --ignored --nocapture watcher_load_500k
/// ```
///
/// The tree lives at `<target tmp>/perf27/ws-<scale>` and is REUSED across
/// runs (generation takes minutes, ~2.5 GB; the mirror store adds another
/// ~2.5 GB) — delete the `perf27` dir to force regeneration. The mirror
/// store is rebuilt every run so [27.1] includes the fixture-seed writes
/// exactly like §15 [1]. `PEAR_PERF_SCALE=<n>` shrinks the tree for
/// reduced-scale harness validation (default 500_000; the mass-edit burst
/// stays 10k files), e.g.:
///
/// ```sh
/// PEAR_PERF_SCALE=50000 cargo test -p pear-core --test perf -- --ignored --nocapture watcher_load_500k
/// ```
#[test]
#[ignore]
fn watcher_load_500k() {
    let scale = std::env::var("PEAR_PERF_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SCALE_27);
    let mode = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // ----- tree: generate once, reuse across runs -----
    let (ws, stats, gen_t) = gen_or_reuse(scale, SEED_27);
    println!(
        "== §27 watcher-load measurement ({mode} build, scale {scale}, \
         seed {SEED_27:#x}, tree {}) ==",
        ws.display()
    );
    match gen_t {
        Some(t) => println!(
            "[gen] {scale} tree: {} scannable files ({} bytes) across {} dirs, \
             {} excluded files, {} gitignored files — {} (fresh)",
            stats.scannable_files,
            stats.scannable_bytes,
            stats.dirs,
            stats.excluded_files,
            stats.gitignored_files,
            secs(t),
        ),
        None => println!(
            "[gen] {scale} tree: {} scannable files ({} bytes) across {} dirs — reused",
            stats.scannable_files, stats.scannable_bytes, stats.dirs,
        ),
    }
    // Let mtimes settle past the chunk-cache granularity (see §15). Cheap
    // insurance on reuse, required on a fresh tree.
    std::thread::sleep(Duration::from_millis(2500));

    // The mirror store is rebuilt every run: [27.1]'s chunk pass includes
    // the fixture-seed writes exactly like §15 [1].
    let mirror = perf27_dir().join(format!("mirror-{scale}"));
    if mirror.exists() {
        std::fs::remove_dir_all(&mirror).unwrap();
    }
    let store_chunks = mirror.join(".pear").join("store").join("chunks");
    let (meta, _) = pear_core::init_workspace(&ws, None).unwrap();

    // ----- [27.1] cold scan + chunk (§15 [1] contract: no sink fsync) -----
    let t = Instant::now();
    let scanned = pear_core::scan::scan(&ws).unwrap();
    let scan_t = t.elapsed();
    sanity_check(&scanned, &stats);

    let t = Instant::now();
    let (files, chunks, chunk_bytes) = chunk_all(&ws, &scanned, &store_chunks);
    let chunk_t = t.elapsed();

    // Fixture-seed the writer/mirror pair (same idiom as §15): identical
    // manifests on both sides, store populated by the chunk pass.
    let manifest = Manifest {
        version: pear_core::FORMAT_VERSION,
        workspace_id: meta.id.clone(),
        scanned_at_secs: now_secs(),
        files,
    };
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(ws.join(".pear").join("manifest.json"), &manifest_json).unwrap();
    std::fs::create_dir_all(mirror.join(".pear")).unwrap();
    std::fs::write(mirror.join(".pear").join("manifest.json"), &manifest_json).unwrap();
    println!(
        "[27.1] cold scan+chunk, {scale} tree: scan {scan} + chunk {chunk} = {total} \
         ({files} files, {bytes} bytes in, {chunks} chunks/{cbytes} bytes out; \
         sink fsync excluded — see §15 [1])",
        scan = secs(scan_t),
        chunk = secs(chunk_t),
        total = secs(scan_t + chunk_t),
        files = stats.scannable_files,
        bytes = stats.scannable_bytes,
        chunks = chunks,
        cbytes = chunk_bytes,
    );

    // ----- [27.2] steady-state no-op sync_cycle (§15 [3] equivalent) -----
    let t = Instant::now();
    let noop = sync_cycle(&ws, &mirror).unwrap();
    let noop_t = t.elapsed();
    assert!(noop.written.is_empty() && noop.deleted.is_empty());
    println!("[27.2] no-op sync_cycle, {scale} tree: {}", secs(noop_t));

    // ----- [27.3] manifest.json size + per-cycle parse cost -----
    // The no-op cycle just rewrote the source manifest via the real
    // `write_atomic` (pretty JSON), so this is the exact file every cycle
    // parses. `manifest::load` includes validation — the real per-cycle cost.
    let manifest_path = ws.join(".pear").join("manifest.json");
    let manifest_bytes = std::fs::metadata(&manifest_path).unwrap().len();
    let mut load_ts = Vec::new();
    let mut loaded_entries = 0usize;
    for _ in 0..3 {
        let t = Instant::now();
        let m = manifest::load(&manifest_path).unwrap().unwrap();
        load_ts.push(secs(t.elapsed()));
        loaded_entries = m.files.len();
    }
    println!(
        "[27.3] manifest.json at {loaded_entries} entries: {manifest_bytes} bytes; \
         manifest::load {} (3 runs, warm page cache)",
        load_ts.join("/"),
    );

    // ----- [27.4] recursive watcher registration: wall time + RSS delta -----
    let rss_before = rss_bytes();
    let (ev_tx, ev_rx) = channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = ev_tx.send(res);
    })
    .unwrap();
    let t = Instant::now();
    watcher.watch(&ws, RecursiveMode::Recursive).unwrap();
    let reg_t = t.elapsed();
    // Let the backend (FSEvents here, inotify on Linux) settle before the
    // RSS sample. This watcher stays live: [27.5] reuses its channel to
    // count mass-edit events.
    std::thread::sleep(Duration::from_secs(2));
    let rss_after = rss_bytes();
    let rss_delta = match (rss_before, rss_after) {
        (Some(b), Some(a)) => ((a as i64 - b as i64) / 1048576).to_string(),
        _ => "n/a".to_string(),
    };
    println!(
        "[27.4] watcher registration, {scale} tree: register {} + RSS {} -> {} MiB \
         (delta {rss_delta} MiB, best-effort `ps`)",
        secs(reg_t),
        mib(rss_before),
        mib(rss_after),
    );

    // ----- [27.5] mass-edit: 10k mtime bumps, converge via watch_loop -----
    // The watch loop drives the REAL sync_cycle path ws -> mirror; each
    // completed cycle reports its written set over the channel.
    let (cycle_tx, cycle_rx) = channel::<Vec<String>>();
    {
        let ws_t = ws.clone();
        let mirror_t = mirror.clone();
        std::thread::spawn(move || {
            if let Err(e) = pear_core::watch::watch_loop(&ws_t, &mirror_t, move |report| {
                let _ = cycle_tx.send(report.written.clone());
            }) {
                eprintln!("pear: §27 watch_loop exited: {e:#}");
            }
        });
    }
    // The initial cycle must complete (a no-op — the tree has been quiet
    // since [27.2]) before the burst starts. Timeout scales off the
    // measured no-op cycle so full-scale runs are not falsely failed.
    let init_timeout = Duration::from_secs(60) + noop_t * 20;
    let initial = cycle_rx
        .recv_timeout(init_timeout)
        .expect("watch_loop initial cycle must complete");
    assert!(
        initial.is_empty(),
        "watch_loop initial cycle must be a no-op, wrote {} files",
        initial.len()
    );
    // Drop events the earlier phases queued on the counting watcher.
    while ev_rx.try_recv().is_ok() {}

    // Deterministic burst selection: strided across the whole fan-out so
    // the burst hits as many watched dirs as the tree allows.
    let mut pkg_files: Vec<&str> = scanned
        .files
        .iter()
        .map(|f| f.rel_path.as_str())
        .filter(|p| p.starts_with("pkg-"))
        .collect();
    pkg_files.sort_unstable();
    let n_touch = MASS_EDIT_FILES.min(pkg_files.len());
    assert!(
        n_touch > 0,
        "scale {scale} has no pkg files for the mass-edit burst"
    );
    let stride = (pkg_files.len() / n_touch).max(1);
    let touched: Vec<String> = pkg_files
        .iter()
        .step_by(stride)
        .take(n_touch)
        .map(|s| s.to_string())
        .collect();

    let t0 = Instant::now();
    let burst_mtime = filetime::FileTime::from_system_time(std::time::SystemTime::now());
    for rel in &touched {
        filetime::set_file_mtime(ws.join(rel), burst_mtime).unwrap();
    }
    let burst_t = t0.elapsed();

    // Converged = post-burst cycles have collectively rewritten every
    // touched file on the mirror (an mtime bump re-chunks to identical
    // hashes but still diffs + applies — the real git-checkout cost).
    // Watcher events are counted over the same window.
    let mut remaining: HashSet<&str> = touched.iter().map(String::as_str).collect();
    let mut events = 0usize;
    let mut event_paths = 0usize;
    let mut cycles = 0usize;
    let deadline = t0 + Duration::from_secs(120) + noop_t * 40;
    let converged_at = loop {
        while let Ok(ev) = ev_rx.try_recv() {
            events += 1;
            if let Ok(ev) = &ev {
                event_paths += ev.paths.len();
            }
        }
        match cycle_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(written) => {
                cycles += 1;
                for rel in &written {
                    remaining.remove(rel.as_str());
                }
                if remaining.is_empty() {
                    break Some(t0.elapsed());
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    break None;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break None,
        }
    };
    // Final drain so the count covers the whole convergence window.
    while let Ok(ev) = ev_rx.try_recv() {
        events += 1;
        if let Ok(ev) = &ev {
            event_paths += ev.paths.len();
        }
    }
    // Print before asserting: timings must survive a convergence failure.
    match converged_at {
        Some(conv_t) => println!(
            "[27.5] mass-edit, {scale} tree: mtime-bumped {} files in {} (burst); \
             converged in {} from burst start ({cycles} sync_cycle(s), \
             {events} watcher events/{event_paths} paths received)",
            touched.len(),
            secs(burst_t),
            secs(conv_t),
        ),
        None => println!(
            "[27.5] mass-edit, {scale} tree: mtime-bumped {} files in {} (burst); \
             NOT CONVERGED within {} ({} files pending, {cycles} cycle(s), \
             {events} watcher events/{event_paths} paths)",
            touched.len(),
            secs(burst_t),
            secs(deadline - t0),
            remaining.len(),
        ),
    }
    assert!(
        converged_at.is_some(),
        "mass-edit burst did not converge ({} files pending)",
        remaining.len()
    );
}

/// The §15 single-walk experiment, kept re-runnable: pins how the `ignore`
/// crate's override layer (0.4.31, per Cargo.lock) composes with gitignore.
/// Finding: with any whitelist glob present, every unmatched *file* is
/// ignored outright (override matches short-circuit gitignore; non-matches
/// only defer when NO whitelist glob exists), so "respect gitignore, but
/// force-include `.env*`/`.git/**`/pear.toml includes" is not expressible.
/// If an `ignore` upgrade ever flips these outcomes, revisit the
/// single-walk scan (DESIGN.md §15).
#[test]
#[ignore]
fn override_layer_probe() {
    let tmp = base_tempdir();
    let root = tmp.path();
    write_at(root, ".gitignore", b"*.log\nlogs/\n.env\n");
    write_at(root, ".env", b"A=1\n");
    write_at(root, "README.md", b"# x\n");
    write_at(root, "src/main.rs", b"fn main() {}\n");
    write_at(root, "src/app.log", b"log\n");
    write_at(root, ".git/HEAD", b"ref: refs/heads/main\n");
    write_at(root, ".git/logs/HEAD", b"commit\n");
    write_at(root, "logs/x.txt", b"noise\n");

    let collect = |globs: Option<&[&str]>| {
        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false)
            .git_ignore(true)
            .git_exclude(true)
            .git_global(false)
            .parents(false)
            .require_git(false)
            .follow_links(false);
        if let Some(globs) = globs {
            let mut ov = OverrideBuilder::new(root);
            for g in globs {
                ov.add(g).unwrap();
            }
            builder.overrides(ov.build().unwrap());
        }
        let mut files = Vec::new();
        for entry in builder.build().flatten() {
            if entry.file_type().is_some_and(|ft| ft.is_file()) {
                let rel = entry.path().strip_prefix(root).unwrap();
                files.push(rel.to_string_lossy().into_owned());
            }
        }
        files.sort();
        files
    };

    type Scenario = (
        &'static str,
        Option<&'static [&'static str]>,
        Vec<&'static str>,
    );
    let scenarios: [Scenario; 5] = [
        (
            "A: whitelist .env*/.git — the composition single-walk needs",
            Some(&[".env*", ".git", ".git/**"]),
            vec![".env", ".git/HEAD", ".git/logs/HEAD"],
        ),
        (
            "B: blacklist-only control (!*.log) — unmatched defers to gitignore",
            Some(&["!*.log"]),
            vec![".git/HEAD", ".gitignore", "README.md", "src/main.rs"],
        ),
        (
            "C: whitelist ** + .env* — gitignore is dead",
            Some(&["**", ".env*"]),
            vec![
                ".env",
                ".git/HEAD",
                ".git/logs/HEAD",
                ".gitignore",
                "README.md",
                "logs/x.txt",
                "src/app.log",
                "src/main.rs",
            ],
        ),
        (
            "D: no overrides — .git is not auto-skipped, gitignore applies",
            None,
            vec![".git/HEAD", ".gitignore", "README.md", "src/main.rs"],
        ),
        (
            "E: whitelist with **/ prefix variants — same flip as A",
            Some(&["**/.env*", ".git/**"]),
            vec![".env", ".git/HEAD", ".git/logs/HEAD"],
        ),
    ];
    for (name, globs, want) in scenarios {
        let got = collect(globs);
        println!("{name}\n  -> {got:?}");
        assert_eq!(got, want, "scenario outcome changed: {name}");
    }
}
