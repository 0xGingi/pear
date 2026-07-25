//! Relay client and writer/mirror flows against an in-process mock relay:
//! a minimal but stateful implementation of the §11 HTTP API over a raw
//! TCP listener. The real end-to-end test lives in `crates/relay/tests`.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use pear_core::manifest::Manifest;
use pear_core::relay::{RelayClient, RelayError};
use pear_core::store::{ChunkSink, ChunkSource};
use pear_core::sync::{pull_once, push_cycle, PushError};

const TOKEN: &str = "test-token";

// ---------- mock relay ----------

type Handler = Arc<dyn Fn(&str, &[u8]) -> (u16, Vec<u8>) + Send + Sync>;

struct MockRelay {
    addr: SocketAddr,
    /// Request lines + headers of everything received, for assertions.
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockRelay {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut stream) = conn else { continue };
                let (head, body) = match read_request(&mut stream) {
                    Ok(r) => r,
                    Err(_) => continue, // client gave up; keep serving
                };
                seen.lock().unwrap().push(head.clone());
                let (status, resp_body) = handler(&head, &body);
                let _ = write_response(&mut stream, status, &resp_body);
            }
        });
        Self { addr, requests }
    }

    /// A stateful §11/§32 relay: global chunk pool, CAS head, no lease.
    fn start_stateful() -> (Self, Arc<Mutex<RelayState>>) {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let shared = state.clone();
        let mock = Self::start(Arc::new(move |head, body| route(&shared, head, body)));
        (mock, state)
    }
}

#[derive(Default)]
struct RelayState {
    chunks: HashMap<String, Vec<u8>>,
    head_seq: u64,
    /// (hash, manifest, manifest_enc) — exactly one of the latter two is
    /// set, per the workspace's e2e flag (§17).
    head: Option<(String, serde_json::Value, Option<String>)>,
    snapshots: Vec<SnapshotRow>,
    /// Workspace id -> name, recorded on create (for §13 name resolution).
    workspaces: HashMap<String, String>,
    /// The workspace's §17 flag, recorded on create.
    e2e: bool,
    /// §30: per `get_many` request, (hashes served, payload bytes) — lets
    /// tests assert on the client's batch splitting without sniffing
    /// frames.
    get_many_served: Vec<(usize, u64)>,
}

/// A snapshot row in the mock: per-workspace incrementing id, metadata,
/// and the manifest as submitted (plaintext or, for e2e, the base64 blob).
struct SnapshotRow {
    id: u64,
    name: Option<String>,
    kind: String,
    device: String,
    created_at: i64,
    manifest: serde_json::Value,
    manifest_enc: Option<String>,
}

impl SnapshotRow {
    fn info_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "device": self.device,
            "created_at": self.created_at,
        })
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        assert!(head.len() <= 64 * 1024, "request head too large");
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;
    Ok((head, body))
}

fn write_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn json(status: u16, value: serde_json::Value) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(&value).unwrap())
}

/// Route one request against the stateful mock. `head` starts with the
/// request line (`METHOD PATH HTTP/1.1`).
fn route(state: &Arc<Mutex<RelayState>>, head: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    assert_eq!(seg[0], "v1", "unexpected path {path}");
    // §13 name resolution: GET /v1/teams/:team/workspaces/:name. The mock
    // does not model teams or roles — any team segment resolves any
    // recorded workspace name.
    if seg.len() >= 2 && seg[1] == "teams" {
        assert!(
            method == "GET" && seg.len() == 5 && seg[3] == "workspaces",
            "unexpected path {path}"
        );
        let st = state.lock().unwrap();
        return match st
            .workspaces
            .iter()
            .find(|(_, name)| name.as_str() == seg[4])
        {
            Some((id, name)) => json(
                200,
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "head_seq": st.head_seq,
                    "head_hash": st.head.as_ref().map(|(h, _, _)| h),
                    "e2e": st.e2e,
                }),
            ),
            None => json(404, serde_json::json!({ "error": "no such workspace" })),
        };
    }
    // Collection route: POST /v1/workspaces.
    if method == "POST" && seg.len() == 2 && seg[1] == "workspaces" {
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        let mut st = state.lock().unwrap();
        st.workspaces.insert(
            body["id"].as_str().unwrap().to_string(),
            body["name"].as_str().unwrap().to_string(),
        );
        st.e2e = body["e2e"].as_bool().unwrap_or(false);
        return json(
            201,
            serde_json::json!({ "id": seg.get(2).copied().unwrap_or("ws") }),
        );
    }
    // All other routes are /v1/workspaces/:id[/...].
    assert!(
        seg.len() >= 3 && seg[1] == "workspaces",
        "unexpected path {path}"
    );
    let rest = &seg[3..];
    let mut st = state.lock().unwrap();
    match (method, rest) {
        ("POST", []) => json(201, serde_json::json!({ "id": seg[2] })),
        ("GET", []) => json(
            200,
            serde_json::json!({
                "id": seg[2],
                "name": "mock",
                "head_seq": st.head_seq,
                "head_hash": st.head.as_ref().map(|(h, _, _)| h),
                "e2e": st.e2e,
            }),
        ),
        ("PUT", ["chunks", hash]) => {
            st.chunks.insert((*hash).to_string(), body.to_vec());
            json(200, serde_json::json!({}))
        }
        ("GET", ["chunks", hash]) => match st.chunks.get(*hash) {
            Some(data) => (200, data.clone()),
            None => json(404, serde_json::json!({ "error": "no such chunk" })),
        },
        ("POST", ["chunks", "missing"]) => {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            let missing: Vec<&str> = body["hashes"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|h| h.as_str())
                .filter(|h| !st.chunks.contains_key(*h))
                .collect();
            json(200, serde_json::json!({ "missing": missing }))
        }
        // §23 batched upload: per-entry statuses exactly like the real
        // relay — stored / present / error (a bad entry fails only
        // itself, never the batch).
        ("POST", ["chunks", "put_many"]) => {
            let entries = pear_core::chunk_frame::decode(body).unwrap();
            let mut results = Vec::new();
            for (hash, data) in entries {
                if blake3::hash(&data).to_hex().as_str() != hash {
                    results.push(serde_json::json!({
                        "hash": hash,
                        "status": "error",
                        "reason": "chunk body does not hash to its claimed BLAKE3",
                    }));
                    continue;
                }
                let stored = st.chunks.insert(hash.clone(), data).is_none();
                results.push(serde_json::json!({
                    "hash": hash,
                    "status": if stored { "stored" } else { "present" },
                }));
            }
            json(200, serde_json::json!({ "results": results }))
        }
        // §23 batched download: one frame in request order; any absent
        // hash fails the whole request with a 404 naming it.
        ("POST", ["chunks", "get_many"]) => {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            let hashes: Vec<&str> = body["hashes"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|h| h.as_str())
                .collect();
            let mut entries: Vec<(&str, &[u8])> = Vec::with_capacity(hashes.len());
            let mut served_bytes = 0u64;
            for hash in hashes {
                match st.chunks.get(hash) {
                    Some(data) => {
                        served_bytes += data.len() as u64;
                        entries.push((hash, data.as_slice()));
                    }
                    None => {
                        return json(
                            404,
                            serde_json::json!({ "error": format!("chunk {hash:?} not found") }),
                        );
                    }
                }
            }
            let served = (entries.len(), served_bytes);
            let frame = pear_core::chunk_frame::encode(entries.into_iter());
            st.get_many_served.push(served);
            (200, frame)
        }
        ("GET", ["head"]) => match &st.head {
            Some((hash, manifest, manifest_enc)) => {
                if st.e2e {
                    json(
                        200,
                        serde_json::json!({ "seq": st.head_seq, "hash": hash, "manifest_enc": manifest_enc, "e2e": true }),
                    )
                } else {
                    json(
                        200,
                        serde_json::json!({ "seq": st.head_seq, "hash": hash, "manifest": manifest, "e2e": false }),
                    )
                }
            }
            None => json(404, serde_json::json!({ "error": "no head" })),
        },
        ("PUT", ["head"]) => {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            if body["base_seq"].as_u64().unwrap() != st.head_seq {
                return json(409, serde_json::json!({ "current_seq": st.head_seq }));
            }
            // §32: the device header is attribution only — required,
            // never authorizing. The CAS above is the whole contract.
            if header(head, "x-pear-device").is_none() {
                return json(403, serde_json::json!({ "error": "missing X-Pear-Device" }));
            }
            st.head_seq += 1;
            // §17: an e2e commit carries manifest_enc (stored verbatim;
            // hash = BLAKE3 of it) instead of a plaintext manifest.
            if let Some(enc) = body["manifest_enc"].as_str() {
                let hash = blake3::hash(enc.as_bytes()).to_hex().to_string();
                st.head = Some((hash.clone(), serde_json::Value::Null, Some(enc.to_string())));
                return json(200, serde_json::json!({ "seq": st.head_seq, "hash": hash }));
            }
            let manifest = body["manifest"].clone();
            let hash = blake3::hash(&serde_json::to_vec(&manifest).unwrap())
                .to_hex()
                .to_string();
            st.head = Some((hash.clone(), manifest, None));
            json(200, serde_json::json!({ "seq": st.head_seq, "hash": hash }))
        }
        ("POST", ["snapshots"]) => {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            let id = st.snapshots.len() as u64 + 1;
            let created_at = 1_700_000_000i64 + id as i64;
            st.snapshots.push(SnapshotRow {
                id,
                name: body["name"].as_str().map(str::to_string),
                kind: "named".to_string(),
                device: body["device"].as_str().unwrap_or_default().to_string(),
                created_at,
                manifest: body["manifest"].clone(),
                manifest_enc: body["manifest_enc"].as_str().map(str::to_string),
            });
            (
                201,
                serde_json::to_vec(&serde_json::json!({
                    "id": id,
                    "created_at": created_at,
                }))
                .unwrap(),
            )
        }
        ("GET", ["snapshots"]) => {
            // Newest first.
            let list: Vec<serde_json::Value> = st
                .snapshots
                .iter()
                .rev()
                .map(SnapshotRow::info_json)
                .collect();
            json(200, serde_json::json!({ "snapshots": list }))
        }
        ("GET", ["snapshots", sid]) => {
            let sid: u64 = sid.parse().unwrap_or(0);
            match st.snapshots.iter().find(|s| s.id == sid) {
                Some(s) => {
                    let mut full = s.info_json();
                    full["e2e"] = serde_json::json!(st.e2e);
                    if s.manifest_enc.is_some() {
                        full["manifest_enc"] = serde_json::json!(s.manifest_enc);
                    } else {
                        full["manifest"] = s.manifest.clone();
                    }
                    json(200, full)
                }
                None => json(404, serde_json::json!({ "error": "no such snapshot" })),
            }
        }
        _ => json(404, serde_json::json!({ "error": "no route" })),
    }
}

/// Extract a header value from the raw request head.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

// ---------- helpers ----------

fn client(mock: &MockRelay, workspace: &str, device: &str) -> RelayClient {
    RelayClient::new(&mock.url(), TOKEN, workspace, device)
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

/// Deterministic pseudo-random bytes (distinct per seed) for blob files.
fn prng_bytes(mut seed: u64, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(n);
    out
}

// ---------- tests ----------

#[test]
fn client_error_mapping_and_head_headers() {
    let (mock, _state) = MockRelay::start_stateful();
    let ws = "ws-1";
    let a = client(&mock, ws, "device-a");

    // §32: no lease to acquire — a head commit is just the CAS.
    let manifest = Manifest::new(ws.to_string());
    a.create_workspace("ws").unwrap();
    let commit = a.put_head(0, &manifest).unwrap();
    assert_eq!(commit.seq, 1);

    // CAS conflict carries the relay's current seq.
    let err = a.put_head(0, &manifest).unwrap_err();
    assert!(
        matches!(err, RelayError::HeadConflict { current_seq: 1 }),
        "got {err:?}"
    );

    // A second device with the right base_seq simply commits: concurrent
    // writers are legal, and the CAS is the only serialization.
    let b = client(&mock, ws, "device-b");
    assert_eq!(b.put_head(1, &manifest).unwrap().seq, 2);
    // ...and the first device now loses the CAS, not a fencing check.
    let err = a.put_head(1, &manifest).unwrap_err();
    assert!(
        matches!(err, RelayError::HeadConflict { current_seq: 2 }),
        "got {err:?}"
    );

    // 404 maps to NotFound; ChunkSource surfaces it as ErrorKind::NotFound.
    let missing = blake3::hash(b"nope").to_hex().to_string();
    let err = ChunkSource::get(&a, &missing).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

    // Every request carried the bearer token; head commits carry the
    // device attribution header and NOTHING else (§32: no generation).
    let requests = mock.requests.lock().unwrap();
    assert!(!requests.is_empty());
    for head in requests.iter() {
        assert_eq!(
            header(head, "authorization").as_deref(),
            Some("Bearer test-token")
        );
    }
    let put_heads: Vec<&String> = requests
        .iter()
        .filter(|h| h.starts_with("PUT /v1/workspaces/ws-1/head "))
        .collect();
    assert_eq!(put_heads.len(), 4);
    assert_eq!(
        header(put_heads[0], "x-pear-device").as_deref(),
        Some("device-a")
    );
    assert!(
        put_heads
            .iter()
            .all(|h| header(h, "x-pear-generation").is_none()),
        "the fencing header is gone (§32)"
    );
}

#[test]
fn has_many_uses_the_batch_endpoint() {
    let (mock, _state) = MockRelay::start_stateful();
    let c = client(&mock, "ws-2", "device-a");
    let h1 = blake3::hash(b"one").to_hex().to_string();
    let h2 = blake3::hash(b"two").to_hex().to_string();
    let h3 = blake3::hash(b"three").to_hex().to_string();
    c.put_chunk(&h1, b"one").unwrap();
    c.put_chunk(&h3, b"three").unwrap();

    let present = c.has_many(&[h1, h2, h3]).unwrap();
    assert_eq!(present, vec![true, false, true]);

    // One batch call, zero per-chunk GETs.
    let requests = mock.requests.lock().unwrap();
    let missing_calls = requests
        .iter()
        .filter(|h| h.starts_with("POST /v1/workspaces/ws-2/chunks/missing "))
        .count();
    assert_eq!(missing_calls, 1);
    assert!(!requests
        .iter()
        .any(|h| h.contains("/chunks/") && h.starts_with("GET ")));
}

#[test]
fn has_uses_the_batch_endpoint_not_a_download() {
    let (mock, _state) = MockRelay::start_stateful();
    let c = client(&mock, "ws-3", "device-a");
    let h = blake3::hash(b"data").to_hex().to_string();
    c.put_chunk(&h, b"data").unwrap();

    assert!(ChunkSink::has(&c, &h).unwrap());
    let missing = blake3::hash(b"nope").to_hex().to_string();
    assert!(!ChunkSink::has(&c, &missing).unwrap());

    let requests = mock.requests.lock().unwrap();
    assert!(
        !requests
            .iter()
            .any(|r| r.starts_with("GET /v1/workspaces/ws-3/chunks/")),
        "has must not download chunk bodies"
    );
}

/// §23: a full push/pull round trip must not make ANY per-chunk HTTP
/// calls — the up-leg is one `chunks/put_many`, the down-leg one
/// `chunks/get_many` (small transfers; sub-batch splitting is exercised
/// by the relay/client unit-level contracts).
#[test]
fn push_and_pull_use_the_batched_chunk_endpoints() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f1.txt", b"first file\n");
    write(&dir_a, "f2.txt", b"second file\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    let report = push_cycle(&dir_a, &a, 0, false).unwrap();
    assert_eq!(report.chunks_uploaded, 2);

    let (_meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert_eq!(pulled.chunks_fetched, 2);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    let requests = mock.requests.lock().unwrap();
    let count = |method: &str, mark: &str| {
        requests
            .iter()
            .filter(|h| h.starts_with(method) && h.contains(mark))
            .count()
    };
    assert_eq!(
        count("PUT ", "/chunks/"),
        0,
        "no single-chunk PUTs on the push leg: {requests:?}"
    );
    assert_eq!(
        count("GET ", "/chunks/"),
        0,
        "no single-chunk GETs on the pull leg: {requests:?}"
    );
    assert_eq!(count("POST ", "/chunks/put_many"), 1);
    assert_eq!(count("POST ", "/chunks/get_many"), 1);
}

/// §30: a pull of mixed small + 4 MiB-blob files issues MULTIPLE
/// `chunks/get_many` requests, none over the 32 MiB byte budget — the
/// manifest's per-file sizes let the mirror split by bytes (a file's
/// chunks partition it exactly) instead of by hash count alone. Count-only
/// splitting would make this ONE ≤128-hash request of ~40 MiB. The pull
/// still converges with exact counters.
#[test]
fn pull_splits_get_many_by_the_byte_budget() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();

    // Ten distinct 4 MiB blobs (40 MiB total: far over the 32 MiB budget,
    // far under the 128-hash cap) plus three small files.
    const BLOB: usize = 4 * 1024 * 1024;
    let mut total_bytes = 0u64;
    for i in 0..10u64 {
        write(&dir_a, &format!("blob-{i:02}.bin"), &prng_bytes(1000 + i, BLOB));
        total_bytes += BLOB as u64;
    }
    for i in 0..3 {
        let data = format!("small file {i}\n");
        total_bytes += data.len() as u64;
        write(&dir_a, &format!("small-{i}.txt"), data.as_bytes());
    }

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let (_meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b), "the pull still converges");
    assert_eq!(pulled.bytes_fetched, total_bytes);

    let log = &state.lock().unwrap().get_many_served;
    assert_eq!(log.len(), 2, "the byte budget splits the fetch: {log:?}");
    for (hashes, bytes) in log {
        assert!(
            *bytes <= pear_core::chunk_frame::GET_MANY_TARGET_BYTES,
            "a batch exceeded the byte budget: {log:?}"
        );
        assert!(
            *hashes <= pear_core::chunk_frame::GET_MANY_MAX_HASHES,
            "a batch exceeded the hash cap: {log:?}"
        );
    }
    // First-fit packs the first batch to EXACTLY the budget: the 8 sorted
    // blob files at 4 MiB each; the remaining two + the smalls follow.
    assert_eq!(log[0].1, pear_core::chunk_frame::GET_MANY_TARGET_BYTES);
    // Every served chunk was downloaded once, verified, and counted.
    let served_bytes: u64 = log.iter().map(|(_, b)| b).sum();
    let served_hashes: usize = log.iter().map(|(h, _)| h).sum();
    assert_eq!(served_bytes, total_bytes);
    assert_eq!(served_hashes, pulled.chunks_fetched);
}

#[test]
fn push_pull_converges_and_idles() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();

    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, ".git/HEAD", b"ref: refs/heads/main\n");

    // Writer A: init, register, acquire, push.
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    let report = push_cycle(&dir_a, &a, 0, false).unwrap();
    assert!(report.committed);
    assert_eq!(report.head_seq, 1);
    assert_eq!(report.chunks_uploaded, 3);

    // Mirror B: init with the remote id, pull -> byte-identical tree.
    let (meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    assert_eq!(meta_b.id, meta.id);
    let b = client(&mock, &meta.id, "device-b");
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    assert_eq!(pulled.head_seq, 1);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(
        std::fs::read(dir_b.join(".env")).unwrap(),
        b"SECRET=hunter2\n"
    );

    // Unchanged seq: the mirror idles.
    let idle = pull_once(&dir_b, &b).unwrap();
    assert!(!idle.changed);
    assert_eq!(idle.head_seq, 1);

    // A no-change push does not bump the head.
    let noop = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(!noop.committed);
    assert_eq!(noop.head_seq, 1);

    // Edit propagates; only the changed file's chunk crosses the wire.
    std::fs::write(
        dir_a.join("src/main.rs"),
        b"fn main() { println!(\"hi\"); }\n",
    )
    .unwrap();
    let report = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(report.committed);
    assert_eq!(report.head_seq, 2);
    assert_eq!(report.chunks_uploaded, 1);
    assert_eq!(report.changed, vec!["src/main.rs".to_string()]);
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // Delete propagates.
    std::fs::remove_file(dir_a.join(".env")).unwrap();
    let report = push_cycle(&dir_a, &a, 2, false).unwrap();
    assert_eq!(report.deleted, vec![".env".to_string()]);
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    assert_eq!(pulled.deleted, vec![".env".to_string()]);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert!(!dir_b.join(".env").exists());

    // The writer's own manifest cache makes a repeat push a pure no-op:
    // no chunk uploads, no head commit.
    let noop = push_cycle(&dir_a, &a, 3, false).unwrap();
    assert!(!noop.committed);
    assert_eq!(noop.chunks_uploaded, 0);

    // Sanity: the mock served exactly the commits the reports claim.
    assert_eq!(state.lock().unwrap().head_seq, 3);
}

/// Every blob file name under a local store's `chunks/<2>/` layout.
fn store_chunk_names(store_root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for shard in std::fs::read_dir(store_root.join("chunks")).unwrap() {
        for entry in std::fs::read_dir(shard.unwrap().path()).unwrap() {
            names.push(entry.unwrap().file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    names
}

/// §24: after a converging second pull, the mirror's store holds exactly
/// the applied head's chunks — the superseded content's chunk is swept,
/// the new one kept, and an idle pull changes nothing.
#[test]
fn pull_sweeps_superseded_chunks() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"version one\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let (_meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();
    let store_root = dir_b.join(".pear/store");
    let before = store_chunk_names(&store_root);
    assert_eq!(before.len(), 1, "one file, one chunk");

    // The edit converges; the sweep follows the successful apply.
    write(&dir_a, "f.txt", b"version two, changed\n");
    push_cycle(&dir_a, &a, 1, false).unwrap();
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    let after = store_chunk_names(&store_root);
    assert_eq!(after.len(), 1, "the superseded chunk was swept");
    assert_ne!(before, after, "what survives is the new content's chunk");
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // An idle pull right after deletes nothing (it does not even sweep).
    let idle = pull_once(&dir_b, &b).unwrap();
    assert!(!idle.changed);
    assert_eq!(store_chunk_names(&store_root), after);
}

/// §32: a device whose `base_seq` is behind loses the CAS — that is a
/// retryable `HeadConflict`, not a fatal fence, and the winner's commit
/// is untouched.
#[test]
fn a_stale_base_seq_loses_the_cas_not_the_workspace() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    write(&dir_b, "g.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let winner = client(&mock, &meta.id, "device-winner");
    let straggler = client(&mock, &meta.id, "device-straggler");
    winner.create_workspace("a").unwrap();

    assert_eq!(push_cycle(&dir_a, &winner, 0, false).unwrap().head_seq, 1);
    let err = push_cycle(&dir_b, &straggler, 0, false).unwrap_err();
    assert!(
        matches!(err, PushError::HeadConflict { current_seq: 1 }),
        "got {err:?}"
    );
    // Rebased onto the winner's seq, the same device commits fine.
    assert_eq!(
        push_cycle(&dir_b, &straggler, 1, false).unwrap().head_seq,
        2
    );
}

#[test]
fn writer_commit_gate_survives_local_sync_cache_poisoning() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    let first = push_cycle(&dir_a, &a, 0, false).unwrap();
    assert!(first.committed && first.head_seq == 1);

    // A LOCAL sync writes the source's manifest cache without committing
    // anything to the relay (`.pear/manifest.json` is shared between the
    // two modes).
    write(&dir_a, "f.txt", b"v2\n");
    pear_core::sync::sync_cycle(&dir_a, &dir_b).unwrap();

    // The next writer cycle must still commit: the gate is the last
    // COMMITTED file set, not the (now-poisoned) cache — otherwise the
    // edit never reaches the relay and mirrors stay stale indefinitely.
    let second = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(
        second.committed && second.head_seq == 2,
        "edits hidden behind a poisoned cache must still reach the relay"
    );
}

#[test]
fn resolve_workspace_percent_encodes_names() {
    let mock = MockRelay::start(Arc::new(|head, _body| {
        if head.starts_with("GET /v1/teams/") {
            return json(
                200,
                serde_json::json!({
                    "id": "ws1", "name": "my ws", "head_seq": 0, "head_hash": null,
                }),
            );
        }
        json(404, serde_json::json!({}))
    }));
    let c = client(&mock, "ws1", "device-a");
    let info = c.resolve_workspace("my team", "my ws").unwrap();
    assert_eq!(info.id, "ws1");

    // Names with URL-reserved characters must round-trip through the
    // resolve route: encoded in the path, decoded by the server.
    let requests = mock.requests.lock().unwrap();
    assert!(
        requests[0].starts_with("GET /v1/teams/my%20team/workspaces/my%20ws "),
        "names must be percent-encoded in the path, got: {}",
        requests[0]
    );
}

#[test]
fn team_routes_percent_encode_team_ids() {
    let mock = MockRelay::start(Arc::new(|head, _body| {
        if head.starts_with("POST /v1/teams/") {
            return json(200, serde_json::json!({}));
        }
        json(404, serde_json::json!({}))
    }));
    let c = client(&mock, "ws1", "device-a");
    c.team_add_member("team/one", "jane", "writer").unwrap();

    // A raw `/` in a team id would address a different route: every
    // user-influenced path segment goes through encode_segment.
    let requests = mock.requests.lock().unwrap();
    assert!(
        requests[0].starts_with("POST /v1/teams/team%2Fone/members "),
        "team ids must be percent-encoded in the path, got: {}",
        requests[0]
    );
}

#[test]
fn client_percent_encodes_workspace_ids_in_urls() {
    let mock = MockRelay::start(Arc::new(|head, _body| {
        if head.starts_with("GET /v1/workspaces/") && !head.contains("/head") {
            return json(
                200,
                serde_json::json!({
                    "id": "x/head", "name": "w", "head_seq": 0, "head_hash": null,
                }),
            );
        }
        json(404, serde_json::json!({}))
    }));
    let c = client(&mock, "x/head", "device-a");
    c.get_workspace().unwrap();

    // A user-supplied workspace id must be encoded before interpolation,
    // not land on a different route.
    let requests = mock.requests.lock().unwrap();
    assert!(
        requests[0].starts_with("GET /v1/workspaces/x%2Fhead "),
        "workspace id must be percent-encoded, got: {}",
        requests[0]
    );
}

#[test]
fn create_workspace_name_conflict_is_an_error() {
    // The relay's 409 is ambiguous without the kind field: name_conflict
    // must be an error, id_conflict stays idempotent.
    let mock = MockRelay::start(Arc::new(|head, body| {
        if head.starts_with("POST /v1/workspaces ") {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            let kind = if body["id"] == "taken" {
                "name_conflict"
            } else {
                "id_conflict"
            };
            return json(
                409,
                serde_json::json!({ "error": "conflict", "kind": kind }),
            );
        }
        json(404, serde_json::json!({}))
    }));
    let taken = client(&mock, "taken", "device-a");
    let err = taken.create_workspace_with_team("api", None).unwrap_err();
    assert!(
        matches!(err, RelayError::Http { status: 409, .. }),
        "name_conflict must surface as an error, got {err:?}"
    );
    let fresh = client(&mock, "fresh", "device-a");
    fresh
        .create_workspace_with_team("api", None)
        .expect("id_conflict stays idempotent");
}

#[test]
fn pull_requires_the_remote_workspace_id() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("m");
    std::fs::create_dir_all(&dir).unwrap();

    // Mirror inited with a different id than the client's workspace.
    let (meta, _) = pear_core::init_workspace(&dir, Some("ws-other")).unwrap();
    let c = client(&mock, "ws-1", "device-a");
    let err = pull_once(&dir, &c).unwrap_err();
    assert!(
        format!("{err:#}").contains(&meta.id),
        "error should name the local id: {err:#}"
    );
}


#[test]
fn pull_rejects_chunk_bytes_that_do_not_match_their_hash() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"honest content\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // Poison the relay pool: the head references the chunk, but the pool
    // now serves wrong bytes for it.
    let hash = blake3::hash(b"honest content\n").to_hex().to_string();
    state
        .lock()
        .unwrap()
        .chunks
        .insert(hash, b"forged bytes\n".to_vec());

    let (_meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match"),
        "pull must reject forged chunk bytes: {err:#}"
    );
    assert!(!dir_b.join("f.txt").exists());
}

#[test]
fn last_applied_seq_tracks_pulls() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // Nothing applied yet: the mirror has no recorded head.
    assert_eq!(pear_core::sync::last_applied_seq(&dir_b), None);
    let (_meta_b, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();
    assert_eq!(pear_core::sync::last_applied_seq(&dir_b), Some(1));
}

#[test]
fn writer_base_seq_refuses_a_silent_rewind() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_stale = tmp.path().join("stale");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();
    // A commit persists the writer's known head for restarts.
    assert_eq!(pear_core::sync::last_applied_seq(&dir_a), Some(1));

    // The same writer resuming where it left off: fine.
    assert_eq!(
        pear_core::sync::writer_base_seq(&dir_a, &a, false).unwrap(),
        1
    );

    // A device that never saw the head: refused without --force...
    std::fs::create_dir_all(&dir_stale).unwrap();
    let (_m, _) = pear_core::init_workspace(&dir_stale, Some(&meta.id)).unwrap();
    let err = pear_core::sync::writer_base_seq(&dir_stale, &a, false).unwrap_err();
    assert!(format!("{err:#}").contains("pear mirror"), "{err:#}");
    // ...allowed only through the explicit takeover.
    assert_eq!(
        pear_core::sync::writer_base_seq(&dir_stale, &a, true).unwrap(),
        1
    );
}

#[test]
fn get_head_reads_manifests_larger_than_ureqs_default_limit() {
    // ureq's body helpers cap reads at 10 MB; the relay contract allows
    // manifests up to 256 MiB.
    let chunk = blake3::hash(b"x").to_hex().to_string();
    let mut files = serde_json::Map::new();
    for i in 0..150_000 {
        files.insert(
            format!("dir{i:06}/f.txt"),
            serde_json::json!({
                "size": 1, "mode": 420, "mtime_secs": 1, "mtime_nanos": 0,
                "chunks": [chunk],
            }),
        );
    }
    let manifest = serde_json::json!({
        "version": 1, "workspace_id": "ws-big", "scanned_at_secs": 0, "files": files,
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    assert!(
        manifest_bytes.len() > 10 * 1024 * 1024,
        "the test manifest must exceed the ureq default limit"
    );
    let body = serde_json::json!({ "seq": 1, "hash": "h", "manifest": manifest });
    let mock = MockRelay::start(Arc::new(move |head, _body| {
        if head.starts_with("GET /v1/workspaces/ws-big/head ") {
            json(200, body.clone())
        } else {
            json(404, serde_json::json!({}))
        }
    }));
    let c = client(&mock, "ws-big", "device-a");
    let head = c.get_head().unwrap().expect("head exists");
    assert_eq!(head.manifest.files.len(), 150_000);
}

#[test]
fn forced_takeover_commits_even_when_tree_is_unchanged() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    // Writer A commits v1; B mirrors it. A commits v2; B never sees it.
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let (_m, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();
    assert_eq!(std::fs::read(dir_b.join("f.txt")).unwrap(), b"v1\n");

    write(&dir_a, "f.txt", b"v2\n");
    push_cycle(&dir_a, &a, 1, false).unwrap();

    // B force-takes with an unchanged (stale) tree: the takeover contract
    // is "this tree becomes the head" — the first push must commit even
    // though nothing changed locally.
    let base = pear_core::sync::writer_base_seq(&dir_b, &b, true).unwrap();
    assert_eq!(base, 2);
    let report = push_cycle(&dir_b, &b, base, true).unwrap();
    assert!(
        report.committed,
        "a forced takeover must commit its tree as the head"
    );
    assert_eq!(report.head_seq, 3);

    // The head now holds B's (older) tree: a fresh mirror converges to it.
    let dir_c = tmp.path().join("c");
    let (_m, _) = pear_core::init_workspace(&dir_c, Some(&meta.id)).unwrap();
    let c = client(&mock, &meta.id, "device-c");
    pull_once(&dir_c, &c).unwrap();
    assert_eq!(std::fs::read(dir_c.join("f.txt")).unwrap(), b"v1\n");
}

#[test]
fn lost_commit_response_recovers_instead_of_self_fencing() {
    // A relay that commits head writes but "loses" the second 200,
    // answering 409 as if the response never arrived.
    let state = Arc::new(Mutex::new(RelayState::default()));
    let shared = state.clone();
    let head_puts = Arc::new(Mutex::new(0u32));
    let puts = head_puts.clone();
    let mock = MockRelay::start(Arc::new(move |head, body| {
        let is_head_put = head.starts_with("PUT /v1/workspaces/") && head.contains("/head ");
        if !is_head_put {
            return route(&shared, head, body);
        }
        *puts.lock().unwrap() += 1;
        let (status, resp) = route(&shared, head, body);
        if *puts.lock().unwrap() == 2 && status == 200 {
            let seq = state.lock().unwrap().head_seq;
            return json(409, serde_json::json!({ "current_seq": seq }));
        }
        (status, resp)
    }));

    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();
    write(&dir_a, "f.txt", b"v2\n");

    // The second commit "loses" its response: the writer must recognize
    // its own commit on the relay and adopt it, not self-fence.
    let report = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(report.committed);
    assert_eq!(report.head_seq, 2);
    assert_eq!(pear_core::sync::last_applied_seq(&dir_a), Some(2));
}

#[test]
fn pull_once_initializes_fresh_mirror_with_client_workspace_id() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // No init on the mirror dir: pull_once must adopt the client's
    // workspace id, not mint a random one that strands the directory.
    let dir_b = tmp.path().join("b");
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();
    assert_eq!(std::fs::read(dir_b.join("f.txt")).unwrap(), b"v1\n");
    let meta_b = pear_core::load_workspace(&dir_b).unwrap().unwrap();
    assert_eq!(meta_b.id, meta.id);
}

#[test]
fn relay_client_error_is_fatal_not_retryable() {
    // A relay that deterministically rejects head commits (400).
    let state = Arc::new(Mutex::new(RelayState::default()));
    let shared = state.clone();
    let mock = MockRelay::start(Arc::new(move |head, body| {
        if head.starts_with("PUT /v1/workspaces/") && head.contains("/head ") {
            return json(400, serde_json::json!({ "error": "manifest rejected" }));
        }
        route(&shared, head, body)
    }));

    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    let err = push_cycle(&dir_a, &a, 0, false).unwrap_err();
    assert!(
        matches!(err, PushError::Client(_)),
        "a deterministic 4xx must be fatal, got {err:?}"
    );
}

#[test]
fn transient_4xx_stays_retryable() {
    // An intermediary-style transient 429 must NOT be fatal to the writer.
    let state = Arc::new(Mutex::new(RelayState::default()));
    let shared = state.clone();
    let mock = MockRelay::start(Arc::new(move |head, body| {
        if head.starts_with("PUT /v1/workspaces/") && head.contains("/head ") {
            return json(429, serde_json::json!({ "error": "slow down" }));
        }
        route(&shared, head, body)
    }));

    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    let err = push_cycle(&dir_a, &a, 0, false).unwrap_err();
    assert!(
        matches!(err, PushError::Other(_)),
        "a transient 429 must stay retryable, got {err:?}"
    );
}

#[test]
fn pull_errors_when_workspace_is_missing_not_just_headless() {
    // A relay that 404s everything: the mirror must surface the missing
    // workspace, not idle forever.
    let mock = MockRelay::start(Arc::new(|_head, _body| {
        json(
            404,
            serde_json::json!({ "error": "workspace does not exist" }),
        )
    }));
    let tmp = tempfile::tempdir().unwrap();
    let dir_b = tmp.path().join("b");
    let (_m, _) = pear_core::init_workspace(&dir_b, Some("ws-ghost")).unwrap();
    let b = client(&mock, "ws-ghost", "device-b");
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(format!("{err:#}").contains("ws-ghost"), "{err:#}");
}

#[test]
fn chunk_get_refuses_an_unbounded_relay_body() {
    // The relay is semi-trusted (§7): a chunk response larger than the
    // contract's 4 MiB max is an error, not an unbounded allocation.
    let mock = MockRelay::start(Arc::new(|_head, _body| (200, vec![0u8; 5 * 1024 * 1024])));
    let c = client(&mock, "ws-1", "dev");
    let hash = blake3::hash(b"x").to_hex().to_string();
    let err = ChunkSource::get(&c, &hash).unwrap_err();
    assert!(
        err.to_string().contains("exceeds"),
        "oversized chunk body must error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn mirror_records_masked_modes_and_stays_idle() {
    use std::os::unix::fs::PermissionsExt;

    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "priv.sh", b"#!/bin/sh\nid\n");
    std::fs::set_permissions(
        dir_a.join("priv.sh"),
        std::fs::Permissions::from_mode(0o6755),
    )
    .unwrap();

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let dir_b = tmp.path().join("b");
    let b = client(&mock, &meta.id, "device-b");
    let first = pull_once(&dir_b, &b).unwrap();
    assert!(first.changed);

    // Disk got the masked mode — and so did the mirror's recorded
    // manifest, or every later diff (and a role reversal) sees a
    // phantom mode change.
    let disk_mode = std::fs::metadata(dir_b.join("priv.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(disk_mode, 0o755, "disk: {disk_mode:o}");
    let local: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir_b.join(".pear/manifest.json")).unwrap()).unwrap();
    let recorded = local["files"]["priv.sh"]["mode"].as_u64().unwrap();
    assert_eq!(recorded, 0o755, "mirror manifest: {recorded:o}");

    let second = pull_once(&dir_b, &b).unwrap();
    assert!(!second.changed, "no phantom mode change on the next pull");
}

#[test]
fn pull_marks_invalid_relay_manifest_fatal_not_retryable() {
    // A head whose manifest fails validation fails on EVERY poll — the
    // mirror must classify it Fatal (exit) instead of retrying forever.
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_b = tmp.path().join("b");

    let (meta, _) = pear_core::init_workspace(&dir_b, Some("ws-evil")).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    b.create_workspace("b").unwrap();
    // Inject the hostile head directly (a real relay would validate it
    // away; this stands in for a buggy or compromised relay, §7).
    {
        let mut st = state.lock().unwrap();
        st.head_seq = 1;
        st.head = Some((
            "hash".to_string(),
            serde_json::json!({
                "version": 1,
                "workspace_id": "ws-evil",

                "scanned_at_secs": 0,
                "files": {
                    "../evil.txt": {
                        "size": 0, "mode": 420, "mtime_secs": 0,
                        "mtime_nanos": 0, "chunks": []
                    }
                }
            }),
            None,
        ));
    }
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "expected Fatal, got {err:?}"
    );
}

#[test]
fn pull_marks_case_colliding_manifest_fatal_not_retryable() {
    // The apply-time collision refusal is deterministic for the same
    // head: Fatal like a validation failure, never an infinite retry.
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_b = tmp.path().join("b");

    let (meta, _) = pear_core::init_workspace(&dir_b, Some("ws-collide")).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    b.create_workspace("b").unwrap();
    let entry = || {
        serde_json::json!({
            "size": 0, "mode": 420, "mtime_secs": 0,
            "mtime_nanos": 0, "chunks": []
        })
    };
    {
        let mut st = state.lock().unwrap();
        st.head_seq = 1;
        st.head = Some((
            "hash".to_string(),
            serde_json::json!({
                "version": 1,
                "workspace_id": "ws-collide",
                "scanned_at_secs": 0,
                "files": { "README": entry(), "readme": entry() }
            }),
            None,
        ));
    }
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "expected Fatal, got {err:?}"
    );
}

#[test]
fn refused_clone_leaves_the_target_untouched() {
    // A rejected clone must leave no filesystem side effects — not even a
    // freshly created directory (§15 autoreview): refusal checks run
    // before anything is created.
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();
    let snap = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap();

    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    write(&dir_b, "keep.txt", b"keep\n");
    let err = pear_core::snapshot::clone_from_snapshot(&dir_b, &a, snap.id).unwrap_err();
    assert!(format!("{err:#}").contains("not empty"), "{err:#}");
    assert!(!dir_b.join(".pear").exists(), "no metadata side effects");
    let left: Vec<_> = std::fs::read_dir(&dir_b).unwrap().flatten().collect();
    assert_eq!(left.len(), 1, "the directory is untouched");
}

#[test]
fn pull_idles_when_workspace_exists_but_has_no_head() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_b = tmp.path().join("b");
    let (_m, _) = pear_core::init_workspace(&dir_b, Some("ws-1")).unwrap();
    let b = client(&mock, "ws-1", "device-b");
    let report = pull_once(&dir_b, &b).unwrap();
    assert!(!report.changed);
    assert_eq!(report.head_seq, 0);
}

#[test]
fn snapshot_does_not_poison_the_next_push() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // Edit, snapshot (the preserve-first step), then resume the writer:
    // the first cycle MUST commit — a snapshot is not a head commit and
    // must not touch the writer's last-committed manifest cache.
    write(&dir_a, "f.txt", b"v2\n");
    pear_core::snapshot::push_snapshot(&dir_a, &a, Some("preserve")).unwrap();
    let report = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(
        report.committed,
        "the push after a snapshot must commit the edits"
    );
    assert_eq!(report.head_seq, 2);
}

#[cfg(unix)]
#[test]
fn snapshot_fails_on_unreadable_file_instead_of_omitting_it() {
    use std::os::unix::fs::PermissionsExt;

    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "ok.txt", b"ok\n");
    write(&dir_a, "locked.txt", b"secret\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();

    std::fs::set_permissions(
        dir_a.join("locked.txt"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    if std::fs::read(dir_a.join("locked.txt")).is_ok() {
        return; // root bypasses permission bits
    }
    let err = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("locked.txt"),
        "snapshot must fail loudly on an unreadable file: {err:#}"
    );
    std::fs::set_permissions(
        dir_a.join("locked.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

#[test]
fn failed_clone_leaves_no_pear_behind() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();

    // A snapshot referencing a chunk that was never uploaded.
    let a = client(&mock, "ws-x", "device-a");
    a.create_workspace("x").unwrap();
    let mut m = Manifest::new("ws-x".to_string());
    m.files.insert(
        "ghost.txt".to_string(),
        pear_core::manifest::FileEntry {
            size: 5,
            mode: 0o644,
            mtime_secs: 1,
            mtime_nanos: 0,
            chunks: vec![blake3::hash(b"ghost").to_hex().to_string()],
        },
    );
    let snap = a.create_snapshot(Some("ghost"), &m).unwrap();

    let dir_b = tmp.path().join("b");
    let b = client(&mock, "ws-x", "device-b");
    let err = pear_core::snapshot::clone_from_snapshot(&dir_b, &b, snap.id).unwrap_err();
    assert!(format!("{err:#}").contains("missing"), "{err:#}");
    assert!(
        !dir_b.join(".pear").exists(),
        "a failed clone must not strand an initialized .pear"
    );
}

#[test]
fn clone_refuses_a_non_empty_target() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();
    let snap = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap();

    // A target directory that already has unrelated content: refuse
    // before any filesystem side effect.
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    write(&dir_b, "unrelated.txt", b"mine\n");
    let b = client(&mock, &meta.id, "device-b");
    let err = pear_core::snapshot::clone_from_snapshot(&dir_b, &b, snap.id).unwrap_err();
    assert!(format!("{err:#}").contains("not empty"), "{err:#}");
    assert_eq!(
        std::fs::read(dir_b.join("unrelated.txt")).unwrap(),
        b"mine\n"
    );
    assert!(!dir_b.join(".pear").exists());
}

#[test]
fn failed_mid_apply_clone_leaves_target_empty_for_retry() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();

    // A snapshot whose manifest contains both a file `a` and a file
    // `a/b`: apply writes `a`, then fails creating `a/` — mid-apply.
    let a = client(&mock, "ws-x", "device-a");
    a.create_workspace("x").unwrap();
    let chunk = blake3::hash(b"data").to_hex().to_string();
    a.put_chunk(&chunk, b"data").unwrap();
    let mut m = Manifest::new("ws-x".to_string());
    for rel in ["a", "a/b"] {
        m.files.insert(
            rel.to_string(),
            pear_core::manifest::FileEntry {
                size: 4,
                mode: 0o644,
                mtime_secs: 1,
                mtime_nanos: 0,
                chunks: vec![chunk.clone()],
            },
        );
    }
    let snap = a.create_snapshot(Some("hostile"), &m).unwrap();

    let dir_b = tmp.path().join("b");
    let b = client(&mock, "ws-x", "device-b");
    let _err = pear_core::snapshot::clone_from_snapshot(&dir_b, &b, snap.id).unwrap_err();

    // The retry the cleanup exists for must not be blocked by leftovers.
    let target_empty = !dir_b.exists() || std::fs::read_dir(&dir_b).unwrap().next().is_none();
    assert!(
        target_empty,
        "a failed clone must leave the target empty for retry"
    );
}

#[test]
fn lost_commit_recovery_works_across_cycles_with_fresh_timestamps() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // Simulate the commit whose response was lost last cycle: the relay
    // head moved to 2 with THIS tree's files but an older scan timestamp
    // (the retrying cycle scans with a fresh one).
    let local = pear_core::manifest::load(&dir_a.join(".pear/manifest.json"))
        .unwrap()
        .unwrap();
    let mut committed = local.clone();
    committed.scanned_at_secs -= 10;
    {
        let mut st = state.lock().unwrap();
        st.head_seq = 2;
        st.head = Some(("h2".into(), serde_json::to_value(&committed).unwrap(), None));
    }

    // The retry must adopt the lost commit by comparing file sets, not
    // the per-cycle scan timestamp.
    let report = push_cycle(&dir_a, &a, 1, true).unwrap();
    assert_eq!(report.head_seq, 2);
    assert_eq!(pear_core::sync::last_applied_seq(&dir_a), Some(2));
}

#[test]
fn freshness_checks_compare_hash_not_just_seq() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let (_m, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();
    let idle = pull_once(&dir_b, &b).unwrap();
    assert!(!idle.changed);

    // Commit different content, then rewind the relay's seq as if it were
    // restored from a divergent backup: same seq, different head.
    write(&dir_a, "f.txt", b"restored\n");
    push_cycle(&dir_a, &a, 1, false).unwrap();
    {
        let mut st = state.lock().unwrap();
        st.head_seq = 1;
    }

    // The resume guard must refuse: the local proof no longer matches the
    // relay head's content.
    let err = pear_core::sync::writer_base_seq(&dir_b, &b, false).unwrap_err();
    assert!(format!("{err:#}").contains("pear mirror"), "{err:#}");

    // And the mirror must NOT idle on seq alone: different hash, so the
    // divergent head is applied.
    let pulled = pull_once(&dir_b, &b).unwrap();
    assert!(pulled.changed);
    assert_eq!(std::fs::read(dir_b.join("f.txt")).unwrap(), b"restored\n");
}

// ---------- snapshots (§12) ----------

#[test]
fn snapshot_clone_round_trip_byte_identical() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();

    // The files that define the product: `.env` and `.git` contents sync.
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, ".git/HEAD", b"ref: refs/heads/main\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();

    let report = pear_core::snapshot::push_snapshot(&dir_a, &a, Some("before refactor")).unwrap();
    assert_eq!(report.id, 1);
    assert_eq!(report.files, 3);
    assert_eq!(report.chunks_uploaded, 3);

    // Listed with its metadata, newest first.
    let list = a.list_snapshots().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, 1);
    assert_eq!(list[0].name.as_deref(), Some("before refactor"));
    assert_eq!(list[0].kind, "named");
    assert_eq!(list[0].device, "device-a");

    // A missing snapshot is a typed 404.
    let err = a.get_snapshot(99).unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "got {err:?}");

    // Clone into a fresh directory: byte-identical tree, `.env` and `.git`
    // included.
    let dir_b = tmp.path().join("b");
    let clone = pear_core::snapshot::clone_from_snapshot(&dir_b, &a, 1).unwrap();
    assert_eq!(clone.files_written, 3);
    assert_eq!(clone.chunks_fetched, 3);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(
        std::fs::read(dir_b.join(".env")).unwrap(),
        b"SECRET=hunter2\n"
    );
    assert_eq!(
        std::fs::read(dir_b.join(".git/HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );

    // Forked lineage: the clone is a NEW workspace, with provenance in
    // `.pear/origin.json`.
    assert_ne!(clone.workspace_id, meta.id);
    let meta_b = pear_core::load_workspace(&dir_b).unwrap().unwrap();
    assert_eq!(meta_b.id, clone.workspace_id);
    let origin: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir_b.join(".pear/origin.json")).unwrap()).unwrap();
    assert_eq!(origin["workspace_id"].as_str().unwrap(), meta.id);
    assert_eq!(origin["snapshot_id"].as_u64().unwrap(), 1);
    assert_eq!(origin["name"].as_str().unwrap(), "before refactor");
    assert!(origin["cloned_at"].as_i64().unwrap() > 0);

    // A clone never re-targets an existing workspace.
    let err = pear_core::snapshot::clone_from_snapshot(&dir_b, &a, 1).unwrap_err();
    assert!(
        format!("{err:#}").contains("already a pear workspace"),
        "{err:#}"
    );
}

#[test]
fn snapshot_captures_unsynced_state_ahead_and_behind_head() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap(); // head = v1

    // The local tree moves AHEAD of the head (unsynced edit + new file).
    write(&dir_a, "f.txt", b"v2-unsynced\n");
    write(&dir_a, "wip.txt", b"work in progress\n");
    let snap = pear_core::snapshot::push_snapshot(&dir_a, &a, Some("wip")).unwrap();
    // Snapshots do not move the head.
    assert_eq!(a.get_head().unwrap().unwrap().seq, 1);

    // The snapshot holds the unsynced state, restorable via clone.
    let dir_c = tmp.path().join("clone-ahead");
    pear_core::snapshot::clone_from_snapshot(&dir_c, &a, snap.id).unwrap();
    assert_eq!(
        std::fs::read(dir_c.join("f.txt")).unwrap(),
        b"v2-unsynced\n"
    );
    assert_eq!(
        std::fs::read(dir_c.join("wip.txt")).unwrap(),
        b"work in progress\n"
    );

    // Another device force-takes and pushes: the local tree is now BEHIND
    // (diverged from) the head. Snapshotting still succeeds — that is the
    // divergent-snapshot answer to a force takeover.
    let dir_b = tmp.path().join("b");
    pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    write(&dir_b, "f.txt", b"v3-from-b\n");
    let pushed = push_cycle(&dir_b, &b, 1, true).unwrap();
    assert!(pushed.committed);

    let snap2 = pear_core::snapshot::push_snapshot(&dir_a, &a, Some("diverged")).unwrap();
    assert_eq!(snap2.id, 2);
    let list = a.list_snapshots().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, 2, "newest first");
    assert_eq!(list[1].id, 1);

    let dir_d = tmp.path().join("clone-diverged");
    pear_core::snapshot::clone_from_snapshot(&dir_d, &a, snap2.id).unwrap();
    assert_eq!(
        std::fs::read(dir_d.join("f.txt")).unwrap(),
        b"v2-unsynced\n"
    );
    // ...and the head the other device pushed is untouched by any of this.
    let head = a.get_head().unwrap().unwrap();
    assert_eq!(head.seq, 2);
    assert!(head.manifest.files.contains_key("f.txt"));
    assert!(!head.manifest.files.contains_key("wip.txt"));
}

#[test]
fn clone_rejects_a_snapshot_of_another_workspace() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap();

    // A client pointed at a DIFFERENT workspace must not clone it — the
    // manifest's workspace id is checked against the client's target.
    let other = client(&mock, "ws-other", "device-b");
    let dir_b = tmp.path().join("b");
    let err = pear_core::snapshot::clone_from_snapshot(&dir_b, &other, 1).unwrap_err();
    assert!(
        format!("{err:#}").contains("belongs to workspace"),
        "{err:#}"
    );
    assert!(!dir_b.join("f.txt").exists());
    assert!(
        pear_core::load_workspace(&dir_b).unwrap().is_none(),
        "a refused clone leaves no .pear behind"
    );
}

#[test]
fn push_snapshot_requires_a_pear_workspace() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("plain");
    std::fs::create_dir_all(&dir).unwrap();

    let c = client(&mock, "ws-x", "device-a");
    let err = pear_core::snapshot::push_snapshot(&dir, &c, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("not a pear workspace"),
        "{err:#}"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_fails_on_symlink_instead_of_omitting_it() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "real.txt", b"x\n");
    std::os::unix::fs::symlink("real.txt", dir_a.join("link.txt")).unwrap();

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();

    // Strict preservation: a skipped symlink must fail the capture, not
    // be silently omitted from a snapshot the user trusts as complete.
    let err = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap_err();
    assert!(format!("{err:#}").contains("link.txt"), "{err:#}");
}

#[cfg(unix)]
#[test]
fn snapshot_tolerates_unreadable_gitignored_dirs() {
    use std::os::unix::fs::PermissionsExt;

    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, ".gitignore", b"cache/\n");
    write(&dir_a, "ok.txt", b"ok\n");

    let cache = dir_a.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root bypasses permission bits (container CI): scenario not applicable.
    if std::fs::read_dir(&cache).is_ok() {
        return;
    }

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    // The unreadable dir is gitignored: it can at worst hide .env files,
    // which warns — it must not fail the capture.
    pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn snapshot_fails_when_git_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;

    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, ".git/HEAD", b"ref: refs/heads/main\n");
    write(&dir_a, "ok.txt", b"ok\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();

    let git = dir_a.join(".git");
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&git).is_ok() {
        return; // root bypasses permission bits
    }
    // `.git` IS the capture set: unreadable here must fail.
    let err = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap_err();
    assert!(format!("{err:#}").contains(".git"), "{err:#}");
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn snapshot_report_notes_name_excluded_dirs() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(dir_a.join("node_modules/pkg")).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    write(&dir_a, "node_modules/pkg/index.js", b"x\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();

    let report = pear_core::snapshot::push_snapshot(&dir_a, &a, None).unwrap();
    assert!(
        report.excluded.iter().any(|p| p == "node_modules"),
        "the report must surface what was not captured: {:?}",
        report.excluded
    );
}

/// §13 onboarding at the client level: resolve a `team/name` ref to the
/// shared workspace id, adopt it, and mirror-once to convergence.
#[test]
fn resolve_team_name_then_mirror_once_converges() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();

    // The owner registers the workspace as acme's "api" and pushes.
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let owner = client(&mock, &meta.id, "device-a");
    owner
        .create_workspace_with_team("api", Some("team-1"))
        .unwrap();
    let pushed = push_cycle(&dir_a, &owner, 0, false).unwrap();
    assert!(pushed.committed);

    // A teammate resolves acme/api (no workspace id needed)...
    let resolver = RelayClient::unbound(&mock.url(), TOKEN, "device-b");
    let resolved = resolver.resolve_workspace("acme", "api").unwrap();
    assert_eq!(resolved.id, meta.id);
    assert_eq!(resolved.name, "api");
    assert_eq!(resolved.head_seq, 1);

    // ...adopts the shared id and pulls once: byte-identical tree, .env
    // and all.
    pear_core::init_workspace(&dir_b, Some(&resolved.id)).unwrap();
    let mirror = client(&mock, &resolved.id, "device-b");
    let pulled = pull_once(&dir_b, &mirror).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // An unknown name (or a workspace you cannot see, on the real relay)
    // is a typed NotFound.
    let err = resolver.resolve_workspace("acme", "nope").unwrap_err();
    assert!(matches!(err, RelayError::NotFound(_)), "got {err:?}");
}

#[test]
fn chunk_path_auth_failures_are_fatal_not_retryable() {
    // 401 and 403 on the chunk data path must both go fatal, not retry
    // (§32 types 403 apart as `Forbidden` so the converge loop can
    // degrade to a read-only mirror on it).
    for status in [401u16, 403] {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let shared = state.clone();
        let mock = MockRelay::start(Arc::new(move |head, body| {
            if head.contains("/chunks/") {
                return json(status, serde_json::json!({ "error": "revoked" }));
            }
            route(&shared, head, body)
        }));

        let tmp = tempfile::tempdir().unwrap();
        let dir_a = tmp.path().join("a");
        std::fs::create_dir_all(&dir_a).unwrap();
        write(&dir_a, "f.txt", b"v1\n");

        let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
        let a = client(&mock, &meta.id, "device-a");
        a.create_workspace("a").unwrap();
        let err = push_cycle(&dir_a, &a, 0, false).unwrap_err();
        assert!(
            matches!(err, PushError::Client(_) | PushError::Forbidden(_)),
            "HTTP {status} on the chunk path must be fatal, got {err:?}"
        );
    }
}

#[test]
fn unchanged_tree_still_repairs_a_lossy_chunk_pool() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    // The relay loses its chunk pool (the head log survives): the next
    // cycle must re-upload the missing chunks even though nothing
    // changed and no head is committed.
    state.lock().unwrap().chunks.clear();
    let report = push_cycle(&dir_a, &a, 1, false).unwrap();
    assert!(!report.committed, "no tree change: no head commit");
    assert_eq!(report.chunks_uploaded, 1, "the pool repair still uploads");
    assert!(state
        .lock()
        .unwrap()
        .chunks
        .contains_key(&blake3::hash(b"v1\n").to_hex().to_string()));
}

#[test]
fn idle_mirror_polls_do_not_download_the_manifest() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let (_m, _) = pear_core::init_workspace(&dir_b, Some(&meta.id)).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();

    // Idle polls must idle on the tiny workspace read, never on the full
    // manifest body.
    let count_head_gets = |requests: &Vec<String>| {
        requests
            .iter()
            .filter(|r| r.starts_with("GET /v1/workspaces/") && r.contains("/head "))
            .count()
    };
    let before = count_head_gets(&mock.requests.lock().unwrap().clone());
    let report = pull_once(&dir_b, &b).unwrap();
    assert!(!report.changed);
    let after = count_head_gets(&mock.requests.lock().unwrap().clone());
    assert_eq!(before, after, "an idle poll must not download the manifest");
}

#[test]
fn create_workspace_only_treats_id_conflict_409_as_benign() {
    let benign = MockRelay::start(Arc::new(|_head, _body| {
        json(
            409,
            serde_json::json!({ "error": "exists", "kind": "id_conflict" }),
        )
    }));
    client(&benign, "ws-1", "dev")
        .create_workspace("w")
        .unwrap();

    // Anything else in a 409 — a name conflict, a mangled body — means
    // the workspace was NOT created: an error now, not a confusing
    // downstream 404/403 later.
    for body in [
        serde_json::json!({ "error": "weird" }),
        serde_json::json!({ "error": "taken", "kind": "name_conflict" }),
    ] {
        let mock = MockRelay::start(Arc::new(move |_head, _body| json(409, body.clone())));
        let err = client(&mock, "ws-1", "dev")
            .create_workspace("w")
            .unwrap_err();
        assert!(
            matches!(err, RelayError::Http { status: 409, .. }),
            "got {err:?}"
        );
    }
}

#[test]
fn pull_errors_loudly_when_a_wiped_relay_loses_the_head() {
    // The mirror applied seq 1; the relay then reports head_seq 0 (data
    // dir wiped, workspace re-registered). Every other stale/wipe path
    // is an error — this one must not idle silently forever.
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let dir_b = tmp.path().join("b");
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();

    {
        let mut st = state.lock().unwrap();
        st.head_seq = 0;
        st.head = None;
    }
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(
        format!("{err:#}").contains("wiped"),
        "expected a loud wiped-relay error, got {err:#}"
    );
}

#[test]
fn pull_marks_corrupt_local_manifest_fatal_not_retryable() {
    // A corrupt `.pear/manifest.json` can never heal by polling the same
    // head again: Fatal (exit), not an infinite retry.
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    push_cycle(&dir_a, &a, 0, false).unwrap();

    let dir_b = tmp.path().join("b");
    let b = client(&mock, &meta.id, "device-b");
    pull_once(&dir_b, &b).unwrap();

    std::fs::write(dir_b.join(".pear/manifest.json"), b"{ not json").unwrap();
    let err = pull_once(&dir_b, &b).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "expected Fatal, got {err:?}"
    );
}

#[test]
fn chunks_missing_splits_oversized_lists_transparently() {
    // The relay caps each chunks/missing call (DB-mutex fairness); the
    // client splits larger lists instead of failing monorepo pushes.
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = calls.clone();
    let mock = MockRelay::start(Arc::new(move |head, _body| {
        if head.starts_with("POST /v1/workspaces/") && head.contains("/chunks/missing") {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return json(200, serde_json::json!({ "missing": [] }));
        }
        json(404, serde_json::json!({}))
    }));
    let c = client(&mock, "ws-1", "dev");
    let hashes: Vec<String> = (0..50_001u64)
        .map(|i| blake3::hash(&i.to_be_bytes()).to_hex().to_string())
        .collect();
    let missing = c.chunks_missing(&hashes).unwrap();
    assert!(missing.is_empty());
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "50_001 hashes = 2 calls"
    );
}

// ---------- §17 e2e over the stateful mock ----------

/// A string that must never appear in the mock relay's chunk pool or head.
const CANARY: &[u8] = b"E2E-CANARY-mock-4c0ffee";

#[test]
fn e2e_push_pull_converges_over_mock_and_plaintext_stays_local() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", CANARY);

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("a", None).unwrap();
    assert!(a.get_workspace().unwrap().e2e);
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    let pushed = pear_core::sync::push_cycle_e2e(&dir_a, &a, 0, false, &keyring).unwrap();
    assert!(pushed.committed);
    assert_eq!(pushed.head_seq, 1);

    // The relay side holds only ciphertext: no canary, no paths, and the
    // head is a base64 blob whose hash is BLAKE3 of the stored bytes.
    {
        let st = state.lock().unwrap();
        for (hash, bytes) in &st.chunks {
            assert!(
                !bytes.windows(CANARY.len()).any(|w| w == CANARY),
                "chunk {hash} holds plaintext"
            );
        }
        let (hash, _, enc) = st.head.as_ref().unwrap();
        let enc = enc.as_ref().expect("e2e head carries manifest_enc");
        assert_eq!(hash, &blake3::hash(enc.as_bytes()).to_hex().to_string());
        let blob = pear_core::crypto::base64_decode(enc).unwrap();
        assert!(!blob.windows(CANARY.len()).any(|w| w == CANARY));
    }

    // §31: the writer keeps NO local chunk store — ciphertext chunks
    // live only on the relay, plaintext only in the worktree itself.
    assert!(
        !dir_a.join(".pear/store").exists(),
        "the e2e writer has no local chunk store (§31)"
    );

    // A mirror with the keyring converges byte-identically.
    let b = client(&mock, &meta.id, "device-b");
    let pulled = pear_core::sync::pull_once_e2e(&dir_b, &b, &keyring).unwrap();
    assert!(pulled.changed);
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(std::fs::read(dir_b.join(".env")).unwrap(), CANARY);

    // No key at all: the flavor guard refuses loudly (Fatal, with the
    // actionable --name hint), never a silent downgrade attempt.
    let dir_c = tmp.path().join("c");
    let err = pear_core::sync::pull_once(&dir_c, &b).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "got {err:?}"
    );
    assert!(format!("{err:#}").contains("--name"), "{err:#}");

    // The WRONG keyring: decryption fails (Fatal), never garbage on disk.
    let dir_d = tmp.path().join("d");
    let wrong = pear_core::e2e::Keyring::from_legacy(rand::random());
    let err = pear_core::sync::pull_once_e2e(&dir_d, &b, &wrong).unwrap_err();
    assert!(
        matches!(err.downcast_ref::<RelayError>(), Some(RelayError::Fatal(_))),
        "got {err:?}"
    );
    assert!(!dir_d.join(".env").exists(), "nothing decrypted onto disk");
}

#[test]
fn e2e_lost_commit_response_recovers_by_decrypting_the_head() {
    // Same lost-response relay as the plaintext test: it commits head
    // writes but "loses" the second 200, answering 409 as if the response
    // never arrived. E2E re-encrypts per commit (random nonce), so the
    // recovery must decrypt the relay's head and compare file sets.
    let state = Arc::new(Mutex::new(RelayState::default()));
    let shared = state.clone();
    let head_puts = Arc::new(Mutex::new(0u32));
    let puts = head_puts.clone();
    let mock = MockRelay::start(Arc::new(move |head, body| {
        let is_head_put = head.starts_with("PUT /v1/workspaces/") && head.contains("/head ");
        if !is_head_put {
            return route(&shared, head, body);
        }
        *puts.lock().unwrap() += 1;
        let (status, resp) = route(&shared, head, body);
        if *puts.lock().unwrap() == 2 && status == 200 {
            let seq = state.lock().unwrap().head_seq;
            return json(409, serde_json::json!({ "current_seq": seq }));
        }
        (status, resp)
    }));

    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"v1\n");
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    pear_core::sync::push_cycle_e2e(&dir_a, &a, 0, false, &keyring).unwrap();
    write(&dir_a, "f.txt", b"v2\n");

    let report = pear_core::sync::push_cycle_e2e(&dir_a, &a, 1, false, &keyring).unwrap();
    assert!(
        report.committed,
        "the lost commit is adopted, not self-fenced"
    );
    assert_eq!(report.head_seq, 2);
    assert_eq!(pear_core::sync::last_applied_seq(&dir_a), Some(2));
}

#[test]
fn e2e_pull_rejects_tampered_ciphertext() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "f.txt", b"honest content\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    pear_core::sync::push_cycle_e2e(&dir_a, &a, 0, false, &keyring).unwrap();

    // Poison the pool: the head references the ciphertext chunk, but the
    // pool now serves wrong bytes for it.
    let blob = pear_core::crypto::encrypt_chunk(keyring.newest().1, b"honest content\n");
    let hash = blake3::hash(&blob).to_hex().to_string();
    state
        .lock()
        .unwrap()
        .chunks
        .insert(hash, b"forged bytes\n".to_vec());

    let b = client(&mock, &meta.id, "device-b");
    let err = pear_core::sync::pull_once_e2e(&dir_b, &b, &keyring).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match"),
        "tampered ciphertext must fail the hash check: {err:#}"
    );
    assert!(!dir_b.join("f.txt").exists());
}

#[test]
fn e2e_snapshot_and_fork_clone_over_mock() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", CANARY);

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();

    let snap =
        pear_core::snapshot::push_snapshot_e2e(&dir_a, &a, Some("sealed"), &keyring).unwrap();
    assert_eq!(snap.files, 2);
    let fetched = a.get_snapshot(snap.id).unwrap();
    assert!(fetched.e2e && fetched.manifest_enc.is_some());

    // Fork-clone with the keyring: byte-identical tree, provenance intact,
    // and the clone cached the workspace keyring it onboarded with.
    let dir_b = tmp.path().join("b");
    let b = client(&mock, &meta.id, "device-b");
    let clone =
        pear_core::snapshot::clone_from_snapshot_e2e(&dir_b, &b, snap.id, &keyring).unwrap();
    assert_eq!(clone.files_written, 2);
    assert_ne!(clone.workspace_id, meta.id, "forked lineage");
    assert_eq!(tree(&dir_a), tree(&dir_b));
    assert_eq!(
        pear_core::e2e::load_workspace_keyring(&dir_b).unwrap(),
        Some(keyring.clone())
    );
    let origin: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir_b.join(".pear/origin.json")).unwrap()).unwrap();
    assert_eq!(origin["workspace_id"].as_str().unwrap(), meta.id);
    assert_eq!(origin["snapshot_id"].as_u64().unwrap(), snap.id);

    // Without the key the clone refuses loudly, leaving no side effects.
    let dir_c = tmp.path().join("c");
    let err = pear_core::snapshot::clone_from_snapshot(&dir_c, &b, snap.id).unwrap_err();
    assert!(
        format!("{err:#}").contains("end-to-end encrypted"),
        "{err:#}"
    );
    assert!(!dir_c.join(".pear").exists());
}

/// §28 client-side enforcement: with the attached team's policy pinned on
/// the client (watch startup does this), a writer cycle whose scan
/// captures `.env*` files REFUSES — deterministic, `Client` (the watch
/// loop classifies that fatal and exits), the message naming the team,
/// the paths, and the remedy. Nothing uploads and nothing commits.
#[test]
fn writer_refuses_dotenv_cycle_when_team_forbids() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");
    write(&dir_a, "sub/.envrc", b"use nix\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    a.set_env_sync_policy(Some("acme".to_string()));

    let err = push_cycle(&dir_a, &a, 0, false).unwrap_err();
    let PushError::Client(msg) = err else {
        panic!("the refusal must be deterministic (Client), got {err:?}");
    };
    assert!(msg.contains("acme"), "names the team: {msg}");
    assert!(msg.contains(".env"), "names the files: {msg}");
    assert!(
        msg.contains("sub/.envrc"),
        "every captured .env* path: {msg}"
    );
    assert!(msg.contains("pear team policy"), "names the remedy: {msg}");

    // The refusal fires before ANY upload or commit: no chunk traffic, no
    // head. (The scan chunks locally but never flushes.)
    {
        let requests = mock.requests.lock().unwrap();
        assert!(
            !requests.iter().any(|r| r.contains("chunks")),
            "nothing uploads when the cycle refuses: {requests:?}"
        );
    }
    assert!(a.get_head().unwrap().is_none(), "nothing commits");

    // Removing the .env* files lets the very same workspace watch
    // normally — the check fires only on the captured set.
    std::fs::remove_file(dir_a.join(".env")).unwrap();
    std::fs::remove_file(dir_a.join("sub/.envrc")).unwrap();
    let report = push_cycle(&dir_a, &a, 0, false).unwrap();
    assert!(report.committed);
}

/// §28: a workspace with NO `.env*` files watches normally even under a
/// forbidding team — the refusal fires only on the captured set. Boundary
/// names included: a `.env*` DIRECTORY's contents are not `.env*` (the
/// scanner's own definition, `is_dotenv`).
#[test]
fn writer_without_dotenv_pushes_normally_under_forbidding_team() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, "sub/env", b"not a .env* name\n");
    write(
        &dir_a,
        ".env.d/local",
        b"a .env* dir's contents are not .env*\n",
    );

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace("a").unwrap();
    a.set_env_sync_policy(Some("acme".to_string()));

    let report = push_cycle(&dir_a, &a, 0, false).unwrap();
    assert!(report.committed);
    assert_eq!(report.chunks_uploaded, 3);
}

/// §28: for an e2e workspace the client-side refusal is the ONLY line —
/// the relay cannot see encrypted paths, so it fires on the plaintext
/// scan before anything is encrypted or uploaded.
#[test]
fn e2e_writer_refuses_dotenv_cycle_when_team_forbids() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    write(&dir_a, "src/main.rs", b"fn main() {}\n");
    write(&dir_a, ".env", b"SECRET=hunter2\n");

    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("a", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    a.set_env_sync_policy(Some("acme".to_string()));

    let err = pear_core::sync::push_cycle_e2e(&dir_a, &a, 0, false, &keyring).unwrap_err();
    let PushError::Client(msg) = err else {
        panic!("the refusal must be deterministic (Client), got {err:?}");
    };
    assert!(msg.contains("acme"), "names the team: {msg}");
    assert!(msg.contains(".env"), "names the files: {msg}");
    let requests = mock.requests.lock().unwrap();
    assert!(
        !requests.iter().any(|r| r.contains("chunks")),
        "nothing uploads when the cycle refuses: {requests:?}"
    );
}

// ---------- §32 converge (multi-writer) ----------

/// A converging writer (§32): register the workspace and hand back a
/// client. Nothing is acquired — every Writer device may commit whenever
/// the CAS lets it.
fn converge_writer(mock: &MockRelay, dir: &Path, ws: &str, device: &str) -> RelayClient {
    std::fs::create_dir_all(dir).unwrap();
    let c = client(mock, ws, device);
    c.create_workspace("ws").unwrap();
    c
}

fn converge(dir: &Path, c: &RelayClient, device: &str) -> pear_core::converge::ConvergeReport {
    pear_core::converge::converge_once(dir, c, device, None).unwrap()
}

fn set_mtime(dir: &Path, rel: &str, secs: i64) {
    filetime::set_file_mtime(dir.join(rel), filetime::FileTime::from_unix_time(secs, 0)).unwrap();
}

/// The (hash, bytes) of a payload small enough to be exactly one chunk.
fn one_chunk(data: &[u8]) -> (String, Vec<u8>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), data).unwrap();
    let mut chunks: Vec<(String, Vec<u8>)> = pear_core::chunk::chunk_file(tmp.path())
        .unwrap()
        .map(|c| {
            let c = c.unwrap();
            (c.hash, c.data)
        })
        .collect();
    assert_eq!(chunks.len(), 1, "fixture must be a single chunk");
    chunks.pop().unwrap()
}

#[test]
fn converge_publishes_a_fresh_tree_then_idles() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = converge_writer(&mock, &dir_a, &meta.id, "device-a");
    write(&dir_a, "src/main.rs", b"fn main() {}\n");

    let report = converge(&dir_a, &a, "device-a");
    assert!(report.pushed);
    assert_eq!(report.head_seq, 1);
    assert_eq!(report.attempts, 1);
    assert!(report.conflict_copies.is_empty());
    assert_eq!(pear_core::sync::last_applied_seq(&dir_a), Some(1));

    let head = a.get_head().unwrap().unwrap();
    assert!(head.manifest.files.contains_key("src/main.rs"));

    // Nothing moved: the second converge neither pushes nor bumps the seq.
    let report = converge(&dir_a, &a, "device-a");
    assert!(!report.pushed, "an unchanged tree must not bump the head");
    assert_eq!(report.head_seq, 1);
}

/// Two writers editing disjoint files converge with both edits (§32).
#[test]
fn two_writers_converge_with_both_edits() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = converge_writer(&mock, &dir_a, &meta.id, "device-a");
    write(&dir_a, "a.txt", b"from a\n");
    assert!(converge(&dir_a, &a, "device-a").pushed);

    // B joins into an empty directory: its first converge materializes the
    // tree and publishes its own file in the same pass.
    let b = converge_writer(&mock, &dir_b, &meta.id, "device-b");
    write(&dir_b, "b.txt", b"from b\n");
    let report = converge(&dir_b, &b, "device-b");
    assert!(report.pushed);
    assert_eq!(report.written, vec!["a.txt"]);
    assert!(report.conflict_copies.is_empty());

    // A converges onto B's head and picks up b.txt.
    let report = converge(&dir_a, &a, "device-a");
    assert_eq!(report.written, vec!["b.txt"]);
    assert!(!report.pushed, "A had nothing of its own to publish");
    assert_eq!(tree(&dir_a), tree(&dir_b), "both devices end identical");
    assert_eq!(tree(&dir_a).len(), 2);
}

/// The same file edited on both devices: LWW picks one winner and the
/// loser survives as a conflict copy — on BOTH devices, byte-identically.
#[test]
fn conflicting_edits_end_with_the_same_conflict_copy_everywhere() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = converge_writer(&mock, &dir_a, &meta.id, "device-a");
    write(&dir_a, "notes.txt", b"shared\n");
    set_mtime(&dir_a, "notes.txt", 1_700_000_000);
    assert!(converge(&dir_a, &a, "device-a").pushed);

    let b = converge_writer(&mock, &dir_b, &meta.id, "device-b");
    assert!(!converge(&dir_b, &b, "device-b").pushed, "B only catches up");
    assert_eq!(std::fs::read(dir_b.join("notes.txt")).unwrap(), b"shared\n");

    // Both edit the same file offline; B's edit is the newer one.
    write(&dir_a, "notes.txt", b"from a\n");
    set_mtime(&dir_a, "notes.txt", 1_700_000_100);
    write(&dir_b, "notes.txt", b"from b\n");
    set_mtime(&dir_b, "notes.txt", 1_700_000_200);

    // A publishes first: only A moved since its base, so no conflict.
    let report = converge(&dir_a, &a, "device-a");
    assert!(report.pushed && report.conflict_copies.is_empty());

    // B merges: its newer edit wins the path, A's becomes the copy.
    let report = converge(&dir_b, &b, "device-b");
    assert!(report.pushed);
    assert_eq!(report.conflict_copies.len(), 1, "{report:?}");
    let copy = report.conflict_copies[0].clone();
    assert!(copy.starts_with("notes (conflict from remote "), "{copy}");
    assert!(copy.ends_with(".txt"), "{copy}");
    assert_eq!(std::fs::read(dir_b.join("notes.txt")).unwrap(), b"from b\n");
    assert_eq!(std::fs::read(dir_b.join(&copy)).unwrap(), b"from a\n");

    // A converges onto that head: same winner, same copy, no new conflict.
    let report = converge(&dir_a, &a, "device-a");
    assert!(report.conflict_copies.is_empty(), "{report:?}");
    assert_eq!(tree(&dir_a), tree(&dir_b), "both devices end identical");
    assert_eq!(std::fs::read(dir_a.join(&copy)).unwrap(), b"from a\n");
}

/// Delete on one device, edit on the other: the edit wins both ways (§32).
#[test]
fn converge_delete_versus_edit_both_directions() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = converge_writer(&mock, &dir_a, &meta.id, "device-a");
    write(&dir_a, "keep.txt", b"v1\n");
    write(&dir_a, "drop.txt", b"v1\n");
    converge(&dir_a, &a, "device-a");
    let b = converge_writer(&mock, &dir_b, &meta.id, "device-b");
    converge(&dir_b, &b, "device-b");

    // A deletes `keep.txt`; B edits it. The edit wins and restores it.
    std::fs::remove_file(dir_a.join("keep.txt")).unwrap();
    converge(&dir_a, &a, "device-a");
    write(&dir_b, "keep.txt", b"v2\n");
    let report = converge(&dir_b, &b, "device-b");
    assert!(report.pushed && report.conflict_copies.is_empty());
    converge(&dir_a, &a, "device-a");
    assert_eq!(
        std::fs::read(dir_a.join("keep.txt")).unwrap(),
        b"v2\n",
        "an edit restores a file the other device deleted"
    );

    // The other direction: B deletes `drop.txt` with nobody editing it, so
    // the delete propagates.
    std::fs::remove_file(dir_b.join("drop.txt")).unwrap();
    converge(&dir_b, &b, "device-b");
    let report = converge(&dir_a, &a, "device-a");
    assert_eq!(report.deleted, vec!["drop.txt"]);
    assert!(!dir_a.join("drop.txt").exists());
    assert_eq!(tree(&dir_a), tree(&dir_b));
}

/// A lost CAS race re-merges against the head that won and retries (§32
/// step 5) instead of failing the cycle.
#[test]
fn converge_rebases_onto_a_head_that_won_the_cas_race() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let shared = state.clone();
    // Armed below: the next `PUT /head` finds the head already advanced by
    // "another writer" and 409s, exactly like a real lost race.
    let interloper: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let armed = interloper.clone();
    let mock = MockRelay::start(Arc::new(move |head, body| {
        let line = head.lines().next().unwrap_or("");
        if line.starts_with("PUT ") && line.contains("/head") {
            if let Some(manifest) = armed.lock().unwrap().take() {
                let mut st = shared.lock().unwrap();
                st.head_seq += 1;
                let hash = blake3::hash(&serde_json::to_vec(&manifest).unwrap())
                    .to_hex()
                    .to_string();
                st.head = Some((hash, manifest, None));
            }
        }
        route(&shared, head, body)
    }));

    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = converge_writer(&mock, &dir_a, &meta.id, "device-a");
    write(&dir_a, "a.txt", b"from a\n");
    assert_eq!(converge(&dir_a, &a, "device-a").head_seq, 1);

    // The competing head is seq 1's plus a file only that writer has.
    let mut winner = a.get_head().unwrap().unwrap().manifest;
    let (hash, data) = one_chunk(b"from c\n");
    a.put_chunk(&hash, &data).unwrap();
    winner.files.insert(
        "c.txt".to_string(),
        pear_core::manifest::FileEntry {
            size: data.len() as u64,
            mode: 0o644,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 0,
            chunks: vec![hash],
        },
    );
    *interloper.lock().unwrap() = Some(serde_json::to_value(&winner).unwrap());

    write(&dir_a, "b.txt", b"from b\n");
    let report = converge(&dir_a, &a, "device-a");
    assert_eq!(report.attempts, 2, "the 409 costs exactly one re-merge");
    assert!(report.pushed);
    assert_eq!(report.head_seq, 3, "seq 2 was the interloper's");
    assert_eq!(report.written, vec!["c.txt"], "the winner's file is applied");
    let files = tree(&dir_a);
    assert_eq!(files.len(), 3, "{files:?}");
    assert_eq!(files["c.txt"], b"from c\n");
    assert_eq!(files["b.txt"], b"from b\n");
}

/// §32 under §17: two writers converge on an e2e workspace. Paths and
/// bytes never leave the devices in the clear — the head carries only
/// `manifest_enc` and the pool only ciphertext chunks.
#[test]
fn two_e2e_writers_converge_with_both_edits() {
    let (mock, state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("ws", None).unwrap();
    let keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
    write(&dir_a, "a.txt", b"from a\n");
    let report =
        pear_core::converge::converge_once(&dir_a, &a, "device-a", Some(&keyring)).unwrap();
    assert!(report.pushed && report.head_seq == 1);

    // B holds the same workspace key (a `pear join` unwraps it from the
    // relay; the test plants it directly).
    std::fs::create_dir_all(dir_b.join(".pear")).unwrap();
    pear_core::e2e::store_workspace_keyring(&dir_b, &keyring).unwrap();
    let b = client(&mock, &meta.id, "device-b");
    write(&dir_b, "b.txt", b"from b\n");
    let report =
        pear_core::converge::converge_once(&dir_b, &b, "device-b", Some(&keyring)).unwrap();
    assert!(report.pushed);
    assert_eq!(report.written, vec!["a.txt"]);
    assert_eq!(std::fs::read(dir_b.join("a.txt")).unwrap(), b"from a\n");

    pear_core::converge::converge_once(&dir_a, &a, "device-a", Some(&keyring)).unwrap();
    assert_eq!(tree(&dir_a), tree(&dir_b));

    // The relay saw ciphertext only: no plaintext head, no plaintext chunk.
    let st = state.lock().unwrap();
    let (_, manifest, manifest_enc) = st.head.as_ref().unwrap();
    assert!(manifest.is_null(), "an e2e head carries no plaintext manifest");
    assert!(manifest_enc.is_some());
    for blob in st.chunks.values() {
        assert!(
            !blob.windows(6).any(|w| w == b"from a" || w == b"from b"),
            "a plaintext byte reached the pool"
        );
    }
}

/// Converging an e2e workspace without its key is a deterministic refusal,
/// not a plaintext head published over an encrypted one (§17 pinning).
#[test]
fn converge_refuses_an_e2e_workspace_without_the_key() {
    let (mock, _state) = MockRelay::start_stateful();
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
    let a = client(&mock, &meta.id, "device-a");
    a.create_workspace_e2e("ws", None).unwrap();
    write(&dir_a, "a.txt", b"from a\n");

    let err = pear_core::converge::converge_once(&dir_a, &a, "device-a", None).unwrap_err();
    assert!(
        format!("{err:#}").contains("end-to-end encrypted"),
        "got {err:#}"
    );
    assert!(a.get_head().unwrap().is_none(), "nothing was published");
}
