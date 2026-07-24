//! End-to-end tests against a live relay: server on an ephemeral port,
//! temp data dir, driven with a real HTTP client.

use super::{serve_listener, AppState};

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::TryRecvError;

use std::time::Duration;

const TOKEN: &str = "test-token";

struct TestRelay {
    base: String,
    client: reqwest::Client,
    state: AppState,
    _data_dir: tempfile::TempDir,
}

async fn start_relay(lease_ttl_secs: u64) -> TestRelay {
    start_relay_with(lease_ttl_secs, 60).await
}

/// `start_relay` with a tunable WS role re-check interval (§14).
async fn start_relay_with(lease_ttl_secs: u64, ws_recheck_secs: u64) -> TestRelay {
    let data_dir = tempfile::tempdir().unwrap();
    let state = AppState::new(TOKEN, data_dir.path(), lease_ttl_secs)
        .unwrap()
        .with_ws_recheck_secs(ws_recheck_secs);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Bound before spawn, so connections queue in the backlog: no race.
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = serve_listener(listener, serve_state).await;
    });
    TestRelay {
        base: format!("http://{addr}"),
        client: reqwest::Client::new(),
        state,
        _data_dir: data_dir,
    }
}

impl TestRelay {
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("authorization", format!("Bearer {TOKEN}"))
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.authed(self.client.get(format!("{}{path}", self.base)))
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.authed(self.client.post(format!("{}{path}", self.base)))
    }

    fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.authed(self.client.put(format!("{}{path}", self.base)))
    }

    /// The same requests authenticated as some other token (§13 users).
    fn get_as(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {token}"))
    }

    fn post_as(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {token}"))
    }

    fn put_as(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .put(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {token}"))
    }

    fn delete_as(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .delete(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {token}"))
    }

    /// Live WS fan-out tasks for a workspace (§14): each holds one
    /// broadcast receiver, so this counts connected subscribers.
    fn ws_receiver_count(&self, workspace: &str) -> usize {
        self.state
            .broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(workspace)
            .map_or(0, |tx| tx.receiver_count())
    }
}

fn chunk_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// A valid pear-core manifest document (one file, one chunk).
fn test_manifest(ws: &str) -> String {
    json!({
        "version": 1,
        "workspace_id": ws,
        "scanned_at_secs": 0,
        "files": {
            "src/main.rs": {
                "size": 3,
                "mode": 420,
                "mtime_secs": 1,
                "mtime_nanos": 0,
                "chunks": [chunk_hash(b"foo")],
            }
        }
    })
    .to_string()
}

async fn create_ws(relay: &TestRelay, id: &str) {
    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": id, "name": "demo" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

async fn acquire(relay: &TestRelay, ws: &str, device: &str) -> Value {
    let resp = relay
        .post(&format!("/v1/workspaces/{ws}/lease/acquire"))
        .json(&json!({ "device_id": device }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn transfer(
    relay: &TestRelay,
    ws: &str,
    device: &str,
    generation: i64,
    base_seq: i64,
) -> reqwest::Response {
    relay
        .post(&format!("/v1/workspaces/{ws}/lease/transfer"))
        .json(&json!({
            "device_id": device,
            "generation": generation,
            "base_seq": base_seq,
        }))
        .send()
        .await
        .unwrap()
}

/// PUT /head with the raw manifest bytes preserved exactly as submitted.
async fn put_head_raw(
    relay: &TestRelay,
    ws: &str,
    base_seq: i64,
    manifest_json: &str,
    device: &str,
    generation: i64,
) -> reqwest::Response {
    relay
        .put(&format!("/v1/workspaces/{ws}/head"))
        .header("content-type", "application/json")
        .header("x-pear-device", device)
        .header("x-pear-generation", generation.to_string())
        .body(format!(
            r#"{{"base_seq":{base_seq},"manifest":{manifest_json}}}"#
        ))
        .send()
        .await
        .unwrap()
}

/// Upload one chunk body; returns its hash. (Unlike
/// `upload_fixture_chunk`, for tests that need several distinct chunks.)
async fn upload_chunk(relay: &TestRelay, ws: &str, data: &[u8]) -> String {
    let hash = chunk_hash(data);
    let resp = relay
        .put(&format!("/v1/workspaces/{ws}/chunks/{hash}"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    hash
}

/// Upload the fixture chunk every `test_manifest` references (the relay
/// rejects heads that point at chunks absent from the pool).
async fn upload_fixture_chunk(relay: &TestRelay, ws: &str) {
    let resp = relay
        .put(&format!(
            "/v1/workspaces/{ws}/chunks/{}",
            chunk_hash(b"foo")
        ))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn workspace_create_validates_id_and_name() {
    let relay = start_relay(300).await;
    for body in [
        json!({ "id": "", "name": "x" }),
        json!({ "id": "has/slash", "name": "x" }),
        json!({ "id": "ok-id", "name": "" }),
        json!({ "id": ".", "name": "x" }),
        json!({ "id": "..", "name": "x" }),
        json!({ "id": "...", "name": "x" }),
    ] {
        let resp = relay
            .post("/v1/workspaces")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{body}");
    }
}

#[tokio::test]
async fn auth_required_on_all_routes() {
    let relay = start_relay(300).await;
    let url = format!("{}/v1/workspaces/ws-x", relay.base);

    let resp = relay.client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401, "no token");

    let resp = relay
        .client
        .get(&url)
        .header("authorization", "Bearer nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong token");

    // The right token reaches the route (404 = unknown workspace, not 401).
    let resp = relay.get("/v1/workspaces/ws-x").send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // Auth applies to every route, not just workspace reads.
    let resp = relay.client.post(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn workspace_create_conflict_and_get() {
    let relay = start_relay(300).await;

    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-1", "name": "demo" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "id": "ws-1" }));

    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-1", "name": "demo again" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "same id must conflict");

    let resp = relay.get("/v1/workspaces/ws-1").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], "ws-1");
    assert_eq!(body["name"], "demo");
    assert_eq!(body["head_seq"], Value::Null);
    assert_eq!(body["head_hash"], Value::Null);
    assert_eq!(body["lease"], Value::Null);

    let resp = relay.get("/v1/workspaces/nope").send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn chunk_roundtrip_missing_check_and_hash_validation() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let data = b"hello relay";
    let hash = chunk_hash(data);

    // PUT is idempotent; GET returns byte-identical content.
    let resp = relay
        .put(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "repeat PUT is idempotent");

    let resp = relay
        .get(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&resp.bytes().await.unwrap()[..], data);

    // Batch presence check returns exactly the absent hashes, in order.
    let absent1 = chunk_hash(b"absent one");
    let absent2 = chunk_hash(b"absent two");
    let resp = relay
        .post("/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": [hash, absent1, absent2] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "missing": [absent1, absent2] }));

    // Invalid :hash values are rejected before the store is touched.
    for bad in ["xyz".to_string(), "A".repeat(64), "ab".repeat(31)] {
        let resp = relay
            .put(&format!("/v1/workspaces/ws-1/chunks/{bad}"))
            .body(b"x".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "PUT {bad}");
        let resp = relay
            .get(&format!("/v1/workspaces/ws-1/chunks/{bad}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "GET {bad}");
    }
    let resp = relay
        .post("/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": ["not-hex"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "missing-check with invalid hash");

    // Unknown chunk and unknown workspace are 404.
    let resp = relay
        .get(&format!(
            "/v1/workspaces/ws-1/chunks/{}",
            chunk_hash(b"never stored")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = relay
        .put(&format!("/v1/workspaces/nope/chunks/{hash}"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// §22: with the pool store deferred, a chunk PUT followed immediately by
/// GET + chunks/missing behaves exactly as it did eagerly — visibility
/// never waits on the fsync — and the store the routes write to flushes
/// cleanly. `flush` is driven DIRECTLY here: no test may depend on the
/// backstop task's tick, so the manual call is the deterministic stand-in
/// for it (TestRelay gets the real flusher for free — it serves through
/// `serve_listener`). Note what this does NOT pin: deferred vs
/// eager is invisible black-box (the rename serves bytes pre-fsync
/// either way) — the deferred wiring itself lives in `AppState::new`'s
/// `open_deferred` and is a code-review fact, not an observable one.
#[tokio::test]
async fn chunk_routes_behave_identically_behind_the_deferred_pool() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let data = b"deferred pool roundtrip";
    let hash = chunk_hash(data);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET and chunks/missing answer immediately, no flush waited on.
    let resp = relay
        .get(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&resp.bytes().await.unwrap()[..], data);
    let resp = relay
        .post("/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": [hash] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "missing": [] }));

    // The deterministic flush: succeeds, and moves no bytes — the chunk
    // is still served byte-identically afterwards.
    relay.state.store.flush().unwrap();
    let resp = relay
        .get(&format!("/v1/workspaces/ws-1/chunks/{hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&resp.bytes().await.unwrap()[..], data);
}

/// §22 commit-point durability: a `put_head` commit flushes the deferred
/// pool BEFORE the head row commits, so the commit leaves the pool's
/// deferred queue EMPTY — and a snapshot commit does the same. Only the
/// post-commit zero is asserted, never the pre-commit depth: the 5 s
/// backstop tick may legitimately drain the queue first, and no test may
/// depend on any tick timing (the zero is race-free either way — the
/// commit flushes, and nothing PUTs afterwards). `pending_len` is the
/// store's test-only queue view, `debug_assertions`-gated so it crosses
/// the crate boundary from pear-core.
#[tokio::test]
async fn head_and_snapshot_commits_drain_the_deferred_pool_queue() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // One chunk PUT queues its fd in the deferred store (far below the
    // 64-pending self-flush threshold); the head commit must drain it.
    upload_fixture_chunk(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "dev").await;
    let generation = lease["generation"].as_i64().unwrap();
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        relay.state.store.pending_len(),
        0,
        "a head commit flushes the deferred pool before committing"
    );

    // Same for a snapshot commit: a second chunk PUT queues again, and a
    // snapshot whose manifest references it must drain the queue.
    let data2 = b"snapshot-referenced chunk";
    let hash2 = chunk_hash(data2);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-1/chunks/{hash2}"))
        .body(data2.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": "snap",
            "device": "dev",
            "manifest": json!({
                "version": 1,
                "workspace_id": "ws-1",
                "scanned_at_secs": 0,
                "files": {
                    "src/other.rs": {
                        "size": data2.len() as u64,
                        "mode": 420,
                        "mtime_secs": 1,
                        "mtime_nanos": 0,
                        "chunks": [hash2],
                    }
                }
            }),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert_eq!(
        relay.state.store.pending_len(),
        0,
        "a snapshot commit flushes the deferred pool before committing"
    );
}

// --- §23 batched chunk transfer ----------------------------------------------

/// Encode (hash, bytes) entries with the shared §23 codec.
fn put_many_frame<'a>(entries: impl Iterator<Item = (&'a str, &'a [u8])>) -> Vec<u8> {
    pear_core::chunk_frame::encode(entries)
}

/// POST a frame to put_many as `token`; returns the response.
async fn post_put_many(relay: &TestRelay, token: &str, ws: &str, frame: Vec<u8>) -> reqwest::Response {
    relay
        .post_as(token, &format!("/v1/workspaces/{ws}/chunks/put_many"))
        .header("content-type", "application/octet-stream")
        .body(frame)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn put_many_stores_dedupes_and_isolates_bad_entries() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // h_existing is already in the pool via a single PUT, so the batch
    // sees every status: stored, present, error.
    let h_existing = chunk_hash(b"already there");
    let resp = relay
        .put(&format!("/v1/workspaces/ws-1/chunks/{h_existing}"))
        .body(b"already there".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // A bad entry: bytes that do not hash to their claimed name (the
    // frame itself is well-formed — its hashes are 64 lowercase hex).
    let h_bad = chunk_hash(b"honest bytes");
    // An oversized entry: over MAX_CHUNK_SIZE, so its own error status.
    let oversized = vec![b'x'; pear_core::chunk::MAX_CHUNK_SIZE as usize + 1];
    let h_oversized = chunk_hash(&oversized);

    let h1 = chunk_hash(b"batch one");
    let h2 = chunk_hash(b"batch two");
    let frame = put_many_frame([
        (h1.as_str(), &b"batch one"[..]),
        (h_existing.as_str(), &b"already there"[..]),
        (h_bad.as_str(), &b"forged bytes"[..]),
        (h_oversized.as_str(), oversized.as_slice()),
        (h2.as_str(), &b"batch two"[..]),
    ]
    .into_iter());
    let resp = post_put_many(&relay, TOKEN, "ws-1", frame).await;
    assert_eq!(
        resp.status(),
        200,
        "one bad entry must not fail the batch (§23)"
    );
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    // One result per entry, in REQUEST order.
    let statuses: Vec<(&str, &str)> = results
        .iter()
        .map(|r| {
            (
                r["hash"].as_str().unwrap(),
                r["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        vec![
            (h1.as_str(), "stored"),
            (h_existing.as_str(), "present"),
            (h_bad.as_str(), "error"),
            (h_oversized.as_str(), "error"),
            (h2.as_str(), "stored"),
        ]
    );
    // Each error entry carries a short reason; the good ones none.
    assert!(results[2]["reason"]
        .as_str()
        .unwrap()
        .contains("does not hash"));
    assert!(results[3]["reason"]
        .as_str()
        .unwrap()
        .contains("over the"));
    assert!(results[0].get("reason").is_none());

    // The good entries are in the pool AND earned visibility (refs rows
    // inserted even for the deduped one — the §22 single-PUT behavior):
    // chunks/missing reports only the failed entries' hashes.
    let resp = relay
        .post("/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": [h1, h2, h_existing, h_bad, h_oversized] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "missing": [h_bad, h_oversized] }));
}

#[tokio::test]
async fn put_many_enforces_the_entry_and_byte_caps() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // One entry over the 256-entry cap → 400 before anything is stored.
    let too_many: Vec<(String, Vec<u8>)> = (0..=pear_core::chunk_frame::PUT_MANY_MAX_ENTRIES)
        .map(|i| {
            let data = format!("entry {i}").into_bytes();
            (chunk_hash(&data), data)
        })
        .collect();
    let frame = put_many_frame(too_many.iter().map(|(h, d)| (h.as_str(), d.as_slice())));
    let resp = post_put_many(&relay, TOKEN, "ws-1", frame).await;
    assert_eq!(resp.status(), 400, "over the entry cap");

    // 33 × 1 MiB decoded blobs — each entry individually legal, the SUM
    // over the 32 MiB cap → 400.
    let one_mib = vec![7u8; 1024 * 1024];
    let big: Vec<(String, Vec<u8>)> = (0..33)
        .map(|i| (chunk_hash(&[i]), one_mib.clone()))
        .collect();
    let frame = put_many_frame(big.iter().map(|(h, d)| (h.as_str(), d.as_slice())));
    let resp = post_put_many(&relay, TOKEN, "ws-1", frame).await;
    assert_eq!(resp.status(), 400, "over the decoded-bytes cap");

    // A body that is not a frame at all → 400, never a panic.
    let resp = post_put_many(&relay, TOKEN, "ws-1", b"\x01\x02".to_vec()).await;
    assert_eq!(resp.status(), 400, "hostile bytes are a 400");
    // A truncated frame (count claims entries the body does not hold).
    let resp = post_put_many(&relay, TOKEN, "ws-1", 5u32.to_le_bytes().to_vec()).await;
    assert_eq!(resp.status(), 400, "truncated frame");
}

#[tokio::test]
async fn put_many_requires_the_writer_role() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let bob = create_user(&relay, "bob").await;
    let carol = create_user(&relay, "carol").await;
    // Alice owns a team workspace; bob is a team reader; carol has no role.
    let team = create_team(&relay, &alice, "dev").await;
    add_member(&relay, &alice, &team, "bob", "reader").await;
    create_ws_as(&relay, &alice, "ws-r", "r", Some(&team)).await;

    let data = b"gated batch";
    let frame = put_many_frame([(chunk_hash(data).as_str(), &data[..])].into_iter());

    // A reader cannot upload (Writer required, same as the single PUT).
    let resp = post_put_many(&relay, &bob, "ws-r", frame.clone()).await;
    assert_eq!(resp.status(), 403, "reader may not put_many");
    // No role at all is the existence-hiding 404 (§13).
    let resp = post_put_many(&relay, &carol, "ws-r", frame.clone()).await;
    assert_eq!(resp.status(), 404, "no role hides the workspace");
    // The workspace owner stores fine.
    let resp = post_put_many(&relay, &alice, "ws-r", frame).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["results"][0]["status"], "stored");
}

#[tokio::test]
async fn get_many_returns_request_order_and_enforces_visibility() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let mallory = create_user(&relay, "mallory").await;
    create_ws_as(&relay, &alice, "ws-a2", "a", None).await;

    // Store three chunks via put_many (the batch round trip, end to end).
    let datas: [&[u8]; 3] = [b"one", b"two two", b"three three three"];
    let hashes: Vec<String> = datas.iter().map(|d| chunk_hash(d)).collect();
    let frame = put_many_frame(
        hashes
            .iter()
            .zip(datas)
            .map(|(h, d)| (h.as_str(), d)),
    );
    let resp = post_put_many(&relay, &alice, "ws-a2", frame).await;
    assert_eq!(resp.status(), 200);

    // GET in a scrambled order: the frame comes back in REQUEST order,
    // content-typed as an octet stream.
    let order = [hashes[2].clone(), hashes[0].clone(), hashes[1].clone()];
    let resp = relay
        .post_as(&alice, "/v1/workspaces/ws-a2/chunks/get_many")
        .json(&json!({ "hashes": order }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    let entries = pear_core::chunk_frame::decode(&resp.bytes().await.unwrap()).unwrap();
    let got: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(h, b)| (h.as_str(), b.as_slice()))
        .collect();
    assert_eq!(
        got,
        vec![
            (hashes[2].as_str(), &b"three three three"[..]),
            (hashes[0].as_str(), &b"one"[..]),
            (hashes[1].as_str(), &b"two two"[..]),
        ]
    );

    // An absent (well-formed) hash fails the WHOLE request with a 404
    // naming it — even though the other hash exists.
    let absent = chunk_hash(b"not in the pool");
    let resp = relay
        .post_as(&alice, "/v1/workspaces/ws-a2/chunks/get_many")
        .json(&json!({ "hashes": [hashes[0], absent] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains(&absent),
        "the 404 names the missing chunk: {body}"
    );

    // Mallory (own workspace, no refs to these chunks): the pool is
    // global but content visibility is not — same whole-request 404.
    create_ws_as(&relay, &mallory, "ws-m2", "m", None).await;
    let resp = relay
        .post_as(&mallory, "/v1/workspaces/ws-m2/chunks/get_many")
        .json(&json!({ "hashes": [hashes[0]] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "no cross-tenant batched reads");
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains(&hashes[0]));

    // Over the 128-hash cap → 400; a malformed hash → 400.
    let too_many: Vec<String> = (0..=pear_core::chunk_frame::GET_MANY_MAX_HASHES)
        .map(|i| chunk_hash(format!("x{i}").as_bytes()))
        .collect();
    let resp = relay
        .post_as(&alice, "/v1/workspaces/ws-a2/chunks/get_many")
        .json(&json!({ "hashes": too_many }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "over the hash cap");
    let resp = relay
        .post_as(&alice, "/v1/workspaces/ws-a2/chunks/get_many")
        .json(&json!({ "hashes": ["not-hex"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "malformed hash");
}

#[tokio::test]
async fn head_put_cas_fencing_and_verbatim_get() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let manifest = test_manifest("ws-1");
    let manifest_hash = blake3::hash(manifest.as_bytes()).to_hex().to_string();

    // No head yet.
    let resp = relay.get("/v1/workspaces/ws-1/head").send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // Head writes are fenced without a lease.
    let resp = put_head_raw(&relay, "ws-1", 0, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 403, "no lease held");

    let lease = acquire(&relay, "ws-1", "laptop-a").await;
    assert_eq!(lease["generation"].as_i64().unwrap(), 1);

    // First write commits at seq 1; hash = BLAKE3 of the exact manifest bytes.
    let resp = put_head_raw(&relay, "ws-1", 0, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"].as_i64().unwrap(), 1);
    assert_eq!(body["hash"].as_str().unwrap(), manifest_hash);

    // Stale base_seq is a CAS conflict carrying the current seq.
    let resp = put_head_raw(&relay, "ws-1", 0, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "current_seq": 1 }));

    // Fencing: wrong device, wrong generation.
    let resp = put_head_raw(&relay, "ws-1", 1, &manifest, "laptop-b", 1).await;
    assert_eq!(resp.status(), 403, "wrong device");
    let resp = put_head_raw(&relay, "ws-1", 1, &manifest, "laptop-a", 99).await;
    assert_eq!(resp.status(), 403, "stale generation");

    // Correct base_seq advances the log.
    let resp = put_head_raw(&relay, "ws-1", 1, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"].as_i64().unwrap(), 2);

    // GET /head returns the manifest bytes verbatim.
    let resp = relay.get("/v1/workspaces/ws-1/head").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains(&manifest), "manifest not verbatim in {text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["seq"].as_i64().unwrap(), 2);
    assert_eq!(body["hash"].as_str().unwrap(), manifest_hash);

    // The workspace read mirrors head and lease state.
    let resp = relay.get("/v1/workspaces/ws-1").send().await.unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["head_seq"].as_i64().unwrap(), 2);
    assert_eq!(body["head_hash"].as_str().unwrap(), manifest_hash);
    assert_eq!(body["lease"]["holder"], "laptop-a");
    assert_eq!(body["lease"]["generation"].as_i64().unwrap(), 1);

    // Unknown workspace: 404 on both GET and PUT.
    let resp = relay.get("/v1/workspaces/nope/head").send().await.unwrap();
    assert_eq!(resp.status(), 404);
    let resp = put_head_raw(&relay, "nope", 0, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn head_put_rejects_unsafe_and_malformed_manifests() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    acquire(&relay, "ws-1", "laptop-a").await;

    // Path traversal must never reach the head log.
    let evil = json!({
        "version": 1,
        "workspace_id": "ws-1",
        "scanned_at_secs": 0,
        "files": {
            "../evil": {
                "size": 1, "mode": 420, "mtime_secs": 0, "mtime_nanos": 0, "chunks": []
            }
        }
    })
    .to_string();
    let resp = put_head_raw(&relay, "ws-1", 0, &evil, "laptop-a", 1).await;
    assert_eq!(resp.status(), 400, "unsafe path");

    // Well-formed JSON, but not a pear manifest.
    let resp = put_head_raw(&relay, "ws-1", 0, r#"{"files": 42}"#, "laptop-a", 1).await;
    assert_eq!(resp.status(), 400, "not a manifest");

    // Malformed request JSON.
    let resp = relay
        .put("/v1/workspaces/ws-1/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", "1")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "malformed JSON");

    // Missing required field (base_seq).
    let resp = relay
        .put("/v1/workspaces/ws-1/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", "1")
        .body(format!(r#"{{"manifest":{}}}"#, test_manifest("ws-1")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "missing base_seq");
}

#[tokio::test]
async fn lease_acquire_conflict_and_heartbeat() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // Lease ops on an unknown workspace are 404.
    let resp = relay
        .post("/v1/workspaces/nope/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let lease = acquire(&relay, "ws-1", "laptop-a").await;
    assert_eq!(lease["generation"].as_i64().unwrap(), 1);
    let expires_at = lease["expires_at"].as_i64().unwrap();

    // A second device cannot take a held lease.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/acquire")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["holder"], "laptop-a");
    assert_eq!(body["expires_at"].as_i64().unwrap(), expires_at);

    // Re-acquire by the holder succeeds without a generation bump.
    let lease = acquire(&relay, "ws-1", "laptop-a").await;
    assert_eq!(lease["generation"].as_i64().unwrap(), 1);

    // Heartbeat extends the lease.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-a", "generation": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["expires_at"].as_i64().unwrap() >= expires_at);

    // Wrong holder or stale generation is fenced.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-a", "generation": 99 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "stale generation");
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-b", "generation": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "not the holder");
}

#[tokio::test]
async fn lease_expiry_allows_steal_and_fences_old_writer() {
    let relay = start_relay(1).await;
    create_ws(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "laptop-a").await;
    assert_eq!(lease["generation"].as_i64().unwrap(), 1);

    // Whole-second expiry granularity: 1.2s always crosses a 1s TTL.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    // Expired lease: a steal succeeds and bumps the generation.
    let lease = acquire(&relay, "ws-1", "laptop-b").await;
    assert_eq!(
        lease["generation"].as_i64().unwrap(),
        2,
        "steal bumps generation"
    );

    // The old writer is fenced: heartbeat and head writes fail.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-a", "generation": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 403);

    // Keep laptop-b's lease fresh for the still-valid assertion below —
    // under load, the 1s TTL could otherwise lapse mid-test.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-b", "generation": 2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The new holder now holds a valid lease.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn lease_transfer_requires_synced_requester_and_expired_or_own_lease() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    acquire(&relay, "ws-1", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200, "head at seq 1");

    // Not synced to head.
    let resp = transfer(&relay, "ws-1", "laptop-b", 1, 0).await;
    assert_eq!(resp.status(), 409, "requester behind head");

    // Synced, but the lease is valid and held by another device.
    let resp = transfer(&relay, "ws-1", "laptop-b", 1, 1).await;
    assert_eq!(resp.status(), 409, "valid lease held by another device");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["holder"], "laptop-a");

    // Transfer to the current holder succeeds and keeps the generation.
    let resp = transfer(&relay, "ws-1", "laptop-a", 1, 1).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["generation"].as_i64().unwrap(), 1);
}

#[tokio::test]
async fn lease_transfer_after_expiry_bumps_generation_and_fences() {
    let relay = start_relay(1).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    acquire(&relay, "ws-1", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    // Synced requester + expired lease: transfer succeeds, generation bumps.
    let resp = transfer(&relay, "ws-1", "laptop-b", 1, 1).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["generation"].as_i64().unwrap(), 2);

    // The old writer is fenced out of head writes...
    let resp = put_head_raw(&relay, "ws-1", 1, &test_manifest("ws-1"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 403);

    // Keep laptop-b's lease fresh for the write below (1s TTL, slow CI).
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-b", "generation": 2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // ...and the new holder writes at seq 2.
    let resp = put_head_raw(&relay, "ws-1", 1, &test_manifest("ws-1"), "laptop-b", 2).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"].as_i64().unwrap(), 2);
}

#[tokio::test]
async fn lease_force_always_succeeds_and_bumps_generation() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // Force with no lease at all starts at generation 1.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["generation"].as_i64().unwrap(), 1);

    // Force over a valid lease held by another device.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["generation"].as_i64().unwrap(), 2);

    // The revoked writer's heartbeat is fenced.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-a", "generation": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Force again bumps even for the current holder.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["generation"].as_i64().unwrap(), 3);
}

#[tokio::test]
async fn chunk_put_rejects_body_that_does_not_hash_to_its_name() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-verify").await;

    // Correct body for its hash: accepted.
    let good = b"honest bytes";
    let good_hash = chunk_hash(good);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-verify/chunks/{good_hash}"))
        .body(good.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Wrong bytes under a well-formed hash: rejected, and nothing stored.
    let bad_hash = chunk_hash(b"something else entirely");
    let resp = relay
        .put(&format!("/v1/workspaces/ws-verify/chunks/{bad_hash}"))
        .body(b"forged bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = relay
        .get(&format!("/v1/workspaces/ws-verify/chunks/{bad_hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn chunk_put_enforces_the_max_chunk_size() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-size").await;

    // Exactly the chunker maximum: accepted.
    let max = pear_core::chunk::MAX_CHUNK_SIZE as usize;
    let ok_body = vec![7u8; max];
    let ok_hash = chunk_hash(&ok_body);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-size/chunks/{ok_hash}"))
        .body(ok_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // One byte over the chunk contract: the per-route body limit rejects
    // it before any hashing (413 Payload Too Large), and nothing is stored.
    let big_body = vec![7u8; max + 1];
    let big_hash = chunk_hash(&big_body);
    let resp = relay
        .put(&format!("/v1/workspaces/ws-size/chunks/{big_hash}"))
        .body(big_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    let resp = relay
        .get(&format!("/v1/workspaces/ws-size/chunks/{big_hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn head_put_rejects_manifest_of_another_workspace() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-a").await;
    let resp = relay
        .post("/v1/workspaces/ws-a/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let generation = body["generation"].clone();

    // A head whose manifest belongs to ws-b, committed under ws-a: 400.
    let resp = relay
        .put("/v1/workspaces/ws-a/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({
            "base_seq": 0,
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-b")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[test]
fn head_log_is_pruned_to_the_newest_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open(&dir.path().join("relay.db")).unwrap();
    let created = db.create_workspace("ws", "w", None, None, false).unwrap();
    assert!(matches!(
        created,
        crate::db::CreateWorkspaceOutcome::Created
    ));
    for seq in 1..=60 {
        db.insert_head("ws", seq, &format!("h{seq}"), "{}", &Default::default())
            .unwrap();
    }
    // Only the newest HEAD_KEEP rows are retained.
    assert_eq!(db.head_count("ws").unwrap(), 50);
    let head = db.current_head("ws").unwrap().unwrap();
    assert_eq!(head.seq, 60);
}

#[test]
fn failed_head_insert_rolls_back_chunk_refs() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open(&dir.path().join("relay.db")).unwrap();
    let created = db
        .create_workspace("ws2", "w2", Some("alice"), None, false)
        .unwrap();
    assert!(matches!(
        created,
        crate::db::CreateWorkspaceOutcome::Created
    ));

    // A successful commit makes its refs visible atomically.
    let refs1: std::collections::HashSet<String> = ["h1".to_string()].into_iter().collect();
    db.insert_head("ws2", 1, "hash1", "{}", &refs1).unwrap();
    assert!(db.chunk_visible_to("h1", "alice").unwrap());

    // A duplicate head (PK violation) fails: its refs must roll back with
    // it, never leaving a head-invisible-to-readers window.
    let refs2: std::collections::HashSet<String> = ["h2".to_string()].into_iter().collect();
    assert!(db.insert_head("ws2", 1, "hash1b", "{}", &refs2).is_err());
    assert!(
        !db.chunk_visible_to("h2", "alice").unwrap(),
        "refs from the failed insert must not persist"
    );
}

#[test]
fn failed_team_create_rolls_back_the_team_row() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open(&dir.path().join("relay.db")).unwrap();

    // The owner insert fails (fault injection): the team row must roll
    // back with it, leaving the name free — an ownerless team could
    // never gain an owner (member management is owner-gated) and would
    // squat the unique name forever.
    assert!(db
        .create_team_with_owner_fault("t1", "acme", 1, "alice")
        .is_err());
    assert!(db.get_team_by_name("acme").unwrap().is_none());

    // ...so the same name succeeds on retry, with its owner seated.
    assert!(db
        .create_team_with_owner("t2", "acme", 2, "alice", true)
        .unwrap());
    assert_eq!(
        db.member_role("t2", "alice").unwrap().as_deref(),
        Some("owner")
    );
}

#[test]
fn empty_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // An empty token would authorize `Authorization: Bearer ` (empty
    // credential) for every request — refuse to start at all.
    let err = crate::AppState::new("", dir.path(), 300)
        .err()
        .expect("an empty token must be rejected");
    assert!(format!("{err:#}").contains("empty"));
}

#[tokio::test]
async fn chunks_are_only_visible_to_readers_of_referencing_workspaces() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let mallory = create_user(&relay, "mallory").await;

    // Alice's workspace references the fixture chunk (upload + head).
    create_ws_as(&relay, &alice, "ws-a", "a", None).await;
    let chunk = chunk_hash(b"foo");
    let resp = relay
        .put_as(&alice, &format!("/v1/workspaces/ws-a/chunks/{chunk}"))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    acquire(&relay, "ws-a", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-a", 0, &test_manifest("ws-a"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);

    // Mallory self-provisions a workspace: the pool stays global, but
    // content visibility is not.
    create_ws_as(&relay, &mallory, "ws-m", "m", None).await;
    let resp = relay
        .get_as(&mallory, &format!("/v1/workspaces/ws-m/chunks/{chunk}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "no cross-tenant chunk reads");
    let resp = relay
        .post_as(&mallory, "/v1/workspaces/ws-m/chunks/missing")
        .json(&json!({ "hashes": [chunk] }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["missing"].as_array().unwrap().len(),
        1,
        "no cross-tenant presence oracle"
    );

    // Alice reads her own workspace's chunk fine.
    let resp = relay
        .get_as(&alice, &format!("/v1/workspaces/ws-a/chunks/{chunk}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Dedup flow: mallory supplies the same bytes herself and commits;
    // her workspace then references the chunk and reads succeed.
    let resp = relay
        .put_as(&mallory, &format!("/v1/workspaces/ws-m/chunks/{chunk}"))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    acquire(&relay, "ws-m", "laptop-m").await;
    let resp = put_head_raw(&relay, "ws-m", 0, &test_manifest("ws-m"), "laptop-m", 1).await;
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get_as(&mallory, &format!("/v1/workspaces/ws-m/chunks/{chunk}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn snapshot_cannot_reference_chunks_the_caller_cannot_see() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let mallory = create_user(&relay, "mallory").await;

    // Alice's workspace references the fixture chunk (upload + head).
    create_ws_as(&relay, &alice, "ws-a", "a", None).await;
    let chunk = chunk_hash(b"foo");
    relay
        .put_as(&alice, &format!("/v1/workspaces/ws-a/chunks/{chunk}"))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    acquire(&relay, "ws-a", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-a", 0, &test_manifest("ws-a"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);

    // Mallory cannot snapshot a manifest referencing alice's chunk, and
    // the response is the same 400 as for a chunk that does not exist at
    // all: no cross-tenant presence oracle via the validation boundary.
    create_ws_as(&relay, &mallory, "ws-m", "m", None).await;
    acquire(&relay, "ws-m", "laptop-m").await;
    for hash in [chunk.clone(), chunk_hash(b"never existed")] {
        let mut manifest: Value = serde_json::from_str(&test_manifest("ws-m")).unwrap();
        manifest["files"]["src/main.rs"]["chunks"] = json!([hash]);
        let resp = relay
            .post_as(&mallory, "/v1/workspaces/ws-m/snapshots")
            .json(&json!({
                "name": null,
                "device": "laptop-m",
                "manifest": manifest,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            400,
            "referencing an invisible or absent chunk must fail identically"
        );
    }

    // After she supplies the bytes herself (proof of knowledge, recorded
    // at put_chunk), the same snapshot commits.
    let resp = relay
        .put_as(&mallory, &format!("/v1/workspaces/ws-m/chunks/{chunk}"))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .post_as(&mallory, "/v1/workspaces/ws-m/snapshots")
        .json(&json!({
            "name": null,
            "device": "laptop-m",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-m")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn user_tokens_are_stored_as_digests_only() {
    let relay = start_relay(300).await;
    let jane_token = create_user(&relay, "jane").await;
    let db = crate::db::Db::open(&relay._data_dir.path().join("relay.db")).unwrap();
    let stored = db.user_token_digests().unwrap();
    assert_eq!(stored.len(), 1);
    let expected = blake3::hash(jane_token.as_bytes()).to_hex().to_string();
    assert_eq!(stored[0].1, expected, "only the digest is stored");
    assert_ne!(stored[0].1, jane_token);
}

#[tokio::test]
async fn workspace_conflicts_carry_a_machine_kind() {
    let relay = start_relay(300).await;
    let owner = create_user(&relay, "owner").await;
    let team = create_team(&relay, &owner, "acme").await;
    create_ws_as(&relay, &owner, "ws-1", "api", Some(&team)).await;

    // Same id again: id_conflict (the benign idempotent case).
    let resp = relay
        .post_as(&owner, "/v1/workspaces")
        .json(&json!({ "id": "ws-1", "name": "api", "team_id": team }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "id_conflict");

    // Different id, same name in the same team: name_conflict.
    let resp = relay
        .post_as(&owner, "/v1/workspaces")
        .json(&json!({ "id": "ws-2", "name": "api", "team_id": team }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "name_conflict");
}

#[tokio::test]
async fn id_conflict_is_hidden_from_users_without_a_role() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let mallory = create_user(&relay, "mallory").await;
    create_ws_as(&relay, &alice, "ws-secret", "s", None).await;

    // A user with no role on ws-secret cannot probe its existence (§13
    // existence hiding beats the idempotent-conflict signal).
    let resp = relay
        .post_as(&mallory, "/v1/workspaces")
        .json(&json!({ "id": "ws-secret", "name": "s" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The owner sees the benign id_conflict.
    let resp = relay
        .post_as(&alice, "/v1/workspaces")
        .json(&json!({ "id": "ws-secret", "name": "s" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "id_conflict");
}

#[tokio::test]
async fn last_owner_cannot_demote_themselves() {
    let relay = start_relay(300).await;
    let alice = create_user(&relay, "alice").await;
    let _bob = create_user(&relay, "bob").await;
    let team = create_team(&relay, &alice, "acme").await;

    // Sole owner demoting themselves: refused — a team must never be left
    // ownerless (member management is owner-gated with no override).
    let resp = relay
        .post_as(&alice, &format!("/v1/teams/{team}/members"))
        .json(&json!({ "user": "alice", "role": "writer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // With a second owner in place, demotion is fine.
    add_member(&relay, &alice, &team, "bob", "owner").await;
    let resp = relay
        .post_as(&alice, &format!("/v1/teams/{team}/members"))
        .json(&json!({ "user": "alice", "role": "writer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn snapshot_create_list_get_roundtrip() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let manifest = test_manifest("ws-1");

    // First snapshot: named. Ids are per-workspace incrementing (§12).
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": "before refactor",
            "device": "laptop-a",
            "manifest": serde_json::from_str::<Value>(&manifest).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_i64().unwrap(), 1);
    assert!(body["created_at"].as_i64().unwrap() > 0);

    // Second: name may be null.
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "device": "laptop-a",
            "manifest": serde_json::from_str::<Value>(&manifest).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_i64().unwrap(), 2);

    // List: newest first, metadata only.
    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let list = body["snapshots"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["id"].as_i64().unwrap(), 2, "newest first");
    assert_eq!(list[1]["id"].as_i64().unwrap(), 1);
    assert_eq!(list[0]["name"], Value::Null);
    assert_eq!(list[1]["name"], "before refactor");
    assert_eq!(list[0]["kind"], "named");
    assert_eq!(list[0]["device"], "laptop-a");
    assert!(list[0].get("manifest").is_none(), "list is metadata only");

    // Get one: the manifest comes back verbatim.
    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots/1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains(&manifest), "manifest not verbatim in {text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["id"].as_i64().unwrap(), 1);
    assert_eq!(body["kind"], "named");

    // Absent snapshot: 404.
    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots/99")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn snapshot_create_validation_failures() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    // Unknown workspace: 404 on create, list, and get.
    let resp = relay
        .post("/v1/workspaces/nope/snapshots")
        .json(&json!({ "name": null, "device": "d", "manifest": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = relay
        .get("/v1/workspaces/nope/snapshots")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = relay
        .get("/v1/workspaces/nope/snapshots/1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The manifest references a well-formed hash that was never uploaded.
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "device": "d",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-1")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "missing chunks");

    // A manifest belonging to a different workspace id: 400.
    upload_fixture_chunk(&relay, "ws-1").await;
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "device": "d",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-other")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "workspace-id mismatch");

    // Malformed chunk hash (uppercase/short): 400.
    let mut manifest: Value = serde_json::from_str(&test_manifest("ws-1")).unwrap();
    manifest["files"]["src/main.rs"]["chunks"] = json!(["ABCDEF0123"]);
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({ "name": null, "device": "d", "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "malformed hash");

    // `device` is a required string.
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-1")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "device is required");
}

#[tokio::test]
async fn lease_force_checkpoints_the_overwritten_head() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let manifest = test_manifest("ws-1");

    // Force with no head: no checkpoint.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["snapshots"].as_array().unwrap().len(),
        0,
        "no head, no checkpoint"
    );

    // Commit a head, then force from another device: the old head is
    // checkpointed first, credited to the outgoing holder (§12).
    acquire(&relay, "ws-1", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-1", 0, &manifest, "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let list = body["snapshots"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"].as_i64().unwrap(), 1);
    assert_eq!(list[0]["kind"], "checkpoint");
    assert_eq!(
        list[0]["device"], "laptop-a",
        "credited to the outgoing holder"
    );
    assert_eq!(list[0]["name"], Value::Null);

    // The checkpoint's manifest is the overwritten head, verbatim.
    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots/1")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert!(
        text.contains(&manifest),
        "checkpoint manifest not verbatim in {text}"
    );
}

#[tokio::test]
async fn force_checkpoint_dedupes_unchanged_heads_and_self_force() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-d").await;
    upload_fixture_chunk(&relay, "ws-d").await;
    acquire(&relay, "ws-d", "laptop-a").await;
    let resp = put_head_raw(&relay, "ws-d", 0, &test_manifest("ws-d"), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);

    // Force by another device: one checkpoint of the current head.
    let resp = relay
        .post("/v1/workspaces/ws-d/lease/force")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Force by yet another device with the head unchanged: already
    // captured — no duplicate row.
    let resp = relay
        .post("/v1/workspaces/ws-d/lease/force")
        .json(&json!({ "device_id": "laptop-c" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Force by the current holder: nothing new to preserve.
    let resp = relay
        .post("/v1/workspaces/ws-d/lease/force")
        .json(&json!({ "device_id": "laptop-c" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = relay
        .get("/v1/workspaces/ws-d/snapshots")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let checkpoints = body["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["kind"] == "checkpoint")
        .count();
    assert_eq!(
        checkpoints, 1,
        "exactly one checkpoint for an unchanged head"
    );
}

#[test]
fn checkpoint_retention_keeps_the_last_hour_unconditionally() {
    let prune = crate::db::checkpoints_to_prune;
    let now = 1_000_000_000;
    assert!(prune(now, &[]).is_empty());
    // Anything younger than an hour survives, even in a crowd and right at
    // the boundary's edge.
    let cps: Vec<(i64, i64)> = (1..=10).map(|id| (id, now - id * 60)).collect();
    assert!(prune(now, &cps).is_empty());
    assert!(prune(now, &[(1, now - 3599)]).is_empty());
    // Future timestamps (clock skew) count as the last hour.
    assert!(prune(now, &[(1, now + 42)]).is_empty());
}

#[test]
fn checkpoint_retention_bucket_boundaries() {
    let prune = crate::db::checkpoints_to_prune;
    let now = 1_000_000_000;
    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;
    // Exactly one hour old: past the keep-all tier, but the newest (only)
    // entry of hour bucket 1 — kept. Likewise the 24h edge is the daily
    // tier and the 7d edge is the cutoff: inside keeps, at/past deletes.
    assert!(prune(now, &[(1, now - HOUR)]).is_empty());
    assert!(prune(now, &[(1, now - DAY + 1)]).is_empty());
    assert!(prune(now, &[(1, now - DAY)]).is_empty());
    assert!(prune(now, &[(1, now - 7 * DAY + 1)]).is_empty());
    assert_eq!(prune(now, &[(1, now - 7 * DAY)]), vec![1]);
    assert_eq!(prune(now, &[(1, now - 365 * DAY)]), vec![1]);
}

#[test]
fn checkpoint_retention_keeps_only_the_newest_per_bucket() {
    let prune = crate::db::checkpoints_to_prune;
    let now = 1_000_000_000;
    // Same trailing hour (ages 2h00m and 2h10m share hour bucket 2): only
    // the newest stays; a checkpoint in a different hour is unaffected.
    let cps = [(1, now - 7200), (2, now - 7800), (3, now - 10800)];
    assert_eq!(prune(now, &cps), vec![2]);
    // Input order does not change the decision.
    let shuffled = [(3, now - 10800), (2, now - 7800), (1, now - 7200)];
    assert_eq!(prune(now, &shuffled), vec![2]);
    // Equal timestamps: the higher id is the later insert and wins.
    let tied = [(7, now - 7200), (9, now - 7200)];
    assert_eq!(prune(now, &tied), vec![7]);
    // The daily tier buckets the same way (ages 30h and 40h share day 1).
    let days = [(1, now - 30 * 3600), (2, now - 40 * 3600)];
    assert_eq!(prune(now, &days), vec![2]);
}

/// §14: a checkpoint insert prunes the workspace's old checkpoints (keep
/// the last hour, then newest/hour for 24h, then newest/day for 7d); named
/// snapshots are never pruned and the chunk pool is never touched.
#[tokio::test]
async fn checkpoint_retention_prunes_on_force_checkpoint() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    acquire(&relay, "ws-1", "laptop-a").await;

    // Distinct manifest bytes per head (scanned_at_secs) so every force
    // has new state to checkpoint (unchanged heads dedupe, §12).
    let manifest = |n: i64| {
        let mut m: Value = serde_json::from_str(&test_manifest("ws-1")).unwrap();
        m["scanned_at_secs"] = json!(n);
        m.to_string()
    };
    let resp = put_head_raw(&relay, "ws-1", 0, &manifest(0), "laptop-a", 1).await;
    assert_eq!(resp.status(), 200);

    // Six checkpoints: a new device forces (checkpointing the head), then
    // pushes a fresh head under the forced lease. Devices rotate because a
    // forcer who already holds the lease records nothing.
    let devices = [
        "laptop-b", "laptop-c", "laptop-d", "laptop-e", "laptop-f", "laptop-g",
    ];
    for (i, device) in devices.iter().enumerate() {
        let i = i as i64 + 1;
        let resp = relay
            .post("/v1/workspaces/ws-1/lease/force")
            .json(&json!({ "device_id": device }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let generation = resp.json::<Value>().await.unwrap()["generation"]
            .as_i64()
            .unwrap();
        let resp = put_head_raw(&relay, "ws-1", i, &manifest(i), device, generation).await;
        assert_eq!(resp.status(), 200);
    }

    // A named snapshot: never pruned, whatever its age (§14).
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": "keep me",
            "device": "laptop-a",
            "manifest": serde_json::from_str::<Value>(&manifest(6)).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Backdate ids 1..=6 (the checkpoints) and 7 (the named snapshot) via a
    // second connection. The ages sit mid-bucket, so a slow test run cannot
    // straddle an edge.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let db = crate::db::Db::open(&relay._data_dir.path().join("relay.db")).unwrap();
    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;
    for (id, age) in [
        (1, 30 * 60),         // last hour: kept
        (2, 2 * HOUR + 300),  // hourly tier, newest of its hour: kept
        (3, 2 * HOUR + 1800), // same hour bucket but older: pruned
        (4, DAY + 6 * HOUR),  // daily tier, newest of day 1: kept
        (5, 3 * DAY),         // daily tier, newest of day 3: kept
        (6, 8 * DAY),         // past 7 days: pruned
        (7, 8 * DAY),         // named: kept at any age
    ] {
        db.backdate_snapshot("ws-1", id, now - age).unwrap();
    }

    // The trigger: one more checkpoint via lease/force (the head moved
    // since the last checkpoint, so this inserts one and prunes).
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "laptop-h" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = relay
        .get("/v1/workspaces/ws-1/snapshots")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let snapshots = body["snapshots"].as_array().unwrap();
    let ids: Vec<i64> = snapshots
        .iter()
        .map(|s| s["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, vec![8, 7, 5, 4, 2, 1], "newest first");
    assert_eq!(snapshots[1]["kind"], "named");
    assert_eq!(snapshots[1]["name"], "keep me");
    for s in snapshots {
        if s["id"] != 7 {
            assert_eq!(s["kind"], "checkpoint");
        }
    }

    // Retention is metadata-only: the chunks a pruned snapshot referenced
    // are still served (there is no GC, §14).
    let resp = relay
        .get(&format!(
            "/v1/workspaces/ws-1/chunks/{}",
            chunk_hash(b"foo")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn head_put_rejects_malformed_chunk_hashes() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-hash").await;
    let resp = relay
        .post("/v1/workspaces/ws-hash/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let generation = body["generation"].clone();

    // A manifest whose entry references an uppercase/short hash: 400.
    let mut manifest: Value = serde_json::from_str(&test_manifest("ws-hash")).unwrap();
    manifest["files"]["src/main.rs"]["chunks"] = json!(["ABCDEF0123"]);
    let resp = relay
        .put("/v1/workspaces/ws-hash/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({ "base_seq": 0, "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn head_put_rejects_chunks_absent_from_the_pool() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-absent").await;
    let resp = relay
        .post("/v1/workspaces/ws-absent/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let generation = body["generation"].clone();

    // The manifest references a well-formed hash that was never uploaded.
    let manifest: Value = serde_json::from_str(&test_manifest("ws-absent")).unwrap();
    let resp = relay
        .put("/v1/workspaces/ws-absent/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({ "base_seq": 0, "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Upload the chunk: the same commit is then accepted.
    let chunk = chunk_hash(b"foo");
    let resp = relay
        .put(&format!("/v1/workspaces/ws-absent/chunks/{chunk}"))
        .body(b"foo".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .put("/v1/workspaces/ws-absent/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({
            "base_seq": 0,
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-absent")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn head_put_rejects_file_dir_path_conflicts() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-conflict").await;
    upload_fixture_chunk(&relay, "ws-conflict").await;
    let resp = relay
        .post("/v1/workspaces/ws-conflict/lease/acquire")
        .json(&json!({ "device_id": "laptop-a" }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let generation = body["generation"].clone();

    // A manifest with both a file `src` and a file `src/main.rs`: a file
    // cannot also be a directory. The `src-x` sibling makes the conflict
    // non-adjacent in byte order ('-' sorts before '/'), defeating any
    // adjacent-pair check.
    let mut manifest: Value = serde_json::from_str(&test_manifest("ws-conflict")).unwrap();
    for extra in ["src", "src-x"] {
        manifest["files"][extra] = json!({
            "size": 3, "mode": 420, "mtime_secs": 1, "mtime_nanos": 0,
            "chunks": [chunk_hash(b"foo")],
        });
    }
    let resp = relay
        .put("/v1/workspaces/ws-conflict/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({ "base_seq": 0, "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// --- M4: users, teams, and role-based ACLs (§13) -----------------------------

/// Create a user through the admin API; return their (shown-once) token.
async fn create_user(relay: &TestRelay, name: &str) -> String {
    let resp = relay
        .post("/v1/users")
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create user {name}");
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// Create a team as `token`; return the team id.
async fn create_team(relay: &TestRelay, token: &str, name: &str) -> String {
    let resp = relay
        .post_as(token, "/v1/teams")
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create team {name}");
    let body: Value = resp.json().await.unwrap();
    body["id"].as_str().unwrap().to_string()
}

/// Add `user` to `team` with `role` as `token`; expects 200.
async fn add_member(relay: &TestRelay, token: &str, team: &str, user: &str, role: &str) {
    let resp = relay
        .post_as(token, &format!("/v1/teams/{team}/members"))
        .json(&json!({ "user": user, "role": role }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "add {user} as {role}");
}

/// Create a workspace as `token`, optionally attached to a team at create.
async fn create_ws_as(relay: &TestRelay, token: &str, id: &str, name: &str, team: Option<&str>) {
    let resp = relay
        .post_as(token, "/v1/workspaces")
        .json(&json!({ "id": id, "name": name, "team_id": team }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create workspace {id}");
}

/// Upload one valid chunk as `token`; returns the status.
async fn put_chunk_as(
    relay: &TestRelay,
    token: &str,
    ws: &str,
    data: &[u8],
) -> reqwest::StatusCode {
    relay
        .put_as(
            token,
            &format!("/v1/workspaces/{ws}/chunks/{}", chunk_hash(data)),
        )
        .body(data.to_vec())
        .send()
        .await
        .unwrap()
        .status()
}

/// Lease acquire as `token`; returns the status.
async fn acquire_as(relay: &TestRelay, token: &str, ws: &str, device: &str) -> reqwest::StatusCode {
    relay
        .post_as(token, &format!("/v1/workspaces/{ws}/lease/acquire"))
        .json(&json!({ "device_id": device }))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn users_create_and_list_are_admin_only() {
    let relay = start_relay(300).await;

    // Admin creates a user: 201 with the shown-once token (16 bytes of
    // hex, like workspace ids).
    let resp = relay
        .post("/v1/users")
        .json(&json!({ "name": "jane" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "jane");
    let shown_once = body["token"].as_str().unwrap();
    assert_eq!(shown_once.len(), 32);
    assert!(shown_once.bytes().all(|b| b.is_ascii_hexdigit()));

    // Duplicate name conflicts; an empty name is a 400.
    let resp = relay
        .post("/v1/users")
        .json(&json!({ "name": "jane" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let resp = relay
        .post("/v1/users")
        .json(&json!({ "name": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Admin lists users; tokens are never listed.
    let resp = relay.get("/v1/users").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let users = body["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["name"], "jane");
    assert!(users[0]["created_at"].as_i64().unwrap() > 0);
    assert!(users[0].get("token").is_none());

    // A user token may not create or list users.
    let resp = relay
        .post_as(shown_once, "/v1/users")
        .json(&json!({ "name": "bob" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = relay.get_as(shown_once, "/v1/users").send().await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn principal_resolution_admin_user_and_unknown_tokens() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;

    // An unknown token is a 401, as is no token at all.
    let resp = relay
        .client
        .get(format!("{}/v1/teams", relay.base))
        .header("authorization", "Bearer nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = relay
        .client
        .get(format!("{}/v1/teams", relay.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // A user token authenticates as that user; the admin token still works.
    let resp = relay.get_as(&jane, "/v1/teams").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay.get("/v1/teams").send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn teams_create_membership_and_owner_only_management() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;
    // Carol's token is never used directly — she only needs to exist so
    // jane can add her as a member.
    let _carol = create_user(&relay, "carol").await;

    // Jane creates acme and becomes its first owner.
    let acme = create_team(&relay, &jane, "acme").await;

    // Team list is per-requester: jane sees acme, bob sees nothing yet,
    // the admin sees all teams.
    let body: Value = relay
        .get_as(&jane, "/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["teams"].as_array().unwrap().len(), 1);
    assert_eq!(body["teams"][0]["name"], "acme");
    let body: Value = relay
        .get_as(&bob, "/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["teams"].as_array().unwrap().len(), 0);
    let body: Value = relay
        .get("/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["teams"].as_array().unwrap().len(), 1);

    // Team names are unique; the admin credential owns no teams.
    let resp = relay
        .post_as(&bob, "/v1/teams")
        .json(&json!({ "name": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let resp = relay
        .post("/v1/teams")
        .json(&json!({ "name": "ops" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "the admin credential owns no teams");

    // Member management is team-owner only: a non-member and a writer both
    // get 403; only jane (owner) can add.
    let resp = relay
        .post_as(&bob, &format!("/v1/teams/{acme}/members"))
        .json(&json!({ "user": "carol", "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-member cannot manage");
    add_member(&relay, &jane, &acme, "bob", "writer").await;
    let resp = relay
        .post_as(&bob, &format!("/v1/teams/{acme}/members"))
        .json(&json!({ "user": "carol", "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "writer cannot manage members");
    add_member(&relay, &jane, &acme, "carol", "reader").await;

    // The target user must exist; the role must be valid; the team must
    // exist.
    let resp = relay
        .post_as(&jane, &format!("/v1/teams/{acme}/members"))
        .json(&json!({ "user": "nobody", "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "nonexistent user");
    let resp = relay
        .post_as(&jane, &format!("/v1/teams/{acme}/members"))
        .json(&json!({ "user": "bob", "role": "boss" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "invalid role");
    let resp = relay
        .post_as(&jane, "/v1/teams/nope/members")
        .json(&json!({ "user": "bob", "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "nonexistent team");

    // Member list: members only (the admin holds no implicit membership).
    // §19: entries carry the nullable bundle halves too (all null here —
    // nobody keygenned).
    let resp = relay
        .get_as(&jane, &format!("/v1/teams/{acme}/members"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 3);
    assert_eq!(
        members[0],
        json!({ "user": "bob", "role": "writer", "pubkey": null, "ed25519": null, "sig": null })
    );
    assert_eq!(
        members[1],
        json!({ "user": "carol", "role": "reader", "pubkey": null, "ed25519": null, "sig": null })
    );
    assert_eq!(
        members[2],
        json!({ "user": "jane", "role": "owner", "pubkey": null, "ed25519": null, "sig": null })
    );
    let resp = relay
        .get_as(&bob, &format!("/v1/teams/{acme}/members"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a member may list");
    let dave = create_user(&relay, "dave").await;
    let resp = relay
        .get_as(&dave, &format!("/v1/teams/{acme}/members"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-member");
    let resp = relay
        .get(&format!("/v1/teams/{acme}/members"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "admin holds no implicit membership");
    let resp = relay
        .get_as(&jane, "/v1/teams/nope/members")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// §28: commit a one-file plaintext head as `token`, with the file's path
/// the variable under test. Acquires the lease fresh each call so 409
/// rejections (which commit nothing) can be retried back-to-back.
async fn put_head_one_file(
    relay: &TestRelay,
    token: &str,
    ws: &str,
    base_seq: i64,
    path: &str,
) -> reqwest::Response {
    assert_eq!(put_chunk_as(relay, token, ws, b"foo").await, 200);
    let resp = relay
        .post_as(token, &format!("/v1/workspaces/{ws}/lease/acquire"))
        .json(&json!({ "device_id": "dev" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "acquire lease on {ws}");
    let lease: Value = resp.json().await.unwrap();
    let generation = lease["generation"].as_i64().unwrap();
    let manifest = json!({
        "version": 1,
        "workspace_id": ws,
        "scanned_at_secs": 0,
        "files": {
            path: {
                "size": 3,
                "mode": 420,
                "mtime_secs": 1,
                "mtime_nanos": 0,
                "chunks": [chunk_hash(b"foo")],
            }
        }
    });
    relay
        .put_as(token, &format!("/v1/workspaces/{ws}/head"))
        .header("content-type", "application/json")
        .header("x-pear-device", "dev")
        .header("x-pear-generation", generation.to_string())
        .body(format!(
            r#"{{"base_seq":{base_seq},"manifest":{manifest}}}"#
        ))
        .send()
        .await
        .unwrap()
}

/// §28: the policy is set at create or via `PUT /v1/teams/:id/policy`,
/// surfaced in team responses, and gated to team owners — exactly the
/// member-management gate (no admin override).
#[tokio::test]
async fn team_env_policy_create_set_get_and_owner_gate() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;

    // The default is the product promise: sync_env = true, surfaced in
    // the team list.
    let acme = create_team(&relay, &jane, "acme").await;
    let body: Value = relay
        .get_as(&jane, "/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["teams"][0]["sync_env"], true,
        "default keeps the .env promise"
    );

    // The create-time flag (`pear team create --no-env`).
    let resp = relay
        .post_as(&jane, "/v1/teams")
        .json(&json!({ "name": "strict", "sync_env": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["sync_env"], false);
    let strict = body["id"].as_str().unwrap().to_string();

    // A team owner flips the policy; the response and a fresh list agree.
    let resp = relay
        .put_as(&jane, &format!("/v1/teams/{acme}/policy"))
        .json(&json!({ "sync_env": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "id": acme, "name": "acme", "sync_env": false })
    );
    let body: Value = relay
        .get_as(&jane, "/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        body["teams"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["sync_env"] == false),
        "both teams now forbid: {body}"
    );

    // ...and back on — the switch is reversible.
    let resp = relay
        .put_as(&jane, &format!("/v1/teams/{acme}/policy"))
        .json(&json!({ "sync_env": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["sync_env"], true);

    // The gate is the team-owner gate, exactly like member management: a
    // writer 403s, a non-member 403s, the admin 403s (no override).
    add_member(&relay, &jane, &strict, "bob", "writer").await;
    let carol = create_user(&relay, "carol").await;
    for (token, who) in [
        (bob.clone(), "writer"),
        (carol, "non-member"),
        (TOKEN.to_string(), "admin"),
    ] {
        let resp = relay
            .put_as(&token, &format!("/v1/teams/{strict}/policy"))
            .json(&json!({ "sync_env": true }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{who} may not set policy");
    }
    let resp = relay
        .put_as(&jane, "/v1/teams/nope/policy")
        .json(&json!({ "sync_env": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown team");

    // All those 403s never moved the policy.
    let body: Value = relay
        .get_as(&jane, "/v1/teams")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let strict_row = body["teams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "strict")
        .unwrap();
    assert_eq!(strict_row["sync_env"], false);
}

/// §28 relay-side enforcement: a plaintext manifest containing `.env*`
/// paths conflicts (409, `kind: "sync_env"`, naming the policy and the
/// team) when — and ONLY when — the workspace's attached team forbids.
/// The path set is the scanner's own definition (`is_dotenv`).
#[tokio::test]
async fn sync_env_commit_validation() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;

    // A forbidding team and a default team, each with a workspace, plus
    // one unattached workspace (no policy lives anywhere).
    let strict = create_team(&relay, &jane, "strict").await;
    let resp = relay
        .put_as(&jane, &format!("/v1/teams/{strict}/policy"))
        .json(&json!({ "sync_env": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let lax = create_team(&relay, &jane, "lax").await;
    create_ws_as(&relay, &jane, "ws-strict", "s", Some(&strict)).await;
    create_ws_as(&relay, &jane, "ws-lax", "l", Some(&lax)).await;
    create_ws_as(&relay, &jane, "ws-solo", "solo", None).await;

    // `.env` and the scanner's boundary names all conflict, and the body
    // names the policy, the team, and the offending path.
    for path in [".env", ".envrc", "sub/.env.local"] {
        let resp = put_head_one_file(&relay, &jane, "ws-strict", 0, path).await;
        assert_eq!(resp.status(), 409, "{path} must conflict");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["kind"], "sync_env", "{body}");
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("sync_env=false") && msg.contains("strict") && msg.contains(path),
            "409 names the policy, team, and path: {msg}"
        );
    }

    // Names that are NOT `.env*` by the scanner's rule commit exactly as
    // before §28 (this commit moves ws-strict's head to seq 1).
    for path in ["env", "foo.env", ".env.d/local"] {
        let base = match path {
            "env" => 0,
            "foo.env" => 1,
            _ => 2,
        };
        let resp = put_head_one_file(&relay, &jane, "ws-strict", base, path).await;
        assert_eq!(resp.status(), 200, "{path} is not .env*: accepted");
    }

    // Snapshots share the manifest trust boundary: same 409.
    let manifest = json!({
        "version": 1,
        "workspace_id": "ws-strict",
        "scanned_at_secs": 0,
        "files": {
            ".env": {
                "size": 3,
                "mode": 420,
                "mtime_secs": 1,
                "mtime_nanos": 0,
                "chunks": [chunk_hash(b"foo")],
            }
        }
    });
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-strict/snapshots")
        .json(&json!({ "device": "dev", "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "snapshot validation shares the rule");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "sync_env", "{body}");

    // An allowing team accepts `.env`; an unattached workspace has no
    // policy at all and accepts it too.
    let resp = put_head_one_file(&relay, &jane, "ws-lax", 0, ".env").await;
    assert_eq!(resp.status(), 200, "default team keeps the promise");
    let resp = put_head_one_file(&relay, &jane, "ws-solo", 0, ".env").await;
    assert_eq!(resp.status(), 200, "no team, no policy");

    // Lifting the policy re-opens the door at once (ws-strict sits at
    // seq 3 after the three accepted commits above).
    let resp = relay
        .put_as(&jane, &format!("/v1/teams/{strict}/policy"))
        .json(&json!({ "sync_env": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = put_head_one_file(&relay, &jane, "ws-strict", 3, ".env").await;
    assert_eq!(resp.status(), 200, "lifted policy accepts .env again");
}

/// §28: e2e workspaces are EXEMPT from relay-side enforcement by
/// construction — the relay cannot see encrypted paths, so the client-side
/// refusal is the only line. Pinned so the exemption is deliberate, not an
/// oversight: an e2e head commits fine on a forbidding team.
#[tokio::test]
async fn sync_env_e2e_workspace_is_exempt_relay_side() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let strict = create_team(&relay, &jane, "strict").await;
    let resp = relay
        .put_as(&jane, &format!("/v1/teams/{strict}/policy"))
        .json(&json!({ "sync_env": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    create_ws_e2e_as(&relay, &jane, "ws-e2e", "sealed", Some(&strict)).await;

    assert_eq!(put_chunk_as(&relay, &jane, "ws-e2e", b"foo").await, 200);
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-e2e/lease/acquire")
        .json(&json!({ "device_id": "dev" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let lease: Value = resp.json().await.unwrap();
    let generation = lease["generation"].as_i64().unwrap();
    let resp = relay
        .put_as(&jane, "/v1/workspaces/ws-e2e/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "dev")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({
            "base_seq": 0,
            "manifest_enc": fake_manifest_enc(),
            "chunk_hashes": [chunk_hash(b"foo")],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "e2e paths are invisible to the relay: exempt from §28 by construction"
    );
}

/// §13 capability matrix over the workspace routes: a reader mirrors but
/// cannot write (403), a writer can, and a non-member cannot even see the
/// workspace (404 — existence hiding).
#[tokio::test]
async fn role_matrix_on_workspace_routes() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;
    let carol = create_user(&relay, "carol").await;
    let dave = create_user(&relay, "dave").await;
    let acme = create_team(&relay, &jane, "acme").await;
    add_member(&relay, &jane, &acme, "bob", "writer").await;
    add_member(&relay, &jane, &acme, "carol", "reader").await;

    // Jane creates the workspace attached to acme at create time and
    // pushes a head.
    create_ws_as(&relay, &jane, "ws-1", "api", Some(&acme)).await;
    assert_eq!(put_chunk_as(&relay, &jane, "ws-1", b"foo").await, 200);
    assert_eq!(acquire_as(&relay, &jane, "ws-1", "jane-laptop").await, 200);
    let resp = relay
        .put_as(&jane, "/v1/workspaces/ws-1/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "jane-laptop")
        .header("x-pear-generation", "1")
        .body(format!(
            r#"{{"base_seq":0,"manifest":{}}}"#,
            test_manifest("ws-1")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "owner pushes the head");

    // The workspace read exposes owner and team.
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-1")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["owner"], "jane");
    assert_eq!(body["team_id"].as_str().unwrap(), acme);

    // Reader (carol): every read route works. (No snapshots exist yet, so
    // the list is empty; the snapshot-get check comes after bob's below.)
    for path in [
        "/v1/workspaces/ws-1".to_string(),
        "/v1/workspaces/ws-1/head".to_string(),
        format!("/v1/workspaces/ws-1/chunks/{}", chunk_hash(b"foo")),
        "/v1/workspaces/ws-1/snapshots".to_string(),
    ] {
        let resp = relay.get_as(&carol, &path).send().await.unwrap();
        assert_eq!(resp.status(), 200, "reader GET {path}");
    }
    let resp = relay
        .post_as(&carol, "/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": [chunk_hash(b"foo")] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "reader presence check");

    // ...but every write route is a 403 (a role, but insufficient).
    assert_eq!(
        put_chunk_as(&relay, &carol, "ws-1", b"carol bytes").await,
        403,
        "reader put chunk"
    );
    let resp = relay
        .put_as(&carol, "/v1/workspaces/ws-1/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "carol-laptop")
        .header("x-pear-generation", "1")
        .body(format!(
            r#"{{"base_seq":1,"manifest":{}}}"#,
            test_manifest("ws-1")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader put head");
    assert_eq!(
        acquire_as(&relay, &carol, "ws-1", "carol-laptop").await,
        403,
        "reader acquire"
    );
    let resp = relay
        .post_as(&carol, "/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "carol-laptop" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader force");
    let resp = relay
        .post_as(&carol, "/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "device": "carol-laptop",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-1")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader snapshot create");
    let resp = relay
        .post_as(&carol, "/v1/workspaces/ws-1/team")
        .json(&json!({ "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader cannot attach");

    // Writer (bob): the write routes accept him — force the lease (jane's
    // is valid) and commit on top of her head.
    assert_eq!(
        put_chunk_as(&relay, &bob, "ws-1", b"foo").await,
        200,
        "writer put chunk"
    );
    let resp = relay
        .post_as(&bob, "/v1/workspaces/ws-1/lease/force")
        .json(&json!({ "device_id": "bob-laptop" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "writer force");
    let generation = resp.json::<Value>().await.unwrap()["generation"].clone();
    let resp = relay
        .put_as(&bob, "/v1/workspaces/ws-1/head")
        .header("content-type", "application/json")
        .header("x-pear-device", "bob-laptop")
        .header("x-pear-generation", generation.to_string())
        .body(format!(
            r#"{{"base_seq":1,"manifest":{}}}"#,
            test_manifest("ws-1")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "writer put head");
    let resp = relay
        .post_as(&bob, "/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": "bob was here",
            "device": "bob-laptop",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-1")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "writer snapshot create");
    // ...and a reader can fetch that snapshot back (id 1 is the checkpoint
    // bob's force recorded first).
    let resp = relay
        .get_as(&carol, "/v1/workspaces/ws-1/snapshots/2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "reader snapshot get");
    // ...but attach is owner-only even for a writer.
    let resp = relay
        .post_as(&bob, "/v1/workspaces/ws-1/team")
        .json(&json!({ "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "writer cannot attach");

    // Non-member (dave): everything workspace-scoped is a 404 — the
    // workspace's existence is hidden, even on write routes.
    for req in [
        relay.get_as(&dave, "/v1/workspaces/ws-1"),
        relay.get_as(&dave, "/v1/workspaces/ws-1/head"),
        relay.get_as(
            &dave,
            &format!("/v1/workspaces/ws-1/chunks/{}", chunk_hash(b"foo")),
        ),
        relay.get_as(&dave, "/v1/workspaces/ws-1/snapshots"),
    ] {
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), 404, "non-member read must be hidden");
    }
    assert_eq!(
        put_chunk_as(&relay, &dave, "ws-1", b"dave bytes").await,
        404,
        "non-member put chunk"
    );
    assert_eq!(
        acquire_as(&relay, &dave, "ws-1", "dave-laptop").await,
        404,
        "non-member acquire"
    );
    let resp = relay
        .post_as(&dave, "/v1/workspaces/ws-1/snapshots")
        .json(&json!({
            "name": null,
            "device": "dave-laptop",
            "manifest": serde_json::from_str::<Value>(&test_manifest("ws-1")).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "non-member snapshot create");
    let resp = relay
        .post_as(&dave, "/v1/workspaces/ws-1/team")
        .json(&json!({ "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "non-member attach");

    // The admin is an implicit owner everywhere: reads and writes work.
    let resp = relay.get("/v1/workspaces/ws-1").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        put_chunk_as(&relay, TOKEN, "ws-1", b"foo").await,
        200,
        "admin put chunk"
    );
}

#[tokio::test]
async fn workspace_resolution_by_team_and_name() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let carol = create_user(&relay, "carol").await;
    let dave = create_user(&relay, "dave").await;
    let acme = create_team(&relay, &jane, "acme").await;
    add_member(&relay, &jane, &acme, "carol", "reader").await;
    create_ws_as(&relay, &jane, "ws-1", "api", Some(&acme)).await;

    // A reader resolves acme/api to the workspace record.
    let resp = relay
        .get_as(&carol, "/v1/teams/acme/workspaces/api")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], "ws-1");
    assert_eq!(body["name"], "api");

    // The owner and the admin resolve too.
    let resp = relay
        .get_as(&jane, "/v1/teams/acme/workspaces/api")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get("/v1/teams/acme/workspaces/api")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A non-member gets a 404, as do unknown teams and names.
    let resp = relay
        .get_as(&dave, "/v1/teams/acme/workspaces/api")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "non-member resolution is hidden");
    let resp = relay
        .get_as(&carol, "/v1/teams/nope/workspaces/api")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = relay
        .get_as(&carol, "/v1/teams/acme/workspaces/nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn attach_route_requires_workspace_owner_and_team_writer() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;
    let carol = create_user(&relay, "carol").await;
    let dave = create_user(&relay, "dave").await;
    let beta = create_team(&relay, &jane, "beta").await;
    add_member(&relay, &jane, &beta, "bob", "writer").await;
    add_member(&relay, &jane, &beta, "carol", "reader").await;
    // A team where jane is only a reader.
    let delta = create_team(&relay, &bob, "delta").await;
    add_member(&relay, &bob, &delta, "jane", "reader").await;

    // Jane owns ws-2, unattached.
    create_ws_as(&relay, &jane, "ws-2", "billing", None).await;

    // Only the workspace owner may attach. On this still-unattached
    // workspace carol, bob, and dave hold no role at all, so the attach is
    // a 404 (existence hiding). The 403 case — a role via the attached
    // team, but not the owner — is covered in the role matrix test above.
    for token in [&carol, &bob, &dave] {
        let resp = relay
            .post_as(token, "/v1/workspaces/ws-2/team")
            .json(&json!({ "team_id": beta }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "attach as non-owner is hidden");
    }

    // Jane attaches; bob (team writer) can now write the workspace.
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-2/team")
        .json(&json!({ "team_id": beta }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        put_chunk_as(&relay, &bob, "ws-2", b"foo").await,
        200,
        "team writer writes after attach"
    );

    // The workspace owner must ALSO be owner/writer in the team: jane is
    // only a reader in delta.
    create_ws_as(&relay, &jane, "ws-3", "search", None).await;
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-3/team")
        .json(&json!({ "team_id": delta }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "workspace owner but team reader");
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-3/team")
        .json(&json!({ "team_id": "no-such-team" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown team");

    // Two workspaces with the same name cannot share a team: attaching the
    // second one conflicts.
    create_ws_as(&relay, &jane, "ws-4", "dup", Some(&beta)).await;
    create_ws_as(&relay, &jane, "ws-5", "dup", None).await;
    let resp = relay
        .post_as(&jane, "/v1/workspaces/ws-5/team")
        .json(&json!({ "team_id": beta }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "name already used in the team");

    // A pre-M4 workspace (owner NULL, created via the admin token) is
    // admin-owned: a user has no role on it.
    create_ws(&relay, "ws-legacy").await;
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-legacy")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "pre-M4 workspace is hidden from users");
    let resp = relay.get("/v1/workspaces/ws-legacy").send().await.unwrap();
    assert_eq!(resp.status(), 200, "admin owns pre-M4 workspaces");
}

#[tokio::test]
async fn workspace_names_are_unique_within_a_team() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;
    let carol = create_user(&relay, "carol").await;
    let acme = create_team(&relay, &jane, "acme").await;
    add_member(&relay, &jane, &acme, "carol", "reader").await;
    let beta = create_team(&relay, &bob, "beta").await;

    create_ws_as(&relay, &jane, "ws-a", "api", Some(&acme)).await;
    // Same name, same team, different id: conflict.
    let resp = relay
        .post_as(&jane, "/v1/workspaces")
        .json(&json!({ "id": "ws-b", "name": "api", "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    // Same name in a different team, or outside any team: fine.
    create_ws_as(&relay, &bob, "ws-c", "api", Some(&beta)).await;
    create_ws_as(&relay, &jane, "ws-d", "api", None).await;

    // Attach-at-create enforces the same rule as the attach route: a team
    // reader cannot create into the team, and the team must exist. The
    // admin holds no team membership either.
    let resp = relay
        .post_as(&carol, "/v1/workspaces")
        .json(&json!({ "id": "ws-e", "name": "web", "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "team reader cannot create into the team"
    );
    let resp = relay
        .post_as(&jane, "/v1/workspaces")
        .json(&json!({ "id": "ws-f", "name": "web", "team_id": "no-such-team" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown team");
    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-g", "name": "web", "team_id": acme }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "admin holds no team membership");
}

// --- §14: WebSocket fan-out ---------------------------------------------------

/// A GET with real WebSocket upgrade headers, authenticated as `token`.
/// Tests that assert pre-upgrade status codes never complete the
/// handshake; the key just has to be valid base64.
fn ws_upgrade(relay: &TestRelay, token: &str, workspace: &str) -> reqwest::RequestBuilder {
    relay
        .client
        .get(format!("{}/v1/ws?workspace={workspace}", relay.base))
        .header("authorization", format!("Bearer {token}"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
}

/// The pear-core listener connects on a background thread; poll its flag.
async fn wait_ws_connected(feed: &pear_core::relay::HeadFeed) {
    for _ in 0..100 {
        if feed.connected() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ws listener did not connect");
}

#[tokio::test]
async fn ws_fanout_delivers_head_changed_after_commit() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "dev").await;
    let generation = lease["generation"].as_i64().unwrap();

    // Subscribe with the real pear-core listener before the commit.
    let client = pear_core::relay::RelayClient::new(&relay.base, TOKEN, "ws-1", "ws-test");
    let feed = client.head_changes().expect("http base url");
    wait_ws_connected(&feed).await;

    // §21: the first hint is the catch-up — no head committed yet, so 0 —
    // and it precedes every post-connect broadcast.
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_now catch-up");
    assert_eq!(seq, 0);

    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_changed hint for the first commit");
    assert_eq!(seq, 1);

    let resp = put_head_raw(&relay, "ws-1", 1, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);
    let seq = feed
        .recv_timeout(Duration::from_secs(5))
        .expect("head_changed hint for the second commit");
    assert_eq!(seq, 2);
}

/// §21: a subscriber that connects AFTER a commit gets the current head
/// seq as `head_now`, as the first frame — this is what a late or
/// reconnecting mirror converges on without waiting for the next commit.
#[tokio::test]
async fn ws_subscribe_sends_head_now_with_the_current_seq_first() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite;

    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "dev").await;
    let generation = lease["generation"].as_i64().unwrap();
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);

    let url = format!(
        "{}/v1/ws?workspace=ws-1",
        relay.base.replacen("http", "ws", 1)
    );
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
    let auth = tungstenite::http::HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap();
    request.headers_mut().insert("Authorization", auth);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await.unwrap();

    // First frame: the catch-up, with the CURRENT seq (1), not 0.
    let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("head_now within 5s")
        .unwrap()
        .unwrap();
    let first: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(
        first,
        json!({ "type": "head_now", "workspace": "ws-1", "seq": 1 })
    );

    // Ordering: a post-connect commit's head_changed arrives after it.
    let resp = put_head_raw(&relay, "ws-1", 1, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);
    let next = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("head_changed within 5s")
        .unwrap()
        .unwrap();
    let next: Value = serde_json::from_str(next.to_text().unwrap()).unwrap();
    assert_eq!(
        next,
        json!({ "type": "head_changed", "workspace": "ws-1", "seq": 2 })
    );
}

/// §21: with no head committed yet the catch-up reports seq 0 — "nothing
/// to pull", which the mirror's idle check absorbs for free.
#[tokio::test]
async fn ws_subscribe_head_now_is_zero_without_a_head() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite;

    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let url = format!(
        "{}/v1/ws?workspace=ws-1",
        relay.base.replacen("http", "ws", 1)
    );
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
    let auth = tungstenite::http::HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap();
    request.headers_mut().insert("Authorization", auth);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("head_now within 5s")
        .unwrap()
        .unwrap();
    let first: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(
        first,
        json!({ "type": "head_now", "workspace": "ws-1", "seq": 0 })
    );
}

#[tokio::test]
async fn ws_requires_bearer_and_role_like_other_routes() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await; // admin-owned

    // No token at all: the router-wide auth middleware rejects first.
    let resp = relay
        .client
        .get(format!("{}/v1/ws?workspace=ws-1", relay.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no token");
    let resp = ws_upgrade(&relay, "wrong-token", "ws-1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong token");

    // A user with no role gets the same existence-hiding 404 as every
    // other workspace route; the admin gets it for an unknown workspace.
    let nate = create_user(&relay, "nate").await;
    let resp = ws_upgrade(&relay, &nate, "ws-1").send().await.unwrap();
    assert_eq!(resp.status(), 404, "no role hides the workspace");
    let resp = ws_upgrade(&relay, TOKEN, "no-such-ws")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown workspace");

    // A team reader passes the role gate: the server upgrades (101).
    let owner = create_user(&relay, "owner").await;
    let team = create_team(&relay, &owner, "acme").await;
    create_ws_as(&relay, &owner, "ws-2", "demo", Some(&team)).await;
    let rita = create_user(&relay, "rita").await;
    add_member(&relay, &owner, &team, "rita", "reader").await;
    let resp = ws_upgrade(&relay, &rita, "ws-2").send().await.unwrap();
    assert_eq!(resp.status(), 101, "reader role upgrades");
}

#[tokio::test]
async fn ws_head_commit_succeeds_with_zero_subscribers() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    upload_fixture_chunk(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "dev").await;
    let generation = lease["generation"].as_i64().unwrap();

    // Nobody has ever subscribed: the commit is unaffected (§14).
    let resp = put_head_raw(&relay, "ws-1", 0, &test_manifest("ws-1"), "dev", generation).await;
    assert_eq!(resp.status(), 200);
}

/// §14: fan-out is a hint, never a commit blocker — broadcast sends are
/// non-blocking, and the channel tells a lagging receiver it dropped hints
/// (the §21 reaction to that — a polite Close — lives in `ws_fanout`; the
/// channel semantics pinned here are unchanged).
#[tokio::test]
async fn ws_broadcast_tolerates_lagging_subscribers() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = AppState::new(TOKEN, data_dir.path(), 300).unwrap();

    // No receivers at all: the send is dropped, never an error path.
    state.notify_head_changed("ws-1", 1);

    // Overflow the small per-workspace buffer without reading.
    let mut rx = state.subscribe_head("ws-1");
    for seq in 2..=64 {
        state.notify_head_changed("ws-1", seq);
    }
    // The lagging receiver is told it dropped hints, keeps what fits...
    match rx.try_recv() {
        Err(TryRecvError::Lagged(_)) => {}
        other => panic!("expected Lagged, got {other:?}"),
    }
    while rx.try_recv().is_ok() {}
    // ...and receives fresh hints normally, in the §14 wire shape.
    state.notify_head_changed("ws-1", 65);
    let hint: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    assert_eq!(
        hint,
        json!({ "type": "head_changed", "workspace": "ws-1", "seq": 65 })
    );
}

/// §15 (autoreview): a broadcast channel with no live receivers is
/// dropped on the next notify, so the map stays bounded by live
/// subscribers rather than every workspace ever watched.
#[test]
fn broadcast_channels_are_dropped_when_no_receivers_remain() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = AppState::new(TOKEN, data_dir.path(), 300).unwrap();

    let rx = state.subscribe_head("ws-1");
    state.notify_head_changed("ws-1", 1);
    assert!(
        state.broadcasts.lock().unwrap().contains_key("ws-1"),
        "a live subscriber keeps the channel"
    );

    drop(rx);
    state.notify_head_changed("ws-1", 2);
    assert!(
        !state.broadcasts.lock().unwrap().contains_key("ws-1"),
        "no receivers left: the channel is dropped"
    );
}

/// §14 (autoreview): the fan-out task also READS the socket — protocol
/// Pings get Pongs, and a client disconnect ends the task promptly
/// (its broadcast receiver is dropped) instead of lingering until the
/// next hint.
#[tokio::test]
async fn ws_fanout_reads_socket_pongs_ping_and_ends_on_disconnect() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{self, Message};

    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let url = format!(
        "{}/v1/ws?workspace=ws-1",
        relay.base.replacen("http", "ws", 1)
    );
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
    let auth = tungstenite::http::HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap();
    request.headers_mut().insert("Authorization", auth);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await.unwrap();
    wait_ws_receiver_count(&relay, "ws-1", 1).await;

    // §21: the first frame is the catch-up (no head yet → seq 0); it must
    // be consumed before the Pong assertion below.
    let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("head_now within 5s")
        .unwrap()
        .unwrap();
    let first: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(
        first,
        json!({ "type": "head_now", "workspace": "ws-1", "seq": 0 })
    );

    // A protocol-level Ping must be answered with a Pong — that only
    // happens when the server reads the socket.
    ws.send(Message::Ping(vec![7].into())).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("pong within 5s")
        .unwrap()
        .unwrap();
    assert!(
        matches!(reply, Message::Pong(_)),
        "expected Pong, got {reply:?}"
    );

    // Dropping the client ends the fan-out task: receiver count falls.
    drop(ws);
    wait_ws_receiver_count(&relay, "ws-1", 0).await;
}

async fn wait_ws_receiver_count(relay: &TestRelay, workspace: &str, want: usize) {
    for _ in 0..250 {
        if relay.ws_receiver_count(workspace) == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ws receiver count for {workspace} did not reach {want}");
}

/// §14 (autoreview): lease fencing and auth/role failures share the 403
/// status — the fencing body carries `"fenced": true`, the role body
/// does not, so clients can tell "lease lost" from "role revoked".
#[tokio::test]
async fn forbidden_bodies_distinguish_fencing_from_auth() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "laptop-a").await;
    let generation = lease["generation"].as_i64().unwrap();

    // Fencing: another device heartbeats → 403 with the fenced marker.
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "laptop-b", "generation": generation }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["fenced"], true, "fencing body is marked");

    // Auth/role: a team reader heartbeats (writer required) → 403 with
    // no marker, so the client can print "token or role revoked".
    let owner = create_user(&relay, "owner").await;
    let team = create_team(&relay, &owner, "acme").await;
    create_ws_as(&relay, &owner, "ws-2", "demo", Some(&team)).await;
    let rita = create_user(&relay, "rita").await;
    add_member(&relay, &owner, &team, "rita", "reader").await;
    let resp = relay
        .post_as(&rita, "/v1/workspaces/ws-2/lease/heartbeat")
        .json(&json!({ "device_id": "x", "generation": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("fenced").is_none(), "auth body carries no marker");
}

/// §14 (autoreview): a live WS subscription re-checks the reader role
/// periodically — a subscriber whose access is revoked gets a Close and
/// the fan-out task ends, instead of streaming hints indefinitely.
#[tokio::test]
async fn ws_fanout_drops_subscriber_when_role_revoked() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::{self, Message};

    let relay = start_relay_with(300, 1).await;
    let owner = create_user(&relay, "owner").await;
    let acme = create_team(&relay, &owner, "acme").await;
    let other = create_team(&relay, &owner, "other").await;
    create_ws_as(&relay, &owner, "ws-2", "demo", Some(&acme)).await;
    let rita = create_user(&relay, "rita").await;
    add_member(&relay, &owner, &acme, "rita", "reader").await;

    let url = format!(
        "{}/v1/ws?workspace=ws-2",
        relay.base.replacen("http", "ws", 1)
    );
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
    let auth = tungstenite::http::HeaderValue::from_str(&format!("Bearer {rita}")).unwrap();
    request.headers_mut().insert("Authorization", auth);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await.unwrap();
    wait_ws_receiver_count(&relay, "ws-2", 1).await;

    // Re-attach the workspace to a team rita is not in: her role is gone.
    let resp = relay
        .post_as(&owner, "/v1/workspaces/ws-2/team")
        .json(&json!({ "team_id": other }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Within a re-check interval the fan-out task ends and the server
    // closes her socket politely.
    wait_ws_receiver_count(&relay, "ws-2", 0).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(item) = ws.next().await {
            if matches!(item, Ok(Message::Close(_))) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(closed, "server must send a Close frame");
}

/// §14 (autoreview): workspace and team names become URL path segments
/// (`team/name` resolution), so create-time validation must reject names
/// that could never be addressed as one segment.
#[tokio::test]
async fn create_rejects_unaddressable_names() {
    let relay = start_relay(300).await;
    // Team creation needs a user principal (the admin seats no owner).
    let owner = create_user(&relay, "owner").await;

    for bad in ["api/v2", ".", "..", "with\ttab", ""] {
        let resp = relay
            .post("/v1/workspaces")
            .json(&json!({ "id": "ws-ok", "name": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "workspace name {bad:?}");
        let resp = relay
            .post_as(&owner, "/v1/teams")
            .json(&json!({ "name": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "team name {bad:?}");
        let resp = relay
            .post("/v1/users")
            .json(&json!({ "name": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "user name {bad:?}");
    }

    // Human names with spaces or unicode percent-encode fine and stay
    // allowed — and resolve through the `team/name` route.
    let team = create_team(&relay, &owner, "acme research").await;
    create_ws_as(&relay, &owner, "ws-ok", "möcking bird", Some(&team)).await;
    let resp = relay
        .get_as(
            &owner,
            "/v1/teams/acme%20research/workspaces/m%C3%B6cking%20bird",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "percent-encoded name resolves");
}

/// §14 (autoreview): snapshot name/device and lease device ids are stored
/// and echoed verbatim (named snapshots forever), so they are bounded
/// like every other stored string.
#[tokio::test]
async fn stored_strings_are_bounded() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let huge = "x".repeat(4096);
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/acquire")
        .json(&json!({ "device_id": huge }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "unbounded lease device id");
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/acquire")
        .json(&json!({ "device_id": "with\nnewline" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "control characters in device id");

    let manifest: Value = serde_json::from_str(&test_manifest("ws-1")).unwrap();
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({ "name": huge, "device": "dev", "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "unbounded snapshot name");
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("1-128"),
        "the bounds check must be what fired: {body}"
    );
    let resp = relay
        .post("/v1/workspaces/ws-1/snapshots")
        .json(&json!({ "name": "ok", "device": "dev/x", "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "slash in snapshot device");
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("1-128"),
        "the bounds check must be what fired: {body}"
    );
}

/// §15 (autoreview): expiry is terminal for a generation — a lapsed
/// lease cannot be revived by heartbeat (acquire treats the same
/// situation as a steal with a generation bump).
#[tokio::test]
async fn heartbeat_after_expiry_is_fenced_not_revived() {
    let relay = start_relay(1).await;
    create_ws(&relay, "ws-1").await;
    let lease = acquire(&relay, "ws-1", "dev").await;
    let generation = lease["generation"].as_i64().unwrap();

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let resp = relay
        .post("/v1/workspaces/ws-1/lease/heartbeat")
        .json(&json!({ "device_id": "dev", "generation": generation }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "an expired lease cannot be revived");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["fenced"], true);

    // The same device can only come back via acquire, with the bump.
    let lease2 = acquire(&relay, "ws-1", "dev").await;
    assert_eq!(lease2["generation"].as_i64().unwrap(), generation + 1);
}

/// §15 (autoreview): chunks/missing bounds the batch — every hash costs
/// a visibility query under the one global DB mutex, so an unbounded
/// list lets any reader stall every route.
#[tokio::test]
async fn chunks_missing_bounds_the_batch() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-1").await;

    let hashes = vec!["a".repeat(64); 50_001];
    let resp = relay
        .post("/v1/workspaces/ws-1/chunks/missing")
        .json(&json!({ "hashes": hashes }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "over the batch cap");
}

// --- §17: E2E envelope (e2e workspaces, user keys, wrapped keys) ---------------

/// Create an e2e workspace as `token`, optionally attached to a team.
async fn create_ws_e2e_as(
    relay: &TestRelay,
    token: &str,
    id: &str,
    name: &str,
    team: Option<&str>,
) {
    let resp = relay
        .post_as(token, "/v1/workspaces")
        .json(&json!({ "id": id, "name": name, "team_id": team, "e2e": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create e2e workspace {id}");
}

/// PUT /head on an e2e workspace: manifest_enc + chunk_hashes.
async fn put_head_enc(
    relay: &TestRelay,
    ws: &str,
    base_seq: i64,
    manifest_enc: &str,
    chunk_hashes: &[String],
    device: &str,
    generation: i64,
) -> reqwest::Response {
    relay
        .put(&format!("/v1/workspaces/{ws}/head"))
        .header("content-type", "application/json")
        .header("x-pear-device", device)
        .header("x-pear-generation", generation.to_string())
        .json(&json!({
            "base_seq": base_seq,
            "manifest_enc": manifest_enc,
            "chunk_hashes": chunk_hashes,
        }))
        .send()
        .await
        .unwrap()
}

/// A valid base64 manifest_enc stand-in (the relay never decrypts it).
fn fake_manifest_enc() -> String {
    pear_core::crypto::base64_encode(b"nonce-12-bytesciphertext-tag16")
}

/// A real §19 signed bundle for `name`: runtime-generated X25519 + ed25519
/// keys (no committed key material), the signature over the canonical
/// statement for `name` — exactly what `pear user keygen` PUTs.
struct SignedBundle {
    x25519: String,
    ed25519: String,
    sig: String,
}

impl SignedBundle {
    fn json(&self) -> Value {
        json!({ "x25519": self.x25519, "ed25519": self.ed25519, "sig": self.sig })
    }
}

fn signed_bundle(name: &str) -> SignedBundle {
    use pear_core::crypto;
    let x = crypto::UserKeypair::generate();
    let ed = crypto::EdKeypair::generate();
    let sig = ed.sign(&crypto::bundle_statement(name, &x.public));
    SignedBundle {
        x25519: crypto::hex_encode(&x.public),
        ed25519: crypto::hex_encode(&ed.public),
        sig: crypto::hex_encode(&sig),
    }
}

#[tokio::test]
async fn e2e_flag_at_create_immutable_and_visible_in_reads() {
    let relay = start_relay(300).await;

    // Plain by default; e2e when requested — both visible on GET.
    create_ws(&relay, "ws-plain").await;
    let resp = relay.get("/v1/workspaces/ws-plain").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], false, "plain by default");

    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-e2e", "name": "sealed", "e2e": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = relay.get("/v1/workspaces/ws-e2e").send().await.unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], true);

    // Immutable: re-registering under the other flavor is a loud
    // e2e_mismatch 409 (never a silent downgrade), both directions.
    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-e2e", "name": "sealed" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "e2e_mismatch", "{body}");
    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-plain", "name": "demo", "e2e": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "e2e_mismatch", "{body}");

    // Same-flavor re-registration stays the benign id_conflict.
    let resp = relay
        .post("/v1/workspaces")
        .json(&json!({ "id": "ws-e2e", "name": "sealed", "e2e": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "id_conflict", "{body}");

    // The team/name resolution route carries the flag too.
    let owner = create_user(&relay, "owner").await;
    let team = create_team(&relay, &owner, "acme").await;
    create_ws_e2e_as(&relay, &owner, "ws-t", "sealed", Some(&team)).await;
    let resp = relay
        .get_as(&owner, "/v1/teams/acme/workspaces/sealed")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], true, "resolution carries the e2e flag");
}

#[tokio::test]
async fn e2e_head_commit_rules_and_plain_head_unchanged() {
    let relay = start_relay(300).await;
    create_ws(&relay, "ws-plain").await;
    create_ws_e2e_as(&relay, TOKEN, "ws-e2e", "sealed", None).await;
    upload_fixture_chunk(&relay, "ws-plain").await;
    upload_fixture_chunk(&relay, "ws-e2e").await;
    let chunk = chunk_hash(b"foo");
    let enc = fake_manifest_enc();

    // Plain manifest on the e2e workspace: 409 e2e_mismatch (no downgrade).
    let lease = acquire(&relay, "ws-e2e", "laptop-a").await;
    let generation = lease["generation"].as_i64().unwrap();
    let resp = put_head_raw(
        &relay,
        "ws-e2e",
        0,
        &test_manifest("ws-e2e"),
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 409, "plaintext head on an e2e workspace");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "e2e_mismatch", "{body}");

    // manifest_enc on the plain workspace: 409 e2e_mismatch (no upgrade
    // confusion either).
    let lease = acquire(&relay, "ws-plain", "laptop-a").await;
    let plain_gen = lease["generation"].as_i64().unwrap();
    let resp = put_head_enc(
        &relay,
        "ws-plain",
        0,
        &enc,
        std::slice::from_ref(&chunk),
        "laptop-a",
        plain_gen,
    )
    .await;
    assert_eq!(resp.status(), 409, "manifest_enc on a plain workspace");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "e2e_mismatch", "{body}");

    // Malformed e2e bodies: bad base64, bad hash format, absent chunk,
    // missing chunk_hashes — all 400s.
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        0,
        "not base64!",
        std::slice::from_ref(&chunk),
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 400, "bad base64");
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        0,
        &enc,
        &["zz".to_string()],
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 400, "bad chunk hash");
    let absent = chunk_hash(b"never uploaded");
    let resp = put_head_enc(&relay, "ws-e2e", 0, &enc, &[absent], "laptop-a", generation).await;
    assert_eq!(resp.status(), 400, "chunk not in the pool");
    let resp = relay
        .put("/v1/workspaces/ws-e2e/head")
        .header("x-pear-device", "laptop-a")
        .header("x-pear-generation", generation.to_string())
        .json(&json!({ "base_seq": 0, "manifest_enc": enc }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "missing chunk_hashes");

    // A valid e2e commit: hash = BLAKE3 of the stored §24 envelope
    // (manifest_enc + canonicalized chunk_hashes), and GET /head returns
    // bare manifest_enc with the e2e flag — the wire never sees the
    // envelope.
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        0,
        &enc,
        std::slice::from_ref(&chunk),
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"], 1);
    assert_eq!(
        body["hash"].as_str().unwrap(),
        blake3::hash(
            crate::routes::e2e_stored_manifest(&enc, std::slice::from_ref(&chunk)).as_bytes()
        )
        .to_hex()
        .to_string()
    );
    let resp = relay
        .get("/v1/workspaces/ws-e2e/head")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], true);
    assert_eq!(body["manifest_enc"], enc, "returned verbatim");
    assert!(body.get("manifest").is_none(), "no plaintext half");

    // CAS and fencing are unchanged on the e2e path.
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        0,
        &enc,
        std::slice::from_ref(&chunk),
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "current_seq": 1 }));
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        1,
        &enc,
        std::slice::from_ref(&chunk),
        "laptop-b",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 403, "fenced: wrong device");

    // The plain workspace's head flow is byte-for-byte the old one.
    let resp = put_head_raw(
        &relay,
        "ws-plain",
        0,
        &test_manifest("ws-plain"),
        "laptop-a",
        plain_gen,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get("/v1/workspaces/ws-plain/head")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], false);
    assert!(body.get("manifest").is_some());
    assert!(body.get("manifest_enc").is_none());
}

#[tokio::test]
async fn e2e_snapshot_commit_get_and_force_checkpoint() {
    let relay = start_relay(300).await;
    create_ws_e2e_as(&relay, TOKEN, "ws-e2e", "sealed", None).await;
    create_ws(&relay, "ws-plain").await;
    upload_fixture_chunk(&relay, "ws-e2e").await;
    let chunk = chunk_hash(b"foo");
    let enc = fake_manifest_enc();

    // Plaintext snapshot on the e2e workspace → 409; and vice versa.
    let manifest: Value = serde_json::from_str(&test_manifest("ws-e2e")).unwrap();
    let resp = relay
        .post("/v1/workspaces/ws-e2e/snapshots")
        .json(&json!({ "name": "plain", "device": "dev", "manifest": manifest }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "plaintext snapshot on e2e workspace");
    let resp = relay
        .post("/v1/workspaces/ws-plain/snapshots")
        .json(&json!({ "name": "enc", "device": "dev", "manifest_enc": enc, "chunk_hashes": [chunk] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "manifest_enc snapshot on plain workspace"
    );

    // A valid e2e snapshot round-trips verbatim.
    let resp = relay
        .post("/v1/workspaces/ws-e2e/snapshots")
        .json(&json!({ "name": "sealed snap", "device": "dev", "manifest_enc": enc, "chunk_hashes": [chunk] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let sid = body["id"].as_i64().unwrap();
    let resp = relay
        .get(&format!("/v1/workspaces/ws-e2e/snapshots/{sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["e2e"], true);
    assert_eq!(body["manifest_enc"], enc, "snapshot manifest_enc verbatim");
    assert!(body.get("manifest").is_none());

    // A force takeover checkpoints the e2e head verbatim (the checkpoint
    // path cannot parse the encrypted manifest — it must not 500).
    acquire(&relay, "ws-e2e", "laptop-a").await;
    let lease = acquire(&relay, "ws-e2e", "laptop-a").await;
    let generation = lease["generation"].as_i64().unwrap();
    let resp = put_head_enc(
        &relay,
        "ws-e2e",
        0,
        &enc,
        std::slice::from_ref(&chunk),
        "laptop-a",
        generation,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = relay
        .post("/v1/workspaces/ws-e2e/lease/force")
        .json(&json!({ "device_id": "laptop-b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get("/v1/workspaces/ws-e2e/snapshots")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let checkpoints: Vec<&Value> = body["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["kind"] == "checkpoint")
        .collect();
    assert_eq!(checkpoints.len(), 1, "the force made one checkpoint");
    let checkpoint_id = checkpoints[0]["id"].as_i64().unwrap();
    let resp = relay
        .get(&format!("/v1/workspaces/ws-e2e/snapshots/{checkpoint_id}"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["manifest_enc"], enc, "checkpointed e2e head verbatim");
}

/// §24 pool GC on an e2e workspace, committed entirely through the e2e
/// routes: the stored envelope must yield each retained row's chunk list
/// back to the GC, so a snapshot/retained-head chunk survives while a
/// superseded head's exclusive chunk and a never-committed upload are
/// collected (refs row AND blob). Drives `run_pool_gc` directly — never
/// the hourly timer.
#[tokio::test]
async fn pool_gc_collects_unreferenced_e2e_chunks_and_keeps_pinned_ones() {
    let relay = start_relay(300).await;
    create_ws_e2e_as(&relay, TOKEN, "ws-e2e", "sealed", None).await;
    let old = upload_chunk(&relay, "ws-e2e", b"superseded ciphertext").await;
    let snapped = upload_chunk(&relay, "ws-e2e", b"snapshotted ciphertext").await;
    let current = upload_chunk(&relay, "ws-e2e", b"current ciphertext").await;
    // Uploaded but never committed: PUT-only refs, no retained row.
    let stray = upload_chunk(&relay, "ws-e2e", b"never committed ciphertext").await;
    let enc = fake_manifest_enc();

    let lease = acquire(&relay, "ws-e2e", "laptop-a").await;
    let generation = lease["generation"].as_i64().unwrap();
    // seq 1 references `old`; a named snapshot references `snapped`.
    let resp = put_head_enc(&relay, "ws-e2e", 0, &enc, std::slice::from_ref(&old), "laptop-a", generation).await;
    assert_eq!(resp.status(), 200);
    let resp = relay
        .post("/v1/workspaces/ws-e2e/snapshots")
        .json(&json!({ "name": "pin", "device": "dev", "manifest_enc": enc, "chunk_hashes": [snapped.clone()] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    // 50 newer heads supersede seq 1 out of HEAD_KEEP retention.
    for base in 1..=50 {
        let resp = put_head_enc(
            &relay,
            "ws-e2e",
            base,
            &enc,
            std::slice::from_ref(&current),
            "laptop-a",
            generation,
        )
        .await;
        assert_eq!(resp.status(), 200, "head {} superseded", base + 1);
    }

    // One sweep, grace ZERO for determinism, off the runtime threads and
    // under the one DB mutex — exactly how the spawner runs it.
    let state = relay.state.clone();
    let hashes = [&old, &snapped, &current, &stray].map(String::clone);
    let (report, refs) = tokio::task::spawn_blocking(move || {
        let db = state.db.lock().unwrap();
        let report = crate::gc::run_pool_gc(&db, &state.store, std::time::Duration::ZERO).unwrap();
        let refs = hashes.map(|h| db.hash_has_refs(&h).unwrap());
        (report, refs)
    })
    .await
    .unwrap();
    let [old_refs, snapped_refs, current_refs, stray_refs] = refs;
    assert_eq!(report.scanned, 4);
    assert_eq!(report.refs_deleted, 2, "the superseded and the stray chunk");
    assert_eq!(report.blobs_deleted, 2);
    assert!(!old_refs && !stray_refs, "refs rows gone");
    assert!(snapped_refs && current_refs, "pinned chunks keep refs");
    let pool_has = |hash: &str| {
        pear_core::store::ChunkSink::has(&*relay.state.store, hash).unwrap()
    };
    assert!(!pool_has(&old), "superseded head's exclusive chunk collected");
    assert!(!pool_has(&stray), "never-committed upload collected");
    assert!(pool_has(&snapped), "the named snapshot pins its chunk");
    assert!(pool_has(&current), "the retained heads pin theirs");
}

#[tokio::test]
async fn user_key_registration_requires_a_signed_bundle() {
    let relay = start_relay(300).await;
    let jane = create_user(&relay, "jane").await;
    let bob = create_user(&relay, "bob").await;
    let bundle = signed_bundle("jane");

    // Jane registers her signed bundle; the response carries all fields.
    let resp = relay
        .put_as(&jane, "/v1/users/jane/key")
        .json(&bundle.json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "name": "jane",
            "pubkey": bundle.x25519,
            "ed25519": bundle.ed25519,
            "sig": bundle.sig,
        })
    );

    // §19: the bundle is served to ANY authenticated user (pubkeys are
    // public — teammates wrap to them and `pear trust` pins them).
    for token in [&jane, &bob, TOKEN] {
        let resp = relay
            .get_as(token, "/v1/users/jane/key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "any authenticated user may read");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["pubkey"], bundle.x25519);
        assert_eq!(body["ed25519"], bundle.ed25519);
        assert_eq!(body["sig"], bundle.sig);
    }

    // Bob cannot register a key for jane (403), and the admin cannot
    // enroll anyone (403 — self only, no override).
    let resp = relay
        .put_as(&bob, "/v1/users/jane/key")
        .json(&signed_bundle("jane").json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "other user");
    let resp = relay
        .put("/v1/users/jane/key")
        .json(&signed_bundle("jane").json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "admin cannot enroll others");

    // Re-registration replaces the bundle.
    let rotated = signed_bundle("jane");
    let resp = relay
        .put_as(&jane, "/v1/users/jane/key")
        .json(&rotated.json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "re-registration is allowed");
    let resp = relay
        .get_as(&jane, "/v1/users/jane/key")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["pubkey"], rotated.x25519, "the bundle was replaced");
    assert_eq!(body["ed25519"], rotated.ed25519);

    // A bare legacy {pubkey} body is a 400 pointing at keygen.
    let resp = relay
        .put_as(&bob, "/v1/users/bob/key")
        .json(&json!({ "pubkey": signed_bundle("bob").x25519 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "unsigned body");
    let body: Value = resp.json().await.unwrap();
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(msg.contains("keys must be signed"), "{msg}");
    assert!(msg.contains("pear user keygen"), "{msg}");

    // A bundle whose signature was made by a DIFFERENT ed25519 key than
    // the enclosed one is a 400...
    let mut tampered = signed_bundle("bob");
    tampered.sig = signed_bundle("bob").sig;
    let resp = relay
        .put_as(&bob, "/v1/users/bob/key")
        .json(&tampered.json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "signature from another identity");
    // ...and so is a bundle signed for another user (the statement binds
    // the name: no replay).
    let resp = relay
        .put_as(&bob, "/v1/users/bob/key")
        .json(&signed_bundle("mallory").json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "statement made for another user");
    // ...and so is a partial bundle or malformed hex.
    let resp = relay
        .put_as(&bob, "/v1/users/bob/key")
        .json(&json!({ "x25519": signed_bundle("bob").x25519 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "partial bundle");
    let resp = relay
        .put_as(&bob, "/v1/users/bob/key")
        .json(&json!({ "x25519": "not-hex", "ed25519": "ab", "sig": "cd" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "malformed hex");

    // An unknown user's key is a 404; a user with no key reads back nulls.
    let resp = relay
        .get_as(&jane, "/v1/users/nobody/key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown user");
    let resp = relay
        .get_as(&jane, "/v1/users/bob/key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["pubkey"], Value::Null, "never enrolled");
    assert_eq!(body["ed25519"], Value::Null);
    assert_eq!(body["sig"], Value::Null);
}

#[tokio::test]
async fn wrapped_keys_put_get_me_and_visibility_rules() {
    let relay = start_relay(300).await;
    let owner = create_user(&relay, "owner").await;
    let jane = create_user(&relay, "jane").await;
    let rita = create_user(&relay, "rita").await;
    let nate = create_user(&relay, "nate").await;
    let team = create_team(&relay, &owner, "acme").await;
    add_member(&relay, &owner, &team, "jane", "writer").await;
    add_member(&relay, &owner, &team, "rita", "reader").await;
    create_ws_e2e_as(&relay, &owner, "ws-e2e", "sealed", Some(&team)).await;

    // One legacy single-key wrap: 32 (ephemeral pub) ‖ 12 (nonce) ‖ 32
    // (key ciphertext) ‖ 16 (tag) = 92 raw bytes.
    let blob = pear_core::crypto::hex_encode(&[0x42; 92]);

    // The workspace owner (and a writer) may wrap for an existing user.
    let resp = relay
        .put_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .put_as(&jane, "/v1/workspaces/ws-e2e/keys/rita")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a writer may wrap too");

    // keys/me returns exactly what was wrapped for the caller; a member
    // with no wrap gets a 404 saying so.
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["blob"], blob, "the wrapped blob verbatim");
    let resp = relay
        .get_as(&owner, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "nothing wrapped for the caller");

    // Role rules: a reader cannot PUT (403); a non-member gets the
    // existence-hiding 404 on both routes.
    let resp = relay
        .put_as(&rita, "/v1/workspaces/ws-e2e/keys/jane")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader cannot wrap");
    let resp = relay
        .put_as(&nate, "/v1/workspaces/ws-e2e/keys/jane")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "no role: existence hidden");
    let resp = relay
        .get_as(&nate, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "no role: existence hidden");

    // The target user must exist; the blob must be hex of plausible
    // length (§20 relaxed the §17 fixed 92-byte size to a range).
    let resp = relay
        .put_as(&owner, "/v1/workspaces/ws-e2e/keys/nobody")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "target user must exist");
    for bad in [
        "zz",                 // non-hex
        "abc",                // odd length
        &"ab".repeat(59),     // below an empty sealed box
        &"ab".repeat(65_537), // beyond the generous ceiling
    ] {
        let resp = relay
            .put_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
            .json(&json!({ "blob": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "blob {bad:?} is not a plausible wrap");
    }
    // ...while any plausible length goes: the legacy 92-byte single-key
    // wrap AND a multi-generation keyring payload (§20).
    for good in [&blob, &pear_core::crypto::hex_encode(&[0x42; 400])] {
        let resp = relay
            .put_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
            .json(&json!({ "blob": good }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "a {}-raw-byte blob is accepted", good.len() / 2);
    }

    // Re-wrapping replaces the stored blob.
    let rotated = pear_core::crypto::hex_encode(&[0x7a; 92]);
    let resp = relay
        .put_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
        .json(&json!({ "blob": rotated }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["blob"], rotated, "re-wrapping replaces");
}

#[tokio::test]
async fn wrapped_keys_delete_gate_and_idempotency() {
    let relay = start_relay(300).await;
    let owner = create_user(&relay, "owner").await;
    let jane = create_user(&relay, "jane").await;
    let rita = create_user(&relay, "rita").await;
    let nate = create_user(&relay, "nate").await;
    let team = create_team(&relay, &owner, "acme").await;
    add_member(&relay, &owner, &team, "jane", "writer").await;
    add_member(&relay, &owner, &team, "rita", "reader").await;
    create_ws_e2e_as(&relay, &owner, "ws-e2e", "sealed", Some(&team)).await;

    // A legacy-size wrap blob for jane (92 raw bytes).
    let blob = pear_core::crypto::hex_encode(&[0x42; 92]);
    let resp = relay
        .put_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Same gate as the PUT: a reader cannot DELETE (403), and a
    // non-member gets the existence-hiding 404.
    let resp = relay
        .delete_as(&rita, "/v1/workspaces/ws-e2e/keys/jane")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "reader cannot delete a wrap");
    let resp = relay
        .delete_as(&nate, "/v1/workspaces/ws-e2e/keys/jane")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "no role: existence hidden");
    // The wrap survived both refusals.
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "refused deletes touched nothing");

    // A writer may delete; the owner may too (§20 rotation runs as either).
    let resp = relay
        .delete_as(&jane, "/v1/workspaces/ws-e2e/keys/jane")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "writer deletes");
    let resp = relay
        .get_as(&jane, "/v1/workspaces/ws-e2e/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "the wrap is gone");

    // Idempotent: deleting again — and deleting a wrap that never existed —
    // is still 204, so a retried rotation pass converges.
    let resp = relay
        .delete_as(&owner, "/v1/workspaces/ws-e2e/keys/jane")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "deleting twice is still success");
    let resp = relay
        .delete_as(&owner, "/v1/workspaces/ws-e2e/keys/rita")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "deleting a never-wrapped user too");
}

#[tokio::test]
async fn team_members_list_carries_registered_key_bundles() {
    let relay = start_relay(300).await;
    let owner = create_user(&relay, "owner").await;
    let jane = create_user(&relay, "jane").await;
    let team = create_team(&relay, &owner, "acme").await;
    add_member(&relay, &owner, &team, "jane", "writer").await;

    let bundle = signed_bundle("jane");
    let resp = relay
        .put_as(&jane, "/v1/users/jane/key")
        .json(&bundle.json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = relay
        .get_as(&owner, &format!("/v1/teams/{team}/members"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert_eq!(
        members[0],
        json!({
            "user": "jane",
            "role": "writer",
            "pubkey": bundle.x25519,
            "ed25519": bundle.ed25519,
            "sig": bundle.sig,
        }),
        "enrolled member carries her full bundle"
    );
    assert_eq!(
        members[1],
        json!({ "user": "owner", "role": "owner", "pubkey": null, "ed25519": null, "sig": null }),
        "a member who never keygenned reads nulls"
    );
}

#[tokio::test]
async fn team_remove_member_gate_last_owner_and_wrap_cascade() {
    let relay = start_relay(300).await;
    let owner = create_user(&relay, "owner").await;
    let bob = create_user(&relay, "bob").await;
    let carol = create_user(&relay, "carol").await;
    let nate = create_user(&relay, "nate").await;
    let team = create_team(&relay, &owner, "acme").await;
    add_member(&relay, &owner, &team, "bob", "reader").await;
    add_member(&relay, &owner, &team, "carol", "writer").await;

    // Gate (§20): same as the POST — a reader member, a stranger, and the
    // admin are all 403; an unknown team is the owner's 404.
    let resp = relay
        .delete_as(&bob, &format!("/v1/teams/{team}/members/carol"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a reader cannot remove others");
    let resp = relay
        .delete_as(&nate, &format!("/v1/teams/{team}/members/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a stranger cannot remove anyone");
    let resp = relay
        .delete_as(TOKEN, &format!("/v1/teams/{team}/members/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "no admin override, as with the POST");
    let resp = relay
        .delete_as(&owner, "/v1/teams/no-such-team/members/bob")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown team");

    // The cascade: bob holds wraps on two workspaces attached to acme.
    let blob = pear_core::crypto::hex_encode(&[0x42; 92]);
    create_ws_e2e_as(&relay, &owner, "ws-1", "one", Some(&team)).await;
    create_ws_e2e_as(&relay, &owner, "ws-2", "two", Some(&team)).await;
    for ws in ["ws-1", "ws-2"] {
        let resp = relay
            .put_as(&owner, &format!("/v1/workspaces/{ws}/keys/bob"))
            .json(&json!({ "blob": blob }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    // ...and carol holds one on ws-1 too (hers must survive bob's removal).
    let resp = relay
        .put_as(&owner, "/v1/workspaces/ws-1/keys/carol")
        .json(&json!({ "blob": blob }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Removal: 204 — and bob's wraps die WITH the membership. Re-adding
    // him must NOT resurrect them (a surviving row would read 200 again).
    let resp = relay
        .delete_as(&owner, &format!("/v1/teams/{team}/members/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "owner removes");
    let resp = relay
        .delete_as(&owner, &format!("/v1/teams/{team}/members/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "idempotent: removing a non-member too");
    add_member(&relay, &owner, &team, "bob", "reader").await;
    for ws in ["ws-1", "ws-2"] {
        let resp = relay
            .get_as(&bob, &format!("/v1/workspaces/{ws}/keys/me"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "bob's wrap died with the membership on {ws}"
        );
    }
    // Carol's wrap on the same workspace is untouched.
    let resp = relay
        .get_as(&carol, "/v1/workspaces/ws-1/keys/me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "only the departed user's rows go");

    // Leaving: a non-owner member removes THEMSELVES — no owner needed.
    let resp = relay
        .delete_as(&bob, &format!("/v1/teams/{team}/members/bob"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "a reader may leave");
    let resp = relay
        .get_as(&owner, &format!("/v1/teams/{team}/members"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(
        !body["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["user"] == "bob"),
        "bob actually left"
    );

    // The last-owner guard: removing the team's last owner is a 409,
    // whoever asks — even the owner themselves...
    let resp = relay
        .delete_as(&owner, &format!("/v1/teams/{team}/members/owner"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "the last owner cannot be removed");
    // ...but with another owner promoted, the owner may step down.
    add_member(&relay, &owner, &team, "carol", "owner").await;
    let resp = relay
        .delete_as(&owner, &format!("/v1/teams/{team}/members/owner"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "an owner leaves when owners remain");
    // Now carol is the last owner: the guard fires again, for her too.
    let resp = relay
        .delete_as(&carol, &format!("/v1/teams/{team}/members/carol"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "carol is now the last owner");
}
