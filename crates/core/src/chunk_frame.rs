//! The §23 batched chunk transfer frame: the ONE binary shape shared by
//! the relay's `chunks/put_many`/`chunks/get_many` endpoints and the
//! pear-core relay client. Count-prefixed and ordered:
//!
//! ```text
//! u32 count (LE), then per entry:
//!     64 bytes ASCII lowercase hex hash ‖ u64 blob_len (LE) ‖ blob bytes
//! ```
//!
//! Blobs are opaque to the frame — e2e ciphertext rides it unchanged.
//! The asymmetric caps below are enforced by BOTH sides: the client splits
//! its requests transparently under them, and the relay rejects over-cap
//! requests with a 400. `put_many` is byte-capped because the writer knows
//! its blob sizes up front. `get_many` is hash-capped on the wire — the
//! hard bound, since every stored chunk is ≤ MAX_CHUNK_SIZE, so one
//! response is bounded structurally by [`GET_MANY_MAX_HASHES`] ×
//! [`crate::chunk::MAX_CHUNK_SIZE`] — and byte-BUDGETED at the call site
//! (§30): a file's chunks partition it exactly, so the manifest's
//! per-file `size` gives the mirror the exact byte total of any chunk
//! group, and the fetch loop splits under [`GET_MANY_TARGET_BYTES`]
//! instead of letting the hash cap stack 128 worst-case blobs into one
//! response.

use anyhow::{bail, Result};

/// `put_many`: max entries per request (§23).
pub const PUT_MANY_MAX_ENTRIES: usize = 256;
/// `put_many`: max summed decoded blob bytes per request (§23).
pub const PUT_MANY_MAX_BYTES: u64 = 32 * 1024 * 1024;
/// `get_many`: max hashes per request (§23) — the hard wire cap both
/// sides enforce; with every stored chunk ≤ MAX_CHUNK_SIZE this alone
/// bounds one response at 128 × 4 MiB.
pub const GET_MANY_MAX_HASHES: usize = 128;
/// `get_many`: the CLIENT-side byte budget per fetch batch (§30), the
/// same 32 MiB target as the put side. The mirror plans batches from
/// manifest file sizes — a file's chunks partition it exactly, so a
/// `FileEntry`'s `size` is the exact byte cost of its chunk group — and
/// closes a batch at this many bytes. Not relay-enforced (the relay's
/// hard cap is [`GET_MANY_MAX_HASHES`]): a single file larger than the
/// budget rides in its own batch, so overshoot is bounded by one file.
pub const GET_MANY_TARGET_BYTES: u64 = 32 * 1024 * 1024;

/// The hash field is exactly one BLAKE3 hex digest.
const HASH_LEN: usize = 64;
/// Fixed per-entry header: hash ‖ u64 blob_len. Also the MINIMUM wire
/// cost of one entry (a zero-length blob), which is what lets `decode`
/// bound its pre-allocation by the actual buffer size.
const ENTRY_HEADER: usize = HASH_LEN + 8;

/// Serialize entries in order. Every hash must already be 64 lowercase
/// hex chars (all callers pass BLAKE3 digests or route-validated hashes);
/// a hash of any other shape would produce a frame `decode` rejects.
pub fn encode<'a>(entries: impl Iterator<Item = (&'a str, &'a [u8])>) -> Vec<u8> {
    let entries: Vec<(&str, &[u8])> = entries.collect();
    let mut out = Vec::with_capacity(
        4 + entries
            .iter()
            .map(|(_, blob)| ENTRY_HEADER + blob.len())
            .sum::<usize>(),
    );
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (hash, blob) in entries {
        debug_assert_eq!(
            hash.len(),
            HASH_LEN,
            "chunk frame hashes are 64-char BLAKE3 hex"
        );
        out.extend_from_slice(hash.as_bytes());
        out.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        out.extend_from_slice(blob);
    }
    out
}

/// Parse a frame back into (hash, blob) pairs, in order. Total on hostile
/// input — truncated frames, bogus counts, absurd lengths, non-hex hashes
/// are all clean errors, never a panic — and it never pre-allocates from
/// an untrusted length field: a declared count or blob_len is only ever
/// trusted after it checks out against the bytes actually present.
pub fn decode(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if bytes.len() < 4 {
        bail!(
            "chunk frame is {} bytes, shorter than the 4-byte count",
            bytes.len()
        );
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut rest = &bytes[4..];
    // A frame of N bytes can hold at most N / ENTRY_HEADER entries, so a
    // forged count cannot make this allocate more than the input's own
    // size would allow anyway.
    let mut entries = Vec::with_capacity(count.min(rest.len() / ENTRY_HEADER));
    for i in 0..count {
        if rest.len() < ENTRY_HEADER {
            bail!(
                "chunk frame ends inside entry {i}: {} byte(s) left, need at least {ENTRY_HEADER}",
                rest.len()
            );
        }
        let hash_bytes = &rest[..HASH_LEN];
        if !hash_bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            bail!("chunk frame entry {i}: hash is not 64 lowercase hex chars");
        }
        // Safe: validated as ASCII (a subset of UTF-8) above.
        let hash = std::str::from_utf8(hash_bytes).unwrap().to_string();
        let blob_len = u64::from_le_bytes(rest[HASH_LEN..ENTRY_HEADER].try_into().unwrap());
        rest = &rest[ENTRY_HEADER..];
        // Absurd lengths and truncation are the same check: the declared
        // blob must fit in what remains of the frame.
        if blob_len > rest.len() as u64 {
            bail!(
                "chunk frame entry {i}: blob is {blob_len} bytes but only {} remain",
                rest.len()
            );
        }
        let blob = rest[..blob_len as usize].to_vec();
        rest = &rest[blob_len as usize..];
        entries.push((hash, blob));
    }
    if !rest.is_empty() {
        bail!(
            "chunk frame has {} trailing byte(s) after {count} entries",
            rest.len()
        );
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed (hash, data) entry: the hash IS the blob's BLAKE3.
    fn entry(data: &[u8]) -> (String, Vec<u8>) {
        (blake3::hash(data).to_hex().to_string(), data.to_vec())
    }

    fn frame_of(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        encode(entries.iter().map(|(h, d)| (h.as_str(), d.as_slice())))
    }

    #[test]
    fn round_trip_zero_one_many() {
        // Empty frame: just the count.
        assert_eq!(frame_of(&[]), vec![0, 0, 0, 0]);
        assert_eq!(decode(&frame_of(&[])).unwrap(), vec![]);

        for entries in [
            vec![entry(b"only")],
            // Many, exercising empty and binary blobs plus ORDER: decode
            // must answer in exactly the encode order.
            vec![
                entry(b"first"),
                entry(b""),
                entry(&[0, 159, 146, 150, 255, 13]),
                entry(&vec![7u8; 100_000]),
                entry(b"last"),
            ],
        ] {
            assert_eq!(decode(&frame_of(&entries)).unwrap(), entries);
        }
    }

    #[test]
    fn decode_rejects_truncated_frames() {
        // Shorter than the count field.
        assert!(decode(&[]).is_err());
        assert!(decode(&[1, 0, 0]).is_err());

        let frame = frame_of(&[entry(b"alpha"), entry(b"beta")]);
        // The exact end of entry 0 is a clean one-entry frame once the
        // count agrees; anything into entry 1 — header or blob — errors.
        let first_entry_len = 4 + ENTRY_HEADER + 5; // count + header + "alpha"
        let mut one_entry = frame[..first_entry_len].to_vec();
        one_entry[0] = 1;
        assert_eq!(decode(&one_entry).unwrap().len(), 1);
        for cut in [first_entry_len + 1, frame.len() - 1] {
            assert!(decode(&frame[..cut]).is_err(), "truncated at {cut}");
        }
    }

    #[test]
    fn decode_rejects_count_mismatch() {
        let mut frame = frame_of(&[entry(b"one")]);
        // Count claims MORE entries than the frame holds.
        frame[0] = 2;
        assert!(decode(&frame).is_err());
        // Count claims FEWER: the trailing entry is a count mismatch too.
        let frame = frame_of(&[entry(b"one"), entry(b"two")]);
        let mut undercounted = frame.clone();
        undercounted[0] = 1;
        assert!(decode(&undercounted).is_err());
    }

    #[test]
    fn decode_rejects_absurd_blob_len_without_huge_allocation() {
        let frame = frame_of(&[entry(b"tiny")]);
        // Rewrite the blob_len field to u64::MAX: larger than the whole
        // frame. Must be a clean error — if decode pre-allocated from it,
        // this test would abort on allocation failure instead.
        let mut forged = frame.clone();
        forged[4 + HASH_LEN..4 + ENTRY_HEADER].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode(&forged).is_err());
        // Same for a forged count: 4 billion entries in a frame holding
        // none. The capacity bound (remaining bytes / ENTRY_HEADER) keeps
        // this a fast, small error.
        let mut forged_count = frame_of(&[]);
        forged_count[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&forged_count).is_err());
    }

    #[test]
    fn decode_rejects_non_hex_and_wrong_length_hashes() {
        // Uppercase, non-ASCII, and non-hex bytes in the hash field all
        // fail (the field is fixed at 64 bytes, so a short hash shows up
        // as non-hex padding, and a long one desyncs the frame).
        for bad in [b'A', b'g', 0xFF, b' '] {
            let (hash, data) = entry(b"payload");
            let mut frame = frame_of(&[(hash, data)]);
            frame[4] = bad; // first hash byte of the first entry
            assert!(decode(&frame).is_err(), "hash byte {bad:#04x}");
        }
    }
}
