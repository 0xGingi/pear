use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use fastcdc::v2020::StreamCDC;

pub const MIN_CHUNK_SIZE: u32 = 256 * 1024;
pub const AVG_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// One content-defined chunk: its BLAKE3 hash (hex) and the raw bytes.
pub struct ChunkRef {
    pub hash: String,
    pub data: Vec<u8>,
}

/// Split a stream into FastCDC chunks (~1 MiB average), hashing each with
/// BLAKE3. Lazy: each chunk is produced on demand and can be dropped before
/// the next is read, so memory stays bounded to one chunk even for huge
/// files.
pub fn chunk_reader<R: Read>(reader: R) -> impl Iterator<Item = io::Result<ChunkRef>> {
    StreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE).map(|res| {
        res.map(|chunk| ChunkRef {
            hash: blake3::hash(&chunk.data).to_hex().to_string(),
            data: chunk.data,
        })
        .map_err(io::Error::from)
    })
}

pub fn chunk_file(path: &Path) -> io::Result<impl Iterator<Item = io::Result<ChunkRef>>> {
    Ok(chunk_reader(File::open(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    fn chunk_vec(data: &[u8]) -> Vec<ChunkRef> {
        chunk_reader(data).collect::<io::Result<Vec<_>>>().unwrap()
    }

    fn hashes(chunks: &[ChunkRef]) -> Vec<&str> {
        chunks.iter().map(|c| c.hash.as_str()).collect()
    }

    #[test]
    fn deterministic_boundaries() {
        let data = prng_bytes(7, 3 * 1024 * 1024);
        let a = chunk_vec(&data);
        let b = chunk_vec(&data);
        assert_eq!(hashes(&a), hashes(&b));
        assert!(a.len() > 1, "3 MiB should split into multiple chunks");
        let total: usize = a.iter().map(|c| c.data.len()).sum();
        assert_eq!(total, data.len());
    }

    #[test]
    fn small_edit_changes_few_chunks() {
        let mut data = prng_bytes(11, 8 * 1024 * 1024);
        let original = chunk_vec(&data);

        // Same-length mid-file edit.
        let edit = prng_bytes(999, 100);
        let pos = 4 * 1024 * 1024;
        data[pos..pos + edit.len()].copy_from_slice(&edit);
        let updated = chunk_vec(&data);

        // Multiset difference of chunk hashes: CDC should localize the change.
        let mut counts: HashMap<&str, i64> = HashMap::new();
        for c in &original {
            *counts.entry(c.hash.as_str()).or_default() += 1;
        }
        for c in &updated {
            *counts.entry(c.hash.as_str()).or_default() -= 1;
        }
        let changed: i64 = counts.values().map(|v| v.abs()).sum();
        assert!(changed > 0, "edit must change at least one chunk");
        assert!(
            changed <= 4,
            "a 100-byte edit changed {changed} chunks out of {}",
            original.len()
        );
    }

    #[test]
    fn reassembly_round_trip() {
        let data = prng_bytes(42, 5 * 1024 * 1024 + 123);
        let chunks = chunk_vec(&data);
        let mut reassembled = Vec::new();
        for c in &chunks {
            reassembled.extend_from_slice(&c.data);
        }
        assert_eq!(reassembled, data);
    }
}
