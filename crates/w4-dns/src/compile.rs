//! Compiling blocklists (SPEC §13), when they're downloaded rather than at
//! startup: each domain hashed with a keyed 64-bit hash (SipHash-1-3, a fresh
//! key per file), duplicates removed, sorted, with the list each came from.
//!
//! File layout, little-endian:
//!
//! | offset | size | |
//! |---|---|---|
//! | 0 | 4 | magic `W4BL` |
//! | 4 | 4 | version (1) |
//! | 8 | 16 | SipHash key |
//! | 24 | 8 | entries, n |
//! | 32 | 32 | reserved |
//! | 64 | 8n | hashes, ascending |
//! | 64 + 8n | 2n | list id of each |

use std::hash::Hasher;
use std::path::Path;

use siphasher::sip::SipHasher13;

pub const MAGIC: &[u8; 4] = b"W4BL";
pub const VERSION: u32 = 1;
pub const HEADER: usize = 64;

pub fn hash(key: &[u8; 16], name: &str) -> u64 {
    let mut h = SipHasher13::new_with_key(key);
    h.write(name.as_bytes());
    h.finish()
}

/// A key that differs per file, so a list can't be crafted against it.
pub fn new_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() ^ (u128::from(std::process::id()) << 64);
    // Mixed through SipHash itself so neighbouring seeds give unrelated keys.
    let a = hash(&seed.to_le_bytes(), "w4bl-a");
    let b = hash(&seed.to_le_bytes(), "w4bl-b");
    key[..8].copy_from_slice(&a.to_le_bytes());
    key[8..].copy_from_slice(&b.to_le_bytes());
    key
}

/// The compiled file for `lists` (list id, normalized domains). A domain in
/// several lists keeps the first list's id.
pub fn compile(lists: &[(u16, &[String])], key: [u8; 16]) -> Vec<u8> {
    let mut entries: Vec<(u64, u16)> = lists
        .iter()
        .flat_map(|(id, domains)| domains.iter().map(move |d| (hash(&key, d), *id)))
        .collect();
    entries.sort_unstable();
    entries.dedup_by_key(|(h, _)| *h);
    let n = entries.len();
    let mut out = Vec::with_capacity(HEADER + n * 10);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(&(n as u64).to_le_bytes());
    out.resize(HEADER, 0);
    for (h, _) in &entries {
        out.extend_from_slice(&h.to_le_bytes());
    }
    for (_, id) in &entries {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

/// Writes next to `path` and renames over it, so a reader never sees half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_duplicates() {
        let a = vec!["ads.example.com".to_string(), "x.example.com".to_string()];
        let b = vec!["ads.example.com".to_string()];
        let key = [7u8; 16];
        let bytes = compile(&[(1, &a), (2, &b)], key);
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 2);
        assert_eq!(bytes.len(), HEADER + 2 * 10);
        let h0 = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let h1 = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
        assert!(h0 < h1);
    }

    #[test]
    fn keys_differ() {
        assert_ne!(new_key(), new_key());
    }
}
