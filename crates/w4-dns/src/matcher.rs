//! The compiled blocklist, memory-mapped (SPEC §13): a lookup hashes the name
//! and each parent and binary-searches the sorted hashes, so memory is the
//! pages touched and start-up is opening a file.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::compile::{HEADER, MAGIC, VERSION, hash};
use crate::suffixes;

enum Bytes {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Bytes {
    fn get(&self) -> &[u8] {
        match self {
            Bytes::Mapped(m) => m,
            Bytes::Owned(v) => v,
        }
    }
}

pub struct Blocklist {
    bytes: Bytes,
    key: [u8; 16],
    count: usize,
}

/// Where a name matched: the list and the listed name (itself or a parent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit<'a> {
    pub list: u16,
    pub listed: &'a str,
}

impl Blocklist {
    fn check(bytes: Bytes) -> Result<Blocklist, String> {
        let b = bytes.get();
        if b.len() < HEADER || &b[..4] != MAGIC {
            return Err("not a compiled blocklist".into());
        }
        let version = u32::from_le_bytes(b[4..8].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(format!("blocklist version {version}, expected {VERSION}"));
        }
        let key: [u8; 16] = b[8..24].try_into().expect("16 bytes");
        let count = u64::from_le_bytes(b[24..32].try_into().expect("8 bytes"));
        let count = usize::try_from(count).map_err(|_| "too many entries")?;
        let needed = count
            .checked_mul(10)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or("too many entries")?;
        if b.len() != needed {
            return Err(format!("blocklist is {} bytes, expected {needed}", b.len()));
        }
        Ok(Blocklist { bytes, key, count })
    }

    /// Maps a compiled file.
    pub fn open(path: &Path) -> Result<Blocklist, String> {
        let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // SAFETY: each compiled file gets a name of its own and is never
        // written again once in use; a new list is a new file (spike 0.8:
        // Windows won't replace a mapped file anyway).
        let map =
            unsafe { Mmap::map(&file) }.map_err(|e| format!("mapping {}: {e}", path.display()))?;
        Self::check(Bytes::Mapped(map))
    }

    pub fn from_vec(bytes: Vec<u8>) -> Result<Blocklist, String> {
        Self::check(Bytes::Owned(bytes))
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn hash_at(&self, i: usize) -> u64 {
        let at = HEADER + i * 8;
        u64::from_le_bytes(self.bytes.get()[at..at + 8].try_into().expect("8 bytes"))
    }

    fn list_at(&self, i: usize) -> u16 {
        let at = HEADER + self.count * 8 + i * 2;
        u16::from_le_bytes(self.bytes.get()[at..at + 2].try_into().expect("2 bytes"))
    }

    fn find(&self, h: u64) -> Option<u16> {
        let (mut lo, mut hi) = (0, self.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.hash_at(mid).cmp(&h) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(self.list_at(mid)),
            }
        }
        None
    }

    /// The name (normalized) or its closest listed parent.
    pub fn lookup<'a>(&self, name: &'a str) -> Option<Hit<'a>> {
        suffixes(name).find_map(|s| {
            self.find(hash(&self.key, s))
                .map(|list| Hit { list, listed: s })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{compile, write_atomic};

    fn list(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn names_and_parents_match() {
        let a = list(&["ads.example.com", "tracker.net"]);
        let b = list(&["evil.org"]);
        let bl = Blocklist::from_vec(compile(&[(3, &a), (9, &b)], [1; 16])).unwrap();
        assert_eq!(bl.len(), 3);
        assert_eq!(
            bl.lookup("ads.example.com"),
            Some(Hit {
                list: 3,
                listed: "ads.example.com"
            })
        );
        assert_eq!(
            bl.lookup("x.y.tracker.net"),
            Some(Hit {
                list: 3,
                listed: "tracker.net"
            })
        );
        assert_eq!(bl.lookup("cdn.evil.org").map(|h| h.list), Some(9));
        assert_eq!(
            bl.lookup("example.com"),
            None,
            "a parent of a listed name isn't blocked"
        );
        assert_eq!(bl.lookup("notevil.org"), None);
    }

    #[test]
    fn files_map_and_bad_files_are_refused() {
        let dir = std::env::temp_dir().join(format!("w4bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.w4bl");
        let names = list(&["ads.example.com"]);
        write_atomic(&path, &compile(&[(1, &names)], [2; 16])).unwrap();
        let bl = Blocklist::open(&path).unwrap();
        assert!(bl.lookup("ads.example.com").is_some());
        drop(bl);
        std::fs::write(&path, b"W4BL\x01\0\0\0short").unwrap();
        assert!(Blocklist::open(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(Blocklist::from_vec(vec![0; 64]).is_err());
        assert!(
            Blocklist::from_vec(compile(&[], [0; 16]))
                .unwrap()
                .is_empty()
        );
    }
}
