//! Where the service keeps its data: `%ProgramData%\win4tress`, readable and
//! writable only by SYSTEM and Administrators (SPEC §9).

use std::io;
use std::path::{Path, PathBuf};

pub fn default_dir() -> PathBuf {
    w4_store::default_dir()
}

/// Creates the folder if needed and (re)applies the admin-only access list.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    w4_sys::fs::create_private_dir(dir, w4_sys::fs::ADMIN_ONLY_SDDL)
}

/// Database size including the write-ahead log.
pub fn db_size(db: &Path) -> u64 {
    let wal = db.with_extension("db-wal");
    [db, wal.as_path()]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}
