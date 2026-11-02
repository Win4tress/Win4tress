//! "System file changed": the files under `drivers\etc` (hosts, networks,
//! protocol, services, lmhosts), which malware edits to redirect names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use w4_ipc::api::{AlertBody, FileChange};

/// File name → SHA-256 (lower-case hex).
pub type Hashes = BTreeMap<String, String>;

/// `%SystemRoot%\System32\drivers\etc`.
pub fn etc_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join(r"System32\drivers\etc")
}

/// The files directly in `dir`, hashed.
pub fn read(dir: &Path) -> Hashes {
    let mut out = Hashes::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_file()
            && let Some(hash) = w4_sys::trust::sha256(&path.to_string_lossy())
        {
            out.insert(e.file_name().to_string_lossy().to_lowercase(), hash);
        }
    }
    out
}

/// What changed between two readings of `dir`, as alerts.
pub fn changes(dir: &Path, before: &Hashes, now: &Hashes) -> Vec<AlertBody> {
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let mut out = Vec::new();
    for (name, hash) in now {
        match before.get(name) {
            None => out.push(AlertBody::SystemFileChanged {
                path: path(name),
                change: FileChange::Created,
            }),
            Some(old) if old != hash => out.push(AlertBody::SystemFileChanged {
                path: path(name),
                change: FileChange::Modified,
            }),
            Some(_) => {}
        }
    }
    for name in before.keys().filter(|n| !now.contains_key(*n)) {
        out.push(AlertBody::SystemFileChanged {
            path: path(name),
            change: FileChange::Deleted,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_modified_and_deleted() {
        let dir = Path::new(r"C:\etc");
        let before = Hashes::from([
            ("hosts".into(), "aa".into()),
            ("networks".into(), "bb".into()),
        ]);
        let now = Hashes::from([
            ("hosts".into(), "cc".into()),
            ("lmhosts".into(), "dd".into()),
        ]);
        let mut found: Vec<_> = changes(dir, &before, &now)
            .into_iter()
            .map(|a| match a {
                AlertBody::SystemFileChanged { path, change } => (path, change),
                _ => unreachable!(),
            })
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            found,
            [
                (r"C:\etc\hosts".into(), FileChange::Modified),
                (r"C:\etc\lmhosts".into(), FileChange::Created),
                (r"C:\etc\networks".into(), FileChange::Deleted),
            ]
        );
        assert!(changes(dir, &now, &now).is_empty());
    }

    #[test]
    fn this_pcs_hosts_file_is_read() {
        assert!(read(&etc_dir()).contains_key("hosts"));
    }
}
