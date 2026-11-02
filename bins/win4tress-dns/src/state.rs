//! The resolver's loaded configuration: the config file, the rules built from
//! it and the compiled blocklist it names. Swapped whole when the file
//! changes, so a query always sees one consistent version.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use w4_dns::config::{CONFIG_FILE, Config, Upstream};
use w4_dns::matcher::Blocklist;
use w4_dns::rules::Rules;

pub struct Loaded {
    pub config: Config,
    pub rules: Rules,
    pub blocklist: Option<Blocklist>,
    pub local: HashMap<String, Vec<IpAddr>>,
    /// The DoH server's name: looked up through the system servers.
    pub doh_host: Option<String>,
    pub list_names: HashMap<u16, String>,
    /// What didn't load (bad regexes, a missing blocklist).
    pub problems: Vec<String>,
    pub modified: Option<SystemTime>,
}

impl Loaded {
    pub fn empty() -> Loaded {
        Loaded::from_config(Config::default(), None, None)
    }

    fn from_config(
        config: Config,
        blocklist: Option<Blocklist>,
        modified: Option<SystemTime>,
    ) -> Loaded {
        let (rules, mut problems) = Rules::new(
            config.allow.iter().cloned(),
            config.deny.iter().cloned(),
            config.regex.iter().cloned(),
        );
        if config.blocklist.is_some() && blocklist.is_none() {
            problems.push("the blocklist file couldn't be opened".into());
        }
        let local = config
            .local_records
            .iter()
            .filter_map(|r| Some((w4_dns::normalize(&r.name)?, r.addrs.clone())))
            .collect();
        let doh_host = match &config.upstream {
            Upstream::Doh { url } => url
                .strip_prefix("https://")
                .and_then(|r| r.split(['/', ':']).next())
                .map(str::to_ascii_lowercase),
            Upstream::System => None,
        };
        let list_names = config
            .lists
            .iter()
            .map(|l| (l.id, l.name.clone()))
            .collect();
        Loaded {
            config,
            rules,
            blocklist,
            local,
            doh_host,
            list_names,
            problems,
            modified,
        }
    }

    /// Reads the folder's config (and its blocklist). `None` without a config file.
    pub fn read(dir: &Path) -> Option<Result<Loaded, String>> {
        let path = dir.join(CONFIG_FILE);
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Some(Err(format!("{}: {e}", path.display()))),
        };
        let config: Config = match serde_json::from_str(&text) {
            Ok(c) => c,
            Err(e) => return Some(Err(format!("{}: {e}", path.display()))),
        };
        let blocklist = config
            .blocklist
            .as_deref()
            .filter(|f| !f.contains(['/', '\\']))
            .and_then(|f| match Blocklist::open(&dir.join(f)) {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::warn!("blocklist: {e}");
                    None
                }
            });
        Some(Ok(Loaded::from_config(config, blocklist, Some(modified))))
    }
}

/// The current configuration, replaced when the file changes.
pub struct Current {
    dir: PathBuf,
    loaded: RwLock<Arc<Loaded>>,
    /// A config file that didn't load (its time), and why: reported once, and
    /// in the status, until the file changes again.
    failed: RwLock<Option<(Option<SystemTime>, String)>>,
}

impl Current {
    pub fn new(dir: PathBuf) -> Current {
        let current = Current {
            dir,
            loaded: RwLock::new(Arc::new(Loaded::empty())),
            failed: RwLock::new(None),
        };
        current.reload_if_changed();
        current
    }

    /// Why the config file on disk isn't the one in use, if it isn't.
    pub fn error(&self) -> Option<String> {
        self.failed
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|(_, e)| e.clone())
    }

    pub fn get(&self) -> Arc<Loaded> {
        Arc::clone(&self.loaded.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Reloads when the config file's time changed; returns whether it did.
    pub fn reload_if_changed(&self) -> bool {
        let file_time = std::fs::metadata(self.dir.join(CONFIG_FILE))
            .and_then(|m| m.modified())
            .ok();
        if file_time == self.get().modified
            || self
                .failed
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .is_some_and(|(t, _)| *t == file_time)
        {
            return false;
        }
        match Loaded::read(&self.dir) {
            Some(Ok(loaded)) => {
                tracing::info!(
                    blocked_domains = loaded.blocklist.as_ref().map_or(0, Blocklist::len),
                    regexes = loaded.rules.regex_count(),
                    problems = loaded.problems.len(),
                    "configuration loaded"
                );
                for p in &loaded.problems {
                    tracing::warn!("configuration: {p}");
                }
                *self.loaded.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(loaded);
                *self.failed.write().unwrap_or_else(|p| p.into_inner()) = None;
                true
            }
            Some(Err(e)) => {
                tracing::warn!("configuration not loaded, the previous one stays: {e}");
                *self.failed.write().unwrap_or_else(|p| p.into_inner()) = Some((file_time, e));
                false
            }
            None => false,
        }
    }
}
