//! Automatic cleanup (SPEC §7.10): rules of apps whose program has been gone
//! for 7 days are removed (on by default), and, if the user sets a number of
//! days, rules of apps that haven't used the network or tried to for that
//! long. Removals are in the rules' audit trail; an app that comes back is
//! new again. Baseline rules and win4tress's own programs are left alone.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use w4_core::time::now_unix_ms;
use w4_ipc::api::{CleanupItem, CleanupReason, CleanupResult, CleanupSettings};
use w4_monitor::Monitor;
use w4_store::{AppWithRules, Store};

use crate::enforcer::Enforcer;
use crate::usage::Usage;

const DAY_MS: i64 = 24 * 3600 * 1000;
/// A program gone this long counts as uninstalled.
pub const MISSING_FOR_MS: i64 = 7 * DAY_MS;
const RUN_EVERY: Duration = Duration::from_secs(3600);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A path cleanup can judge: a drive-letter path to a file, not "System" or
/// an unresolved device path.
fn judged(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() > 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":\\"
}

/// What to do about one app: its reason and since when, whether it's due,
/// and the missing-since time to keep (`Some(None)` clears it).
#[derive(Debug, PartialEq, Eq)]
pub struct Judgement {
    pub item: Option<(CleanupReason, i64, bool)>,
    pub missing_since: Option<Option<i64>>,
}

/// Pure: an app with rules, whether its program exists, the settings, now.
pub fn judge(
    app: &AppWithRules,
    exists: bool,
    settings: &CleanupSettings,
    now_ms: i64,
) -> Judgement {
    let mut missing_since = None;
    if !exists {
        let since = app.missing_since_ms.unwrap_or(now_ms);
        if app.missing_since_ms.is_none() {
            missing_since = Some(Some(now_ms));
        }
        if settings.uninstalled {
            let due = now_ms - since >= MISSING_FOR_MS;
            return Judgement {
                item: Some((CleanupReason::Uninstalled, since, due)),
                missing_since,
            };
        }
    } else if app.missing_since_ms.is_some() {
        missing_since = Some(None);
    }
    let item = settings
        .inactive_days
        .filter(|d| *d > 0)
        .filter(|d| now_ms - app.last_active_ms >= i64::from(*d) * DAY_MS)
        .map(|_| (CleanupReason::Inactive, app.last_active_ms, true));
    Judgement {
        item,
        missing_since,
    }
}

pub struct Cleanup {
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    usage: Arc<Usage>,
    enforcer: Arc<Enforcer>,
    last_run: Mutex<Option<i64>>,
}

impl Cleanup {
    pub fn new(
        store: Arc<Mutex<Store>>,
        monitor: Arc<Mutex<Monitor>>,
        usage: Arc<Usage>,
        enforcer: Arc<Enforcer>,
    ) -> Arc<Cleanup> {
        Arc::new(Cleanup {
            store,
            monitor,
            usage,
            enforcer,
            last_run: Mutex::new(None),
        })
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            let _ = tokio::task::spawn_blocking(move || this.pass(now_unix_ms(), true)).await;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(RUN_EVERY) => {}
            }
        }
    }

    /// Looks at every app with rules; with `apply`, removes the due ones'
    /// rules. Returns what's gone or inactive, and what was removed.
    pub fn pass(&self, now_ms: i64, apply: bool) -> CleanupResult {
        let settings = self.usage.settings().cleanup;
        let apps = match lock(&self.store).apps_with_rules() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("cleanup: reading rules failed: {e}");
                return CleanupResult::default();
            }
        };
        let mut items = Vec::new();
        let mut removed = 0u32;
        for app in apps {
            if !judged(&app.path) || self.enforcer.is_protected(&app.path) {
                continue;
            }
            let exists = Path::new(&app.path).exists();
            let j = judge(&app, exists, &settings, now_ms);
            if let Some(since) = j.missing_since {
                let _ = lock(&self.store).set_missing_since(app.app, since);
            }
            let Some((reason, since_ms, due)) = j.item else {
                continue;
            };
            let app_ref = lock(&self.monitor).app_ref(app.app);
            let mut item = CleanupItem {
                app: app_ref,
                reason,
                since_ms,
                rules: app.rules.len() as u32,
                due,
            };
            if apply && due {
                let change = match reason {
                    CleanupReason::Uninstalled => "removed: uninstalled",
                    CleanupReason::Inactive => "removed: inactive",
                };
                match lock(&self.store).clean_up_app(app.app, now_ms, change) {
                    Ok(n) => {
                        removed += n as u32;
                        item.rules = n as u32;
                        lock(&self.monitor).forget_first_activity(app.app);
                        tracing::info!(path = %app.path, rules = n, ?reason, "cleanup removed rules");
                    }
                    Err(e) => tracing::warn!("cleanup of {} failed: {e}", app.path),
                }
            }
            items.push(item);
        }
        if apply {
            *lock(&self.last_run) = Some(now_ms);
            if removed > 0 {
                self.enforcer.changed();
            }
        }
        CleanupResult {
            items,
            last_run_ms: *lock(&self.last_run),
            removed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(missing_since_ms: Option<i64>, last_active_ms: i64) -> AppWithRules {
        AppWithRules {
            app: 1,
            path: r"C:\Tools\old.exe".into(),
            last_active_ms,
            missing_since_ms,
            rules: vec![3, 4],
        }
    }

    const NOW: i64 = 100 * DAY_MS;

    #[test]
    fn a_missing_program_is_due_after_seven_days() {
        let on = CleanupSettings::default();
        let first = judge(&app(None, NOW), false, &on, NOW);
        assert_eq!(first.missing_since, Some(Some(NOW)));
        assert_eq!(first.item, Some((CleanupReason::Uninstalled, NOW, false)));
        let later = judge(&app(Some(NOW - 7 * DAY_MS), NOW), false, &on, NOW);
        assert_eq!(
            later.item,
            Some((CleanupReason::Uninstalled, NOW - 7 * DAY_MS, true))
        );
        assert_eq!(later.missing_since, None, "kept as it is");
        // Back again: forgotten.
        let back = judge(&app(Some(NOW - DAY_MS), NOW), true, &on, NOW);
        assert_eq!((back.item, back.missing_since), (None, Some(None)));
        // Off: noted, not removed.
        let off = CleanupSettings {
            uninstalled: false,
            inactive_days: None,
        };
        assert_eq!(judge(&app(Some(0), NOW), false, &off, NOW).item, None);
    }

    #[test]
    fn inactive_apps_only_when_asked() {
        let default = CleanupSettings::default();
        assert_eq!(
            judge(&app(None, NOW - 90 * DAY_MS), true, &default, NOW).item,
            None
        );
        let thirty = CleanupSettings {
            uninstalled: true,
            inactive_days: Some(30),
        };
        assert_eq!(
            judge(&app(None, NOW - 29 * DAY_MS), true, &thirty, NOW).item,
            None
        );
        assert_eq!(
            judge(&app(None, NOW - 30 * DAY_MS), true, &thirty, NOW).item,
            Some((CleanupReason::Inactive, NOW - 30 * DAY_MS, true))
        );
    }

    #[test]
    fn only_drive_paths_are_judged() {
        assert!(judged(r"C:\Program Files\App\app.exe"));
        assert!(!judged("System"));
        assert!(!judged(r"\Device\HarddiskVolume3\app.exe"));
        assert!(!judged("NULL"));
    }
}
