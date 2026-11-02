//! Desktop pop-ups for new alerts (SPEC §11): per monitor, none, its warnings
//! and critical alerts (the default) or all of them; a few at a time, none
//! while the window has focus, and none for what the user snoozed: an app, or
//! a kind of alert without an app, for 24 hours. Kept in the app's local data
//! folder, per user.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;
use w4_ipc::api::{Alert, AlertsNotification, MONITORS, Severity};

const SNOOZE_MS: i64 = 24 * 3600 * 1000;
/// Pop-ups per batch of new alerts; the rest are summed up in one more.
const MAX_AT_ONCE: usize = 3;
const FILE_NAME: &str = "popups.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Off,
    /// Warnings and critical alerts.
    #[default]
    Warnings,
    All,
}

/// Which of a monitor's alerts pop up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Desktop {
    Off,
    /// Its warnings and critical alerts.
    Important,
    All,
}

impl From<Level> for Desktop {
    fn from(level: Level) -> Self {
        match level {
            Level::Off => Desktop::Off,
            Level::Warnings => Desktop::Important,
            Level::All => Desktop::All,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prefs {
    /// For monitors without a choice of their own in `desktop`.
    #[serde(default)]
    pub level: Level,
    /// Per monitor (alert kind), the user's choice.
    #[serde(default)]
    pub desktop: BTreeMap<String, Desktop>,
    /// "app:<id>" or "kind:<kind>" → snoozed until (Unix ms).
    #[serde(default)]
    pub snoozed: BTreeMap<String, i64>,
    /// In Click to Block, a new app's first connection shows the card, with
    /// Block, instead of a pop-up.
    #[serde(default = "yes")]
    pub new_app_cards: bool,
}

fn yes() -> bool {
    true
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            level: Level::default(),
            desktop: BTreeMap::new(),
            snoozed: BTreeMap::new(),
            new_app_cards: true,
        }
    }
}

impl Prefs {
    /// Whether an alert of `kind` and `severity` pops up (snoozes aside).
    fn pops_up(&self, kind: &str, severity: Severity) -> bool {
        match self.desktop.get(kind).copied().unwrap_or(self.level.into()) {
            Desktop::Off => false,
            Desktop::Important => severity != Severity::Info,
            Desktop::All => true,
        }
    }

    /// "Set all to": every monitor, its own choices cleared.
    fn set_all(&mut self, level: Level) {
        self.level = level;
        self.desktop.clear();
    }
}

#[derive(Default)]
pub struct Popups {
    prefs: Mutex<Option<Prefs>>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// What snoozing this alert silences: its app, or its kind.
pub fn snooze_key(a: &Alert) -> String {
    match &a.app {
        Some(app) => format!("app:{}", app.id),
        None => format!("kind:{}", a.body.kind()),
    }
}

fn path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_local_data_dir()
        .ok()
        .map(|d| d.join(FILE_NAME))
}

impl Popups {
    fn with<T>(&self, app: &AppHandle, f: impl FnOnce(&mut Prefs) -> T) -> T {
        let mut prefs = self.prefs.lock().unwrap_or_else(|p| p.into_inner());
        let prefs = prefs.get_or_insert_with(|| {
            path(app)
                .and_then(|p| std::fs::read_to_string(p).ok())
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default()
        });
        let now = now_ms();
        prefs.snoozed.retain(|_, until| *until > now);
        f(prefs)
    }

    fn save(app: &AppHandle, prefs: &Prefs) -> Result<(), String> {
        let path = path(app).ok_or("no app data folder")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(prefs).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn prefs(&self, app: &AppHandle) -> Prefs {
        self.with(app, |p| p.clone())
    }

    pub fn set_level(&self, app: &AppHandle, level: Level) -> Result<Prefs, String> {
        self.with(app, |p| {
            p.set_all(level);
            Self::save(app, p).map(|()| p.clone())
        })
    }

    /// One monitor's pop-ups; `None` goes back to the default (`level`).
    pub fn set_kind(
        &self,
        app: &AppHandle,
        kind: &str,
        desktop: Option<Desktop>,
    ) -> Result<Prefs, String> {
        if !MONITORS.iter().any(|m| m.kind == kind) {
            return Err(format!("no monitor {kind:?}"));
        }
        self.with(app, |p| {
            match desktop {
                Some(d) => p.desktop.insert(kind.to_string(), d),
                None => p.desktop.remove(kind),
            };
            Self::save(app, p).map(|()| p.clone())
        })
    }

    pub fn set_new_app_cards(&self, app: &AppHandle, on: bool) -> Result<Prefs, String> {
        self.with(app, |p| {
            p.new_app_cards = on;
            Self::save(app, p).map(|()| p.clone())
        })
    }

    /// Snoozes `key` for 24 hours, or wakes it with `on: false`.
    pub fn snooze(&self, app: &AppHandle, key: String, on: bool) -> Result<Prefs, String> {
        self.with(app, |p| {
            if on {
                p.snoozed.insert(key, now_ms() + SNOOZE_MS);
            } else {
                p.snoozed.remove(&key);
            }
            Self::save(app, p).map(|()| p.clone())
        })
    }

    /// New alerts from the service: pop up those the user wants to see, but
    /// not those the card shows (`carded`).
    pub fn on_alerts(&self, app: &AppHandle, params: &serde_json::Value, carded: &[i64]) {
        let Ok(batch) = serde_json::from_value::<AlertsNotification>(params.clone()) else {
            return;
        };
        let focused = app
            .get_webview_window("main")
            .and_then(|w| w.is_focused().ok())
            .unwrap_or(false);
        if focused {
            return;
        }
        let shown: Vec<&Alert> = self.with(app, |p| {
            batch
                .alerts
                .iter()
                .filter(|a| p.pops_up(a.body.kind(), a.severity))
                .filter(|a| !p.snoozed.contains_key(&snooze_key(a)))
                .filter(|a| !carded.contains(&a.id))
                .collect()
        });
        for a in shown.iter().take(MAX_AT_ONCE) {
            let label = MONITORS
                .iter()
                .find(|m| m.kind == a.body.kind())
                .map_or("Alert", |m| m.label);
            let title = match a.severity {
                Severity::Critical => format!("Win4tress: {label} (critical)"),
                _ => format!("Win4tress: {label}"),
            };
            let body = a.body.text(a.app.as_ref().map(|r| r.name.as_str()));
            let _ = app.notification().builder().title(title).body(body).show();
        }
        if shown.len() > MAX_AT_ONCE {
            let _ = app
                .notification()
                .builder()
                .title("Win4tress")
                .body(format!(
                    "{} more alerts; open Win4tress to see them",
                    shown.len() - MAX_AT_ONCE
                ))
                .show();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_monitor_s_own_choice_wins_over_the_level() {
        let mut p = Prefs::default();
        // The default: warnings and critical, for every monitor.
        assert!(!p.pops_up("first_network_activity", Severity::Info));
        assert!(p.pops_up("app_info_changed", Severity::Warning));
        assert!(!p.pops_up("app_info_changed", Severity::Info));

        p.desktop
            .insert("first_network_activity".into(), Desktop::All);
        p.desktop.insert("arp_spoofing".into(), Desktop::Off);
        assert!(p.pops_up("first_network_activity", Severity::Info));
        assert!(!p.pops_up("arp_spoofing", Severity::Critical));
        assert!(!p.pops_up("data_plan", Severity::Info));

        // "Set all to" clears the monitors' own choices.
        p.set_all(Level::All);
        assert!(p.desktop.is_empty());
        assert!(p.pops_up("arp_spoofing", Severity::Critical));
        assert!(p.pops_up("data_plan", Severity::Info));
        p.set_all(Level::Off);
        assert!(!p.pops_up("arp_spoofing", Severity::Critical));
    }

    #[test]
    fn prefs_from_before_per_monitor_choices_still_read() {
        let p: Prefs = serde_json::from_str(r#"{"level":"all","snoozed":{}}"#).unwrap();
        assert_eq!(p.level, Level::All);
        assert!(p.desktop.is_empty() && p.new_app_cards);
    }
}
