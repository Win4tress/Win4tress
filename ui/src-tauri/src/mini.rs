//! The mini viewer (SPEC §10.2): a small always-on-top live graph, without a
//! frame, that remembers where it was and how see-through it is. Opened and
//! closed from the tray or the header; per user, in the app's data folder.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder};

pub const LABEL: &str = "mini";
const FILE_NAME: &str = "mini.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prefs {
    /// Where it was, in physical pixels.
    #[serde(default)]
    pub x: Option<i32>,
    #[serde(default)]
    pub y: Option<i32>,
    /// The background's opacity, 20 to 100 percent.
    #[serde(default = "default_opacity")]
    pub opacity: u8,
}

fn default_opacity() -> u8 {
    85
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            x: None,
            y: None,
            opacity: default_opacity(),
        }
    }
}

#[derive(Default)]
pub struct Mini {
    prefs: Mutex<Option<Prefs>>,
    saved: Mutex<Option<Instant>>,
}

fn path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_local_data_dir()
        .ok()
        .map(|d| d.join(FILE_NAME))
}

impl Mini {
    pub fn prefs(&self, app: &AppHandle) -> Prefs {
        let mut prefs = self.prefs.lock().unwrap_or_else(|p| p.into_inner());
        prefs
            .get_or_insert_with(|| {
                path(app)
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default()
            })
            .clone()
    }

    fn update(&self, app: &AppHandle, f: impl FnOnce(&mut Prefs)) -> Prefs {
        let mut current = self.prefs(app);
        f(&mut current);
        *self.prefs.lock().unwrap_or_else(|p| p.into_inner()) = Some(current.clone());
        if let (Some(p), Ok(json)) = (path(app), serde_json::to_string_pretty(&current)) {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(p, json);
        }
        current
    }

    pub fn set_opacity(&self, app: &AppHandle, percent: u8) -> Prefs {
        let prefs = self.update(app, |p| p.opacity = percent.clamp(20, 100));
        let _ = app.emit_to(LABEL, "w4://mini-prefs", prefs.clone());
        prefs
    }

    /// The window moved: remember where, at most twice a second while dragging.
    pub fn moved(&self, app: &AppHandle, at: PhysicalPosition<i32>) {
        let mut saved = self.saved.lock().unwrap_or_else(|p| p.into_inner());
        if saved.is_some_and(|t| t.elapsed().as_millis() < 500) {
            if let Some(p) = self
                .prefs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_mut()
            {
                (p.x, p.y) = (Some(at.x), Some(at.y));
            }
            return;
        }
        *saved = Some(Instant::now());
        drop(saved);
        self.update(app, |p| (p.x, p.y) = (Some(at.x), Some(at.y)));
    }

    /// Writes the last position (on close).
    pub fn save(&self, app: &AppHandle) {
        self.update(app, |_| {});
    }
}

/// Opens the mini viewer, or closes it if it's open. Returns whether it's open.
pub fn toggle(app: &AppHandle) -> bool {
    if let Some(w) = app.get_webview_window(LABEL) {
        app.state::<Mini>().save(app);
        let _ = w.destroy();
        return false;
    }
    let prefs = app.state::<Mini>().prefs(app);
    let mut builder = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Win4tress mini viewer")
        .inner_size(300.0, 118.0)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .focused(false);
    if prefs.x.is_none() {
        builder = builder.center();
    }
    match builder.build() {
        Ok(w) => {
            if let (Some(x), Some(y)) = (prefs.x, prefs.y) {
                let _ = w.set_position(PhysicalPosition::new(x, y));
            }
            true
        }
        Err(e) => {
            eprintln!("couldn't open the mini viewer: {e}");
            false
        }
    }
}
