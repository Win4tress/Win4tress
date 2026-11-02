//! The main window. Closing it destroys it rather than hiding it, so the web
//! view behind it (some 450 MB across WebView2's processes) is freed while
//! win4tress sits in the tray (SPEC §16: the UI uses resources only while
//! open). Opening it again builds it where it was.

use std::sync::Mutex;

use tauri::{AppHandle, Manager, WebviewWindowBuilder, Window};

pub const LABEL: &str = "main";

/// Where the window was, in logical pixels, when not maximized or minimized.
#[derive(Clone, Copy)]
struct Normal {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Default)]
struct Place {
    normal: Option<Normal>,
    maximized: bool,
}

/// Where the main window was when it closed.
#[derive(Default)]
pub struct Last(Mutex<Place>);

/// The window is closing: remember where it is.
pub fn closing(window: &Window) {
    let last = window.state::<Last>();
    let mut place = last.0.lock().unwrap_or_else(|p| p.into_inner());
    place.maximized = window.is_maximized().unwrap_or(false);
    if place.maximized || window.is_minimized().unwrap_or(false) {
        // Its normal place is the one from before.
        return;
    }
    let (Ok(scale), Ok(at), Ok(size)) = (
        window.scale_factor(),
        window.outer_position(),
        window.inner_size(),
    ) else {
        return;
    };
    let at = at.to_logical::<f64>(scale);
    let size = size.to_logical::<f64>(scale);
    place.normal = Some(Normal {
        x: at.x,
        y: at.y,
        width: size.width,
        height: size.height,
    });
}

/// Shows the window, building it again if it was closed.
pub fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let Some(config) = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == LABEL)
        .cloned()
    else {
        return;
    };
    let (normal, maximized) = {
        let last = app.state::<Last>();
        let place = last.0.lock().unwrap_or_else(|p| p.into_inner());
        (place.normal, place.maximized)
    };
    let mut builder = match WebviewWindowBuilder::from_config(app, &config) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("couldn't open the window: {e}");
            return;
        }
    };
    if let Some(n) = normal {
        builder = builder.position(n.x, n.y).inner_size(n.width, n.height);
    }
    match builder.build() {
        Ok(window) => {
            if maximized {
                let _ = window.maximize();
            }
            let _ = window.set_focus();
        }
        Err(e) => eprintln!("couldn't open the window: {e}"),
    }
}
