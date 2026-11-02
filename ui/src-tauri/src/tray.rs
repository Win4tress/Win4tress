//! Tray icon: opens the window, quits, and shows live rates (and decisions
//! waiting in Ask to Connect) in its tooltip.

use std::sync::atomic::{AtomicUsize, Ordering};

use tauri::AppHandle;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

const ID: &str = "main";

/// Ask to Connect's prompts waiting for a decision.
static WAITING: AtomicUsize = AtomicUsize::new(0);

pub fn setup(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Win4tress", true, None::<&str>)?;
    let mini = MenuItem::with_id(app, "mini", "Mini viewer", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Win4tress", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &mini, &quit])?;
    let mut tray = TrayIconBuilder::with_id(ID)
        .tooltip("Win4tress")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => crate::main_window::show(app),
            "mini" => {
                crate::mini::toggle(app);
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                crate::main_window::show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

/// Live rates in the tooltip, from the newest sample.
pub fn set_rates(app: &AppHandle, recv: u64, sent: u64) {
    let waiting = match WAITING.load(Ordering::Relaxed) {
        0 => String::new(),
        1 => "\n1 connection waiting for you".into(),
        n => format!("\n{n} connections waiting for you"),
    };
    set_tooltip(
        app,
        &format!("Win4tress\n▼ {}  ▲ {}{waiting}", rate(recv), rate(sent)),
    );
}

/// Shown with the next rates.
pub fn set_waiting(n: usize) {
    WAITING.store(n, Ordering::Relaxed);
}

pub fn set_disconnected(app: &AppHandle) {
    set_tooltip(app, "Win4tress: service not running");
}

fn set_tooltip(app: &AppHandle, text: &str) {
    if let Some(tray) = app.tray_by_id(ID) {
        let _ = tray.set_tooltip(Some(text));
    }
}

fn rate(bytes_per_sec: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes_per_sec as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes_per_sec} B/s")
    } else {
        format!("{value:.1} {}/s", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::rate;

    #[test]
    fn rates() {
        assert_eq!(rate(12), "12 B/s");
        assert_eq!(rate(8_600_000), "8.6 MB/s");
    }
}
