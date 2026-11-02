//! The card (SPEC §7.4): a small window in the corner above the taskbar for
//! what wants an answer. In Ask to Connect, connections that were blocked
//! (Allow or Block); in Click to Block, apps using the network for the first
//! time (Block or OK). It never takes the keyboard from what the user is
//! doing, waits while a full-screen game, video or presentation is on, and
//! closes when nothing is left.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::Value;
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder,
};
use w4_ipc::Client;
use w4_ipc::api::{Alert, AlertBody, AlertsNotification, FirewallStatus, method};

use crate::popups::Popups;

pub const LABEL: &str = "card";
/// In logical pixels; the height follows the page (`fit`).
const WIDTH: f64 = 360.0;
const FIRST_HEIGHT: f64 = 190.0;
/// From the work area's edges, in logical pixels.
const MARGIN: f64 = 12.0;
/// New apps held at once; older ones are still in the alert list.
const MAX_NOTICES: usize = 20;
/// How often a held card checks whether the full-screen app has ended.
const HOLD_CHECK: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct Card {
    /// Prompts already shown once: a prompt the user closed the card on isn't
    /// pushed at them again; it stays in the list.
    shown: Mutex<HashSet<u64>>,
    /// Prompts waiting for a decision, open or not.
    prompts: AtomicUsize,
    /// New apps' first connections ("first network activity" alerts) not
    /// answered yet, oldest first.
    notices: Mutex<Vec<Alert>>,
    /// Waiting for a full-screen app to end before showing.
    holding: AtomicBool,
}

impl Card {
    pub fn notices(&self) -> Vec<Alert> {
        self.notices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn change_notices(&self, app: &AppHandle, f: impl FnOnce(&mut Vec<Alert>)) {
        let mut notices = self.notices.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut notices);
        let excess = notices.len().saturating_sub(MAX_NOTICES);
        notices.drain(..excess);
        let _ = app.emit_to(LABEL, "w4://notices", &*notices);
    }

    /// The user answered a new app's card (Block or OK), or it timed out.
    pub fn dismiss(&self, app: &AppHandle, id: i64) {
        self.change_notices(app, |n| n.retain(|a| a.id != id));
    }

    /// The card closed: what it showed of new apps is in the alert list.
    pub fn closed(&self) {
        self.notices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    fn anything(&self) -> bool {
        self.prompts.load(Ordering::Relaxed) > 0
            || !self
                .notices
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
    }
}

/// Shows the card, creating it, unless a full-screen app is on: then it
/// appears when that ends.
pub fn show(app: &AppHandle) {
    if app.get_webview_window(LABEL).is_some() {
        return;
    }
    if crate::desktop::full_screen() {
        hold(app);
        return;
    }
    let built = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Win4tress")
        .inner_size(WIDTH, FIRST_HEIGHT)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        // Shown without taking the keyboard: typing elsewhere goes on.
        .focused(false)
        .build();
    match built {
        Ok(w) => place(&w, FIRST_HEIGHT),
        Err(e) => eprintln!("couldn't open the card: {e}"),
    }
}

/// Shows the card once no full-screen app is on, if anything is still waiting.
fn hold(app: &AppHandle) {
    let card = app.state::<Card>();
    if card.holding.swap(true, Ordering::Relaxed) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        while crate::desktop::full_screen() {
            tokio::time::sleep(HOLD_CHECK).await;
        }
        let card = app.state::<Card>();
        card.holding.store(false, Ordering::Relaxed);
        if card.anything() {
            show(&app);
        }
    });
}

/// Sizes the card to `height` logical pixels and puts it in the bottom right
/// corner of the main display's work area, above the taskbar.
pub fn place(w: &WebviewWindow, height: f64) {
    let monitor = w
        .app_handle()
        .primary_monitor()
        .ok()
        .flatten()
        .or_else(|| w.current_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let scale = monitor.scale_factor();
    let area = monitor.work_area();
    let px = |logical: f64| (logical * scale).round() as i32;
    let margin = px(MARGIN);
    let width = px(WIDTH);
    let height = px(height).clamp(px(80.0), area.size.height as i32 - 2 * margin);
    let _ = w.set_size(PhysicalSize::new(width as u32, height as u32));
    // The window's invisible resize borders (left, right and bottom) are
    // outside what shows: the page is put in the corner, not the window.
    let inset = match (w.inner_position(), w.outer_position()) {
        (Ok(inner), Ok(outer)) => (inner.x - outer.x, inner.y - outer.y),
        _ => (0, 0),
    };
    let _ = w.set_position(PhysicalPosition::new(
        area.position.x + area.size.width as i32 - width - margin - inset.0,
        area.position.y + area.size.height as i32 - height - margin - inset.1,
    ));
}

/// From a `prompts.changed` notification: shows the card for a prompt that
/// opened since, and returns how many prompts there are in all.
pub fn on_prompts(app: &AppHandle, params: &Value) -> usize {
    prompts(app, params, false)
}

/// When the app connects (`prompts.list`): decisions left pending while no
/// app was there to ask get the card too. Returns how many there are.
pub fn on_connect(app: &AppHandle, params: &Value) -> usize {
    prompts(app, params, true)
}

fn prompts(app: &AppHandle, params: &Value, pending_too: bool) -> usize {
    let prompts = params
        .get("prompts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let open: Vec<u64> = prompts
        .iter()
        .filter(|p| {
            let state = p.get("state").and_then(Value::as_str);
            state == Some("open") || (pending_too && state == Some("pending"))
        })
        .filter_map(|p| p.get("id").and_then(Value::as_u64))
        .collect();
    let card = app.state::<Card>();
    card.prompts.store(prompts.len(), Ordering::Relaxed);
    let new = {
        let mut shown = card.shown.lock().unwrap_or_else(|p| p.into_inner());
        // Every id is recorded, not just up to the first new one.
        let mut new = false;
        for id in &open {
            new |= shown.insert(*id);
        }
        new
    };
    if new {
        show(app);
    }
    prompts.len()
}

/// From an `alerts.new` notification: in Click to Block, with cards for new
/// apps on, a new app's first connection gets a card. Returns the alerts it
/// took, which then don't pop up as Windows notifications too.
pub async fn on_alerts(app: &AppHandle, client: &Arc<Client>, params: &Value) -> Vec<i64> {
    let Ok(batch) = serde_json::from_value::<AlertsNotification>(params.clone()) else {
        return Vec::new();
    };
    let new_apps: Vec<Alert> = batch
        .alerts
        .into_iter()
        .filter(|a| matches!(a.body, AlertBody::FirstNetworkActivity { .. }) && a.app.is_some())
        .collect();
    if new_apps.is_empty() || !app.state::<Popups>().prefs(app).new_app_cards {
        return Vec::new();
    }
    // Only Click to Block allows a new app first; Ask to Connect asks anyway.
    let Ok(firewall) = client
        .call::<Value, FirewallStatus>(method::FIREWALL, Value::Null)
        .await
    else {
        return Vec::new();
    };
    if firewall.mode.as_str() != "click_to_block"
        || firewall.block_all.is_some()
        || firewall.monitoring_only.is_some()
    {
        return Vec::new();
    }
    let ids = new_apps.iter().map(|a| a.id).collect();
    app.state::<Card>()
        .change_notices(app, |n| n.extend(new_apps));
    show(app);
    ids
}
