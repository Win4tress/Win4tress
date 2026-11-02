//! win4tress desktop app. Keeps a pipe connection to the service, reconnects when
//! it drops, forwards live samples to the web view, and lets the web view call
//! read-only service methods.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod card;
mod desktop;
mod elevated;
mod files;
mod icons;
mod main_window;
mod mini;
mod popups;
mod titlebar;
mod tray;
mod winver;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::RwLock;
use w4_ipc::Client;
use w4_ipc::api::{SamplesNotification, method, notification};

use card::Card;
use icons::IconCache;
use mini::Mini;
use popups::Popups;

const RECONNECT_EVERY: Duration = Duration::from_secs(2);

/// Methods the web view may call. The service authorizes changes by the token
/// of this process, which runs as the signed-in user (SPEC §4.3). `reset` is
/// left to the CLI: it needs an elevated caller anyway.
const ALLOWED_METHODS: &[&str] = &[
    method::FIREWALL,
    method::RULES,
    method::RULES_SET,
    method::RULES_DELETE,
    method::RULES_APPLY,
    method::FIREWALL_SET_MODE,
    method::FIREWALL_KEEP_CHANGES,
    method::FIREWALL_VERDICTS,
    method::FIREWALL_BLOCK_ALL,
    method::FIREWALL_TURN_ON,
    method::FIREWALL_APP_RULES,
    method::FIREWALL_BLOCKS,
    method::APPS_ALL,
    method::PROMPTS,
    method::PROMPTS_DECIDE,
    method::SETTINGS,
    method::SETTINGS_SET,
    method::PLAN_STATUS,
    method::STATUS,
    method::LIVE,
    method::HISTORY,
    method::BREAKDOWN,
    method::APPS,
    method::HOSTS,
    method::CONNECTIONS,
    method::DNS_LOG,
    method::DNS_TOP,
    method::DNS_STATS,
    method::ALERTS,
    method::ALERTS_MARK_READ,
    method::MONITORS,
    method::DEVICES,
    method::DEVICES_SCAN,
    method::DEVICES_SET_KNOWN,
    method::RULES_ENABLE,
    method::PROFILES,
    method::PROFILES_SAVE,
    method::PROFILES_SWITCH,
    method::PROFILES_DELETE,
    method::CLEANUP,
    method::CLEANUP_RUN,
    method::REPUTATION,
    method::REPUTATION_APP,
    method::REPUTATION_SET_KEY,
    method::REPUTATION_CHECK,
    method::REPUTATION_SCAN,
    method::REPUTATION_UPLOAD,
    method::DNS_FILTER,
    method::DNS_FILTER_UPDATE,
    method::DNS_FILTER_PAUSE,
    method::DNS_FILTER_LOG,
    method::PROFILES_SET_NETWORKS,
    method::NETWORKS,
    method::RULES_EXPORT,
    method::RULES_IMPORT,
    method::CONNECTIONS_CLOSE,
];

#[derive(Clone, Debug, Default, Serialize)]
struct ConnectionState {
    connected: bool,
    reason: Option<String>,
}

#[derive(Default)]
struct Connection {
    client: RwLock<Option<Arc<Client>>>,
    state: Mutex<ConnectionState>,
}

#[tauri::command]
async fn rpc(
    connection: State<'_, Arc<Connection>>,
    method: String,
    params: Value,
) -> Result<Value, String> {
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(format!("method {method} is not available to the UI"));
    }
    let client = connection
        .client
        .read()
        .await
        .clone()
        .ok_or("not connected to the win4tress service")?;
    client
        .call::<Value, Value>(&method, params)
        .await
        .map_err(|e| e.to_string())
}

/// Changes the elevated helper may make (SPEC §4.3 "Require elevation"), and
/// the setting itself, which always needs elevation.
const ELEVATED_METHODS: &[&str] = &[
    method::RULES_SET,
    method::RULES_DELETE,
    method::RULES_APPLY,
    method::FIREWALL_SET_MODE,
    method::FIREWALL_KEEP_CHANGES,
    method::FIREWALL_BLOCK_ALL,
    method::FIREWALL_TURN_ON,
    method::PROMPTS_DECIDE,
    method::SETTINGS_SET,
    method::SETTINGS_REQUIRE_ELEVATION,
    method::DEVICES_SCAN,
    method::DEVICES_SET_KNOWN,
    method::RULES_ENABLE,
    method::PROFILES_SAVE,
    method::PROFILES_SWITCH,
    method::PROFILES_DELETE,
    method::CLEANUP_RUN,
    method::REPUTATION_SET_KEY,
    method::REPUTATION_CHECK,
    method::REPUTATION_SCAN,
    method::REPUTATION_UPLOAD,
    method::DNS_FILTER_UPDATE,
    method::DNS_FILTER_PAUSE,
    method::PROFILES_SET_NETWORKS,
    method::RULES_IMPORT,
    method::CONNECTIONS_CLOSE,
];

/// A change, made by an elevated helper after a UAC prompt.
#[tauri::command]
async fn rpc_elevated(method: String, params: Value) -> Result<Value, String> {
    if !ELEVATED_METHODS.contains(&method.as_str()) {
        return Err(format!("method {method} can't be elevated"));
    }
    let pipe = std::env::var("WIN4TRESS_PIPE").unwrap_or_else(|_| w4_ipc::PIPE_NAME.into());
    tauri::async_runtime::spawn_blocking(move || elevated::call(&pipe, &method, &params))
        .await
        .map_err(|e| e.to_string())?
}

/// The executable's icon as a data URL, or `None` (no icon, not a local .exe).
#[tauri::command]
async fn app_icon(cache: State<'_, IconCache>, path: String) -> Result<Option<String>, String> {
    if !icons::is_local_exe(&path) {
        return Ok(None);
    }
    if let Some(hit) = cache.get(&path) {
        return Ok(hit);
    }
    let lookup = path.clone();
    let url = tauri::async_runtime::spawn_blocking(move || icons::data_url(&lookup))
        .await
        .map_err(|e| e.to_string())?;
    cache.insert(path, url.clone());
    Ok(url)
}

/// The product an executable is part of (its version resource's ProductName,
/// without ® and ™); `None` if it doesn't say or isn't a local .exe.
#[tauri::command]
async fn app_product(path: String) -> Option<String> {
    if !icons::is_local_exe(&path) {
        return None;
    }
    let product = tauri::async_runtime::spawn_blocking(move || {
        w4_sys::version::file_info(&path).and_then(|i| i.product)
    })
    .await
    .ok()
    .flatten()?;
    let clean = product
        .replace(['®', '™', '©'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!clean.is_empty()).then_some(clean)
}

/// The main window's handle, to own a file dialog.
fn owner(app: &AppHandle) -> Option<isize> {
    app.get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .map(|h| h.0 as isize)
}

/// Asks where to save a rules export (suggesting `name`) and writes `contents`
/// there; returns the path, or `None` if the user cancelled.
#[tauri::command]
async fn save_file(
    app: AppHandle,
    name: String,
    contents: String,
) -> Result<Option<String>, String> {
    let owner = owner(&app);
    tauri::async_runtime::spawn_blocking(move || files::save(owner, name, contents))
        .await
        .map_err(|e| e.to_string())?
}

/// Asks for a rules file and returns what's in it, or `None` if cancelled.
#[tauri::command]
async fn open_file(app: AppHandle) -> Result<Option<String>, String> {
    let owner = owner(&app);
    tauri::async_runtime::spawn_blocking(move || files::open(owner))
        .await
        .map_err(|e| e.to_string())?
}

/// Saves the graph (a PNG data URL) to the user's Pictures folder; returns where.
#[tauri::command]
fn save_png(data_url: String) -> Result<String, String> {
    desktop::save_png(&data_url).map(|p| p.display().to_string())
}

/// How often the user's last input (idle shading, SPEC §8.4) and proxy
/// settings ("Proxy changed", SPEC §11) are reported.
const INPUT_EVERY: Duration = Duration::from_secs(60);

/// What only this session can see: the user's last input, and their proxy
/// settings when they change (the service can't read another user's).
async fn report_session(client: Arc<Client>) {
    let mut proxy_reported = None;
    loop {
        if let Some(ms) = desktop::last_input_ms() {
            let _ = client
                .call::<_, Value>(
                    method::SESSION_INPUT,
                    serde_json::json!({ "last_input_ms": ms }),
                )
                .await;
        }
        let proxy = tauri::async_runtime::spawn_blocking(w4_sys::proxy::current_user)
            .await
            .ok()
            .flatten();
        if let Some(proxy) = proxy
            && proxy_reported.as_ref() != Some(&proxy)
        {
            let reported = client
                .call::<_, Value>(method::SESSION_PROXY, serde_json::json!({ "proxy": proxy }))
                .await;
            if reported.is_ok() {
                proxy_reported = Some(proxy);
            }
        }
        tokio::time::sleep(INPUT_EVERY).await;
    }
}

/// Opens or closes the mini viewer; returns whether it's open. Async, like
/// every command that opens a window: on Windows, a window opened from a
/// synchronous command never loads its page (wry#583).
#[tauri::command]
async fn mini_toggle(app: AppHandle) -> bool {
    mini::toggle(&app)
}

#[tauri::command]
fn mini_prefs(app: AppHandle, mini: State<'_, Mini>) -> mini::Prefs {
    mini.prefs(&app)
}

#[tauri::command]
fn mini_set_opacity(app: AppHandle, mini: State<'_, Mini>, percent: u8) -> mini::Prefs {
    mini.set_opacity(&app, percent)
}

/// Whether the app starts when the user signs in.
#[tauri::command]
fn autostart_get() -> bool {
    autostart::enabled()
}

/// Turns starting at sign-in on or off; returns the state now.
#[tauri::command]
fn autostart_set(enabled: bool) -> Result<bool, String> {
    autostart::set(enabled)
}

#[derive(Serialize)]
struct About {
    /// The app's version (the service has its own, in its status).
    version: String,
    /// "Windows 11 Pro 24H2 (build 26100.4652)".
    windows: String,
}

/// Settings → About.
#[tauri::command]
fn about_info(app: AppHandle) -> About {
    About {
        version: app.package_info().version.to_string(),
        windows: winver::describe(),
    }
}

#[tauri::command]
fn popup_prefs(app: AppHandle, popups: State<'_, Popups>) -> popups::Prefs {
    popups.prefs(&app)
}

#[tauri::command]
fn set_popup_level(
    app: AppHandle,
    popups: State<'_, Popups>,
    level: popups::Level,
) -> Result<popups::Prefs, String> {
    popups.set_level(&app, level)
}

/// One monitor's desktop pop-ups (`null`: back to the default).
#[tauri::command]
fn set_popup_kind(
    app: AppHandle,
    popups: State<'_, Popups>,
    kind: String,
    desktop: Option<popups::Desktop>,
) -> Result<popups::Prefs, String> {
    popups.set_kind(&app, &kind, desktop)
}

/// Silences pop-ups for an app ("app:<id>") or a kind of alert ("kind:<kind>")
/// for 24 hours, or ends that with `on: false`.
#[tauri::command]
fn snooze(
    app: AppHandle,
    popups: State<'_, Popups>,
    key: String,
    on: bool,
) -> Result<popups::Prefs, String> {
    if !(key.starts_with("app:") || key.starts_with("kind:")) || key.len() > 100 {
        return Err(format!("can't snooze {key}"));
    }
    popups.snooze(&app, key, on)
}

/// Opens a VirusTotal, MalwareBazaar, abuse.ch or blocklist page, or one of
/// the credits in Settings → About, in the default browser.
/// Only those sites: the web view can't open arbitrary programs through this.
#[tauri::command]
fn open_link(url: String) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "https://www.virustotal.com/",
        "https://bazaar.abuse.ch/",
        "https://abuse.ch/",
        "https://auth.abuse.ch/",
        "https://hashlookup.circl.lu/",
        // Blocklists' homepages and licences (DNS filtering).
        "https://github.com/hagezi/",
        "https://oisd.nl",
        "https://github.com/sjhgvr/",
        "https://github.com/StevenBlack/",
        "https://github.com/AdguardTeam/",
        // Credits (Settings → About).
        "https://db-ip.com",
        "https://creativecommons.org/licenses/by/4.0/",
        "https://feodotracker.abuse.ch/",
        "https://standards.ieee.org/",
        "https://www.naturalearthdata.com/",
        "https://gitlab.com/catamphetamine/country-flag-icons",
    ];
    if !ALLOWED.iter().any(|p| url.starts_with(p))
        || url.chars().any(|c| c.is_whitespace() || c == '"')
    {
        return Err("not a link win4tress opens".into());
    }
    desktop::open_url(&url)
}

/// Shows the card, e.g. for Ask to Connect's decisions still waiting. Async:
/// it may open the window (see `mini_toggle`).
#[tauri::command]
async fn show_prompts(app: AppHandle) {
    card::show(&app);
}

/// New apps' first connections the card shows, besides Ask to Connect's prompts.
#[tauri::command]
fn card_notices(card: State<'_, Card>) -> Vec<w4_ipc::api::Alert> {
    card.notices()
}

/// The user answered a new app's card, or it timed out.
#[tauri::command]
fn card_dismiss(app: AppHandle, card: State<'_, Card>, id: i64) {
    card.dismiss(&app, id);
}

/// The card's page is `height` logical pixels tall: the window follows.
#[tauri::command]
fn card_fit(app: AppHandle, height: f64) {
    if let Some(w) = app.get_webview_window(card::LABEL) {
        card::place(&w, height);
    }
}

#[tauri::command]
fn set_new_app_cards(
    app: AppHandle,
    popups: State<'_, Popups>,
    on: bool,
) -> Result<popups::Prefs, String> {
    popups.set_new_app_cards(&app, on)
}

#[tauri::command]
fn connection_state(connection: State<'_, Arc<Connection>>) -> ConnectionState {
    connection
        .state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

fn set_state(app: &AppHandle, connection: &Connection, state: ConnectionState) {
    let mut current = connection.state.lock().unwrap_or_else(|p| p.into_inner());
    let changed = current.connected != state.connected || current.reason != state.reason;
    *current = state.clone();
    drop(current);
    if changed {
        let _ = app.emit("w4://connection", state);
    }
}

async fn connection_loop(app: AppHandle, connection: Arc<Connection>) {
    let pipe = std::env::var("WIN4TRESS_PIPE").unwrap_or_else(|_| w4_ipc::PIPE_NAME.into());
    loop {
        let reason = match session(&app, &connection, &pipe).await {
            Ok(()) => "the service closed the connection".to_string(),
            Err(e) => e,
        };
        *connection.client.write().await = None;
        set_state(
            &app,
            &connection,
            ConnectionState {
                connected: false,
                reason: Some(reason),
            },
        );
        tray::set_disconnected(&app);
        tokio::time::sleep(RECONNECT_EVERY).await;
    }
}

/// One connected session; returns when the connection ends.
async fn session(app: &AppHandle, connection: &Connection, pipe: &str) -> Result<(), String> {
    let client = Arc::new(Client::connect(pipe).await.map_err(|e| e.to_string())?);
    client
        .hello("win4tress-ui")
        .await
        .map_err(|e| e.to_string())?;
    let mut notes = client
        .subscribe(&[
            notification::SAMPLES,
            notification::ALERTS,
            notification::PROMPTS,
        ])
        .await
        .map_err(|e| e.to_string())?;
    *connection.client.write().await = Some(Arc::clone(&client));
    let reporter = tauri::async_runtime::spawn(report_session(Arc::clone(&client)));
    set_state(
        app,
        connection,
        ConnectionState {
            connected: true,
            reason: None,
        },
    );
    // Decisions that waited for an app to ask them.
    if let Ok(prompts) = client
        .call::<Value, Value>(method::PROMPTS, Value::Null)
        .await
    {
        tray::set_waiting(card::on_connect(app, &prompts));
    }
    while let Some(note) = notes.recv().await {
        match note.method.as_str() {
            notification::SAMPLES => {
                if let Ok(batch) =
                    serde_json::from_value::<SamplesNotification>(note.params.clone())
                    && let Some(last) = batch.samples.last()
                {
                    tray::set_rates(app, last.recv, last.sent);
                }
                let _ = app.emit("w4://samples", note.params);
            }
            notification::ALERTS => {
                // Apart, as the card asks the service about the firewall's
                // mode: notifications keep coming meanwhile.
                let (handle, client, params) =
                    (app.clone(), Arc::clone(&client), note.params.clone());
                tauri::async_runtime::spawn(async move {
                    let carded = card::on_alerts(&handle, &client, &params).await;
                    handle
                        .state::<Popups>()
                        .on_alerts(&handle, &params, &carded);
                });
                let _ = app.emit("w4://alerts", note.params);
            }
            notification::PROMPTS => {
                let waiting = card::on_prompts(app, &note.params);
                tray::set_waiting(waiting);
                let _ = app.emit("w4://prompts", note.params);
            }
            _ => {}
        }
    }
    reporter.abort();
    Ok(())
}

fn main() {
    // `--autostart on|off`: the installer's step for starting at sign-in, run
    // as the user; nothing opens.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--autostart") {
        let on = args.get(i + 1).is_some_and(|v| v == "on");
        std::process::exit(if autostart::set(on).is_ok() { 0 } else { 1 });
    }
    // `--quit-others`: the installer's first step on an upgrade or uninstall,
    // so this program's files aren't in use; it has nothing unsaved.
    if args.iter().any(|a| a == "--quit-others") {
        if let Ok(exe) = std::env::current_exe() {
            w4_sys::process::kill_all(&exe);
        }
        return;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let connection = Arc::new(Connection::default());
            app.manage(Arc::clone(&connection));
            app.manage(IconCache::default());
            app.manage(Card::default());
            app.manage(Popups::default());
            app.manage(Mini::default());
            app.manage(main_window::Last::default());
            tray::setup(app)?;
            autostart::refresh();
            // Started at sign-in: in the tray only, the window built when opened.
            if !std::env::args().any(|a| a == autostart::MINIMIZED) {
                main_window::show(app.handle());
            }
            tauri::async_runtime::spawn(connection_loop(app.handle().clone(), connection));
            Ok(())
        })
        // Closing a window destroys it, freeing its web view; win4tress
        // stays in the tray until "Quit" (see `run` below). The main window
        // and the mini viewer remember where they were.
        .on_window_event(|window, event| {
            if window.label() == card::LABEL && matches!(event, tauri::WindowEvent::Destroyed) {
                window.app_handle().state::<Card>().closed();
            }
            if window.label() == mini::LABEL {
                let app = window.app_handle();
                match event {
                    tauri::WindowEvent::Moved(at) => app.state::<Mini>().moved(app, *at),
                    tauri::WindowEvent::CloseRequested { .. } => app.state::<Mini>().save(app),
                    _ => {}
                }
                return;
            }
            let hwnd = || window.hwnd().ok().map(|h| h.0);
            match event {
                tauri::WindowEvent::CloseRequested { .. }
                    if window.label() == main_window::LABEL =>
                {
                    main_window::closing(window)
                }
                tauri::WindowEvent::Focused(active) => titlebar::apply(hwnd(), *active),
                tauri::WindowEvent::ThemeChanged(_) => {
                    titlebar::apply(hwnd(), window.is_focused().unwrap_or(false))
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            rpc,
            rpc_elevated,
            save_png,
            save_file,
            open_file,
            show_prompts,
            card_notices,
            card_dismiss,
            card_fit,
            set_new_app_cards,
            connection_state,
            app_icon,
            app_product,
            popup_prefs,
            set_popup_level,
            set_popup_kind,
            snooze,
            mini_toggle,
            mini_prefs,
            mini_set_opacity,
            autostart_get,
            autostart_set,
            about_info,
            open_link
        ])
        .build(tauri::generate_context!())
        .expect("failed to start the win4tress window")
        .run(|_app, event| {
            // The last window closing leaves win4tress in the tray; the tray's
            // "Quit" exits with a code.
            if let tauri::RunEvent::ExitRequested {
                code: None, api, ..
            } = event
            {
                api.prevent_exit();
            }
        });
}
