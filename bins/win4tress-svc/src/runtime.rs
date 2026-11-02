//! Wires the collector, monitor, history and IPC server together and runs until shutdown.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use w4_core::NetEvent;
use w4_core::firewall::BlockedByKind;
use w4_core::time::now_unix_ms;
use w4_core::trust::Trust;
use w4_etw::{Collector, EventSink};
use w4_ipc::api::{
    AlertBody, AlertsNotification, MonitorInfo, SamplesNotification, Settings, Severity,
    notification,
};
use w4_ipc::server::{self, ServerConfig};
use w4_ipc::{Notification, PIPE_SDDL};
use w4_monitor::{Monitor, PendingAlert};
use w4_store::Store;

use crate::autoprofile::AutoProfile;
use crate::cleanup::Cleanup;
use crate::data;
use crate::dnsfilter::DnsFilter;
use crate::enforcer::Enforcer;
use crate::handler::{self, History, SvcHandler};
use crate::prompts::{Attempt, Prompter};
use crate::reputation::ReputationService;
use crate::resolver::Win32Resolver;
use crate::security::Security;
use crate::usage::Usage;

/// How often closed seconds are pushed to subscribers.
const PUBLISH_EVERY: Duration = Duration::from_millis(250);
/// How often newly seen apps get their version info read.
const APP_INFO_EVERY: Duration = Duration::from_secs(2);
/// How often closed minutes, app changes and DNS queries are written to history.
const SAVE_EVERY: Duration = Duration::from_secs(10);
const PRUNE_EVERY: Duration = Duration::from_secs(3600);
/// Reverse DNS: a few lookups at a time, so a slow resolver can't pile up threads.
const REVERSE_EVERY: Duration = Duration::from_secs(1);
const REVERSE_BATCH: usize = 8;
/// How often the ETW session is checked, and restarted if it was stopped.
const WATCHDOG_EVERY: Duration = Duration::from_secs(10);
/// How often new alerts are stored and announced.
const ALERTS_EVERY: Duration = Duration::from_secs(1);
/// Default for [`Options::learning_ms`].
const FIRST_ACTIVITY_LEARNING_MS: i64 = 3600 * 1000;

pub struct Options {
    pub pipe_name: String,
    pub etw_session: String,
    /// The ETW session for WFP drops ("Blocked by", SPEC §7.9).
    pub drops_session: String,
    pub data_dir: PathBuf,
    pub db_name: &'static str,
    pub record_to: Option<PathBuf>,
    /// After the first run, apps using the network are recorded without alerts
    /// for this long: what runs in that time is the PC's normal.
    pub learning_ms: i64,
    /// Our Windows Firewall rule group. Each instance owns its group outright and
    /// removes rules in it that it doesn't know.
    pub firewall_group: String,
}

impl Options {
    pub fn console(pipe_name: String, data_dir: Option<PathBuf>) -> Self {
        // Separate names, so a console run never touches the installed service's
        // ETW session, database or firewall rules. A console run on its own pipe
        // also gets its own session and rule group.
        let instance = pipe_name
            .rsplit('\\')
            .next()
            .filter(|name| *name != "win4tress");
        let suffix = instance.map(|name| format!("-{name}")).unwrap_or_default();
        Options {
            etw_session: format!("{}-console{suffix}", w4_etw::DEFAULT_SESSION),
            drops_session: format!("{}-console{suffix}", w4_etw::drops::DEFAULT_DROPS_SESSION),
            firewall_group: match instance {
                Some(name) => format!("{} (console {name})", w4_enforce::GROUP),
                None => format!("{} (console)", w4_enforce::GROUP),
            },
            pipe_name,
            data_dir: data_dir.unwrap_or_else(data::default_dir),
            db_name: "history-console.db",
            record_to: None,
            learning_ms: FIRST_ACTIVITY_LEARNING_MS,
        }
    }

    pub fn service() -> Self {
        Options {
            pipe_name: w4_ipc::PIPE_NAME.into(),
            etw_session: w4_etw::DEFAULT_SESSION.into(),
            drops_session: w4_etw::drops::DEFAULT_DROPS_SESSION.into(),
            data_dir: data::default_dir(),
            db_name: "history.db",
            record_to: None,
            learning_ms: FIRST_ACTIVITY_LEARNING_MS,
            firewall_group: w4_enforce::GROUP.into(),
        }
    }
}

/// DNS query type for reverse (PTR) lookups.
const DNS_TYPE_PTR: u16 = 12;

struct MonitorSink {
    monitor: Arc<Mutex<Monitor>>,
    own_pid: u32,
}

impl EventSink for MonitorSink {
    fn on_event(&self, event: NetEvent) {
        // Our own reverse lookups (resolve_names) would otherwise fill the DNS log.
        if let NetEvent::DnsQuery {
            pid, query_type, ..
        } = &event
            && *pid == self.own_pid
            && *query_type == DNS_TYPE_PTR
        {
            return;
        }
        lock(&self.monitor).on_event(event, now_unix_ms());
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn run(options: Options, shutdown: CancellationToken) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("starting async runtime")?
        .block_on(run_async(options, shutdown))
}

/// History is optional: without it the service still runs on live data.
fn open_history(options: &Options) -> Option<(Store, PathBuf)> {
    if let Err(e) = data::ensure_dir(&options.data_dir) {
        tracing::warn!(dir = %options.data_dir.display(), "history disabled: can't prepare data folder: {e}");
        return None;
    }
    let path = options.data_dir.join(options.db_name);
    match Store::open(&path) {
        Ok(store) => {
            tracing::info!(path = %path.display(), "history database opened");
            Some((store, path))
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), "history disabled: {e}");
            None
        }
    }
}

async fn run_async(options: Options, shutdown: CancellationToken) -> Result<()> {
    let mut monitor = Monitor::new(Box::new(Win32Resolver::new()), now_unix_ms());
    monitor.set_own_resolvers(
        own_programs()
            .into_iter()
            .filter(|(_, path)| path.ends_with("win4tress-dns.exe"))
            .map(|(_, path)| path),
    );
    let history = open_history(&options).map(|(store, path)| {
        match store.load_apps() {
            Ok(apps) => monitor.load_apps(apps),
            Err(e) => tracing::warn!("couldn't load saved apps: {e}"),
        }
        // Telling a new app from a known one needs the app history kept here.
        match store.first_run_ms(now_unix_ms()) {
            Ok(first_run) => {
                monitor.set_first_activity_alerts_from(first_run + options.learning_ms)
            }
            Err(e) => tracing::warn!("first-network-activity alerts off: {e}"),
        }
        History {
            store: Arc::new(Mutex::new(store)),
            path,
        }
    });
    let monitor = Arc::new(Mutex::new(monitor));
    let adapters_at_start = w4_sys::adapters::snapshot().unwrap_or_default();

    let collector = Collector::start(
        w4_etw::Config {
            session_name: options.etw_session.clone(),
            record_to: options.record_to.clone(),
            ..Default::default()
        },
        Arc::new(MonitorSink {
            monitor: Arc::clone(&monitor),
            own_pid: std::process::id(),
        }),
    )
    .context("starting ETW collector")?;

    // Connections opened before we started tracing.
    let open: Vec<_> = w4_sys::net::established_tcp()
        .into_iter()
        .map(|c| (c.pid, c.local, c.remote))
        .collect();
    lock(&monitor).seed_connections(&open, now_unix_ms());

    // Firewall rules live in history; without it there's nothing to enforce.
    let enforcer = history.as_ref().and_then(|h| {
        match w4_enforce::ComFirewall::start(options.firewall_group.clone()) {
            Ok(backend) => {
                tracing::info!(group = %options.firewall_group, "Windows Firewall enforcement ready");
                Some(Enforcer::new(
                    Arc::new(backend),
                    Arc::clone(&h.store),
                    Arc::clone(&monitor),
                    own_programs(),
                ))
            }
            Err(e) => {
                tracing::warn!("firewall rules unavailable: {e}");
                None
            }
        }
    });
    let (notes, _) = broadcast::channel::<Notification>(64);
    // Ask to Connect's prompts: blocked attempts in, decisions out (SPEC §7.4).
    let prompter = match (&history, &enforcer) {
        (Some(h), Some(e)) => Some(Prompter::new(
            Arc::clone(&monitor),
            Arc::clone(&h.store),
            Arc::clone(e),
            notes.clone(),
        )),
        _ => None,
    };
    // Blocked connections and what blocked them; needs admin (the WFP engine).
    let drops = start_drops(
        &options.drops_session,
        &monitor,
        prompter.as_ref().map(|(p, _)| Arc::clone(p)),
    );

    // Usage settings, data plan and idle time live in history.
    let usage = history
        .as_ref()
        .map(|h| Usage::new(Arc::clone(&h.store), Arc::clone(&monitor)));
    // The security monitors keep what they've seen in history too.
    let security = history.as_ref().zip(usage.as_ref()).map(|(h, u)| {
        Security::new(
            Arc::clone(&h.store),
            Arc::clone(&monitor),
            Arc::clone(u),
            options.data_dir.clone(),
        )
    });
    // Reputation lookups (opt-in) and automatic cleanup of rules (SPEC §12, §7.10).
    let reputation = history.as_ref().zip(usage.as_ref()).map(|(h, u)| {
        ReputationService::new(
            Arc::clone(&h.store),
            Arc::clone(&monitor),
            Arc::clone(u),
            enforcer.clone(),
        )
    });
    // DNS filtering (SPEC §13): off until turned on; with history, for its settings.
    let dns = usage.as_ref().map(|u| {
        DnsFilter::new(
            Arc::clone(u),
            Arc::clone(&monitor),
            &options.data_dir,
            w4_dns::status::PIPE_NAME.into(),
        )
    });
    let cleanup = match (&history, &usage, &enforcer) {
        (Some(h), Some(u), Some(e)) => Some(Cleanup::new(
            Arc::clone(&h.store),
            Arc::clone(&monitor),
            Arc::clone(u),
            Arc::clone(e),
        )),
        _ => None,
    };

    // Profiles switched by the network the PC joins (SPEC §7.6).
    let autoprofile = match (&history, &enforcer) {
        (Some(h), Some(e)) => Some(AutoProfile::new(
            Arc::clone(&h.store),
            Arc::clone(&monitor),
            Arc::clone(e),
            prompter.as_ref().map(|(p, _)| Arc::clone(p)),
            usage.clone(),
        )),
        _ => None,
    };

    let handler = Arc::new(SvcHandler {
        monitor: Arc::clone(&monitor),
        collector: collector.health_probe(),
        adapters_at_start,
        history: history.clone(),
        enforcer: enforcer.clone(),
        prompter: prompter.as_ref().map(|(p, _)| Arc::clone(p)),
        usage: usage.clone(),
        security: security.clone(),
        reputation: reputation.clone(),
        cleanup: cleanup.clone(),
        dns: dns.clone(),
        autoprofile: autoprofile.clone(),
    });
    let server = tokio::spawn(server::serve(
        ServerConfig {
            pipe_name: options.pipe_name.clone(),
            sddl: PIPE_SDDL.into(),
        },
        handler,
        notes.clone(),
        shutdown.clone(),
    ));
    let collector = Arc::new(Mutex::new(collector));
    let mut tasks = JoinSet::new();
    tasks.spawn(watch_collector(
        Arc::clone(&collector),
        Arc::clone(&monitor),
        shutdown.clone(),
    ));
    tasks.spawn(publish_alerts(
        Arc::clone(&monitor),
        history.as_ref().map(|h| Arc::clone(&h.store)),
        usage.clone(),
        notes.clone(),
        shutdown.clone(),
    ));
    tasks.spawn(publish_samples(
        Arc::clone(&monitor),
        notes,
        shutdown.clone(),
    ));
    tasks.spawn(read_app_info(Arc::clone(&monitor), shutdown.clone()));
    if let Some(drops) = drops {
        tasks.spawn(watch_drops(drops, shutdown.clone()));
    }
    if let Some((p, attempts)) = prompter {
        tasks.spawn(p.run(attempts, shutdown.clone()));
    }
    tasks.spawn(resolve_names(Arc::clone(&monitor), shutdown.clone()));
    if let (Some(h), Some(u)) = (&history, &usage) {
        tasks.spawn(save_history(
            Arc::clone(&monitor),
            Arc::clone(&h.store),
            Arc::clone(u),
            shutdown.clone(),
        ));
        tasks.spawn(Arc::clone(u).run(shutdown.clone()));
    }
    if let Some(s) = &security {
        tasks.spawn(Arc::clone(s).run(shutdown.clone()));
    }
    if let Some(r) = &reputation {
        tasks.spawn(Arc::clone(r).run(shutdown.clone()));
    }
    if let Some(c) = &cleanup {
        tasks.spawn(Arc::clone(c).run(shutdown.clone()));
    }
    if let Some(d) = &dns {
        tasks.spawn(Arc::clone(d).run(shutdown.clone()));
    }
    if let Some(a) = &autoprofile {
        tasks.spawn(Arc::clone(a).run(shutdown.clone()));
    }
    // Outside changes are seen as Windows Firewall logs them; the 60 s check
    // remains the backstop. Kept until shutdown.
    let _firewall_events = enforcer.as_ref().and_then(watch_firewall_events);
    if let Some(e) = enforcer {
        tasks.spawn(e.run(shutdown.clone()));
    }
    tracing::info!(pipe = %options.pipe_name, "win4tress service running");

    // A server error (e.g. the pipe name is taken) also ends the run.
    let served = tokio::select! {
        _ = shutdown.cancelled() => Ok(()),
        result = server => result.context("IPC server task")?.context("IPC server"),
    };
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    match Arc::try_unwrap(collector) {
        Ok(collector) => collector
            .into_inner()
            .unwrap_or_else(|p| p.into_inner())
            .stop()?,
        // Unreachable once the tasks have ended; dropping stops the session anyway.
        Err(_) => tracing::warn!("collector still referenced at shutdown"),
    }
    tracing::info!("win4tress service stopped");
    served
}

/// win4tress's own programs, from this service's folder (SPEC §7.4 "Protected
/// components").
fn own_programs() -> Vec<(String, String)> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    [
        ("win4tress service", "win4tress-svc.exe"),
        ("win4tress app", "win4tress-ui.exe"),
        ("win4tress command line", "win4tress.exe"),
        ("win4tress DNS resolver", "win4tress-dns.exe"),
    ]
    .into_iter()
    .map(|(label, file)| (label.to_string(), dir.join(file)))
    .filter(|(_, path)| path.exists())
    .map(|(label, path)| (label, path.display().to_string()))
    .collect()
}

/// WFP drops → what dropped them → the monitor.
struct DropRecorder {
    monitor: Arc<Mutex<Monitor>>,
    filters: Mutex<w4_enforce::wfp::Filters>,
    prompter: Option<Arc<Prompter>>,
}

impl w4_etw::drops::DropSink for DropRecorder {
    fn on_drop(&self, drop: w4_etw::drops::WfpDrop) {
        let Some(remote) = drop.remote else { return };
        if drop.app.is_empty() {
            return;
        }
        // Looked up at once: Windows rebuilds filters when rules change (spike 0.4).
        let by = lock(&self.filters).lookup(drop.filter_id);
        // No rule allowed an outgoing attempt: in Ask to Connect, a question.
        let ask = !drop.inbound && by.kind == BlockedByKind::WindowsDefault;
        let app = lock(&self.monitor).record_block(
            drop.ts_ms,
            &drop.app,
            drop.pid,
            drop.inbound,
            remote,
            by,
            now_unix_ms(),
        );
        if let (true, Some(app), Some(p)) = (ask, app, &self.prompter) {
            p.offer(Attempt {
                app,
                remote,
                ts_ms: drop.ts_ms,
            });
        }
    }
}

fn start_drops(
    session: &str,
    monitor: &Arc<Mutex<Monitor>>,
    prompter: Option<Arc<Prompter>>,
) -> Option<w4_etw::drops::DropWatcher> {
    let filters = match w4_enforce::wfp::Filters::open() {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("\"Blocked by\" unavailable: {e}");
            return None;
        }
    };
    let sink = Arc::new(DropRecorder {
        monitor: Arc::clone(monitor),
        filters: Mutex::new(filters),
        prompter,
    });
    match w4_etw::drops::DropWatcher::start(session, sink) {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::warn!("\"Blocked by\" unavailable: {e}");
            None
        }
    }
}

/// Restarts the drop session if something outside stopped it.
async fn watch_drops(mut drops: w4_etw::drops::DropWatcher, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(WATCHDOG_EVERY) => {}
        }
        match drops.ensure_running() {
            Ok(true) => tracing::warn!("WFP drop session was stopped from outside; restarted it"),
            Ok(false) => {}
            Err(e) => tracing::error!("WFP drop session stopped and can't be restarted: {e}"),
        }
    }
}

fn watch_firewall_events(enforcer: &Arc<Enforcer>) -> Option<w4_enforce::events::Watcher> {
    let own_exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let group = enforcer.group().to_string();
    let target = Arc::clone(enforcer);
    let watcher = w4_enforce::events::watch(move |event| {
        // Ours changed from outside (put back), or another program's rule
        // (what Windows allows or blocks for apps): check soon either way.
        if event.concerns(&group, &own_exe) || event.about_other_rules(&group) {
            tracing::debug!(id = event.id, rule = ?event.rule_name, by = ?event.application, "Windows Firewall changed");
            target.nudge();
        }
    });
    match watcher {
        Ok(w) => {
            enforcer.set_live_events(true);
            Some(w)
        }
        Err(e) => {
            tracing::warn!("outside firewall changes will be found by the 60 s check only: {e}");
            None
        }
    }
}

/// Restarts the ETW session if something outside stopped it (another tool reusing
/// the name, `logman stop`, a crash in a previous run's cleanup).
async fn watch_collector(
    collector: Arc<Mutex<Collector>>,
    monitor: Arc<Mutex<Monitor>>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(WATCHDOG_EVERY) => {}
        }
        let collector = Arc::clone(&collector);
        match tokio::task::spawn_blocking(move || lock(&collector).ensure_running()).await {
            Ok(Ok(true)) => {
                tracing::warn!("ETW session was stopped from outside; restarted it");
                lock(&monitor).raise(now_unix_ms(), None, AlertBody::MonitoringInterrupted);
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => tracing::error!("ETW session stopped and can't be restarted: {e}"),
            Err(e) => tracing::warn!("collector watchdog failed: {e}"),
        }
    }
}

/// Stores new alerts and announces them to subscribers. Without history they are
/// only logged: the Alerts view reads from the database.
async fn publish_alerts(
    monitor: Arc<Mutex<Monitor>>,
    store: Option<Arc<Mutex<Store>>>,
    usage: Option<Arc<Usage>>,
    notes: broadcast::Sender<Notification>,
    shutdown: CancellationToken,
) {
    loop {
        // On shutdown, one last pass stores what's pending.
        let stopping = tokio::select! {
            _ = shutdown.cancelled() => true,
            _ = tokio::time::sleep(ALERTS_EVERY) => false,
        };
        let mut pending = lock(&monitor).take_alerts();
        let settings = usage.as_ref().map(|u| u.settings()).unwrap_or_default();
        pending = gate(pending, &settings);
        if !pending.is_empty() {
            for a in &pending {
                tracing::info!(app = ?a.app, alert = ?a.body, "alert");
            }
            if settings.event_log {
                to_event_log(&pending);
            }
            if let Some(store) = &store {
                store_and_announce(&monitor, store, &notes, pending).await;
            }
        }
        if stopping {
            break;
        }
    }
}

/// The user's monitor settings (SPEC §11): alerts of kinds switched off are
/// dropped, and a chosen severity replaces the alert's own.
fn gate(pending: Vec<PendingAlert>, settings: &Settings) -> Vec<PendingAlert> {
    pending
        .into_iter()
        .filter(|a| settings.monitor_enabled(a.body.kind()))
        .map(|mut a| {
            if let Some(s) = settings.severity_for(a.body.kind()) {
                a.severity = Some(s);
            }
            a
        })
        .collect()
}

/// Copies alerts to the Application log, source "win4tress", one event id per
/// kind (registered on first use).
fn to_event_log(alerts: &[PendingAlert]) {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        if let Err(e) = w4_sys::eventlog::register() {
            tracing::warn!("Event Log source not registered; events show without text: {e}");
        }
    });
    for a in alerts {
        let level = match a.severity.unwrap_or(a.body.severity()) {
            Severity::Info => w4_sys::eventlog::Level::Information,
            Severity::Warning => w4_sys::eventlog::Level::Warning,
            Severity::Critical => w4_sys::eventlog::Level::Error,
        };
        let kind = a.body.kind();
        let text = a.body.text(a.app_name.as_deref());
        if let Err(e) = w4_sys::eventlog::report(level, MonitorInfo::event_id(kind), &text) {
            tracing::warn!("writing to the Event Log failed: {e}");
            break;
        }
    }
}

async fn store_and_announce(
    monitor: &Arc<Mutex<Monitor>>,
    store: &Arc<Mutex<Store>>,
    notes: &broadcast::Sender<Notification>,
    pending: Vec<PendingAlert>,
) {
    let store = Arc::clone(store);
    let saved = tokio::task::spawn_blocking(move || {
        let mut s = lock(&store);
        let ids = s.insert_alerts(&pending)?;
        let unread = s.unread_alerts()?;
        Ok::<_, w4_store::Error>((ids, pending, unread))
    })
    .await;
    let (ids, pending, unread) = match saved {
        Ok(Ok(saved)) => saved,
        Ok(Err(e)) => return tracing::warn!("saving alerts failed: {e}"),
        Err(e) => return tracing::warn!("alerts task failed: {e}"),
    };
    if notes.receiver_count() == 0 {
        return;
    }
    let alerts = {
        let m = lock(monitor);
        ids.into_iter()
            .zip(pending)
            .map(|(id, a)| {
                let stored = w4_store::StoredAlert {
                    id,
                    ts_ms: a.ts_ms,
                    severity: a.severity.unwrap_or(a.body.severity()),
                    app: a.app,
                    app_name: a.app_name,
                    body: a.body,
                    read: false,
                };
                handler::alert(stored, &m)
            })
            .collect()
    };
    let params = serde_json::to_value(AlertsNotification { alerts, unread }).unwrap_or_default();
    let _ = notes.send(Notification::new(notification::ALERTS, params));
}

async fn publish_samples(
    monitor: Arc<Mutex<Monitor>>,
    notes: broadcast::Sender<Notification>,
    shutdown: CancellationToken,
) {
    let mut tick = tokio::time::interval(PUBLISH_EVERY);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
        let now = now_unix_ms();
        let samples = {
            let mut m = lock(&monitor);
            m.evict(now);
            m.take_new_samples(now)
        };
        if samples.is_empty() || notes.receiver_count() == 0 {
            continue;
        }
        let params = serde_json::to_value(SamplesNotification { samples }).unwrap_or_default();
        let _ = notes.send(Notification::new(notification::SAMPLES, params));
    }
}

/// A file's trust details, kept while its size and modified time stay the same:
/// every svchost instance is the same file, and hashing it once is enough.
type TrustCache = HashMap<String, ((u64, Option<std::time::SystemTime>), Trust)>;

fn trust_of(path: &str, cache: &mut TrustCache) -> Trust {
    let stamp = std::fs::metadata(path)
        .map(|m| (m.len(), m.modified().ok()))
        .unwrap_or_default();
    let key = path.to_lowercase();
    if let Some((s, t)) = cache.get(&key)
        && *s == stamp
    {
        return t.clone();
    }
    let trust = w4_sys::trust::read(path);
    cache.insert(key, (stamp, trust.clone()));
    trust
}

/// Reads version info and trust details (signature, signer, hash, download
/// origin) off the hot path; file I/O never runs under the lock.
async fn read_app_info(monitor: Arc<Mutex<Monitor>>, shutdown: CancellationToken) {
    let cache = Arc::new(Mutex::new(TrustCache::new()));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(APP_INFO_EVERY) => {}
        }
        let pending = lock(&monitor).take_pending_info();
        if pending.is_empty() {
            continue;
        }
        let cache = Arc::clone(&cache);
        let Ok(infos) = tokio::task::spawn_blocking(move || {
            let mut cache = lock(&cache);
            pending
                .into_iter()
                .map(|(id, path)| {
                    let info = w4_sys::version::file_info(&path);
                    (id, info, trust_of(&path, &mut cache))
                })
                .collect::<Vec<_>>()
        })
        .await
        else {
            continue;
        };
        let mut m = lock(&monitor);
        for (id, info, trust) in infos {
            // No version resource (or the file is busy): keep what's known.
            let info = match info {
                Some(info) => info,
                None => match m.app_record(id) {
                    Some(r) => w4_sys::version::FileInfo {
                        description: r.description,
                        company: r.company,
                        version: r.version,
                        ..Default::default()
                    },
                    None => continue,
                },
            };
            m.set_app_info(
                id,
                w4_monitor::AppInfo {
                    description: info.description,
                    company: info.company,
                    version: info.version,
                    trust,
                },
                now_unix_ms(),
            );
        }
    }
}

/// Reverse DNS for addresses no app looked up (SPEC §8.3). Lookups block, so
/// they run on blocking threads, a batch at a time.
async fn resolve_names(monitor: Arc<Mutex<Monitor>>, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(REVERSE_EVERY) => {}
        }
        let ips = lock(&monitor).take_reverse_lookups(REVERSE_BATCH);
        let mut lookups = JoinSet::new();
        for ip in ips {
            lookups.spawn_blocking(move || (ip, w4_sys::net::reverse_lookup(ip)));
        }
        loop {
            let next = tokio::select! {
                _ = shutdown.cancelled() => return,
                next = lookups.join_next() => next,
            };
            match next {
                Some(Ok((ip, Some(name)))) => lock(&monitor).set_reverse_name(ip, &name),
                Some(_) => {}
                None => break,
            }
        }
    }
}

/// Writes closed minutes, changed apps and DNS queries to history, and prunes it.
async fn save_history(
    monitor: Arc<Mutex<Monitor>>,
    store: Arc<Mutex<Store>>,
    usage: Arc<Usage>,
    shutdown: CancellationToken,
) {
    let mut last_prune: Option<Instant> = None;
    loop {
        let stopping = tokio::select! {
            _ = shutdown.cancelled() => true,
            _ = tokio::time::sleep(SAVE_EVERY) => false,
        };
        let now = now_unix_ms();
        // On shutdown also hand over the minute in progress; the next run adds to it.
        let close_until = if stopping { now + 61_000 } else { now };
        let (apps, mut minutes, mut dns, mut blocks) = {
            let mut m = lock(&monitor);
            (
                m.take_dirty_apps(),
                m.take_closed_minutes(close_until),
                m.take_unsaved_dns(),
                m.take_unsaved_blocks(),
            )
        };
        // Incognito (SPEC §8.4): no traffic, lookups or blocked attempts in
        // history, for every app or the chosen ones.
        let settings = usage.settings();
        if settings.incognito {
            minutes.clear();
            dns.clear();
            blocks.clear();
        } else if !settings.incognito_apps.is_empty() {
            let hidden = &settings.incognito_apps;
            minutes.retain(|m| !hidden.contains(&m.row.app));
            dns.retain(|d| !hidden.contains(&d.app));
            blocks.retain(|b| !hidden.contains(&b.key.app));
        }
        let prune = last_prune.is_none_or(|t| t.elapsed() > PRUNE_EVERY);
        let store = Arc::clone(&store);
        let context = usage.save_context();
        let saved = tokio::task::spawn_blocking(move || {
            let mut s = lock(&store);
            s.set_save_context(context);
            s.save(&apps, &minutes, &dns)?;
            s.save_blocks(&blocks)?;
            if prune {
                s.prune(now)?;
            }
            Ok::<_, w4_store::Error>(minutes.len())
        })
        .await;
        match saved {
            Ok(Ok(rows)) => {
                tracing::debug!(rows, "history saved");
                if prune {
                    last_prune = Some(Instant::now());
                }
            }
            Ok(Err(e)) => tracing::warn!("saving history failed: {e}"),
            Err(e) => tracing::warn!("history task failed: {e}"),
        }
        if stopping {
            break;
        }
    }
}
