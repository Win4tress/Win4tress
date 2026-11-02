//! Enforcement (SPEC §4.4, §7.8): keeps our Windows Firewall rule group equal to
//! the rules and mode in history. Runs at start, right after every change, soon
//! after Windows Firewall logs an outside change, and every 60 s. Anything else
//! that changed our rules is put back and reported; the user can keep it instead.
//! Temporary rules end here too (SPEC §7.2).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use w4_core::ask::BaselineEntry;
use w4_core::firewall::{
    Action, Direction, Environment, Expiry, FirewallState, Mode, ProfileState, RuleId, RuleRecord,
    Scope,
};
use w4_core::time::now_unix_ms;
use w4_enforce::address::literal;
use w4_enforce::{
    ActualRule, AppTarget, Change, EnforcementBackend, OtherRules, WindowsRule, default_blocks,
    expand_env, is_rename_only, package_family, package_sid, plan, project, verdict,
};
use w4_ipc::api::{
    AlertBody, AppVerdicts, FirewallStatus, OutsideChange, OutsideKind, VerdictsResult,
    WindowsRuleInfo,
};
use w4_monitor::{AppRecord, Monitor, SYSTEM_APP};
use w4_store::Store;

/// How often the group is compared with the stored rules when nothing changes.
const CHECK_EVERY: Duration = Duration::from_secs(60);
/// After Windows Firewall logs a change, wait this long so a burst (a script
/// changing several rules) is handled in one pass and one alert.
const SETTLE: Duration = Duration::from_millis(500);
/// While host rules exist, how often new DNS answers are looked for: their
/// addresses go into the rules (SPEC §7.3, "updates are batched").
const HOST_REFRESH: Duration = Duration::from_secs(5);
/// While a rule lasts until its app quits, how often that's looked for.
const QUIT_CHECK: Duration = Duration::from_secs(5);

pub struct Enforcer {
    backend: Arc<dyn EnforcementBackend>,
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    /// win4tress's own programs, (label, path): always allowed out, never
    /// blockable from the UI.
    protected: Vec<(String, String)>,
    /// Windows services Ask to Connect always allows out (SPEC §7.4).
    baseline: Vec<BaselineEntry>,
    state: Mutex<State>,
    /// One pass at a time: the run loop's, or a caller's waiting for the result.
    passes: Mutex<()>,
    wake: Notify,
    nudge: Notify,
    live_events: AtomicBool,
}

#[derive(Default)]
struct State {
    /// The rules the last clean pass left Windows Firewall matching: what
    /// differs from them was changed by something else. `None` before the
    /// first pass, while monitoring only, and after a pass that failed (then
    /// nothing is reported until a clean pass: the difference may be ours).
    written: Option<Vec<WindowsRule>>,
    /// A pass has run in this run of the service.
    checked: bool,
    /// Ask to Connect: win4tress has blocked the outbound default on every
    /// profile in this run, so a profile open again was changed outside.
    outbound_blocked: bool,
    /// The mode the group was last switched on or off for, in this run.
    group_mode: Option<Mode>,
    firewall: Option<FirewallState>,
    /// Windows Firewall's own rules for apps, as of the last pass (re-read
    /// each pass: all of them take ~25 ms, spike 0.2).
    others: Arc<OtherRules>,
    environment: Environment,
    /// When the active Block All ends, if it has an end.
    block_all_until: Option<i64>,
    /// When the next temporary rule's time is up.
    next_expiry: Option<i64>,
    /// Rules that last until their app quits: (rule, the app's program, lower-case).
    until_quit: Vec<(RuleId, String)>,
    /// Some stored rule names hosts; and the DNS answers seen when last resolved.
    host_rules: bool,
    dns_seen: u64,
    rules: usize,
    windows_rules: usize,
    in_sync: bool,
    last_check_ms: Option<i64>,
    last_error: Option<String>,
    repairs: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// What a Windows Firewall rule can match for this app, if anything.
pub fn target_of(app: &AppRecord) -> Option<AppTarget> {
    if app.path == SYSTEM_APP {
        return Some(AppTarget::System);
    }
    if let Some(family) = app.package.as_deref().and_then(package_family) {
        return Some(AppTarget::Package { family });
    }
    if !app.path.contains('\\') {
        return None; // "Unknown": no executable to name
    }
    match &app.service {
        Some(services) => Some(AppTarget::Services {
            program: app.path.clone(),
            services: services
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }),
        None => Some(AppTarget::Program(app.path.clone())),
    }
}

impl Enforcer {
    pub fn new(
        backend: Arc<dyn EnforcementBackend>,
        store: Arc<Mutex<Store>>,
        monitor: Arc<Mutex<Monitor>>,
        protected: Vec<(String, String)>,
    ) -> Arc<Self> {
        Arc::new(Enforcer {
            backend,
            store,
            monitor,
            protected,
            baseline: w4_core::ask::baseline(),
            state: Mutex::new(State::default()),
            passes: Mutex::new(()),
            wake: Notify::new(),
            nudge: Notify::new(),
            live_events: AtomicBool::new(false),
        })
    }

    pub fn group(&self) -> &str {
        self.backend.group()
    }

    /// Call after changing rules or the mode in history: they're applied right away.
    pub fn changed(&self) {
        self.wake.notify_one();
    }

    /// Windows Firewall logged a change that may concern us: check soon.
    pub fn nudge(&self) {
        self.nudge.notify_one();
    }

    /// Whether Windows Firewall's event log is being watched (for the status).
    pub fn set_live_events(&self, on: bool) {
        self.live_events.store(on, Ordering::Relaxed);
    }

    /// Runs a pass now and returns its result, for callers that report when
    /// Windows Firewall matches (reset). Blocking.
    pub fn sync(&self) -> Result<(), String> {
        self.pass()
    }

    /// Whether each app is allowed or blocked, per direction, and by what. From
    /// the last pass's view of Windows Firewall and the stored rules now.
    pub fn verdicts(&self, apps: &[AppRecord]) -> Result<VerdictsResult, String> {
        let now = now_unix_ms();
        let (rules, mode, block_all) = {
            let store = lock(&self.store);
            let rules = store.rules().map_err(|e| format!("reading rules: {e}"))?;
            let block_all = store
                .block_all()
                .ok()
                .flatten()
                .is_some_and(|b| b.active(now));
            (rules, store.firewall_mode().unwrap_or_default(), block_all)
        };
        let (state, others) = {
            let s = lock(&self.state);
            (s.firewall.clone(), Arc::clone(&s.others))
        };
        let Some(state) = state else {
            return Ok(VerdictsResult::default());
        };
        let ours = |app: u32, direction: Direction| {
            rules
                .iter()
                .find(|r| r.app == app && r.direction == direction && r.scope == Scope::Any)
        };
        let verdicts = apps
            .iter()
            .filter_map(|app| {
                let target = target_of(app)?;
                let theirs = others.for_app(&target, &app.path, sid_of(&target).as_deref());
                let v = |d| verdict(d, ours(app.id, d), &theirs, &state, mode, block_all);
                Some(AppVerdicts {
                    app: app.id,
                    inbound: v(Direction::In),
                    outbound: v(Direction::Out),
                    protected: self.is_protected(&app.path),
                })
            })
            .collect();
        Ok(VerdictsResult {
            apps: verdicts,
            inbound_default_blocks: default_blocks(&state, true),
            outbound_default_blocks: default_blocks(&state, false),
        })
    }

    /// Windows Firewall's own rules that name this app, as of the last pass.
    pub fn app_rules(&self, app: &AppRecord) -> Vec<WindowsRuleInfo> {
        let (state, others) = {
            let s = lock(&self.state);
            (
                s.firewall.clone().unwrap_or_default(),
                Arc::clone(&s.others),
            )
        };
        let Some(target) = target_of(app) else {
            return Vec::new();
        };
        let active = profile_mask(&state);
        others
            .for_app(&target, &app.path, sid_of(&target).as_deref())
            .into_iter()
            .map(|r| WindowsRuleInfo {
                name: r.name.clone(),
                direction: if r.inbound {
                    Direction::In
                } else {
                    Direction::Out
                },
                action: if r.block {
                    Action::Block
                } else {
                    Action::Allow
                },
                active: r.profiles & active != 0,
                profiles: profile_names(r.profiles),
            })
            .collect()
    }

    /// One of win4tress's own programs (SPEC §7.4 "Protected components").
    pub fn is_protected(&self, path: &str) -> bool {
        self.protected
            .iter()
            .any(|(_, p)| p.eq_ignore_ascii_case(path))
    }

    /// Why win4tress can only monitor, if it can't enforce (SPEC §7.7).
    pub fn monitoring_only(&self) -> Option<String> {
        lock(&self.state).environment.monitoring_only()
    }

    /// Puts back the profile settings saved before win4tress first changed
    /// them, if any were. Blocking.
    pub fn restore_profiles(&self, who: &str) -> Result<bool, String> {
        let saved = lock(&self.store)
            .profile_originals()
            .map_err(|e| format!("reading saved profile settings: {e}"))?;
        let Some(saved) = saved else {
            return Ok(false);
        };
        for p in &saved {
            self.backend
                .set_defaults(&p.name, p.inbound_default_block, p.outbound_default_block)
                .map_err(|e| format!("restoring the {} profile: {e}", p.name))?;
        }
        lock(&self.store)
            .clear_profile_originals(now_unix_ms(), who)
            .map_err(|e| format!("{e}"))?;
        tracing::info!("original firewall profile settings restored");
        Ok(true)
    }

    /// Ask to Connect: blocks outgoing connections that no rule allows, on
    /// every profile, saving the settings to put back first (only the first
    /// time). Returns the profiles something else had opened again since
    /// win4tress blocked them in this run, and whether any profile changed.
    fn block_outbound(
        &self,
        firewall: Option<&FirewallState>,
        now_ms: i64,
    ) -> Result<(Vec<String>, bool), String> {
        let Some(fw) = firewall else {
            return Ok((Vec::new(), false));
        };
        let open: Vec<&ProfileState> = fw
            .profiles
            .iter()
            .filter(|p| !p.outbound_default_block)
            .collect();
        let was_blocked = lock(&self.state).outbound_blocked;
        if !open.is_empty() {
            lock(&self.store)
                .save_profile_originals(&fw.profiles, now_ms)
                .map_err(|e| format!("saving the profile settings: {e}"))?;
            for p in &open {
                self.backend
                    .set_defaults(&p.name, p.inbound_default_block, true)
                    .map_err(|e| {
                        format!("blocking the {} profile's outbound default: {e}", p.name)
                    })?;
            }
            let names: Vec<&str> = open.iter().map(|p| p.name.as_str()).collect();
            tracing::info!(profiles = ?names, "Ask to Connect: outgoing connections without a rule are blocked");
        }
        lock(&self.state).outbound_blocked = true;
        let reopened = if was_blocked {
            open.iter().map(|p| p.name.clone()).collect()
        } else {
            Vec::new()
        };
        Ok((reopened, !open.is_empty()))
    }

    /// Turns Windows Firewall on for `profile`, or every profile where it's off.
    /// Returns the profiles turned on. Blocking.
    pub fn turn_on(&self, profile: Option<&str>) -> Result<Vec<String>, String> {
        let state = self
            .backend
            .state()
            .map_err(|e| format!("reading Windows Firewall: {e}"))?;
        let mut done = Vec::new();
        for p in state.profiles.iter().filter(|p| !p.firewall_on) {
            if profile.is_none_or(|want| want == p.name) {
                self.backend
                    .turn_on(&p.name)
                    .map_err(|e| format!("turning on the {} profile: {e}", p.name))?;
                done.push(p.name.clone());
            }
        }
        self.nudge();
        Ok(done)
    }

    pub fn status(&self) -> FirewallStatus {
        // From the store, so a change shows at once.
        let (mode, block_all, require_elevation) = {
            let store = lock(&self.store);
            (
                store.firewall_mode().unwrap_or_default(),
                store
                    .block_all()
                    .ok()
                    .flatten()
                    .filter(|b| b.active(now_unix_ms())),
                store.require_elevation().unwrap_or(false),
            )
        };
        let s = lock(&self.state);
        FirewallStatus {
            mode,
            block_all,
            environment: s.environment.clone(),
            monitoring_only: s.environment.monitoring_only(),
            require_elevation,
            live_events: self.live_events.load(Ordering::Relaxed),
            state: s.firewall.clone(),
            group: self.backend.group().to_string(),
            rules: s.rules,
            windows_rules: s.windows_rules,
            in_sync: s.in_sync,
            last_check_ms: s.last_check_ms,
            last_error: s.last_error.clone(),
            repairs: s.repairs,
        }
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            match tokio::task::spawn_blocking(move || this.pass()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("firewall check failed: {e}");
                    lock(&self.state).last_error = Some(e);
                }
                Err(e) => tracing::warn!("firewall task failed: {e}"),
            }
            // The next check: in a minute, when Block All or a temporary rule
            // runs out, or sooner for an event, a change, new DNS answers for
            // host rules, or an app quitting that a rule lasts for.
            let (ends, host_rules, quits) = {
                let s = lock(&self.state);
                let ends = [s.block_all_until, s.next_expiry]
                    .into_iter()
                    .flatten()
                    .min();
                (ends, s.host_rules, !s.until_quit.is_empty())
            };
            let mut wait = CHECK_EVERY;
            if let Some(until) = ends {
                let left = Duration::from_millis((until - now_unix_ms()).max(0) as u64);
                wait = wait.min(left + Duration::from_millis(50));
            }
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                let tick = match (host_rules, quits) {
                    (true, _) => HOST_REFRESH.min(left),
                    (false, true) => QUIT_CHECK.min(left),
                    (false, false) => wait,
                };
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.wake.notified() => break,
                    _ = self.nudge.notified() => {
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            _ = tokio::time::sleep(SETTLE) => {}
                        }
                        break;
                    }
                    _ = tokio::time::sleep(tick) => {
                        if tokio::time::Instant::now() >= deadline
                            || self.new_dns_answers()
                            || (quits && self.an_app_quit())
                        {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// DNS answers arrived since host rules were last resolved.
    fn new_dns_answers(&self) -> bool {
        let seen = lock(&self.state).dns_seen;
        lock(&self.monitor).dns_generation() != seen
    }

    /// An app that a rule lasts for has no process left. Blocking: lists processes.
    fn an_app_quit(&self) -> bool {
        let programs: Vec<String> = lock(&self.state)
            .until_quit
            .iter()
            .map(|(_, p)| p.clone())
            .collect();
        let running = w4_sys::process::running_paths();
        programs.iter().any(|p| !running.contains(p))
    }

    /// Ends the temporary rules that are over (SPEC §7.2): the time is up,
    /// Windows restarted, or the app quit. Our own change, audited as such.
    /// Returns when the next one's time is up and the rules lasting until
    /// their app quits.
    fn expire(&self, rules: &[RuleRecord], now: i64) -> (Option<i64>, Vec<(RuleId, String)>) {
        let temporary: Vec<&RuleRecord> = rules.iter().filter(|r| r.expires.is_some()).collect();
        if temporary.is_empty() {
            return (None, Vec::new());
        }
        let boot = w4_sys::time::boot_ms();
        let programs: BTreeMap<u32, String> = {
            let monitor = lock(&self.monitor);
            temporary
                .iter()
                .filter(|r| r.expires == Some(Expiry::AppQuits))
                .filter_map(|r| Some((r.app, monitor.app_record(r.app)?.path.to_lowercase())))
                .collect()
        };
        let running: HashSet<String> = if programs.is_empty() {
            HashSet::new()
        } else {
            w4_sys::process::running_paths()
        };
        let mut next = None;
        let mut until_quit = Vec::new();
        let mut store = lock(&self.store);
        for r in temporary {
            let Some(expiry) = r.expires else { continue };
            let why = match expiry {
                Expiry::AppQuits => match programs.get(&r.app) {
                    Some(p) if running.contains(p) => {
                        until_quit.push((r.id, p.clone()));
                        None
                    }
                    _ => Some("app quit"),
                },
                Expiry::At { ms } if !expiry.over(now, boot) => {
                    next = Some(next.map_or(ms, |n: i64| n.min(ms)));
                    None
                }
                Expiry::At { .. } => Some("time up"),
                Expiry::Restart { .. } => expiry.over(now, boot).then_some("restart"),
            };
            if let Some(why) = why {
                match store.expire_rule(r.id, now, &format!("win4tress ({why})")) {
                    Ok(_) => tracing::info!(rule = r.id, app = r.app, why, "temporary rule ended"),
                    Err(e) => tracing::warn!(rule = r.id, "ending a temporary rule: {e}"),
                }
            }
        }
        (next, until_quit)
    }

    /// One comparison of stored rules with our group, and the fixes. Blocking.
    fn pass(&self) -> Result<(), String> {
        let _one_at_a_time = lock(&self.passes);
        let now = now_unix_ms();
        // Block All that has run out ends here: our own change, not an outside one.
        {
            let mut store = lock(&self.store);
            if let Ok(Some(b)) = store.block_all()
                && !b.active(now)
            {
                store
                    .set_block_all(None, now, "win4tress (time up)")
                    .map_err(|e| format!("ending Block All: {e}"))?;
                tracing::info!("Block All ended: its time was up");
            }
        }
        let stored = lock(&self.store)
            .rules()
            .map_err(|e| format!("reading rules: {e}"))?;
        let (next_expiry, until_quit) = self.expire(&stored, now);
        {
            let mut s = lock(&self.state);
            s.next_expiry = next_expiry;
            s.until_quit = until_quit;
        }
        let (rules, mode, block_all) = {
            let store = lock(&self.store);
            let rules = store.rules().map_err(|e| format!("reading rules: {e}"))?;
            let mode = store
                .firewall_mode()
                .map_err(|e| format!("reading the mode: {e}"))?;
            let block_all = store
                .block_all()
                .map_err(|e| format!("reading Block All: {e}"))?;
            (rules, mode, block_all)
        };

        // Windows Firewall and what else is in charge (SPEC §7.7). If win4tress
        // can only monitor, nothing is changed: our rules wait as they are.
        let firewall = self.backend.state().ok();
        let active: Vec<&str> = firewall
            .as_ref()
            .map(|f| {
                f.profiles
                    .iter()
                    .filter(|p| p.active)
                    .map(|p| p.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let environment = match w4_enforce::environment::detect(&active) {
            Ok(env) => env,
            Err(e) => {
                tracing::debug!("checking the firewall environment: {e}");
                lock(&self.state).environment.clone()
            }
        };
        let others = match self.backend.others() {
            Ok(rules) => Some(Arc::new(OtherRules::new(rules, expand_env))),
            Err(e) => {
                tracing::debug!("reading Windows Firewall's other rules: {e}");
                None
            }
        };
        if let Some(why) = environment.monitoring_only() {
            let mut s = lock(&self.state);
            if s.environment.monitoring_only().is_none() {
                tracing::warn!("monitoring only: {why}");
            }
            s.environment = environment;
            s.firewall = firewall;
            if let Some(others) = others {
                s.others = others;
            }
            s.rules = rules.len();
            s.last_check_ms = Some(now);
            s.block_all_until = None;
            // Applied again from scratch once enforcement is possible.
            s.written = None;
            s.checked = true;
            s.outbound_blocked = false;
            s.group_mode = None;
            return Ok(());
        }

        // Host rules: the addresses each app received for the names, from
        // history (read first: the history and monitor locks never nest).
        let host_rules = rules.iter().any(|r| !r.scope.hosts().is_empty());
        let dns_seen = lock(&self.monitor).dns_generation();
        let mut stored: BTreeMap<(u32, String), Vec<std::net::IpAddr>> = BTreeMap::new();
        if host_rules {
            let store = lock(&self.store);
            for r in &rules {
                for h in r.scope.hosts() {
                    if literal(h).is_none() {
                        let ips = store.dns_addresses(r.app, h).unwrap_or_default();
                        stored.insert((r.app, h.clone()), ips);
                    }
                }
            }
        }

        // Rules whose app can't be resolved are left as they are in Windows
        // Firewall rather than removed.
        let mut keep_as_is: BTreeSet<RuleId> = BTreeSet::new();
        let mut desired: Vec<WindowsRule> = Vec::new();
        let mut app_names: BTreeMap<RuleId, String> = BTreeMap::new();
        {
            let monitor = lock(&self.monitor);
            for r in &rules {
                let name = monitor.app_ref(r.app).name;
                let addresses = |host: &str| -> Vec<String> {
                    if let Some(l) = literal(host) {
                        return vec![l];
                    }
                    let mut ips = monitor.dns_addresses(r.app, host);
                    ips.extend(stored.get(&(r.app, host.to_string())).into_iter().flatten());
                    ips.sort_unstable();
                    ips.dedup();
                    ips.into_iter().map(|ip| ip.to_string()).collect()
                };
                let projected = monitor.app_record(r.app).and_then(|app| {
                    let target = target_of(&app)?;
                    project(r, &name, &target, package_sid, &addresses)
                });
                app_names.insert(r.id, name);
                match projected {
                    Some(rules) => desired.extend(rules),
                    None => {
                        tracing::warn!(
                            rule = r.id,
                            app = r.app,
                            "rule's app can't be targeted; leaving it as it is"
                        );
                        keep_as_is.insert(r.id);
                    }
                }
            }
        }
        desired.extend(w4_enforce::model::protected(&self.protected));
        // Ask to Connect: Windows' own services keep working (SPEC §7.4).
        let ask = mode == Mode::AskToConnect && environment.outbound_default_forced_by.is_empty();
        if ask {
            desired.extend(w4_enforce::model::baseline(&self.baseline, &expand_env));
        }
        // Off: the rules stay in Windows Firewall, switched off (SPEC §7.1).
        if mode == Mode::Off {
            for d in &mut desired {
                d.enabled = false;
            }
        }
        // Block All applies in every mode: it's an explicit, timed action.
        let block_all = block_all.filter(|b| b.active(now));
        if block_all.is_some() {
            desired.extend(w4_enforce::model::block_all());
        }
        // A mode switch turns the whole group on or off in one call (SPEC §7.2);
        // the plan below then only fixes rules that differ from that. Not at
        // startup: there, a difference may be an outside change to report.
        let switched = lock(&self.state).group_mode.is_some_and(|m| m != mode);
        if switched {
            self.backend
                .set_group_enabled(mode != Mode::Off)
                .map_err(|e| format!("switching the rule group: {e}"))?;
            tracing::info!(mode = mode.as_str(), "firewall mode applied");
        }

        let actual: Vec<_> = self
            .backend
            .list()
            .map_err(|e| format!("reading Windows Firewall: {e}"))?
            .into_iter()
            .filter(|a| a.key().is_none_or(|k| !keep_as_is.contains(&k.rule)))
            .collect();
        let changes = plan(&desired, &actual);

        // Compared before applying: what something else changed.
        let (written, checked) = {
            let s = lock(&self.state);
            (s.written.clone(), s.checked)
        };
        let (base, outside) = outside_changes(
            Written {
                rules: written,
                checked,
                keep_as_is: &keep_as_is,
                group_switched_on: switched.then_some(mode != Mode::Off),
            },
            &desired,
            &changes,
            &actual,
            &rules,
        );
        let outside: Vec<&Change> = outside.iter().collect();

        // The outbound default is blocked once the rules that keep Windows
        // working are in, and put back before they go.
        let mut errors = Vec::new();
        let mut defaults_changed = false;
        if !ask {
            match self.restore_profiles("win4tress (mode)") {
                Ok(restored) => defaults_changed = restored,
                Err(e) => errors.push(e),
            }
            lock(&self.state).outbound_blocked = false;
        }
        for c in &changes {
            if let Err(e) = self.backend.apply(c) {
                errors.push(e.to_string());
            }
        }
        let mut reopened = Vec::new();
        if ask && errors.is_empty() {
            match self.block_outbound(firewall.as_ref(), now) {
                Ok((opened, changed)) => {
                    reopened = opened;
                    defaults_changed |= changed;
                }
                Err(e) => errors.push(e),
            }
        }
        let firewall = if defaults_changed {
            self.backend.state().ok().or(firewall)
        } else {
            firewall
        };

        let mut s = lock(&self.state);
        let tampered = !outside.is_empty() || !reopened.is_empty();
        if tampered {
            s.repairs += 1;
        }
        s.written = errors.is_empty().then(|| desired.clone());
        s.checked = true;
        s.group_mode = Some(mode);
        s.firewall = firewall;
        if let Some(others) = others {
            s.others = others;
        }
        s.environment = environment;
        s.block_all_until = block_all.and_then(|b| b.until_ms);
        s.host_rules = host_rules;
        s.dns_seen = dns_seen;
        s.rules = rules.len();
        s.windows_rules = desired.len();
        s.in_sync = errors.is_empty();
        s.last_check_ms = Some(now);
        s.last_error = errors.first().cloned();
        drop(s);

        if !changes.is_empty() {
            tracing::info!(
                changes = changes.len(),
                errors = errors.len(),
                tampered,
                "firewall rules updated"
            );
        }
        if tampered {
            tracing::warn!(
                changes = outside.len() + reopened.len(),
                "win4tress rules were changed outside win4tress; put back"
            );
            let mut described = describe(&outside, &actual, &base, &rules, &app_names, mode);
            described.extend(reopened.iter().map(|profile| OutsideChange {
                rule: None,
                name: format!(
                    "{} network: outgoing connections without a rule",
                    capitalize(profile)
                ),
                direction: None,
                action: None,
                kind: OutsideKind::Allowed,
                keepable: false,
            }));
            lock(&self.monitor).raise(
                now,
                None,
                AlertBody::FirewallChanged {
                    repaired: (outside.len() + reopened.len()) as u32,
                    changes: described,
                    kept_ms: None,
                },
            );
            let touched: BTreeSet<RuleId> = outside
                .iter()
                .filter_map(|c| match c {
                    Change::Create(r)
                    | Change::Update { rule: r, .. }
                    | Change::Recreate { rule: r, .. } => Some(r.key.rule),
                    Change::Delete { .. } => None,
                })
                .collect();
            let mut store = lock(&self.store);
            for r in rules.iter().filter(|r| touched.contains(&r.id)) {
                let _ = store.audit_repair(r, now);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|first| first.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn sid_of(target: &AppTarget) -> Option<String> {
    match target {
        AppTarget::Package { family } => package_sid(family),
        _ => None,
    }
}

/// The profiles in use as NET_FW_PROFILE2 bits (all if none has a network).
fn profile_mask(state: &FirewallState) -> i32 {
    let bit = |name: &str| match name {
        "domain" => 1,
        "private" => 2,
        "public" => 4,
        _ => 0,
    };
    let mask = state
        .profiles
        .iter()
        .filter(|p| p.active)
        .fold(0, |m, p| m | bit(&p.name));
    if mask == 0 { 7 } else { mask }
}

fn profile_names(bits: i32) -> String {
    if bits & 7 == 7 {
        return "all".into();
    }
    [(1, "domain"), (2, "private"), (4, "public")]
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What win4tress last wrote, for telling outside changes from its own.
struct Written<'a> {
    /// See `State::written`.
    rules: Option<Vec<WindowsRule>>,
    /// A pass has run in this run of the service.
    checked: bool,
    /// Stored rules whose app can't be resolved: left alone, not compared.
    keep_as_is: &'a BTreeSet<RuleId>,
    /// This pass switched the whole group on (true) or off (false) first.
    group_switched_on: Option<bool>,
}

/// The changes something else made to our group, and what they're measured
/// against: differences between Windows Firewall and what win4tress last
/// wrote. Rule and mode changes, host rules' new addresses and Block All
/// ending are win4tress's own: they change `desired`, not the group. At
/// startup nothing was written yet in this run: stored rules that differ from
/// what they project to were changed while the service was stopped.
fn outside_changes(
    written: Written,
    desired: &[WindowsRule],
    changes: &[Change],
    actual: &[ActualRule],
    rules: &[RuleRecord],
) -> (Vec<WindowsRule>, Vec<Change>) {
    let (base, outside) = match written.rules {
        Some(rules) => {
            let base: Vec<WindowsRule> = rules
                .into_iter()
                .filter(|w| !written.keep_as_is.contains(&w.key.rule))
                .map(|mut w| {
                    if let Some(on) = written.group_switched_on {
                        w.enabled = on;
                    }
                    w
                })
                .collect();
            let outside = plan(&base, actual);
            (base, outside)
        }
        None if !written.checked => {
            let outside = changes
                .iter()
                .filter(|c| changed_while_stopped(c, actual, rules))
                .cloned()
                .collect();
            (desired.to_vec(), outside)
        }
        None => (desired.to_vec(), Vec::new()),
    };
    let outside = outside
        .into_iter()
        .filter(|c| !is_rename_only(c, actual))
        .collect();
    (base, outside)
}

/// At startup: whether a change this pass makes undoes something done to a
/// stored rule while the service was stopped. win4tress's built-in rules
/// (Block All, its own programs) come and go as needed, and the addresses of
/// host-name and own-DNS rules follow DNS answers and the shipped DoH list:
/// none of that is an outside change.
fn changed_while_stopped(change: &Change, actual: &[ActualRule], rules: &[RuleRecord]) -> bool {
    let resolved = |id: RuleId| {
        rules.iter().find(|r| r.id == id).is_some_and(|r| {
            r.scope == Scope::Dns || r.scope.hosts().iter().any(|h| literal(h).is_none())
        })
    };
    match change {
        Change::Create(w) | Change::Recreate { rule: w, .. } => w.key.rule >= 0,
        Change::Update { name, rule: w } => {
            w.key.rule >= 0
                && actual.iter().find(|a| &a.name == name).is_none_or(|a| {
                    a.enabled != w.enabled || a.block != w.block || !resolved(w.key.rule)
                })
        }
        Change::Delete { name } => actual
            .iter()
            .find(|a| &a.name == name)
            .and_then(ActualRule::key)
            .is_none_or(|k| k.rule >= 0),
    }
}

/// What the outside changes did, per win4tress rule, for the alert and for
/// "keep". `outside` was planned from `actual` towards `desired`: what
/// win4tress last wrote, or at startup what it wants.
fn describe(
    outside: &[&Change],
    actual: &[ActualRule],
    desired: &[WindowsRule],
    rules: &[RuleRecord],
    app_names: &BTreeMap<RuleId, String>,
    mode: Mode,
) -> Vec<OutsideChange> {
    let ours = |id: RuleId, kind: OutsideKind, keepable: bool| {
        // Block All and protected components aren't stored rules: put back, never kept.
        if id < 0 {
            let name = match id {
                w4_enforce::model::BLOCK_ALL_IN | w4_enforce::model::BLOCK_ALL_OUT => "Block All",
                _ => "win4tress's own programs",
            };
            return OutsideChange {
                rule: None,
                name: name.into(),
                direction: None,
                action: None,
                kind,
                keepable: false,
            };
        }
        let rule = rules.iter().find(|r| r.id == id);
        OutsideChange {
            rule: Some(id),
            name: app_names.get(&id).cloned().unwrap_or_default(),
            direction: rule.map(|r| r.direction),
            action: rule.map(|r| r.action),
            kind,
            keepable,
        }
    };
    let mut out: Vec<OutsideChange> = Vec::new();
    for change in outside {
        match change {
            // Copies of one of our rules are deleted, then the rule is created afresh.
            Change::Create(w) if actual.iter().any(|a| a.key() == Some(w.key)) => {
                out.push(ours(w.key.rule, OutsideKind::Added, false));
            }
            Change::Create(w) => out.push(ours(w.key.rule, OutsideKind::Deleted, true)),
            Change::Update { name, rule: w } => {
                let Some(a) = actual.iter().find(|a| &a.name == name) else {
                    continue;
                };
                if a.enabled != w.enabled {
                    // Turning a rule back on can't be kept while win4tress is off.
                    let (kind, keepable) = if a.enabled {
                        (OutsideKind::Enabled, mode != Mode::Off)
                    } else {
                        (OutsideKind::Disabled, true)
                    };
                    out.push(ours(w.key.rule, kind, keepable));
                }
                if a.block != w.block {
                    let kind = if a.block {
                        OutsideKind::Blocked
                    } else {
                        OutsideKind::Allowed
                    };
                    out.push(ours(w.key.rule, kind, true));
                }
                if a.remote != w.remote {
                    out.push(ours(w.key.rule, OutsideKind::Modified, false));
                }
            }
            Change::Recreate { rule: w, .. } => {
                out.push(ours(w.key.rule, OutsideKind::Modified, false));
            }
            Change::Delete { name } => {
                let key = actual
                    .iter()
                    .find(|a| &a.name == name)
                    .and_then(ActualRule::key);
                match key {
                    // A copy of a rule we want: reported with its Create above.
                    Some(k) if desired.iter().any(|d| d.key == k) => {}
                    _ => out.push(OutsideChange {
                        rule: None,
                        name: name.clone(),
                        direction: None,
                        action: None,
                        kind: OutsideKind::Added,
                        keepable: false,
                    }),
                }
            }
        }
    }
    // A rule with several parts (svchost services) reports each change once.
    let mut seen = BTreeSet::new();
    out.retain(|c| seen.insert((c.rule, c.kind as u8, c.name.clone())));
    out
}

/// What keeping an outside change does to the stored rule.
pub fn keep_edit(kind: OutsideKind) -> Option<KeepEdit> {
    match kind {
        OutsideKind::Deleted => Some(KeepEdit::Delete),
        OutsideKind::Disabled => Some(KeepEdit::Enabled(false)),
        OutsideKind::Enabled => Some(KeepEdit::Enabled(true)),
        OutsideKind::Allowed => Some(KeepEdit::Action(Action::Allow)),
        OutsideKind::Blocked => Some(KeepEdit::Action(Action::Block)),
        OutsideKind::Modified | OutsideKind::Added => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepEdit {
    Delete,
    Enabled(bool),
    Action(Action),
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::{Direction, Origin, Scope};
    use w4_enforce::AddressSet;
    use w4_enforce::model::{PROFILES_ALL, PROTOCOL_ANY};

    use super::*;

    fn record(id: RuleId) -> RuleRecord {
        RuleRecord {
            id,
            app: id as u32,
            direction: Direction::Out,
            action: Action::Block,
            scope: Scope::Any,
            enabled: true,
            origin: Origin::User,
            note: None,
            created_ms: 0,
            updated_ms: 0,
            expires: None,
            revert: None,
        }
    }

    fn windows(r: &RuleRecord) -> WindowsRule {
        let target = AppTarget::Program(format!(r"C:\Apps\app{}.exe", r.id));
        project(r, &format!("App {}", r.id), &target, |_| None, &|_| {
            Vec::new()
        })
        .expect("a program can be targeted")
        .remove(0)
    }

    fn written(w: &WindowsRule) -> ActualRule {
        ActualRule {
            name: w.name.clone(),
            description: w.key.description(),
            inbound: w.inbound,
            block: w.block,
            program: w.program.clone(),
            service: w.service.clone(),
            package_sid: w.package_sid.clone(),
            remote: w.remote.clone(),
            local: AddressSet::Any,
            protocol: PROTOCOL_ANY,
            local_ports: "*".into(),
            remote_ports: "*".into(),
            enabled: w.enabled,
            profiles: PROFILES_ALL,
        }
    }

    fn described(
        rules: &[RuleRecord],
        desired: &[WindowsRule],
        actual: &[ActualRule],
        mode: Mode,
    ) -> Vec<(Option<RuleId>, OutsideKind, bool)> {
        let changes = plan(desired, actual);
        let outside: Vec<&Change> = changes.iter().collect();
        let names = rules
            .iter()
            .map(|r| (r.id, format!("App {}", r.id)))
            .collect();
        describe(&outside, actual, desired, rules, &names, mode)
            .into_iter()
            .map(|c| (c.rule, c.kind, c.keepable))
            .collect()
    }

    #[test]
    fn outside_changes_are_described_and_marked_keepable() {
        let rules: Vec<_> = (1..=4).map(record).collect();
        let desired: Vec<_> = rules.iter().map(windows).collect();
        let mut actual: Vec<_> = desired.iter().map(written).collect();
        actual.remove(0); // rule 1 deleted
        actual[0].enabled = false; // rule 2 turned off
        actual[1].block = false; // rule 3 switched to allow
        actual[2].program = Some(r"C:\Elsewhere\other.exe".into()); // rule 4 retargeted
        actual.push(ActualRule {
            name: "Sneaky allow".into(),
            ..Default::default()
        });
        assert_eq!(
            described(&rules, &desired, &actual, Mode::ClickToBlock),
            [
                (Some(1), OutsideKind::Deleted, true),
                (Some(2), OutsideKind::Disabled, true),
                (Some(3), OutsideKind::Allowed, true),
                (Some(4), OutsideKind::Modified, false),
                (None, OutsideKind::Added, false),
            ]
        );
    }

    #[test]
    fn copies_and_turning_on_while_off_cant_be_kept() {
        let rules = vec![record(1), record(2)];
        let mut desired: Vec<_> = rules.iter().map(windows).collect();
        for d in &mut desired {
            d.enabled = false; // mode Off
        }
        let mut actual: Vec<_> = desired.iter().map(written).collect();
        actual.push(written(&desired[0])); // a copy of rule 1
        actual[1].enabled = true; // rule 2 turned back on
        assert_eq!(
            described(&rules, &desired, &actual, Mode::Off),
            [
                (Some(1), OutsideKind::Added, false),
                (Some(2), OutsideKind::Enabled, false),
            ]
        );
        assert_eq!(
            described(&rules, &desired, &actual, Mode::ClickToBlock)[1],
            (Some(2), OutsideKind::Enabled, true)
        );
    }

    #[test]
    fn built_in_rules_changed_outside_are_put_back_but_not_kept() {
        let desired = w4_enforce::model::block_all();
        let mut actual: Vec<_> = desired.iter().map(written).collect();
        actual[1].enabled = false; // someone turned off Block All (Out)
        assert_eq!(
            described(&[], &desired, &actual, Mode::ClickToBlock),
            [(None, OutsideKind::Disabled, false)]
        );
    }

    /// The outside changes a pass would report, as (rule, kind).
    fn reported(
        written: Option<Vec<WindowsRule>>,
        checked: bool,
        switched_on: Option<bool>,
        rules: &[RuleRecord],
        desired: &[WindowsRule],
        actual: &[ActualRule],
    ) -> Vec<(Option<RuleId>, OutsideKind)> {
        let changes = plan(desired, actual);
        let keep_as_is = BTreeSet::new();
        let (base, outside) = outside_changes(
            Written {
                rules: written,
                checked,
                keep_as_is: &keep_as_is,
                group_switched_on: switched_on,
            },
            desired,
            &changes,
            actual,
            rules,
        );
        let outside: Vec<&Change> = outside.iter().collect();
        let names = rules
            .iter()
            .map(|r| (r.id, format!("App {}", r.id)))
            .collect();
        describe(&outside, actual, &base, rules, &names, Mode::ClickToBlock)
            .into_iter()
            .map(|c| (c.rule, c.kind))
            .collect()
    }

    fn protected() -> Vec<WindowsRule> {
        w4_enforce::model::protected(&[(
            "win4tress service".into(),
            r"C:\w4\win4tress-svc.exe".into(),
        )])
    }

    #[test]
    fn at_startup_only_stored_rules_changed_while_stopped_are_reported() {
        let rules = vec![record(1), record(2)];
        let mut desired: Vec<_> = rules.iter().map(windows).collect();
        desired.extend(protected());
        desired.extend(w4_enforce::model::block_all());
        // Rule 1 was deleted while the service was stopped; the built-in rules
        // were never written (a new version, a new Block All).
        let actual = vec![written(&desired[1])];
        assert_eq!(
            reported(None, false, None, &rules, &desired, &actual),
            [(Some(1), OutsideKind::Deleted)]
        );
        // Block All ended while stopped: removing its rules is win4tress's doing.
        let rules = vec![record(1)];
        let desired = vec![windows(&rules[0])];
        let mut actual = vec![written(&desired[0])];
        actual.extend(w4_enforce::model::block_all().iter().map(written));
        assert_eq!(reported(None, false, None, &rules, &desired, &actual), []);
        // After a failed pass nothing is reported: the difference may be ours.
        assert_eq!(reported(None, true, None, &rules, &[], &actual), []);
    }

    #[test]
    fn host_rules_resolving_to_new_addresses_are_not_outside_changes() {
        let mut rule = record(1);
        rule.scope = Scope::Hosts {
            hosts: vec!["example.com".into()],
        };
        let rules = vec![rule];
        let target = AppTarget::Program(r"C:\Apps\app1.exe".into());
        let at = |ips: &'static [&'static str]| {
            project(&rules[0], "App 1", &target, |_| None, &move |_| {
                ips.iter().map(|ip| ip.to_string()).collect()
            })
            .expect("addresses resolve")
        };
        let before = at(&["192.0.2.1"]);
        let after = at(&["192.0.2.1", "192.0.2.2"]);
        let actual: Vec<_> = before.iter().map(written).collect();
        // Running: what was written still matches.
        assert_eq!(
            reported(Some(before.clone()), true, None, &rules, &after, &actual),
            []
        );
        // At startup: the name's addresses grew while stopped.
        assert_eq!(reported(None, false, None, &rules, &after, &actual), []);
        // But addresses changed by something else are.
        let mut tampered = actual.clone();
        tampered[0].remote = AddressSet::Any;
        assert_eq!(
            reported(Some(before), true, None, &rules, &after, &tampered),
            [(Some(1), OutsideKind::Modified)]
        );
    }

    #[test]
    fn running_compares_with_what_was_written() {
        let rules = vec![record(1)];
        let mut desired = vec![windows(&rules[0])];
        desired.extend(protected());
        let actual: Vec<_> = desired.iter().map(written).collect();
        // Someone deleted win4tress's rule for its own program.
        assert_eq!(
            reported(
                Some(desired.clone()),
                true,
                None,
                &rules,
                &desired,
                &actual[..1]
            ),
            [(None, OutsideKind::Deleted)]
        );
        // Switching to Off turned the group off first: not an outside change.
        let off: Vec<_> = desired
            .iter()
            .map(|d| WindowsRule {
                enabled: false,
                ..d.clone()
            })
            .collect();
        let actual_off: Vec<_> = off.iter().map(written).collect();
        assert_eq!(
            reported(
                Some(desired.clone()),
                true,
                Some(false),
                &rules,
                &off,
                &actual_off
            ),
            []
        );
        // A rule the user just deleted is still there until this pass removes it.
        assert_eq!(
            reported(Some(desired), true, None, &rules, &[], &actual),
            []
        );
    }

    #[test]
    fn profiles_by_name() {
        assert_eq!(profile_names(PROFILES_ALL), "all");
        assert_eq!(profile_names(2 | 4), "private, public");
        let mut state = FirewallState::default();
        assert_eq!(profile_mask(&state), 7, "no network: every profile");
        state.profiles.push(w4_core::firewall::ProfileState {
            name: "public".into(),
            active: true,
            ..Default::default()
        });
        assert_eq!(profile_mask(&state), 4);
    }

    #[test]
    fn keeping_maps_to_rule_edits() {
        assert_eq!(keep_edit(OutsideKind::Deleted), Some(KeepEdit::Delete));
        assert_eq!(
            keep_edit(OutsideKind::Disabled),
            Some(KeepEdit::Enabled(false))
        );
        assert_eq!(
            keep_edit(OutsideKind::Allowed),
            Some(KeepEdit::Action(Action::Allow))
        );
        assert_eq!(keep_edit(OutsideKind::Modified), None);
        assert_eq!(keep_edit(OutsideKind::Added), None);
    }

    fn app(path: &str) -> AppRecord {
        AppRecord {
            id: 1,
            key: path.to_lowercase(),
            path: path.into(),
            description: None,
            company: None,
            version: None,
            package: None,
            service: None,
            service_display: None,
            first_seen_ms: 0,
            last_seen_ms: 0,
            net_first_seen_ms: None,
            trust: Default::default(),
            own_dns_ms: None,
        }
    }

    #[test]
    fn targets_by_kind() {
        assert_eq!(
            target_of(&app(r"C:\Tools\curl.exe")),
            Some(AppTarget::Program(r"C:\Tools\curl.exe".into()))
        );
        assert_eq!(target_of(&app("System")), Some(AppTarget::System));
        assert_eq!(target_of(&app("Unknown")), None);
        let mut svc = app(r"C:\Windows\System32\svchost.exe");
        svc.service = Some("Dnscache, NlaSvc".into());
        assert_eq!(
            target_of(&svc),
            Some(AppTarget::Services {
                program: svc.path.clone(),
                services: vec!["Dnscache".into(), "NlaSvc".into()]
            })
        );
        let mut pkg = app(r"C:\Program Files\WindowsApps\Calc\calc.exe");
        pkg.package = Some("Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe".into());
        assert_eq!(
            target_of(&pkg),
            Some(AppTarget::Package {
                family: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into()
            })
        );
    }
}
