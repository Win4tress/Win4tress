//! IPC request handling: reads from the monitor, the collector and history.
//!
//! Lock order: the history and monitor locks are never held at the same time.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use w4_core::firewall::{Action, BlockAll, Direction, Expiry, Mode};
use w4_core::firewall::{Origin, Scope};
use w4_core::time::now_unix_ms;
use w4_enforce::address::literal;
use w4_etw::HealthProbe;
use w4_ipc::api::{
    Alert, AlertsParams, AlertsResult, AppLookups, AppTimeline, AppsResult, BreakdownParams,
    CollectorHealth, ConnectionsParams, ConnectionsResult, DnsLogParams, DnsLogResult, DnsStats,
    DnsStatsParams, DnsTopParams, DnsTopResult, HelloParams, HelloResult, HistoryParams,
    HistoryResult, HistoryStatus, HostsParams, LiveParams, LiveResult, MarkReadParams,
    MarkReadResult, ProcessUsage, Sample, Status, method,
};
use w4_ipc::api::{
    AlertBody, AppId, AppRef, AppRulesParams, AppRulesResult, BlockAllParams, BlockedConnection,
    BlocksParams, BlocksResult, BreakdownFilter, DecideParams, DecideResult, IdleSpan, InputParams,
    KeepChangesParams, KeepChangesResult, KnownAppsResult, RequireElevationParams, ResetResult,
    Rule, RuleChange, RuleDeleteParams, RuleSetParams, RulesApplyParams, RulesApplyResult,
    RulesResult, SetModeParams, Settings, TurnOnParams, VerdictsParams,
};
use w4_ipc::api::{
    AppParams, ProfileParams, ProfilesResult, RuleEnableParams, SetKeyParams, UploadParams,
    UploadResult,
};
use w4_ipc::api::{
    CloseParams, CloseResult, Decision, DecisionScope, ExportedApp, ExportedProfile, ExportedRule,
    ImportParams, ImportResult, Lasts, MAX_RULE_MINUTES, NetworkInfo, NetworkMatch, NetworksResult,
    Profile, RulesExport, SetNetworksParams,
};
use w4_ipc::api::{DnsFilterLogParams, DnsFilterLogResult, DnsPauseParams};
use w4_ipc::api::{MONITORS, MonitorState, MonitorsResult, SetKnownParams, UserProxyParams};
use w4_ipc::{Caller, Handler, PROTOCOL_VERSION, RpcError};
use w4_monitor::{AppRecord, Monitor, build_breakdown};
use w4_store::{NewRule, ProfileRule, RuleEdit, SeriesFilter, Store, StoredAlert};
use w4_sys::adapters::{self, Adapter};

use crate::autoprofile::{self, AutoProfile, SwitchError};
use crate::cleanup::Cleanup;
use crate::data;
use crate::dnsfilter::DnsFilter;
use crate::enforcer::{Enforcer, KeepEdit, keep_edit, target_of};
use crate::prompts::Prompter;
use crate::reputation::ReputationService;
use crate::security::Security;
use crate::usage::Usage;

/// The audit trail's word for adopting a change made outside win4tress.
const KEPT: &str = "kept outside change";

const DEFAULT_BREAKDOWN_LIMIT: u32 = 30;
const MAX_LIMIT: u32 = 200;
const MAX_CONNECTIONS: usize = 2_000;
const DEFAULT_DNS_LOG: u32 = 500;
const MAX_DNS_LOG: u32 = 5_000;
const DEFAULT_DNS_TOP: u32 = 50;
const DEFAULT_DNS_STATS_TOP: u32 = 10;
/// At most this many minutes per history request (a little over the 48 h kept).
/// Samples a history query returns at most; longer ranges get bigger steps.
const MAX_HISTORY_SAMPLES: i64 = 3_000;
const DEFAULT_ALERTS: u32 = 200;
const MAX_ALERTS: u32 = 1_000;
/// At most this many ids per mark-read request.
const MAX_MARK_IDS: usize = 10_000;
/// At most this many changes per `rules.apply`.
const MAX_BATCH: usize = 500;
/// Longest proxy description the app may report.
const MAX_PROXY_TEXT: usize = 4_096;
/// At most this many hosts in one rule.
const MAX_HOSTS: usize = 1_000;
const DEFAULT_BLOCKS: u32 = 200;
const MAX_BLOCKS: u32 = 2_000;
/// Block All for a day at most when timed.
const MAX_BLOCK_ALL_MINUTES: u32 = 24 * 60;

#[derive(Clone)]
pub struct History {
    pub store: Arc<Mutex<Store>>,
    pub path: PathBuf,
}

pub struct SvcHandler {
    pub monitor: Arc<Mutex<Monitor>>,
    pub collector: HealthProbe,
    pub adapters_at_start: Vec<Adapter>,
    pub history: Option<History>,
    /// `None` without history (rules live there) or without Windows Firewall access.
    pub enforcer: Option<Arc<Enforcer>>,
    /// Ask to Connect's prompts; `None` whenever `enforcer` is.
    pub prompter: Option<Arc<Prompter>>,
    /// Usage settings, data plan, idle spans; `None` without history.
    pub usage: Option<Arc<Usage>>,
    /// The security monitors and the network scanner; `None` without history.
    pub security: Option<Arc<Security>>,
    /// Reputation lookups and scans; `None` without history.
    pub reputation: Option<Arc<ReputationService>>,
    /// Automatic cleanup of rules; `None` whenever `enforcer` is.
    pub cleanup: Option<Arc<Cleanup>>,
    /// DNS filtering; `None` without history (its settings live there).
    pub dns: Option<Arc<DnsFilter>>,
    /// Switching profiles by network; `None` whenever `enforcer` is.
    pub autoprofile: Option<Arc<AutoProfile>>,
}

/// At most this many connections per `connections.close`.
const MAX_CLOSE: usize = 1_000;
/// At most this many networks per profile.
const MAX_NETWORKS: usize = 50;

/// When a temporary whole-app rule ends (SPEC §7.2), checked: until the app
/// quits only for a program that's running, not a Windows service.
pub fn expiry_for(lasts: Lasts, app: &AppRecord, name: &str) -> Result<Expiry, String> {
    match lasts {
        Lasts::Minutes { minutes } if (1..=MAX_RULE_MINUTES).contains(&minutes) => Ok(Expiry::At {
            ms: now_unix_ms() + i64::from(minutes) * 60_000,
        }),
        Lasts::Minutes { .. } => Err(format!(
            "a temporary rule lasts 1 to {MAX_RULE_MINUTES} minutes"
        )),
        Lasts::AppQuits => {
            if app.service.is_some() || !app.path.contains('\\') {
                return Err(format!(
                    "{name} is part of Windows: it doesn't quit, so choose a time instead"
                ));
            }
            if !w4_sys::process::running_paths().contains(&app.path.to_lowercase()) {
                return Err(format!(
                    "{name} isn't running, so \"until it quits\" would end at once"
                ));
            }
            Ok(Expiry::AppQuits)
        }
        Lasts::Restart => w4_sys::time::boot_ms()
            .map(|boot_ms| Expiry::Restart { boot_ms })
            .ok_or_else(|| "can't tell when Windows started".into()),
    }
}

fn switch_error(e: SwitchError) -> RpcError {
    match e {
        SwitchError::NotFound(m) => RpcError::not_found(m),
        SwitchError::Unavailable(m) => RpcError::new(RpcError::UNAVAILABLE, m),
        SwitchError::Storage(m) => RpcError::new(RpcError::INTERNAL, m),
    }
}

/// A network a profile can be chosen for: Windows' id, braced, and a name.
fn checked_networks(networks: Vec<NetworkMatch>) -> Result<Vec<NetworkMatch>, RpcError> {
    if networks.len() > MAX_NETWORKS {
        return Err(RpcError::invalid_params(format!(
            "at most {MAX_NETWORKS} networks per profile"
        )));
    }
    let mut out: Vec<NetworkMatch> = Vec::new();
    for m in networks {
        if let NetworkMatch::Network { id, name } = &m {
            let inner = id.trim_start_matches('{').trim_end_matches('}');
            let guid =
                inner.len() == 36 && inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            if !guid || name.chars().count() > 256 || name.chars().any(char::is_control) {
                return Err(RpcError::invalid_params(format!(
                    "{id} isn't a network Windows knows"
                )));
            }
        }
        if !out.contains(&m) {
            out.push(m);
        }
    }
    Ok(out)
}

/// 1 to 40 characters, no control characters, trimmed.
fn profile_name(name: &str) -> Result<String, RpcError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
        return Err(RpcError::invalid_params(
            "a profile name is 1 to 40 characters",
        ));
    }
    Ok(name.to_string())
}

fn unavailable_because(e: String) -> RpcError {
    RpcError::new(RpcError::UNAVAILABLE, e)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn storage_error(e: w4_store::Error) -> RpcError {
    RpcError::new(RpcError::INTERNAL, format!("history query failed: {e}"))
}

impl SvcHandler {
    fn monitor(&self) -> MutexGuard<'_, Monitor> {
        lock(&self.monitor)
    }

    fn status(&self, now_ms: i64) -> Status {
        let health = self.collector.health();
        let adapter_bytes = adapters::snapshot()
            .map(|now| adapters::physical_delta(&self.adapters_at_start, &now))
            .unwrap_or_default();
        let (working_set, cpu_ms) = w4_sys::process::own_usage();
        let (history, unread_alerts) = match &self.history {
            Some(h) => {
                let store = lock(&h.store);
                let status = HistoryStatus {
                    enabled: true,
                    path: Some(h.path.display().to_string()),
                    size_bytes: data::db_size(&h.path),
                    oldest: store.oldest_minute().ok().flatten().map(|m| m * 60),
                };
                (status, store.unread_alerts().unwrap_or(0))
            }
            None => (HistoryStatus::default(), 0),
        };
        let monitor = self.monitor();
        let (apps_bytes, local_bytes) = monitor.totals();
        Status {
            version: env!("CARGO_PKG_VERSION").into(),
            started_ms: monitor.started_ms(),
            now_ms,
            collector: CollectorHealth {
                running: health.running,
                restarts: health.restarts,
                events: health.events,
                data_events: health.data_events,
                parse_errors: health.parse_errors,
                events_lost: health.events_lost,
                buffers_lost: health.buffers_lost,
                last_event_ms: health.last_event_ms,
            },
            apps_bytes,
            local_bytes,
            adapter_bytes,
            app_count: monitor.app_count(),
            process: ProcessUsage {
                working_set,
                cpu_ms,
            },
            history,
            unread_alerts,
        }
    }

    fn alerts(&self, p: AlertsParams) -> Result<Value, RpcError> {
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        let limit = p.limit.unwrap_or(DEFAULT_ALERTS).min(MAX_ALERTS) as usize;
        let (stored, more, unread) = {
            let store = lock(&history.store);
            let (stored, more) = store.alerts(&p, limit).map_err(storage_error)?;
            let unread = store.unread_alerts().map_err(storage_error)?;
            (stored, more, unread)
        };
        let monitor = self.monitor();
        let alerts = stored.into_iter().map(|a| alert(a, &monitor)).collect();
        to_value(AlertsResult {
            alerts,
            more,
            unread,
        })
    }

    fn dns_stats(&self, p: DnsStatsParams) -> Result<Value, RpcError> {
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        if p.to_ms < p.from_ms {
            return Err(RpcError::invalid_params("`to_ms` is before `from_ms`"));
        }
        let limit = p.limit.unwrap_or(DEFAULT_DNS_STATS_TOP).min(MAX_LIMIT) as usize;
        let rows = lock(&history.store)
            .dns_stats(p.from_ms, p.to_ms, p.step_ms, limit)
            .map_err(storage_error)?;
        let monitor = self.monitor();
        to_value(DnsStats {
            start_ms: rows.start_ms,
            step_ms: rows.step_ms,
            lookups: rows.lookups,
            failed: rows.failed,
            domains: rows.domains,
            apps: rows.apps,
            timeline: rows.timeline,
            app_timeline: rows
                .app_timeline
                .into_iter()
                .map(|(app, counts)| AppTimeline {
                    app: monitor.app_ref(app),
                    counts,
                })
                .collect(),
            other_timeline: rows.other_timeline,
            query_types: rows.query_types,
            results: rows.results,
            top_domains: rows.top_domains,
            top_failed: rows.top_failed,
            top_apps: rows
                .top_apps
                .into_iter()
                .map(|(app, lookups, failed)| AppLookups {
                    app: monitor.app_ref(app),
                    lookups,
                    failed,
                })
                .collect(),
        })
    }

    fn enforcement(&self) -> Result<(&History, &Arc<Enforcer>), RpcError> {
        match (&self.history, &self.enforcer) {
            (Some(h), Some(e)) => Ok((h, e)),
            _ => Err(RpcError::new(
                RpcError::UNAVAILABLE,
                "firewall rules are unavailable: they need the history database and access to Windows Firewall",
            )),
        }
    }

    fn rules(&self) -> Result<Value, RpcError> {
        let (history, _) = self.enforcement()?;
        let records = lock(&history.store).rules().map_err(storage_error)?;
        let monitor = self.monitor();
        to_value(RulesResult {
            rules: records
                .into_iter()
                .map(|r| {
                    let app = monitor.app_ref(r.app);
                    Rule::new(r, app)
                })
                .collect(),
        })
    }

    /// Who may change things (SPEC §4.3), and, for `enforcing` changes, whether
    /// win4tress can enforce at all right now (SPEC §7.7).
    fn check_change(&self, caller: &Caller, what: &str, enforcing: bool) -> Result<(), RpcError> {
        if !caller.may_change() {
            return Err(RpcError::forbidden(format!(
                "{what} needs a member of Administrators"
            )));
        }
        if let Some(h) = &self.history
            && lock(&h.store).require_elevation().unwrap_or(false)
            && !caller.elevated()
        {
            return Err(RpcError::new(
                RpcError::ELEVATION_REQUIRED,
                format!("{what} needs an elevated caller: \"Require elevation\" is on"),
            ));
        }
        if enforcing
            && let Some(e) = &self.enforcer
            && let Some(why) = e.monitoring_only()
        {
            return Err(RpcError::new(
                RpcError::UNAVAILABLE,
                format!("win4tress can only monitor here: {why}"),
            ));
        }
        Ok(())
    }

    /// Checks a rule to set and makes it a [`NewRule`].
    fn new_rule(
        &self,
        enforcer: &Enforcer,
        p: RuleSetParams,
    ) -> Result<(NewRule, AppRef), RpcError> {
        let (record, app) = {
            let monitor = self.monitor();
            let record = monitor
                .app_record(p.app)
                .ok_or_else(|| RpcError::not_found(format!("no app with id {}", p.app)))?;
            (record, monitor.app_ref(p.app))
        };
        if target_of(&record).is_none() {
            return Err(RpcError::invalid_params(format!(
                "{} can't be given a firewall rule: its program isn't known",
                app.name
            )));
        }
        if p.action == Action::Block && enforcer.is_protected(&record.path) {
            return Err(RpcError::forbidden(format!(
                "{} is part of win4tress and can't be blocked (Block All still blocks it)",
                app.name
            )));
        }
        let scope = checked_scope(&p.scope, p.action, &record)?;
        let expires = match p.lasts {
            Some(_) if scope != Scope::Any => {
                return Err(RpcError::invalid_params(
                    "only a rule for all of an app's connections can be temporary",
                ));
            }
            Some(lasts) => Some(
                blocking(|| expiry_for(lasts, &record, &app.name))
                    .map_err(RpcError::invalid_params)?,
            ),
            None => None,
        };
        Ok((
            NewRule {
                app: p.app,
                direction: p.direction,
                action: p.action,
                scope,
                origin: Origin::User,
                note: p.note,
                expires,
            },
            app,
        ))
    }

    fn set_rule(&self, caller: &Caller, p: RuleSetParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "changing firewall rules", true)?;
        let (new, app) = self.new_rule(enforcer, p)?;
        let rule = lock(&history.store)
            .set_rule(&new, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        tracing::info!(rule = rule.id, app = %app.name, by = %caller.describe(), "rule set");
        enforcer.changed();
        self.decided(&new);
        to_value(Rule::new(rule, app))
    }

    fn delete_rule(&self, caller: &Caller, p: RuleDeleteParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "changing firewall rules", true)?;
        let deleted = lock(&history.store)
            .delete_rule(p.id, now_unix_ms(), &caller.describe(), "deleted")
            .map_err(storage_error)?
            .ok_or_else(|| RpcError::not_found(format!("no rule with id {}", p.id)))?;
        tracing::info!(rule = deleted.id, by = %caller.describe(), "rule deleted");
        enforcer.changed();
        to_value(serde_json::json!({ "deleted": deleted.id }))
    }

    /// Several changes, each checked and audited, applied to Windows Firewall
    /// in one pass (bulk changes, SPEC §10.2).
    fn apply_rules(&self, caller: &Caller, p: RulesApplyParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "changing firewall rules", true)?;
        if p.changes.len() > MAX_BATCH {
            return Err(RpcError::invalid_params(format!(
                "at most {MAX_BATCH} changes at a time"
            )));
        }
        let now = now_unix_ms();
        let who = caller.describe();
        let mut result = RulesApplyResult::default();
        for change in p.changes {
            let outcome = match change {
                RuleChange::Set(set) => {
                    let app = set.app;
                    self.new_rule(enforcer, set)
                        .and_then(|(new, _)| {
                            lock(&history.store)
                                .set_rule(&new, now, &who)
                                .map_err(storage_error)?;
                            self.decided(&new);
                            Ok(())
                        })
                        .map_err(|e| format!("app {app}: {}", e.message))
                }
                RuleChange::Delete { id } => {
                    match lock(&history.store).delete_rule(id, now, &who, "deleted") {
                        Ok(Some(_)) => Ok(()),
                        Ok(None) => Err(format!("rule {id}: no such rule")),
                        Err(e) => Err(format!("rule {id}: {e}")),
                    }
                }
            };
            match outcome {
                Ok(()) => result.applied += 1,
                Err(e) => result.failed.push(e),
            }
        }
        tracing::info!(applied = result.applied, failed = result.failed.len(), by = %who, "rules applied");
        if result.applied > 0 {
            enforcer.changed();
        }
        to_value(result)
    }

    fn verdicts(&self, p: VerdictsParams, now_ms: i64) -> Result<Value, RpcError> {
        let (_, enforcer) = self.enforcement()?;
        let apps: Vec<_> = {
            let monitor = self.monitor();
            if p.all {
                monitor.app_records()
            } else {
                monitor
                    .apps(now_ms)
                    .iter()
                    .filter_map(|a| monitor.app_record(a.id))
                    .collect()
            }
        };
        to_value(
            enforcer
                .verdicts(&apps)
                .map_err(|e| RpcError::new(RpcError::INTERNAL, e))?,
        )
    }

    fn app_rules(&self, p: AppRulesParams) -> Result<Value, RpcError> {
        let (_, enforcer) = self.enforcement()?;
        let record = self
            .monitor()
            .app_record(p.app)
            .ok_or_else(|| RpcError::not_found(format!("no app with id {}", p.app)))?;
        to_value(AppRulesResult {
            rules: enforcer.app_rules(&record),
        })
    }

    /// Blocked attempts: since the service started, or from history.
    fn blocks(&self, p: BlocksParams) -> Result<Value, RpcError> {
        let limit = p.limit.unwrap_or(DEFAULT_BLOCKS).min(MAX_BLOCKS) as usize;
        let blocks = match (p.since_ms, &self.history) {
            (Some(since), Some(h)) => {
                let rows = lock(&h.store)
                    .blocks(p.app, since, limit)
                    .map_err(storage_error)?;
                let monitor = self.monitor();
                rows.into_iter()
                    .map(|(k, c)| BlockedConnection {
                        app: monitor.app_ref(k.app),
                        inbound: k.inbound,
                        remote: std::net::SocketAddr::new(k.ip, k.port),
                        name: monitor.host_name(k.app, k.ip),
                        by: k.by,
                        count: c.count,
                        first_ms: c.first_ms,
                        last_ms: c.last_ms,
                    })
                    .collect()
            }
            _ => self.monitor().blocks(p.app, limit),
        };
        to_value(BlocksResult { blocks })
    }

    fn block_all(&self, caller: &Caller, p: BlockAllParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "Block All", true)?;
        let now = now_unix_ms();
        let value = if p.on {
            if !p.confirm_remote && caller.pid.is_some_and(w4_sys::process::in_remote_session) {
                return Err(RpcError::new(
                    RpcError::REMOTE_SESSION,
                    "you're connected over Remote Desktop: Block All will disconnect you until it ends",
                ));
            }
            if p.minutes
                .is_some_and(|m| m == 0 || m > MAX_BLOCK_ALL_MINUTES)
            {
                return Err(RpcError::invalid_params(format!(
                    "minutes must be 1 to {MAX_BLOCK_ALL_MINUTES}"
                )));
            }
            Some(BlockAll {
                since_ms: now,
                until_ms: p.minutes.map(|m| now + i64::from(m) * 60_000),
            })
        } else {
            None
        };
        lock(&history.store)
            .set_block_all(value, now, &caller.describe())
            .map_err(storage_error)?;
        tracing::warn!(on = p.on, minutes = ?p.minutes, by = %caller.describe(), "Block All");
        enforcer.changed();
        to_value(enforcer.status())
    }

    fn turn_on(&self, caller: &Caller, p: TurnOnParams) -> Result<Value, RpcError> {
        let (_, enforcer) = self.enforcement()?;
        self.check_change(caller, "turning Windows Firewall on", true)?;
        let turned_on = blocking(|| enforcer.turn_on(p.profile.as_deref()))
            .map_err(|e| RpcError::new(RpcError::INTERNAL, e))?;
        tracing::warn!(?turned_on, by = %caller.describe(), "Windows Firewall turned on");
        to_value(serde_json::json!({ "turned_on": turned_on }))
    }

    /// The hardening option itself always needs elevation, on or off: otherwise
    /// malware running as an administrator unelevated could just turn it off.
    fn require_elevation(
        &self,
        caller: &Caller,
        p: RequireElevationParams,
    ) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        if !caller.elevated() {
            return Err(RpcError::forbidden(
                "changing \"Require elevation\" needs an elevated caller (Run as administrator)",
            ));
        }
        lock(&history.store)
            .set_require_elevation(p.on, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        tracing::warn!(on = p.on, by = %caller.describe(), "\"Require elevation\" set");
        to_value(enforcer.status())
    }

    fn set_mode(&self, caller: &Caller, p: SetModeParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "changing the firewall mode", true)?;
        // Ask to Connect sets the outbound default, which policy may force (SPEC §7.7).
        let forced = enforcer.status().environment.outbound_default_forced_by;
        if p.mode == Mode::AskToConnect && !forced.is_empty() {
            return Err(RpcError::new(
                RpcError::UNAVAILABLE,
                format!(
                    "Ask to Connect is unavailable: {} sets what happens to outgoing connections",
                    forced.join(" and ")
                ),
            ));
        }
        let changed = lock(&history.store)
            .set_firewall_mode(p.mode, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        if changed {
            tracing::info!(mode = p.mode.as_str(), by = %caller.describe(), "firewall mode set");
            enforcer.changed();
            if p.mode != Mode::AskToConnect
                && let Some(prompter) = &self.prompter
            {
                prompter.clear();
            }
        }
        to_value(enforcer.status())
    }

    /// An app's outgoing connections were decided: its prompt has gone.
    fn decided(&self, rule: &NewRule) {
        if rule.direction == Direction::Out
            && rule.scope == Scope::Any
            && let Some(prompter) = &self.prompter
        {
            prompter.forget_app(rule.app);
        }
    }

    fn decide(&self, caller: &Caller, p: DecideParams) -> Result<Value, RpcError> {
        self.enforcement()?;
        self.check_change(caller, "answering a prompt", true)?;
        let prompter = self.prompter.as_ref().ok_or_else(unavailable)?;
        let expires = match p.lasts {
            None => None,
            Some(_) if p.scope != DecisionScope::App || p.decision == Decision::Later => {
                return Err(RpcError::invalid_params(
                    "only allowing or blocking the whole app can be temporary",
                ));
            }
            Some(lasts) => {
                let app = prompter.app_of(p.id).ok_or_else(|| {
                    RpcError::not_found(format!("no prompt {}: it was answered or has gone", p.id))
                })?;
                let (record, name) = {
                    let monitor = self.monitor();
                    (monitor.app_record(app), monitor.app_ref(app).name)
                };
                let record = record.ok_or_else(|| RpcError::not_found(format!("no app {app}")))?;
                Some(
                    blocking(|| expiry_for(lasts, &record, &name))
                        .map_err(RpcError::invalid_params)?,
                )
            }
        };
        let rule =
            blocking(|| prompter.decide(p.id, p.decision, p.scope, expires, &caller.describe()))
                .map_err(RpcError::not_found)?;
        to_value(DecideResult { rule })
    }

    /// Adopts what a "firewall changed" alert reported, in place of the rules
    /// that were put back (SPEC §7.8 "Accept").
    fn keep_changes(&self, caller: &Caller, p: KeepChangesParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "keeping firewall changes", true)?;
        let now = now_unix_ms();
        let who = caller.describe();
        let mut store = lock(&history.store);
        let alert = store
            .alert(p.alert)
            .map_err(storage_error)?
            .ok_or_else(|| RpcError::not_found(format!("no alert with id {}", p.alert)))?;
        let AlertBody::FirewallChanged {
            repaired,
            changes,
            kept_ms,
        } = alert.body
        else {
            return Err(RpcError::invalid_params(
                "that alert isn't about firewall changes",
            ));
        };
        if kept_ms.is_some() {
            return Err(RpcError::invalid_params("those changes were already kept"));
        }
        // A rule changed in win4tress since the alert: that later decision stands.
        let mut current = BTreeSet::new();
        for id in changes.iter().filter_map(|c| c.rule) {
            if let Some(r) = store.rule(id).map_err(storage_error)?
                && r.updated_ms <= alert.ts_ms
            {
                current.insert(id);
            }
        }
        let (mut kept, mut skipped) = (0u32, 0u32);
        for c in &changes {
            let target = c.rule.filter(|id| c.keepable && current.contains(id));
            let (Some(id), Some(edit)) = (target, keep_edit(c.kind)) else {
                skipped += 1;
                continue;
            };
            let done = match edit {
                KeepEdit::Delete => store.delete_rule(id, now, &who, KEPT),
                KeepEdit::Enabled(on) => store.edit_rule(
                    id,
                    RuleEdit {
                        enabled: Some(on),
                        ..Default::default()
                    },
                    now,
                    &who,
                    KEPT,
                ),
                KeepEdit::Action(action) => store.edit_rule(
                    id,
                    RuleEdit {
                        action: Some(action),
                        ..Default::default()
                    },
                    now,
                    &who,
                    KEPT,
                ),
            }
            .map_err(storage_error)?
            .is_some();
            if done {
                kept += 1;
            } else {
                skipped += 1;
            }
        }
        let body = AlertBody::FirewallChanged {
            repaired,
            changes,
            kept_ms: Some(now),
        };
        store
            .set_alert_body(alert.id, &body)
            .map_err(storage_error)?;
        store
            .mark_read(Some(&[alert.id]), true)
            .map_err(storage_error)?;
        drop(store);
        tracing::info!(alert = alert.id, kept, skipped, by = %who, "outside firewall changes kept");
        enforcer.changed();
        to_value(KeepChangesResult { kept, skipped })
    }

    /// Deletes every rule and waits until Windows Firewall matches (SPEC §4.3:
    /// elevated callers only).
    fn reset(&self, caller: &Caller) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        if !caller.elevated() {
            return Err(RpcError::forbidden(
                "resetting the firewall needs an elevated caller (Run as administrator)",
            ));
        }
        let who = caller.describe();
        let now = now_unix_ms();
        let rules = {
            let mut store = lock(&history.store);
            let rules = store.reset_rules(now, &who).map_err(storage_error)?;
            if store.block_all().map_err(storage_error)?.is_some() {
                store
                    .set_block_all(None, now, &who)
                    .map_err(storage_error)?;
            }
            rules
        };
        tracing::warn!(rules, by = %who, "firewall reset");
        enforcer.changed();
        if let Some(prompter) = &self.prompter {
            prompter.clear();
        }
        // Reset also turns DNS filtering off: Windows' own DNS again (SPEC §13).
        if let Some(usage) = &self.usage {
            let mut settings = usage.settings();
            if settings.dns.enabled {
                settings.dns.enabled = false;
                let _ = usage.set_settings(settings, &who);
            }
        }
        if let Some(dns) = &self.dns {
            dns.stop("reset");
        }
        // Removing hundreds of rules takes seconds.
        let synced = blocking(|| {
            enforcer.sync()?;
            enforcer.restore_profiles(&who).map(|_| ())
        });
        to_value(ResetResult {
            rules,
            in_sync: synced.is_ok(),
            error: synced.err(),
        })
    }

    fn mark_read(&self, p: MarkReadParams) -> Result<Value, RpcError> {
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        if p.ids.as_ref().is_some_and(|ids| ids.len() > MAX_MARK_IDS) {
            return Err(RpcError::invalid_params(format!(
                "at most {MAX_MARK_IDS} ids at a time"
            )));
        }
        let store = lock(&history.store);
        store
            .mark_read(p.ids.as_deref(), p.read)
            .map_err(storage_error)?;
        to_value(MarkReadResult {
            unread: store.unread_alerts().map_err(storage_error)?,
        })
    }

    /// Totals per step from the tier that covers the range (SPEC §9.1), with
    /// quiet steps as zeros, and when nobody used the PC.
    fn history_samples(&self, p: HistoryParams, now_ms: i64) -> Result<HistoryResult, RpcError> {
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        if p.to < p.from {
            return Err(RpcError::invalid_params("`to` is before `from`"));
        }
        let span = p.to - p.from + 1;
        let wanted = i64::from(p.step.unwrap_or(60)).max(1);
        let step = wanted.max((span + MAX_HISTORY_SAMPLES - 1) / MAX_HISTORY_SAMPLES);
        let filter = self.series_filter(&p.filter);
        let exclude = self.excluded();
        let (step, stored, idle) = {
            let store = lock(&history.store);
            let (step, rows) = store
                .series(p.from, p.to, step, &filter, &exclude, now_ms)
                .map_err(storage_error)?;
            let idle = store
                .idle(p.from * 1000, p.to * 1000 + 999)
                .map_err(storage_error)?;
            (step, rows, idle)
        };
        // Steps are aligned to local time (a day step starts at local midnight).
        let off = i64::from(w4_sys::time::utc_offset_minutes()) * 60;
        let first = (p.from + off).div_euclid(step) * step - off;
        let mut stored = stored.into_iter().peekable();
        let mut samples = Vec::new();
        let mut t = first;
        while t <= p.to {
            let mut bytes = w4_core::Bytes::default();
            while let Some((at, b)) = stored.peek() {
                if *at < t + step {
                    bytes += *b;
                    stored.next();
                } else {
                    break;
                }
            }
            samples.push(Sample {
                t,
                recv: bytes.recv,
                sent: bytes.sent,
            });
            t += step;
        }
        Ok(HistoryResult {
            step: step as u32,
            samples,
            idle: idle
                .into_iter()
                .map(|(start_ms, end_ms)| IdleSpan { start_ms, end_ms })
                .collect(),
        })
    }

    /// The store's filter: a publisher is all of its apps.
    fn series_filter(&self, f: &BreakdownFilter) -> SeriesFilter {
        let apps = match (&f.app, &f.publisher) {
            (Some(app), _) => Some(vec![*app]),
            (None, Some(publisher)) => Some(self.monitor().apps_by_publisher(publisher)),
            (None, None) => None,
        };
        SeriesFilter {
            apps,
            traffic_type: f.traffic_type,
            country: f.country.clone(),
            local: f.local,
        }
    }

    /// Apps left out of totals (VPN clients, if the user says so).
    fn excluded(&self) -> Vec<AppId> {
        self.usage
            .as_ref()
            .map(|u| u.excluded())
            .unwrap_or_default()
    }

    fn set_settings(&self, caller: &Caller, settings: Settings) -> Result<Value, RpcError> {
        self.check_change(caller, "changing settings", false)?;
        crate::dnsfilter::check(&settings.dns).map_err(RpcError::invalid_params)?;
        let usage = self.usage.as_ref().ok_or_else(unavailable)?;
        usage
            .set_settings(settings, &caller.describe())
            .map_err(RpcError::invalid_params)?;
        to_value(usage.settings())
    }

    fn dns(&self) -> Result<&Arc<DnsFilter>, RpcError> {
        self.dns.as_ref().ok_or_else(unavailable)
    }

    /// Pauses blocking for `minutes`, or resumes with `None`.
    fn pause_dns(&self, caller: &Caller, p: DnsPauseParams) -> Result<Value, RpcError> {
        self.check_change(caller, "pausing DNS filtering", false)?;
        let usage = self.usage.as_ref().ok_or_else(unavailable)?;
        let mut settings = usage.settings();
        settings.dns.paused_until_ms = p
            .minutes
            .filter(|m| *m > 0)
            .map(|m| now_unix_ms() + i64::from(m.min(24 * 60)) * 60_000);
        usage
            .set_settings(settings, &caller.describe())
            .map_err(RpcError::invalid_params)?;
        to_value(self.dns()?.status())
    }

    fn reputation(&self) -> Result<&Arc<ReputationService>, RpcError> {
        self.reputation.as_ref().ok_or_else(unavailable)
    }

    fn cleanup(&self) -> Result<&Arc<Cleanup>, RpcError> {
        self.cleanup
            .as_ref()
            .ok_or_else(|| unavailable_because("cleanup needs history and Windows Firewall".into()))
    }

    /// Turns a rule on or off without removing it: what profiles switch.
    fn enable_rule(&self, caller: &Caller, p: RuleEnableParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "changing firewall rules", true)?;
        let edit = RuleEdit {
            enabled: Some(p.enabled),
            action: None,
        };
        let rule = lock(&history.store)
            .edit_rule(p.id, edit, now_unix_ms(), &caller.describe(), "updated")
            .map_err(storage_error)?
            .ok_or_else(|| RpcError::not_found(format!("no rule with id {}", p.id)))?;
        tracing::info!(rule = rule.id, enabled = p.enabled, by = %caller.describe(), "rule switched");
        enforcer.changed();
        let app = self.monitor().app_ref(rule.app);
        to_value(Rule::new(rule, app))
    }

    fn profiles(&self) -> Result<ProfilesResult, RpcError> {
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        let store = lock(&history.store);
        let profiles = store.profiles().map_err(storage_error)?;
        let active = store.active_profile().map_err(storage_error)?;
        let changed = match &active {
            Some(name) => store.profile_changed(name).map_err(storage_error)?,
            None => false,
        };
        Ok(ProfilesResult {
            profiles,
            active,
            changed,
            last_auto: self.autoprofile.as_ref().and_then(|a| a.last()),
        })
    }

    fn save_profile(&self, caller: &Caller, p: ProfileParams) -> Result<Value, RpcError> {
        let (history, _) = self.enforcement()?;
        self.check_change(caller, "saving a profile", false)?;
        let name = profile_name(&p.name)?;
        lock(&history.store)
            .save_profile(&name, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        tracing::info!(profile = %name, by = %caller.describe(), "profile saved");
        to_value(self.profiles()?)
    }

    /// Puts the profile's rule states and mode in place (SPEC §7.6).
    fn switch_profile(&self, caller: &Caller, p: ProfileParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        self.check_change(caller, "switching profiles", true)?;
        autoprofile::switch(
            &history.store,
            enforcer,
            self.prompter.as_deref(),
            self.usage.as_deref(),
            &p.name,
            &caller.describe(),
        )
        .map_err(switch_error)?;
        to_value(self.profiles()?)
    }

    fn delete_profile(&self, caller: &Caller, p: ProfileParams) -> Result<Value, RpcError> {
        let (history, _) = self.enforcement()?;
        self.check_change(caller, "deleting a profile", false)?;
        let deleted = lock(&history.store)
            .delete_profile(&p.name, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        if !deleted {
            return Err(RpcError::not_found(format!("no profile {}", p.name)));
        }
        to_value(self.profiles()?)
    }

    /// The networks a profile is switched to on (SPEC §7.6).
    fn set_networks(&self, caller: &Caller, p: SetNetworksParams) -> Result<Value, RpcError> {
        let (history, _) = self.enforcement()?;
        self.check_change(caller, "changing a profile", false)?;
        let networks = checked_networks(p.networks)?;
        let found = lock(&history.store)
            .set_profile_networks(&p.name, &networks, now_unix_ms(), &caller.describe())
            .map_err(storage_error)?;
        if !found {
            return Err(RpcError::not_found(format!("no profile {}", p.name)));
        }
        tracing::info!(profile = %p.name, networks = networks.len(), by = %caller.describe(), "profile networks set");
        if let Some(a) = &self.autoprofile {
            a.reconsider();
        }
        to_value(self.profiles()?)
    }

    /// The networks Windows knows, connected first.
    fn networks(&self) -> Result<Value, RpcError> {
        let all = blocking(|| w4_sys::netlist::networks(true));
        let wanted = self.autoprofile.as_ref().and_then(|a| {
            let connected: Vec<_> = all.iter().filter(|n| n.connected).cloned().collect();
            a.wanted(&connected)
        });
        let mut networks: Vec<NetworkInfo> = all
            .into_iter()
            .map(|n| NetworkInfo {
                id: n.id,
                name: n.name,
                category: n.category,
                connected: n.connected,
                internet: n.internet,
            })
            .collect();
        networks.sort_by(|a, b| {
            b.connected
                .cmp(&a.connected)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        to_value(NetworksResult { networks, wanted })
    }

    /// Every rule and profile, as a file for another PC (SPEC §7.2). A
    /// temporary rule is exported as what it goes back to, or left out.
    fn export_rules(&self) -> Result<Value, RpcError> {
        let (history, _) = self.enforcement()?;
        let (records, profiles, mode, dns) = {
            let store = lock(&history.store);
            let records = store.rules().map_err(storage_error)?;
            let mut profiles = Vec::new();
            for p in store.profiles().map_err(storage_error)? {
                if let Some(found) = store.profile(&p.name).map_err(storage_error)? {
                    profiles.push(found);
                }
            }
            (
                records,
                profiles,
                store.firewall_mode().map_err(storage_error)?,
                store.settings().map_err(storage_error)?.dns.without_pause(),
            )
        };
        let monitor = self.monitor();
        // The program, as another PC can find it.
        let program = |app: u32| -> Option<ExportedApp> {
            let record = monitor.app_record(app)?;
            target_of(&record)?;
            Some(ExportedApp {
                name: monitor.app_ref(app).name,
                path: record.path,
                service: record.service,
                package: record.package,
            })
        };
        let mut rules = Vec::new();
        // Each exported rule's app here, for the older index map.
        let mut apps: Vec<u32> = Vec::new();
        for r in records {
            let action = match (r.expires, r.revert) {
                (None, _) => r.action,
                (Some(_), Some(back)) => back,
                (Some(_), None) => continue,
            };
            let Some(app) = program(r.app) else {
                continue;
            };
            apps.push(r.app);
            rules.push(ExportedRule {
                app,
                direction: r.direction,
                action,
                scope: r.scope,
                enabled: r.enabled,
                note: r.note,
            });
        }
        let profiles = profiles
            .into_iter()
            .map(|saved| ExportedProfile {
                name: saved.profile.name,
                mode: saved.profile.mode,
                rules: rules
                    .iter()
                    .zip(&apps)
                    .enumerate()
                    .map(|(i, (x, app))| {
                        let on = saved.rules.iter().any(|w| {
                            w.app == *app
                                && w.direction == x.direction
                                && w.action == x.action
                                && w.scope == x.scope
                        });
                        (i, on)
                    })
                    .collect(),
                networks: saved.profile.networks,
                dns: saved.dns,
                rules_on: Some(
                    saved
                        .rules
                        .into_iter()
                        .filter_map(|w| {
                            Some(ExportedRule {
                                app: program(w.app)?,
                                direction: w.direction,
                                action: w.action,
                                scope: w.scope,
                                enabled: true,
                                note: w.note,
                            })
                        })
                        .collect(),
                ),
            })
            .collect();
        to_value(RulesExport {
            format: RulesExport::FORMAT.into(),
            version: RulesExport::VERSION,
            exported_ms: now_unix_ms(),
            computer: std::env::var("COMPUTERNAME").unwrap_or_default(),
            mode,
            rules,
            profiles,
            dns: Some(dns),
        })
    }

    /// Rules, profiles and DNS filtering from an export: each rule set as it is
    /// there (the app's rule of that kind replaced), profiles added or replaced,
    /// DNS filtering's settings set as in the file (a pause here kept). The
    /// mode isn't changed: the profiles carry theirs.
    fn import_rules(&self, caller: &Caller, p: ImportParams) -> Result<Value, RpcError> {
        let (history, enforcer) = self.enforcement()?;
        if !p.dry_run {
            self.check_change(caller, "importing rules", true)?;
        }
        let e = p.export;
        if e.format != RulesExport::FORMAT {
            return Err(RpcError::invalid_params(
                "that isn't a win4tress rules file",
            ));
        }
        if e.version > RulesExport::VERSION {
            return Err(RpcError::invalid_params(
                "that rules file is from a newer win4tress: update this one first",
            ));
        }
        if e.rules.len() > 10 * MAX_BATCH || e.profiles.len() > 100 {
            return Err(RpcError::invalid_params("that rules file is too big"));
        }
        let now = now_unix_ms();
        let who = format!("{} (import)", caller.describe());
        let mut result = ImportResult::default();
        // As they were before the import: what's added, replaced or already there.
        let before = lock(&history.store).rules().map_err(storage_error)?;
        let known = if p.dry_run {
            self.monitor().known_apps()
        } else {
            Vec::new()
        };
        // The app on this PC for a program in the file (on a dry run, only one
        // already known).
        let app_for = |a: &ExportedApp| -> Option<AppId> {
            if !a.path.contains('\\') && a.path != w4_monitor::SYSTEM_APP {
                return None;
            }
            if p.dry_run {
                known
                    .iter()
                    .find(|k| k.path.eq_ignore_ascii_case(&a.path) && k.service == a.service)
                    .map(|k| k.id)
            } else {
                Some(self.monitor().program_app(
                    &a.path,
                    a.service.as_deref(),
                    a.package.as_deref(),
                    now,
                ))
            }
        };
        for r in &e.rules {
            let what = format!("{} ({:?}, {:?})", r.app.name, r.direction, r.action).to_lowercase();
            if !r.app.path.contains('\\') && r.app.path != w4_monitor::SYSTEM_APP {
                result.failed.push(format!("{what}: no program to name"));
                continue;
            }
            let app = app_for(&r.app);
            if r.app.service.is_none()
                && r.app.package.is_none()
                && r.app.path.contains('\\')
                && !std::path::Path::new(&r.app.path).exists()
                && !result.missing_apps.contains(&r.app.name)
            {
                result.missing_apps.push(r.app.name.clone());
            }
            let existing = app.and_then(|app| {
                before.iter().find(|x| {
                    x.app == app && x.direction == r.direction && x.scope.kind() == r.scope.kind()
                })
            });
            match &existing {
                Some(x)
                    if x.action == r.action
                        && x.scope == r.scope
                        && x.enabled == r.enabled
                        && x.expires.is_none() =>
                {
                    result.unchanged += 1;
                    continue;
                }
                Some(_) => result.replaced += 1,
                None => result.added += 1,
            }
            if p.dry_run {
                continue;
            }
            let Some(app) = app else { continue };
            let set = RuleSetParams {
                app,
                direction: r.direction,
                action: r.action,
                scope: r.scope.clone(),
                note: r.note.clone(),
                lasts: None,
            };
            let made = self.new_rule(enforcer, set).and_then(|(mut new, _)| {
                new.origin = Origin::Import;
                let mut store = lock(&history.store);
                let rule = store.set_rule(&new, now, &who).map_err(storage_error)?;
                if !r.enabled {
                    store
                        .edit_rule(
                            rule.id,
                            RuleEdit {
                                enabled: Some(false),
                                action: None,
                            },
                            now,
                            &who,
                            "updated",
                        )
                        .map_err(storage_error)?;
                }
                drop(store);
                self.decided(&new);
                Ok(rule.id)
            });
            match made {
                Ok(_) => {}
                Err(err) => {
                    match existing {
                        Some(_) => result.replaced -= 1,
                        None => result.added -= 1,
                    }
                    result.failed.push(format!("{what}: {}", err.message));
                }
            }
        }
        for prof in e.profiles {
            let name = match profile_name(&prof.name) {
                Ok(n) => n,
                Err(err) => {
                    result
                        .failed
                        .push(format!("profile {}: {}", prof.name, err.message));
                    continue;
                }
            };
            let networks = match checked_networks(prof.networks) {
                Ok(n) => n,
                Err(err) => {
                    result
                        .failed
                        .push(format!("profile {name}: {}", err.message));
                    continue;
                }
            };
            if let Some(Err(err)) = prof.dns.as_ref().map(crate::dnsfilter::check) {
                result
                    .failed
                    .push(format!("profile {name}: DNS filtering: {err}"));
                continue;
            }
            if !p.dry_run {
                // The rules on in it; a file from before profiles were exact
                // names them by place among the file's rules.
                let on: Vec<&ExportedRule> = match &prof.rules_on {
                    Some(list) => list.iter().collect(),
                    None => prof
                        .rules
                        .iter()
                        .filter(|(_, on)| **on)
                        .filter_map(|(i, _)| e.rules.get(*i))
                        .collect(),
                };
                let rules: Vec<ProfileRule> = on
                    .into_iter()
                    .filter_map(|x| {
                        Some(ProfileRule {
                            app: app_for(&x.app)?,
                            direction: x.direction,
                            action: x.action,
                            scope: x.scope.clone(),
                            origin: Origin::Import,
                            note: x.note.clone(),
                        })
                    })
                    .collect();
                let profile = Profile {
                    name: name.clone(),
                    mode: prof.mode,
                    rules: 0,
                    enabled: 0,
                    saved_ms: now,
                    networks,
                    dns_filtering: None,
                };
                lock(&history.store)
                    .import_profile(&profile, &rules, prof.dns.as_ref(), now, &who)
                    .map_err(storage_error)?;
            }
            result.profiles.push(name);
        }
        if let Some(dns) = e.dns {
            match (crate::dnsfilter::check(&dns), &self.usage) {
                (Err(err), _) => result.failed.push(format!("DNS filtering: {err}")),
                (Ok(()), None) => result
                    .failed
                    .push("DNS filtering: needs history".to_string()),
                (Ok(()), Some(usage)) if p.dry_run => {
                    result.dns = usage.settings().dns.without_pause() != dns.without_pause();
                }
                (Ok(()), Some(usage)) => match usage.set_dns(dns, &who) {
                    Ok(changed) => result.dns = changed,
                    Err(err) => result.failed.push(format!("DNS filtering: {err}")),
                },
            }
        }
        if !p.dry_run {
            tracing::info!(added = result.added, replaced = result.replaced, failed = result.failed.len(), by = %who, "rules imported");
            enforcer.changed();
            if let Some(a) = &self.autoprofile {
                a.reconsider();
            }
        }
        to_value(result)
    }

    /// Ends TCP connections: the ones given, or all of an app's (SPEC §10.2
    /// Connections). Windows can only end IPv4 ones.
    fn close_connections(&self, caller: &Caller, p: CloseParams) -> Result<Value, RpcError> {
        self.check_change(caller, "ending connections", false)?;
        if p.connections.len() > MAX_CLOSE {
            return Err(RpcError::invalid_params(format!(
                "at most {MAX_CLOSE} connections at a time"
            )));
        }
        let wanted: Vec<(SocketAddr, SocketAddr)> = if p.connections.is_empty() {
            let app = p
                .app
                .ok_or_else(|| RpcError::invalid_params("which app's connections?"))?;
            let pids: BTreeSet<u32> = self.monitor().pids_of(app).into_iter().collect();
            blocking(w4_sys::net::established_tcp)
                .into_iter()
                .filter(|c| pids.contains(&c.pid))
                .map(|c| (c.local, c.remote))
                .collect()
        } else {
            p.connections
        };
        let mut result = CloseResult::default();
        for (local, remote) in wanted {
            match (local, remote) {
                (SocketAddr::V4(l), SocketAddr::V4(r)) => match w4_sys::net::close_tcp(l, r) {
                    Ok(()) => result.closed += 1,
                    Err(e) => {
                        result.error.get_or_insert_with(|| format!("{remote}: {e}"));
                    }
                },
                _ => result.not_closable += 1,
            }
        }
        tracing::info!(closed = result.closed, app = ?p.app, by = %caller.describe(), "connections ended");
        to_value(result)
    }

    /// Every known app, with its file's best reputation answer and whether
    /// it's incognito.
    fn known_apps(&self) -> Vec<w4_ipc::api::KnownApp> {
        let mut apps = self.monitor().known_apps();
        let settings = self
            .usage
            .as_ref()
            .map(|u| u.settings())
            .unwrap_or_default();
        let best = self
            .reputation
            .as_ref()
            .map(|r| r.best_by_hash())
            .unwrap_or_default();
        for a in &mut apps {
            a.incognito = settings.incognito_apps.contains(&a.id);
            a.reputation = a
                .trust
                .sha256
                .as_deref()
                .and_then(|h| best.get(&h.to_ascii_lowercase()).cloned());
        }
        apps
    }

    fn security(&self) -> Result<&Arc<Security>, RpcError> {
        self.security.as_ref().ok_or_else(unavailable)
    }

    fn monitors(&self) -> MonitorsResult {
        let settings = self
            .usage
            .as_ref()
            .map(|u| u.settings())
            .unwrap_or_default();
        MonitorsResult {
            monitors: MONITORS
                .iter()
                .map(|m| MonitorState {
                    kind: m.kind.into(),
                    label: m.label.into(),
                    description: m.description.into(),
                    enabled: settings.monitor_enabled(m.kind),
                    default_severity: m.severity(),
                    severity: settings.severity_for(m.kind),
                })
                .collect(),
            threats: self
                .security
                .as_ref()
                .map(|s| s.threat_status())
                .unwrap_or_default(),
        }
    }

    fn set_device_known(&self, caller: &Caller, p: SetKnownParams) -> Result<Value, RpcError> {
        self.check_change(caller, "marking a device", false)?;
        let history = self.history.as_ref().ok_or_else(unavailable)?;
        let found = lock(&history.store)
            .set_device_known(&p.mac, p.known)
            .map_err(storage_error)?;
        if !found {
            return Err(RpcError::invalid_params(format!("no device {}", p.mac)));
        }
        to_value(self.security()?.devices())
    }

    /// Recent ranges come from the live buckets (per second); older ones from history.
    fn breakdown(&self, p: BreakdownParams, now_ms: i64) -> Result<Value, RpcError> {
        if p.to < p.from {
            return Err(RpcError::invalid_params("`to` is before `from`"));
        }
        let limit = p.limit.unwrap_or(DEFAULT_BREAKDOWN_LIMIT).min(MAX_LIMIT) as usize;
        let in_memory = p.from >= self.monitor().live_start(now_ms);
        match (&self.history, in_memory) {
            (Some(history), false) => {
                let exclude = self.excluded();
                let rows = lock(&history.store)
                    .usage_rows(p.from, p.to, &exclude, now_ms)
                    .map_err(storage_error)?;
                let monitor = self.monitor();
                to_value(build_breakdown(
                    rows,
                    &p.filter,
                    limit,
                    |id| monitor.app_ref(id),
                    |id| monitor.publisher(id),
                ))
            }
            // Without history, the live window is all there is.
            _ => to_value(self.monitor().breakdown(p.from, p.to, &p.filter, limit)),
        }
    }

    fn dns_top(&self, p: DnsTopParams) -> Result<Value, RpcError> {
        let limit = p.limit.unwrap_or(DEFAULT_DNS_TOP).min(MAX_LIMIT) as usize;
        let domains = match &self.history {
            Some(h) => lock(&h.store)
                .dns_top(p.from_ms, p.to_ms, p.app, limit)
                .map_err(storage_error)?,
            None => self.monitor().dns_top(p.from_ms, p.to_ms, p.app, limit),
        };
        to_value(DnsTopResult { domains })
    }
}

fn unavailable() -> RpcError {
    RpcError::new(
        RpcError::UNAVAILABLE,
        "history is unavailable; only the last 10 minutes are kept in memory",
    )
}

impl Handler for SvcHandler {
    fn handle(&self, caller: &Caller, method: &str, params: Value) -> Result<Value, RpcError> {
        let now = now_unix_ms();
        match method {
            method::HELLO => {
                let p: HelloParams = parse(params)?;
                tracing::debug!(client = %p.client, pid = ?caller.pid, protocol = p.protocol, "hello");
                to_value(HelloResult {
                    protocol: PROTOCOL_VERSION,
                    server_version: env!("CARGO_PKG_VERSION").into(),
                })
            }
            method::STATUS => to_value(self.status(now)),
            method::LIVE => {
                let p: LiveParams = parse(params)?;
                to_value(LiveResult {
                    samples: self.monitor().live(p.seconds, now),
                })
            }
            method::HISTORY => to_value(self.history_samples(parse(params)?, now)?),
            method::SETTINGS => to_value(
                self.usage
                    .as_ref()
                    .map(|u| u.settings())
                    .unwrap_or_default(),
            ),
            method::SETTINGS_SET => self.set_settings(caller, parse(params)?),
            method::PLAN_STATUS => to_value(self.usage.as_ref().and_then(|u| u.plan_status(now))),
            method::SESSION_INPUT => {
                let p: InputParams = parse(params)?;
                if let Some(usage) = &self.usage {
                    usage
                        .report_input(p.last_input_ms, now)
                        .map_err(|e| RpcError::new(RpcError::INTERNAL, e))?;
                }
                to_value(serde_json::json!({}))
            }
            method::SESSION_PROXY => {
                let p: UserProxyParams = parse(params)?;
                if p.proxy.len() > MAX_PROXY_TEXT {
                    return Err(RpcError::invalid_params("proxy description too long"));
                }
                if let Some(security) = &self.security {
                    security.report_user_proxy(p.proxy);
                }
                to_value(serde_json::json!({}))
            }
            method::MONITORS => to_value(self.monitors()),
            method::DEVICES => to_value(self.security()?.devices()),
            method::DEVICES_SCAN => {
                self.check_change(caller, "scanning the network", false)?;
                let security = self.security()?;
                security.scan_now();
                to_value(security.devices())
            }
            method::DEVICES_SET_KNOWN => self.set_device_known(caller, parse(params)?),
            method::BREAKDOWN => self.breakdown(parse(params)?, now),
            method::APPS => to_value(AppsResult {
                apps: self.monitor().apps(now),
            }),
            method::HOSTS => {
                let p: HostsParams = parse(params)?;
                let hosts = self
                    .monitor()
                    .hosts(p.app)
                    .ok_or_else(|| RpcError::not_found(format!("no app with id {}", p.app)))?;
                to_value(hosts)
            }
            method::CONNECTIONS => {
                let p: ConnectionsParams = parse_or_default(params)?;
                to_value(ConnectionsResult {
                    connections: self.monitor().connections(p.app, MAX_CONNECTIONS),
                })
            }
            method::DNS_LOG => {
                let p: DnsLogParams = parse_or_default(params)?;
                let limit = p.limit.unwrap_or(DEFAULT_DNS_LOG).min(MAX_DNS_LOG) as usize;
                let mut entries = self.monitor().dns_log(limit, p.app, p.query.as_deref());
                // What DNS filtering blocked: answered with nothing usable.
                if let Some(dns) = &self.dns {
                    for e in &mut entries {
                        if e.addrs.iter().all(IpAddr::is_unspecified) {
                            e.blocked_by = dns.blocked_by(&e.name, e.ts_ms);
                        }
                    }
                }
                to_value(DnsLogResult { entries })
            }
            method::DNS_FILTER => to_value(self.dns()?.status()),
            method::DNS_FILTER_UPDATE => {
                self.check_change(caller, "updating blocklists", false)?;
                let dns = self.dns()?;
                dns.update_now();
                to_value(dns.status())
            }
            method::DNS_FILTER_PAUSE => self.pause_dns(caller, parse_or_default(params)?),
            method::DNS_FILTER_LOG => {
                let p: DnsFilterLogParams = parse_or_default(params)?;
                let dns = Arc::clone(self.dns()?);
                let limit = p.limit.unwrap_or(500).min(5_000) as usize;
                let entries = blocking(|| {
                    tokio::runtime::Handle::current().block_on(dns.log(p.after, limit))
                });
                to_value(DnsFilterLogResult { entries })
            }
            method::DNS_TOP => self.dns_top(parse(params)?),
            method::DNS_STATS => self.dns_stats(parse(params)?),
            method::ALERTS => self.alerts(parse_or_default(params)?),
            method::ALERTS_MARK_READ => self.mark_read(parse(params)?),
            method::FIREWALL => to_value(self.enforcement()?.1.status()),
            method::RULES => self.rules(),
            method::RULES_SET => self.set_rule(caller, parse(params)?),
            method::RULES_DELETE => self.delete_rule(caller, parse(params)?),
            method::FIREWALL_SET_MODE => self.set_mode(caller, parse(params)?),
            method::FIREWALL_KEEP_CHANGES => self.keep_changes(caller, parse(params)?),
            method::FIREWALL_RESET => self.reset(caller),
            method::FIREWALL_VERDICTS => self.verdicts(parse_or_default(params)?, now),
            method::FIREWALL_BLOCK_ALL => self.block_all(caller, parse(params)?),
            method::FIREWALL_TURN_ON => self.turn_on(caller, parse_or_default(params)?),
            method::FIREWALL_APP_RULES => self.app_rules(parse(params)?),
            method::FIREWALL_BLOCKS => self.blocks(parse_or_default(params)?),
            method::RULES_APPLY => self.apply_rules(caller, parse(params)?),
            method::APPS_ALL => to_value(KnownAppsResult {
                apps: self.known_apps(),
            }),
            method::RULES_ENABLE => self.enable_rule(caller, parse(params)?),
            method::PROFILES => to_value(self.profiles()?),
            method::PROFILES_SAVE => self.save_profile(caller, parse(params)?),
            method::PROFILES_SWITCH => self.switch_profile(caller, parse(params)?),
            method::PROFILES_DELETE => self.delete_profile(caller, parse(params)?),
            method::PROFILES_SET_NETWORKS => self.set_networks(caller, parse(params)?),
            method::NETWORKS => self.networks(),
            method::RULES_EXPORT => self.export_rules(),
            method::RULES_IMPORT => self.import_rules(caller, parse(params)?),
            method::CONNECTIONS_CLOSE => self.close_connections(caller, parse(params)?),
            method::CLEANUP => to_value(self.cleanup()?.pass(now, false)),
            method::CLEANUP_RUN => {
                self.check_change(caller, "cleaning up rules", true)?;
                let cleanup = self.cleanup()?;
                to_value(blocking(|| cleanup.pass(now, true)))
            }
            method::REPUTATION => to_value(self.reputation()?.status()),
            method::REPUTATION_APP => {
                let p: AppParams = parse(params)?;
                to_value(self.reputation()?.app(p.app))
            }
            method::REPUTATION_SET_KEY => {
                let p: SetKeyParams = parse(params)?;
                self.check_change(caller, "setting an API key", false)?;
                let reputation = self.reputation()?;
                reputation
                    .set_key(p.service, p.key, &caller.describe())
                    .map_err(RpcError::invalid_params)?;
                to_value(reputation.status())
            }
            method::REPUTATION_CHECK => {
                let p: AppParams = parse(params)?;
                self.check_change(caller, "looking an app up", false)?;
                let reputation = self.reputation()?;
                if !self
                    .usage
                    .as_ref()
                    .is_some_and(|u| u.settings().reputation.enabled)
                {
                    return Err(unavailable_because(
                        "reputation lookups are off; turn them on in Settings first".into(),
                    ));
                }
                reputation.check_soon(p.app);
                to_value(reputation.app(p.app))
            }
            method::REPUTATION_SCAN => {
                let p: AppParams = parse(params)?;
                self.check_change(caller, "scanning a file", false)?;
                let reputation = self.reputation()?;
                to_value(blocking(|| reputation.scan(p.app)).map_err(unavailable_because)?)
            }
            method::REPUTATION_UPLOAD => {
                let p: UploadParams = parse(params)?;
                self.check_change(caller, "uploading a file", false)?;
                if !p.confirm {
                    return Err(RpcError::invalid_params(
                        "uploading needs confirm: true; the file becomes visible to VirusTotal's community",
                    ));
                }
                let reputation = self.reputation()?;
                let link = blocking(|| reputation.upload(p.app)).map_err(unavailable_because)?;
                to_value(UploadResult { link })
            }
            method::SETTINGS_REQUIRE_ELEVATION => self.require_elevation(caller, parse(params)?),
            method::PROMPTS => {
                to_value(self.prompter.as_ref().map(|p| p.list()).unwrap_or_default())
            }
            method::PROMPTS_DECIDE => self.decide(caller, parse(params)?),
            other => Err(RpcError::method_not_found(other)),
        }
    }
}

/// Runs a slow, blocking call (Windows Firewall changes) from a request: the
/// runtime moves other connections off this thread meanwhile.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// Windows' DNS Client: it does every app's lookups.
fn is_dns_client(app: &AppRecord) -> bool {
    app.service
        .as_deref()
        .is_some_and(|s| s.to_ascii_lowercase().split(", ").any(|n| n == "dnscache"))
}

/// `name`, or `*.name` for it and its subdomains.
fn valid_host_name(name: &str) -> bool {
    let base = name.strip_prefix("*.").unwrap_or(name);
    !base.is_empty()
        && base.len() <= 253
        && base.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// A rule's scope, checked and tidied: addresses in canonical form, names in
/// lower case, no duplicates.
fn checked_scope(scope: &Scope, action: Action, app: &AppRecord) -> Result<Scope, RpcError> {
    let hosts = |list: &[String]| -> Result<Vec<String>, RpcError> {
        let mut out: Vec<String> = Vec::new();
        for raw in list {
            let h = raw.trim();
            if h.is_empty() {
                continue;
            }
            let entry = match literal(h) {
                Some(address) => address,
                None => {
                    let name = h.trim_end_matches('.').to_ascii_lowercase();
                    if !valid_host_name(&name) {
                        return Err(RpcError::invalid_params(format!(
                            "{h:?} isn't an address, range, network or host name"
                        )));
                    }
                    name
                }
            };
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
        match out.len() {
            0 => Err(RpcError::invalid_params("name at least one host")),
            n if n > MAX_HOSTS => Err(RpcError::invalid_params(format!(
                "at most {MAX_HOSTS} hosts in one rule"
            ))),
            _ => Ok(out),
        }
    };
    match scope {
        Scope::Any => Ok(Scope::Any),
        Scope::Hosts { hosts: h } => Ok(Scope::Hosts { hosts: hosts(h)? }),
        Scope::Except { hosts: h } if action == Action::Block => {
            Ok(Scope::Except { hosts: hosts(h)? })
        }
        Scope::Except { .. } => Err(RpcError::invalid_params(
            "\"allow only these hosts\" is set with the block action (it blocks everything else)",
        )),
        Scope::Dns if action != Action::Block => Err(RpcError::invalid_params(
            "an app's own DNS can only be blocked",
        )),
        Scope::Dns if is_dns_client(app) => Err(RpcError::invalid_params(
            "Windows' DNS Client does every app's lookups; blocking its DNS would stop them all",
        )),
        Scope::Dns => Ok(Scope::Dns),
    }
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(RpcError::invalid_params)
}

/// Like [`parse`], but a missing (null) params object means all defaults.
fn parse_or_default<T: DeserializeOwned + Default>(params: Value) -> Result<T, RpcError> {
    if params.is_null() {
        Ok(T::default())
    } else {
        parse(params)
    }
}

fn to_value<T: Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| RpcError::new(RpcError::INTERNAL, e.to_string()))
}

/// A stored alert for clients: the app named as it was when the alert was raised.
pub fn alert(stored: StoredAlert, monitor: &Monitor) -> Alert {
    let app = stored.app.map(|id| {
        let mut app = monitor.app_ref(id);
        if let Some(name) = stored.app_name {
            app.name = name;
        }
        app
    });
    Alert {
        id: stored.id,
        ts_ms: stored.ts_ms,
        severity: stored.severity,
        app,
        body: stored.body,
        read: stored.read,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(service: Option<&str>) -> AppRecord {
        AppRecord {
            id: 1,
            key: "k".into(),
            path: r"C:\Windows\System32\svchost.exe".into(),
            description: None,
            company: None,
            version: None,
            package: None,
            service: service.map(Into::into),
            service_display: None,
            first_seen_ms: 0,
            last_seen_ms: 0,
            net_first_seen_ms: None,
            trust: Default::default(),
            own_dns_ms: None,
        }
    }

    #[test]
    fn host_lists_are_tidied_and_checked() {
        let hosts = |list: &[&str]| Scope::Hosts {
            hosts: list.iter().map(|s| s.to_string()).collect(),
        };
        assert_eq!(
            checked_scope(
                &hosts(&[
                    " Ads.Example.COM. ",
                    "8.8.8.8/32",
                    "ads.example.com",
                    "*.cdn.net"
                ]),
                Action::Block,
                &app(None)
            )
            .unwrap(),
            hosts(&["ads.example.com", "8.8.8.8", "*.cdn.net"])
        );
        assert!(checked_scope(&hosts(&["not a host!"]), Action::Block, &app(None)).is_err());
        assert!(checked_scope(&hosts(&["  "]), Action::Block, &app(None)).is_err());
        let except = Scope::Except {
            hosts: vec!["1.1.1.1".into()],
        };
        assert!(checked_scope(&except, Action::Allow, &app(None)).is_err());
        assert!(checked_scope(&except, Action::Block, &app(None)).is_ok());
    }

    #[test]
    fn own_dns_scope_rules() {
        assert!(checked_scope(&Scope::Dns, Action::Block, &app(None)).is_ok());
        assert!(checked_scope(&Scope::Dns, Action::Allow, &app(None)).is_err());
        // Never the DNS Client itself.
        assert!(checked_scope(&Scope::Dns, Action::Block, &app(Some("Dnscache"))).is_err());
        assert!(checked_scope(&Scope::Dns, Action::Block, &app(Some("NlaSvc, Dnscache"))).is_err());
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod handler_tests;
