//! Trust & reputation, tiers 2 and 3 (SPEC §12). Opt-in: with it on, apps'
//! file hashes are looked up at CIRCL hashlookup (known good → done), then
//! VirusTotal with the user's key, and MalwareBazaar if asked. On request, the
//! installed antivirus scans a file, or a file is uploaded to VirusTotal.
//!
//! VirusTotal's free API allows 4 lookups a minute and 500 a day: apps using
//! the network now go first, files CIRCL knows are skipped, and answers are
//! kept (unknowns re-checked after a day, others after a week).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use w4_core::firewall::{Action, Direction, Origin, Scope};
use w4_core::time::now_unix_ms;
use w4_ipc::api::{
    AlertBody, AppId, AppReputation, KeyService, RepVerdict, Reputation, ReputationSettings,
    ReputationStatus,
};
use w4_monitor::{AppRecord, Monitor};
use w4_store::{NewRule, Store};

use crate::enforcer::Enforcer;
use crate::usage::Usage;

pub const CIRCL: &str = "CIRCL hashlookup";
pub const VIRUSTOTAL: &str = "VirusTotal";
pub const MALWAREBAZAAR: &str = "MalwareBazaar";

const TICK: Duration = Duration::from_secs(15);
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Unknown files are asked about again after this long.
const UNKNOWN_AGAIN_MS: i64 = DAY_MS;
/// Answers about known files are refreshed after this long.
const KNOWN_AGAIN_MS: i64 = 7 * DAY_MS;
const VT_PER_MINUTE: usize = 4;
const VT_PER_DAY: u32 = 500;
/// CIRCL lookups per tick when VirusTotal isn't involved (politeness).
const CIRCL_PER_TICK: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// VirusTotal takes files up to 32 MB directly, and up to 650 MB through an
/// upload address.
const VT_DIRECT_UPLOAD: u64 = 32 * 1024 * 1024;
const VT_MAX_UPLOAD: u64 = 650 * 1024 * 1024;
/// How often an uploaded file's analysis is asked about.
const ANALYSIS_EVERY_MS: i64 = 60_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn key_name(service: KeyService) -> &'static str {
    match service {
        KeyService::VirusTotal => "virustotal",
        KeyService::AbuseCh => "abuse_ch",
    }
}

pub fn vt_link(sha256: &str) -> String {
    format!(
        "https://www.virustotal.com/gui/file/{}",
        sha256.to_ascii_lowercase()
    )
}

/// CIRCL hashlookup's answer: 200 with the file's record, 404 unknown.
pub fn parse_circl(
    sha256: &str,
    status: u32,
    body: &[u8],
    now_ms: i64,
) -> Result<Reputation, String> {
    let verdict_and_detail = match status {
        404 => (RepVerdict::Unknown, None),
        200 => {
            let v: Value =
                serde_json::from_slice(body).map_err(|e| format!("CIRCL's answer: {e}"))?;
            let name = v["FileName"]
                .as_str()
                .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string());
            match v.get("KnownMalicious").and_then(Value::as_str) {
                Some(by) => (
                    RepVerdict::Malicious,
                    Some(format!("known malicious ({by})")),
                ),
                None => (RepVerdict::KnownGood, name),
            }
        }
        s => return Err(format!("CIRCL hashlookup answered HTTP {s}")),
    };
    Ok(Reputation {
        sha256: sha256.to_ascii_lowercase(),
        source: CIRCL.into(),
        verdict: verdict_and_detail.0,
        detections: None,
        engines: None,
        detail: verdict_and_detail.1,
        link: None,
        checked_ms: now_ms,
    })
}

/// VirusTotal's verdict from engine counts: malicious at the alert threshold,
/// suspicious with any flag below it.
pub fn vt_verdict(flagged: u32, alert_at: u32) -> RepVerdict {
    match flagged {
        0 => RepVerdict::Clean,
        n if n >= alert_at.max(1) => RepVerdict::Malicious,
        _ => RepVerdict::Suspicious,
    }
}

/// Counts from VirusTotal's `last_analysis_stats` (a file report) or `stats`
/// (an analysis): (engines flagging it, engines with an opinion).
fn vt_counts(stats: &Value) -> (u32, u32) {
    let n = |k: &str| stats[k].as_u64().unwrap_or(0) as u32;
    let flagged = n("malicious");
    (
        flagged,
        flagged + n("suspicious") + n("undetected") + n("harmless"),
    )
}

/// VirusTotal's file report: 200 with stats, 404 unknown; 401, 429 and the
/// rest are errors (a bad key, the quota).
pub fn parse_vt(
    sha256: &str,
    status: u32,
    body: &[u8],
    alert_at: u32,
    now_ms: i64,
) -> Result<Reputation, String> {
    let mut r = Reputation {
        sha256: sha256.to_ascii_lowercase(),
        source: VIRUSTOTAL.into(),
        verdict: RepVerdict::Unknown,
        detections: None,
        engines: None,
        detail: None,
        link: None,
        checked_ms: now_ms,
    };
    match status {
        404 => Ok(r),
        200 => {
            let v: Value =
                serde_json::from_slice(body).map_err(|e| format!("VirusTotal's answer: {e}"))?;
            let attributes = &v["data"]["attributes"];
            let (flagged, engines) = vt_counts(&attributes["last_analysis_stats"]);
            r.verdict = vt_verdict(flagged, alert_at);
            r.detections = Some(flagged);
            r.engines = Some(engines);
            r.detail = attributes["popular_threat_classification"]["suggested_threat_label"]
                .as_str()
                .filter(|_| flagged > 0)
                .map(str::to_string);
            r.link = Some(vt_link(sha256));
            Ok(r)
        }
        401 => Err("VirusTotal refused the API key".into()),
        429 => Err("VirusTotal's quota is used up for now".into()),
        s => Err(format!("VirusTotal answered HTTP {s}")),
    }
}

/// MalwareBazaar: "ok" with the sample's family, or "hash_not_found".
pub fn parse_mb(sha256: &str, status: u32, body: &[u8], now_ms: i64) -> Result<Reputation, String> {
    if status == 401 || status == 403 {
        return Err("abuse.ch refused the key".into());
    }
    if status != 200 {
        return Err(format!("MalwareBazaar answered HTTP {status}"));
    }
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("MalwareBazaar's answer: {e}"))?;
    let (verdict, detail) = match v["query_status"].as_str() {
        Some("ok") => (
            RepVerdict::Malicious,
            v["data"][0]["signature"].as_str().map(str::to_string),
        ),
        Some("hash_not_found" | "no_results") => (RepVerdict::Unknown, None),
        Some(other) => return Err(format!("MalwareBazaar: {other}")),
        None => return Err("MalwareBazaar's answer has no status".into()),
    };
    Ok(Reputation {
        sha256: sha256.to_ascii_lowercase(),
        source: MALWAREBAZAAR.into(),
        verdict,
        detections: None,
        engines: None,
        detail,
        link: (verdict == RepVerdict::Malicious).then(|| {
            format!(
                "https://bazaar.abuse.ch/sample/{}/",
                sha256.to_ascii_lowercase()
            )
        }),
        checked_ms: now_ms,
    })
}

/// Whether an answer is due: none yet, an unknown older than a day, or a
/// known one older than a week.
pub fn due(answer: Option<&Reputation>, now_ms: i64) -> bool {
    match answer {
        None => true,
        Some(a) if a.verdict == RepVerdict::Unknown => now_ms - a.checked_ms >= UNKNOWN_AGAIN_MS,
        Some(a) => now_ms - a.checked_ms >= KNOWN_AGAIN_MS,
    }
}

/// The most telling answer: bad ones first, then VirusTotal's, then the
/// others; the latest of equals.
pub fn best(answers: &[Reputation]) -> Option<Reputation> {
    let rank = |r: &Reputation| match r.verdict {
        RepVerdict::Malicious => 6,
        RepVerdict::Suspicious => 5,
        RepVerdict::Clean if r.source == VIRUSTOTAL => 4,
        RepVerdict::Clean => 3,
        RepVerdict::KnownGood => 3,
        RepVerdict::Unknown => 0,
    };
    answers
        .iter()
        .max_by_key(|r| (rank(r), r.checked_ms))
        .cloned()
}

/// multipart/form-data with one file field, as VirusTotal's upload wants.
pub fn multipart(boundary: &str, file_name: &str, data: &[u8]) -> Vec<u8> {
    let safe_name: String = file_name
        .chars()
        .map(|c| if c == '"' || c.is_control() { '_' } else { c })
        .collect();
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// A short name for an antivirus, e.g. "Microsoft Defender".
fn scanner_name(registered: &str) -> String {
    if registered.contains("Defender") {
        "Microsoft Defender".into()
    } else {
        registered
            .trim_end_matches(" IOfficeAntiVirus implementation")
            .to_string()
    }
}

#[derive(Default)]
struct State {
    /// VirusTotal calls in the last minute.
    vt_minute: VecDeque<i64>,
    /// (local day, calls).
    vt_day: (i64, u32),
    /// No VirusTotal calls until then (quota).
    vt_pause_until: Option<i64>,
    /// Apps asked about by the user, first.
    priority: VecDeque<AppId>,
    /// Uploaded files whose analysis isn't done: (sha256, analysis id, last asked).
    analyses: Vec<(String, String, i64)>,
    last_error: Option<String>,
    last_check_ms: Option<i64>,
    queued: u32,
    /// (sha256, source) already alerted about.
    alerted: HashSet<(String, String)>,
}

pub struct ReputationService {
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    usage: Arc<Usage>,
    enforcer: Option<Arc<Enforcer>>,
    state: Mutex<State>,
    wake: Notify,
}

impl ReputationService {
    pub fn new(
        store: Arc<Mutex<Store>>,
        monitor: Arc<Mutex<Monitor>>,
        usage: Arc<Usage>,
        enforcer: Option<Arc<Enforcer>>,
    ) -> Arc<ReputationService> {
        Arc::new(ReputationService {
            store,
            monitor,
            usage,
            enforcer,
            state: Mutex::new(State::default()),
            wake: Notify::new(),
        })
    }

    fn settings(&self) -> ReputationSettings {
        self.usage.settings().reputation
    }

    fn key(&self, service: KeyService) -> Option<String> {
        let sealed = lock(&self.store).secret(key_name(service)).ok().flatten()?;
        let plain = w4_sys::secret::unprotect(&sealed).ok()?;
        String::from_utf8(plain).ok()
    }

    /// Stores (or removes) an API key, encrypted.
    pub fn set_key(
        &self,
        service: KeyService,
        key: Option<String>,
        who: &str,
    ) -> Result<(), String> {
        let key = key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
        if let Some(k) = &key {
            let ok = match service {
                KeyService::VirusTotal => k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()),
                KeyService::AbuseCh => {
                    (16..=128).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphanumeric())
                }
            };
            if !ok {
                return Err(match service {
                    KeyService::VirusTotal => {
                        "a VirusTotal API key is 64 hexadecimal characters".into()
                    }
                    KeyService::AbuseCh => "that doesn't look like an abuse.ch Auth-Key".into(),
                });
            }
        }
        let sealed = key
            .as_deref()
            .map(|k| w4_sys::secret::protect(k.as_bytes()))
            .transpose()?;
        lock(&self.store)
            .set_secret(key_name(service), sealed.as_deref(), now_unix_ms(), who)
            .map_err(|e| format!("saving the key: {e}"))?;
        if key.is_some() {
            self.wake.notify_one();
        }
        Ok(())
    }

    pub fn status(&self) -> ReputationStatus {
        let checked = lock(&self.store)
            .reputations()
            .map(|r| r.len())
            .unwrap_or(0);
        let virustotal_key = lock(&self.store)
            .secret("virustotal")
            .ok()
            .flatten()
            .is_some();
        let abuse_ch_key = lock(&self.store)
            .secret("abuse_ch")
            .ok()
            .flatten()
            .is_some();
        let s = lock(&self.state);
        let today = w4_store::local_day(
            now_unix_ms().div_euclid(60_000),
            w4_sys::time::utc_offset_minutes(),
        );
        ReputationStatus {
            enabled: self.settings().enabled,
            virustotal_key,
            abuse_ch_key,
            queued: s.queued,
            checked: checked as u32,
            virustotal_today: if s.vt_day.0 == today { s.vt_day.1 } else { 0 },
            last_error: s.last_error.clone(),
            last_check_ms: s.last_check_ms,
        }
    }

    /// Every answer for the app's file.
    pub fn app(&self, app: AppId) -> AppReputation {
        let sha256 = self.record(app).and_then(|r| r.trust.sha256);
        let results = sha256
            .as_deref()
            .and_then(|h| lock(&self.store).reputation(h).ok())
            .unwrap_or_default();
        AppReputation {
            app,
            sha256,
            results,
        }
    }

    fn record(&self, app: AppId) -> Option<AppRecord> {
        lock(&self.monitor)
            .app_records()
            .into_iter()
            .find(|r| r.id == app)
    }

    /// Looks the app up at the next tick, ahead of the others.
    pub fn check_soon(&self, app: AppId) {
        let mut s = lock(&self.state);
        s.priority.retain(|a| *a != app);
        s.priority.push_front(app);
        drop(s);
        self.wake.notify_one();
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            let _ = tokio::task::spawn_blocking(move || this.tick(now_unix_ms())).await;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(TICK) => {}
                _ = self.wake.notified() => {}
            }
        }
    }

    /// May VirusTotal be called now? Counts the call if so.
    fn vt_allowed(&self, now_ms: i64) -> bool {
        let today = w4_store::local_day(
            now_ms.div_euclid(60_000),
            w4_sys::time::utc_offset_minutes(),
        );
        let mut s = lock(&self.state);
        if s.vt_pause_until.is_some_and(|t| now_ms < t) {
            return false;
        }
        while s.vt_minute.front().is_some_and(|t| now_ms - t >= 60_000) {
            s.vt_minute.pop_front();
        }
        if s.vt_day.0 != today {
            s.vt_day = (today, 0);
        }
        if s.vt_minute.len() >= VT_PER_MINUTE || s.vt_day.1 >= VT_PER_DAY {
            return false;
        }
        s.vt_minute.push_back(now_ms);
        s.vt_day.1 += 1;
        true
    }

    fn error(&self, e: String) {
        tracing::warn!("reputation: {e}");
        lock(&self.state).last_error = Some(e);
    }

    /// The apps to look up, in order: asked for, using the network now, then
    /// the most recently seen.
    fn candidates(&self, now_ms: i64) -> Vec<(AppId, String, String)> {
        let (records, active, priority) = {
            let monitor = lock(&self.monitor);
            let active: HashSet<AppId> = monitor
                .apps(now_ms)
                .iter()
                .filter(|a| a.recent.recv + a.recent.sent > 0)
                .map(|a| a.id)
                .collect();
            let priority = lock(&self.state).priority.clone();
            (monitor.app_records(), active, priority)
        };
        let mut apps: Vec<(u8, i64, AppId, String, String)> = records
            .into_iter()
            .filter_map(|r| {
                let sha = r.trust.sha256.clone()?;
                let rank = if priority.contains(&r.id) {
                    0
                } else if active.contains(&r.id) {
                    1
                } else {
                    2
                };
                Some((rank, -r.last_seen_ms, r.id, sha, r.path))
            })
            .collect();
        apps.sort();
        let mut seen = HashSet::new();
        apps.into_iter()
            .filter(|(_, _, _, sha, _)| seen.insert(sha.clone()))
            .map(|(_, _, id, sha, path)| (id, sha, path))
            .collect()
    }

    fn tick(&self, now_ms: i64) {
        self.poll_analyses(now_ms);
        let settings = self.settings();
        if !settings.enabled {
            lock(&self.state).priority.clear();
            return;
        }
        let vt_key = self.key(KeyService::VirusTotal);
        let mb_key = settings
            .malwarebazaar
            .then(|| self.key(KeyService::AbuseCh))
            .flatten();
        let answers = lock(&self.store).reputations().unwrap_or_default();
        let candidates = self.candidates(now_ms);
        let pending: Vec<_> = candidates
            .iter()
            .filter(|(_, sha, _)| {
                let mine = answers.get(&sha.to_ascii_lowercase());
                let of = |source: &str| mine.and_then(|a| a.iter().find(|r| r.source == source));
                let known_good = of(CIRCL).is_some_and(|r| r.verdict == RepVerdict::KnownGood);
                due(of(CIRCL), now_ms)
                    || (!known_good && vt_key.is_some() && due(of(VIRUSTOTAL), now_ms))
                    || (!known_good && mb_key.is_some() && due(of(MALWAREBAZAAR), now_ms))
            })
            .cloned()
            .collect();
        lock(&self.state).queued = pending.len() as u32;
        let mut circl_calls = 0;
        for (app, sha, _) in pending {
            let mine = answers
                .get(&sha.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default();
            let of = |source: &str| mine.iter().find(|r| r.source == source).cloned();
            let mut circl = of(CIRCL);
            if due(circl.as_ref(), now_ms) {
                if circl_calls >= CIRCL_PER_TICK {
                    break;
                }
                circl_calls += 1;
                let url = format!("https://hashlookup.circl.lu/lookup/sha256/{sha}");
                match w4_sys::http::request(
                    "GET",
                    &url,
                    &[("Accept", "application/json")],
                    None,
                    MAX_ANSWER,
                    TIMEOUT,
                )
                .and_then(|r| parse_circl(&sha, r.status, &r.body, now_ms))
                {
                    Ok(answer) => {
                        self.record_answer(app, &answer, &settings);
                        circl = Some(answer);
                    }
                    Err(e) => {
                        self.error(e);
                        break;
                    }
                }
            }
            if circl.is_some_and(|c| c.verdict == RepVerdict::KnownGood) {
                continue;
            }
            let mut vt_called = false;
            if let Some(key) = &vt_key
                && due(of(VIRUSTOTAL).as_ref(), now_ms)
            {
                if !self.vt_allowed(now_ms) {
                    break;
                }
                vt_called = true;
                let url = format!("https://www.virustotal.com/api/v3/files/{sha}");
                match w4_sys::http::request(
                    "GET",
                    &url,
                    &[("x-apikey", key), ("Accept", "application/json")],
                    None,
                    MAX_ANSWER,
                    TIMEOUT,
                )
                .and_then(|r| parse_vt(&sha, r.status, &r.body, settings.alert_at, now_ms))
                {
                    Ok(answer) => self.record_answer(app, &answer, &settings),
                    Err(e) => {
                        if e.contains("quota") {
                            lock(&self.state).vt_pause_until = Some(now_ms + 60 * 60_000);
                        }
                        self.error(e);
                        break;
                    }
                }
            }
            if let Some(key) = &mb_key
                && due(of(MALWAREBAZAAR).as_ref(), now_ms)
            {
                let body = format!("query=get_info&hash={sha}");
                match w4_sys::http::request(
                    "POST",
                    "https://mb-api.abuse.ch/api/v1/",
                    &[
                        ("Auth-Key", key),
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ],
                    Some(body.as_bytes()),
                    MAX_ANSWER,
                    TIMEOUT,
                )
                .and_then(|r| parse_mb(&sha, r.status, &r.body, now_ms))
                {
                    Ok(answer) => self.record_answer(app, &answer, &settings),
                    Err(e) => {
                        self.error(e);
                        break;
                    }
                }
            }
            lock(&self.state).priority.retain(|a| *a != app);
            // One VirusTotal file per tick keeps within 4 a minute.
            if vt_called {
                break;
            }
        }
    }

    /// Keeps an answer; a bad one raises an alert once, and blocks the app's
    /// file (every app with that file) when the user asked for that.
    fn record_answer(&self, app: AppId, answer: &Reputation, settings: &ReputationSettings) {
        let previous = lock(&self.store)
            .reputation(&answer.sha256)
            .ok()
            .and_then(|all| all.into_iter().find(|r| r.source == answer.source));
        if let Err(e) = lock(&self.store).save_reputation(answer) {
            self.error(format!("saving a reputation answer: {e}"));
        }
        {
            let mut s = lock(&self.state);
            s.last_check_ms = Some(answer.checked_ms);
            s.last_error = None;
        }
        tracing::info!(app, source = %answer.source, verdict = ?answer.verdict, detections = ?answer.detections, "reputation");
        // Malicious: VirusTotal at the alert threshold, a MalwareBazaar or
        // antivirus find. The same answer again (a weekly refresh) is quiet.
        let bad = answer.verdict == RepVerdict::Malicious;
        let same = previous
            .is_some_and(|p| p.verdict == answer.verdict && p.detections == answer.detections);
        if !bad
            || same
            || !lock(&self.state)
                .alerted
                .insert((answer.sha256.clone(), answer.source.clone()))
        {
            return;
        }
        let block = settings.auto_block
            && (answer.detections.is_some_and(|d| d >= settings.block_at)
                || (answer.detections.is_none() && answer.verdict == RepVerdict::Malicious));
        let blocked = block && self.block_file(&answer.sha256, answer);
        lock(&self.monitor).raise(
            answer.checked_ms,
            Some(app),
            AlertBody::Reputation {
                sha256: answer.sha256.clone(),
                verdict: answer.verdict,
                source: answer.source.clone(),
                detections: answer.detections,
                engines: answer.engines,
                detail: answer.detail.clone(),
                blocked,
            },
        );
    }

    /// Blocks every app with this file both ways. Never win4tress itself.
    fn block_file(&self, sha256: &str, answer: &Reputation) -> bool {
        let Some(enforcer) = &self.enforcer else {
            return false;
        };
        let apps: Vec<AppRecord> = lock(&self.monitor)
            .app_records()
            .into_iter()
            .filter(|r| {
                r.trust
                    .sha256
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(sha256))
            })
            .filter(|r| r.path.contains('\\') && !enforcer.is_protected(&r.path))
            .collect();
        if apps.is_empty() {
            return false;
        }
        let note = match (answer.detections, answer.engines) {
            (Some(d), Some(e)) => format!("{}: {d} of {e} engines", answer.source),
            _ => answer.source.clone(),
        };
        let now = now_unix_ms();
        let mut store = lock(&self.store);
        for a in &apps {
            for direction in [Direction::Out, Direction::In] {
                let rule = NewRule {
                    app: a.id,
                    direction,
                    action: Action::Block,
                    scope: Scope::Any,
                    origin: Origin::Reputation,
                    note: Some(note.clone()),
                    expires: None,
                };
                if let Err(e) = store.set_rule(&rule, now, "reputation auto-block") {
                    tracing::warn!("auto-block of {} failed: {e}", a.path);
                }
            }
            tracing::warn!(path = %a.path, %note, "blocked for its reputation");
        }
        drop(store);
        enforcer.changed();
        true
    }

    /// The installed antivirus scans the app's file (tier 3).
    pub fn scan(&self, app: AppId) -> Result<AppReputation, String> {
        let record = self.record(app).ok_or("no such app")?;
        if !record.path.contains('\\') {
            return Err("this app has no file to scan".into());
        }
        let sha256 = record
            .trust
            .sha256
            .clone()
            .or_else(|| w4_sys::trust::sha256(&record.path));
        let results = w4_sys::av::scan(&record.path)?;
        if results.is_empty() {
            return Err("no antivirus is registered to scan files".into());
        }
        let now = now_unix_ms();
        let settings = self.settings();
        for r in results {
            let (verdict, detail) = match r.outcome {
                w4_sys::av::Outcome::Clean => (RepVerdict::Clean, None),
                w4_sys::av::Outcome::Threat { cleaned } => (
                    RepVerdict::Malicious,
                    Some(
                        if cleaned {
                            "threat found and cleaned"
                        } else {
                            "threat found"
                        }
                        .to_string(),
                    ),
                ),
                w4_sys::av::Outcome::Failed(e) => {
                    tracing::warn!(scanner = %r.scanner, "antivirus scan failed: {e}");
                    continue;
                }
            };
            let Some(sha) = &sha256 else { continue };
            let answer = Reputation {
                sha256: sha.to_ascii_lowercase(),
                source: scanner_name(&r.scanner),
                verdict,
                detections: None,
                engines: None,
                detail,
                link: None,
                checked_ms: now,
            };
            self.record_answer(app, &answer, &settings);
        }
        Ok(self.app(app))
    }

    /// Uploads the app's file to VirusTotal (tier 3); the analysis is fetched
    /// when it's done. Returns the file's VirusTotal page.
    pub fn upload(&self, app: AppId) -> Result<String, String> {
        let key = self
            .key(KeyService::VirusTotal)
            .ok_or("set a VirusTotal API key first")?;
        let record = self.record(app).ok_or("no such app")?;
        let size = std::fs::metadata(&record.path)
            .map_err(|e| format!("reading {}: {e}", record.path))?
            .len();
        if size > VT_MAX_UPLOAD {
            return Err("VirusTotal takes files up to 650 MB".into());
        }
        let data =
            std::fs::read(&record.path).map_err(|e| format!("reading {}: {e}", record.path))?;
        let sha256 = record
            .trust
            .sha256
            .clone()
            .or_else(|| w4_sys::trust::sha256(&record.path))
            .ok_or("can't hash the file")?;
        let now = now_unix_ms();
        if !self.vt_allowed(now) {
            return Err("VirusTotal's rate limit: try again in a minute".into());
        }
        let url = if size > VT_DIRECT_UPLOAD {
            let r = w4_sys::http::request(
                "GET",
                "https://www.virustotal.com/api/v3/files/upload_url",
                &[("x-apikey", &key)],
                None,
                MAX_ANSWER,
                TIMEOUT,
            )?;
            let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
            v["data"]
                .as_str()
                .ok_or(format!("no upload address (HTTP {})", r.status))?
                .to_string()
        } else {
            "https://www.virustotal.com/api/v3/files".to_string()
        };
        let boundary = format!("w4-{now:x}");
        let file_name = record.path.rsplit('\\').next().unwrap_or("file");
        let body = multipart(&boundary, file_name, &data);
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let r = w4_sys::http::request(
            "POST",
            &url,
            &[("x-apikey", &key), ("Content-Type", &content_type)],
            Some(&body),
            MAX_ANSWER,
            Duration::from_secs(300),
        )?;
        if r.status != 200 {
            return Err(match r.status {
                401 => "VirusTotal refused the API key".into(),
                429 => "VirusTotal's quota is used up for now".into(),
                s => format!("VirusTotal answered HTTP {s}"),
            });
        }
        let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
        let analysis = v["data"]["id"]
            .as_str()
            .ok_or("no analysis id in VirusTotal's answer")?;
        tracing::info!(path = %record.path, analysis, "uploaded to VirusTotal");
        lock(&self.state)
            .analyses
            .push((sha256.to_ascii_lowercase(), analysis.to_string(), now));
        Ok(vt_link(&sha256))
    }

    /// Asks about uploaded files' analyses, once a minute each.
    fn poll_analyses(&self, now_ms: i64) {
        let due: Vec<(String, String)> = lock(&self.state)
            .analyses
            .iter()
            .filter(|(_, _, asked)| now_ms - asked >= ANALYSIS_EVERY_MS)
            .map(|(sha, id, _)| (sha.clone(), id.clone()))
            .collect();
        if due.is_empty() {
            return;
        }
        let Some(key) = self.key(KeyService::VirusTotal) else {
            lock(&self.state).analyses.clear();
            return;
        };
        let settings = self.settings();
        for (sha, id) in due {
            if !self.vt_allowed(now_ms) {
                return;
            }
            let url = format!("https://www.virustotal.com/api/v3/analyses/{id}");
            let answer = w4_sys::http::request(
                "GET",
                &url,
                &[("x-apikey", &key)],
                None,
                MAX_ANSWER,
                TIMEOUT,
            )
            .and_then(|r| {
                let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
                Ok(v)
            });
            let mut s = lock(&self.state);
            for a in s.analyses.iter_mut().filter(|a| a.1 == id) {
                a.2 = now_ms;
            }
            drop(s);
            let v = match answer {
                Ok(v) => v,
                Err(e) => {
                    self.error(e);
                    continue;
                }
            };
            let attributes = &v["data"]["attributes"];
            if attributes["status"].as_str() != Some("completed") {
                continue;
            }
            lock(&self.state).analyses.retain(|a| a.1 != id);
            let (flagged, engines) = vt_counts(&attributes["stats"]);
            let answer = Reputation {
                sha256: sha.clone(),
                source: VIRUSTOTAL.into(),
                verdict: vt_verdict(flagged, settings.alert_at),
                detections: Some(flagged),
                engines: Some(engines),
                detail: None,
                link: Some(vt_link(&sha)),
                checked_ms: now_ms,
            };
            let app = lock(&self.monitor)
                .app_records()
                .into_iter()
                .find(|r| {
                    r.trust
                        .sha256
                        .as_deref()
                        .is_some_and(|h| h.eq_ignore_ascii_case(&sha))
                })
                .map(|r| r.id);
            if let Some(app) = app {
                self.record_answer(app, &answer, &settings);
            } else {
                let _ = lock(&self.store).save_reputation(&answer);
            }
        }
    }

    /// The best answer per hash, for the app lists.
    pub fn best_by_hash(&self) -> HashMap<String, Reputation> {
        lock(&self.store)
            .reputations()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(sha, answers)| best(&answers).map(|b| (sha, b)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "301C9EC7A9AADEE4D745E8FD4FA659DAFBBCC6B75B9FF491D14CBBDD840814E9";

    #[test]
    fn circl_answers() {
        let known =
            br#"{"FileName": "snap-hashlookup-import/usr/bin/openssl", "source": "snap:x"}"#;
        let r = parse_circl(SHA, 200, known, 5).unwrap();
        assert_eq!(
            (r.verdict, r.detail.as_deref()),
            (RepVerdict::KnownGood, Some("openssl"))
        );
        assert_eq!(r.sha256, SHA.to_ascii_lowercase());
        let unknown = br#"{"message": "Non existing SHA-256", "query": "x"}"#;
        assert_eq!(
            parse_circl(SHA, 404, unknown, 5).unwrap().verdict,
            RepVerdict::Unknown
        );
        let bad = br#"{"FileName": "x.exe", "KnownMalicious": "malshare"}"#;
        assert_eq!(
            parse_circl(SHA, 200, bad, 5).unwrap().verdict,
            RepVerdict::Malicious
        );
        assert!(parse_circl(SHA, 500, b"", 5).is_err());
    }

    #[test]
    fn virustotal_answers() {
        let report = br#"{"data":{"attributes":{
            "last_analysis_stats":{"malicious":7,"suspicious":1,"undetected":60,"harmless":2,"timeout":3,"type-unsupported":4},
            "popular_threat_classification":{"suggested_threat_label":"trojan.agent"}}}}"#;
        let r = parse_vt(SHA, 200, report, 3, 9).unwrap();
        assert_eq!(
            (r.verdict, r.detections, r.engines),
            (RepVerdict::Malicious, Some(7), Some(70))
        );
        assert_eq!(r.detail.as_deref(), Some("trojan.agent"));
        assert!(r.link.unwrap().ends_with(&SHA.to_ascii_lowercase()));
        assert_eq!(
            parse_vt(SHA, 404, b"{}", 3, 9).unwrap().verdict,
            RepVerdict::Unknown
        );
        assert!(parse_vt(SHA, 401, b"{}", 3, 9).unwrap_err().contains("key"));
        assert!(
            parse_vt(SHA, 429, b"{}", 3, 9)
                .unwrap_err()
                .contains("quota")
        );
        assert_eq!(vt_verdict(0, 3), RepVerdict::Clean);
        assert_eq!(vt_verdict(2, 3), RepVerdict::Suspicious);
        assert_eq!(vt_verdict(3, 3), RepVerdict::Malicious);
    }

    #[test]
    fn malwarebazaar_answers() {
        let found = br#"{"query_status":"ok","data":[{"signature":"AgentTesla"}]}"#;
        let r = parse_mb(SHA, 200, found, 1).unwrap();
        assert_eq!(
            (r.verdict, r.detail.as_deref()),
            (RepVerdict::Malicious, Some("AgentTesla"))
        );
        let none = br#"{"query_status":"hash_not_found"}"#;
        assert_eq!(
            parse_mb(SHA, 200, none, 1).unwrap().verdict,
            RepVerdict::Unknown
        );
        assert!(parse_mb(SHA, 401, b"", 1).is_err());
    }

    fn answer(source: &str, verdict: RepVerdict, at: i64) -> Reputation {
        Reputation {
            sha256: SHA.into(),
            source: source.into(),
            verdict,
            detections: None,
            engines: None,
            detail: None,
            link: None,
            checked_ms: at,
        }
    }

    #[test]
    fn answers_are_due_again_after_a_day_or_a_week() {
        assert!(due(None, 0));
        assert!(!due(
            Some(&answer(CIRCL, RepVerdict::Unknown, 0)),
            DAY_MS - 1
        ));
        assert!(due(Some(&answer(CIRCL, RepVerdict::Unknown, 0)), DAY_MS));
        assert!(!due(
            Some(&answer(VIRUSTOTAL, RepVerdict::Clean, 0)),
            6 * DAY_MS
        ));
        assert!(due(
            Some(&answer(VIRUSTOTAL, RepVerdict::Clean, 0)),
            7 * DAY_MS
        ));
    }

    #[test]
    fn the_most_telling_answer_wins() {
        let all = [
            answer(CIRCL, RepVerdict::KnownGood, 1),
            answer(VIRUSTOTAL, RepVerdict::Clean, 2),
            answer("Microsoft Defender", RepVerdict::Clean, 3),
        ];
        assert_eq!(best(&all).unwrap().source, VIRUSTOTAL);
        let mut worse = all.to_vec();
        worse.push(answer(MALWAREBAZAAR, RepVerdict::Malicious, 0));
        assert_eq!(best(&worse).unwrap().source, MALWAREBAZAAR);
        assert!(best(&[]).is_none());
    }

    #[test]
    fn uploads_are_one_file_field() {
        let body = multipart("b0", "a\"b.exe", b"MZ");
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with(
            "--b0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a_b.exe\"\r\n"
        ));
        assert!(text.ends_with("\r\nMZ\r\n--b0--\r\n"));
    }

    #[test]
    fn antivirus_names_are_short() {
        assert_eq!(
            scanner_name("Windows Defender IOfficeAntiVirus implementation"),
            "Microsoft Defender"
        );
        assert_eq!(
            scanner_name("Acme AV IOfficeAntiVirus implementation"),
            "Acme AV"
        );
    }
}
