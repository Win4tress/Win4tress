//! Spike 0.4: does every block produce a WFP drop notification that leads back
//! to the Windows Firewall rule responsible, and how quickly does it arrive?

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};

use crate::fw::{Firewall, NET_FW_PROFILE_TYPE2, PROFILES, RuleSpec};
use crate::wfp::{DropEvent, Engine};
use crate::{Cleanup, GROUP, HOST_A, HOST_B, Report, reach, spec, test_exe, write_report};

/// Notification latency the plan requires.
const MAX_LATENCY_MS: f64 = 250.0;
/// Audit subcategory "Filtering Platform Connection" (locale-independent GUID).
const AUDIT_FP_CONNECTION: &str = "{0CCE9226-69AE-11D9-BED3-505054503030}";
const ATTEMPTS: usize = 3;

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}

/// Turns WFP net-event collection back off if we turned it on.
struct RestoreCollect<'a> {
    engine: &'a Engine,
    turned_on: bool,
}

impl Drop for RestoreCollect<'_> {
    fn drop(&mut self) {
        if self.turned_on
            && let Err(e) = self.engine.set_collect_net_events(false)
        {
            eprintln!("couldn't turn net-event collection back off: {e:#}");
        }
    }
}

/// Whether failure auditing is on for the subcategory (`auditpol /r` CSV).
fn audit_failure_on(guid: &str) -> Option<bool> {
    let out = Command::new("auditpol")
        .args(["/get", &format!("/subcategory:{guid}"), "/r"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let row = text.lines().nth(1)?;
    // Columns: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    let setting = row.split(',').nth(4)?.to_ascii_lowercase();
    Some(setting.contains("failure"))
}

fn set_audit_failure(guid: &str, on: bool) -> bool {
    Command::new("auditpol")
        .args([
            "/set",
            &format!("/subcategory:{guid}"),
            if on {
                "/failure:enable"
            } else {
                "/failure:disable"
            },
        ])
        .status()
        .is_ok_and(|s| s.success())
}

#[derive(serde::Serialize)]
struct Attempt {
    ip: &'static str,
    start_ms: f64,
}

/// Puts each profile's outbound default back however the test ends.
struct RestoreDefaults<'a> {
    fw: &'a Firewall,
    originals: Vec<(&'static str, NET_FW_PROFILE_TYPE2, bool)>,
}

impl RestoreDefaults<'_> {
    fn restore(&self) -> Result<()> {
        for (_, p, block) in &self.originals {
            self.fw.set_default_outbound_block(*p, *block)?;
        }
        Ok(())
    }
}

impl Drop for RestoreDefaults<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            eprintln!("RESTORING OUTBOUND DEFAULTS FAILED: {e:#}");
        }
    }
}

/// Spike 0.4, default outbound block: for a few seconds the outbound default is
/// "block"; the test app (no rules) tries to connect, and the drop notification
/// must name Windows Firewall's default-outbound filter.
pub fn default_block(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let mut r = Report::default();
    let fw = Firewall::open()?;
    let engine = Engine::open()?;
    let _restore_collect = RestoreCollect {
        engine: &engine,
        turned_on: engine.collect_net_events()? == 0 && engine.set_collect_net_events(true).is_ok(),
    };
    let _cleanup = Cleanup(&fw);
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscription = engine.subscribe(Arc::clone(&events))?;
    let trace = crate::etw::WfpTrace::start()?;
    std::thread::sleep(Duration::from_secs(1));
    let exe = test_exe()?;
    let (baseline, _) = reach(&exe, HOST_A);
    r.check("test app connects normally", baseline, "", None);

    // Filter ids → names, captured while each block is in force: Windows rebuilds
    // filters when rules or defaults change, so later lookups can miss.
    let mut names: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let snapshot = |names: &mut BTreeMap<u64, (String, String)>| {
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            for f in engine.filters_at(layer).unwrap_or_default() {
                names.insert(f.id, (f.name, f.provider));
            }
        }
    };

    // Latency samples from an ordinary block rule first (no system-wide change).
    let rule = RuleSpec {
        program: Some(exe.display().to_string()),
        ..spec("latency")
    };
    fw.add(&rule)?;
    let rule_start = now_ms();
    for _ in 0..4 {
        let _ = reach(&exe, HOST_A);
        std::thread::sleep(Duration::from_millis(300));
    }
    snapshot(&mut names);
    fw.remove(&rule.name)?;

    let originals: Vec<_> = PROFILES
        .iter()
        .map(|&(name, p)| fw.default_outbound_block(p).map(|b| (name, p, b)))
        .collect::<Result<_>>()?;
    r.info(
        "outbound defaults before",
        format!(
            "{:?}",
            originals.iter().map(|(n, _, b)| (n, b)).collect::<Vec<_>>()
        ),
        None,
    );
    let guard = RestoreDefaults { fw: &fw, originals };

    // The window: as short as possible.
    let start = now_ms();
    for &(_, p) in &PROFILES {
        fw.set_default_outbound_block(p, true)?;
    }
    let switched_ms = now_ms() - start;
    let mut blocked = Vec::new();
    for _ in 0..20 {
        let t = now_ms();
        let (ok, _) = reach(&exe, HOST_A);
        if !ok {
            blocked.push(t);
            if blocked.len() == 2 {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    snapshot(&mut names);
    guard.restore()?;
    let window_ms = now_ms() - start;
    r.info(
        "block window",
        format!(
            "switching took {switched_ms:.0} ms; outbound default was block for {window_ms:.0} ms"
        ),
        Some(window_ms),
    );
    r.check(
        "test app blocked by the default alone",
        blocked.len() == 2,
        format!("{} blocked attempts", blocked.len()),
        None,
    );

    let restored: Vec<_> = PROFILES
        .iter()
        .map(|&(name, p)| fw.default_outbound_block(p).map(|b| (name, b)))
        .collect::<Result<_>>()?;
    let as_before = restored
        .iter()
        .zip(&guard.originals)
        .all(|((_, now), (_, _, was))| now == was);
    r.check(
        "outbound defaults restored",
        as_before,
        format!("{restored:?}"),
        None,
    );
    let (after, _) = reach(&exe, HOST_A);
    r.check("test app connects again", after, "", None);
    drop(guard);

    std::thread::sleep(Duration::from_millis(2500));
    drop(subscription);
    let etw: Vec<_> = trace
        .drops
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.app.to_ascii_lowercase().ends_with("\\w4fwtest.exe"))
        .collect();
    drop(trace);
    let mine = ours(&events);
    let name_of = |id: u64| {
        names
            .get(&id)
            .map(|(n, p)| format!("{n} ({p})"))
            .unwrap_or_else(|| "?".into())
    };

    // Real-time ETW: every block, quickly, with the filter id.
    let rule_phase: Vec<_> = etw.iter().filter(|e| e.event_ms < start).collect();
    let window_phase: Vec<_> = etw.iter().filter(|e| e.event_ms >= start).collect();
    let mut lat: Vec<f64> = etw.iter().map(|e| e.received_ms - e.event_ms).collect();
    lat.sort_by(f64::total_cmp);
    r.check(
        "ETW event for every rule block",
        rule_phase.len() >= 4,
        format!(
            "{} events for 4 attempts (from {rule_start:.0})",
            rule_phase.len()
        ),
        None,
    );
    if let (Some(max), Some(median)) = (lat.last().copied(), lat.get(lat.len() / 2).copied()) {
        r.check(
            "ETW latency under 250 ms",
            max < 250.0,
            format!(
                "drop → callback: median {median:.0} ms, max {max:.0} ms ({} events)",
                lat.len()
            ),
            Some(max),
        );
    }
    r.info(
        "ETW: rule-phase filters",
        format!(
            "{:?}",
            rule_phase
                .iter()
                .map(|e| name_of(e.filter_id))
                .collect::<BTreeSet<_>>()
        ),
        None,
    );
    let etw_default = !window_phase.is_empty()
        && window_phase.iter().all(|e| {
            names
                .get(&e.filter_id)
                .is_some_and(|(n, _)| n == "Default Outbound")
        });
    r.check(
        "ETW: the default-block drop names the default-outbound filter",
        etw_default,
        format!(
            "{:?}",
            window_phase
                .iter()
                .map(|e| (e.filter_id, name_of(e.filter_id)))
                .collect::<Vec<_>>()
        ),
        None,
    );
    // The batched WFP subscription, for comparison.
    let net_window: Vec<_> = mine.iter().filter(|e| e.event_ms >= start).collect();
    let net_default = !net_window.is_empty()
        && net_window.iter().all(|e| {
            names
                .get(&e.filter_id)
                .is_some_and(|(n, _)| n == "Default Outbound")
        });
    r.check(
        "net event: the default-block drop names the default-outbound filter",
        net_default,
        format!(
            "{:?}",
            net_window
                .iter()
                .map(|e| (e.filter_id, name_of(e.filter_id)))
                .collect::<Vec<_>>()
        ),
        None,
    );
    if let Some(max) = mine
        .iter()
        .map(|e| e.received_ms - e.event_ms)
        .reduce(f64::max)
    {
        r.info(
            "net event latency (batched)",
            format!("max {max:.0} ms"),
            Some(max),
        );
    }
    // Anything else that tried to open a connection in the window was blocked too.
    let others: Vec<String> = events
        .lock()
        .map(|v| {
            v.iter()
                .filter(|e| {
                    !e.app.to_ascii_lowercase().ends_with("\\w4fwtest.exe")
                        && e.event_ms >= start
                        && e.event_ms <= start + window_ms + 1_000.0
                })
                .map(|e| {
                    format!(
                        "{} → {}:{}",
                        e.app.rsplit('\\').next().unwrap_or(""),
                        e.remote,
                        e.remote_port
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    r.info(
        "other apps blocked during the window",
        format!("{} drop(s): {others:?}", others.len()),
        None,
    );
    let _ = std::fs::remove_file(&exe);

    write_report(out, &r)?;
    let failed = r.checks.iter().filter(|c| c.result == "fail").count();
    println!(
        "\n{} checks, {failed} failed. Results in {}",
        r.checks.len(),
        out.display()
    );
    Ok(())
}

/// Blocks the test app, makes the attempts, and records when each started.
pub fn attempts_only(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let fw = Firewall::open()?;
    let _cleanup = Cleanup(&fw);
    fw.clear_group(GROUP)?;
    let exe = test_exe()?;
    let rule = RuleSpec {
        program: Some(exe.display().to_string()),
        ..spec("attempts")
    };
    fw.add(&rule)?;
    let attempts = attempt(&exe);
    fw.remove(&rule.name)?;
    let _ = std::fs::remove_file(&exe);
    std::fs::write(
        out.join("attempts.json"),
        serde_json::to_string_pretty(&attempts)?,
    )?;
    println!("{} attempts recorded", attempts.len());
    Ok(())
}

/// Blocked connection attempts by the test app, a little apart.
fn attempt(exe: &Path) -> Vec<Attempt> {
    let mut out = Vec::new();
    for _ in 0..ATTEMPTS {
        for ip in [HOST_A, HOST_B] {
            let start_ms = now_ms();
            let _ = reach(exe, ip);
            out.push(Attempt { ip, start_ms });
            std::thread::sleep(Duration::from_millis(400));
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    out
}

fn ours(events: &Mutex<Vec<DropEvent>>) -> Vec<DropEvent> {
    events
        .lock()
        .map(|v| {
            v.iter()
                .filter(|e| e.app.to_ascii_lowercase().ends_with("\\w4fwtest.exe"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn run(out: &Path, idle_secs: u64) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let mut r = Report::default();
    let fw = Firewall::open()?;
    let _cleanup = Cleanup(&fw);
    fw.clear_group(GROUP)?;
    let engine = Engine::open()?;

    let collect = engine.collect_net_events()?;
    let keywords = engine.keywords()?;
    r.info(
        "WFP net-event settings",
        format!("collect net events = {collect}, match-any keywords = 0x{keywords:x}"),
        None,
    );
    let _restore = RestoreCollect {
        engine: &engine,
        turned_on: collect == 0 && engine.set_collect_net_events(true).is_ok(),
    };
    let audit_before = audit_failure_on(AUDIT_FP_CONNECTION);
    r.info(
        "audit: Filtering Platform Connection failures",
        format!("{audit_before:?}"),
        None,
    );

    let events = Arc::new(Mutex::new(Vec::new()));
    let subscription = engine.subscribe(Arc::clone(&events))?;

    // A block rule for the test app only.
    let exe = test_exe()?;
    let rule = RuleSpec {
        program: Some(exe.display().to_string()),
        ..spec("blocks")
    };
    fw.add(&rule)?;
    let rule_filters: Vec<_> = engine
        .filters_at(FWPM_LAYER_ALE_AUTH_CONNECT_V4)?
        .into_iter()
        .filter(|f| f.name == rule.name)
        .collect();
    r.info(
        "WFP filters for our rule (connect, IPv4)",
        format!(
            "{} filter(s): {:?}",
            rule_filters.len(),
            rule_filters
                .iter()
                .map(|f| (f.id, &f.action, &f.provider))
                .collect::<Vec<_>>()
        ),
        None,
    );

    let mut attempts = attempt(&exe);
    let mut mine = ours(&events);
    let mut audit_changed = false;
    if mine.is_empty() && audit_before == Some(false) {
        // Some Windows builds only report drops while failure auditing is on.
        audit_changed = set_audit_failure(AUDIT_FP_CONNECTION, true);
        r.info(
            "no notifications without auditing; retrying with failure auditing on",
            format!("set: {audit_changed}"),
            None,
        );
        attempts = attempt(&exe);
        mine = ours(&events);
    }
    r.check(
        "a drop notification for every blocked attempt",
        mine.len() >= attempts.len(),
        format!(
            "{} attempts, {} notifications for the test app",
            attempts.len(),
            mine.len()
        ),
        None,
    );

    // Map each notification to a filter, and the filter to our rule.
    let mut mapped = 0;
    let mut latencies = Vec::new();
    let mut seen_filters = BTreeMap::new();
    for e in &mine {
        let f = engine.filter(e.filter_id);
        if let Ok(f) = &f
            && f.name == rule.name
        {
            mapped += 1;
        }
        seen_filters.entry(e.filter_id).or_insert(f.ok());
        latencies.push(e.received_ms - e.event_ms);
    }
    r.check(
        "each notification maps to our rule",
        !mine.is_empty() && mapped == mine.len(),
        format!(
            "{mapped} of {} via filter name; filters: {:?}",
            mine.len(),
            seen_filters
                .values()
                .flatten()
                .map(|f| (
                    f.id,
                    f.name.clone(),
                    f.provider.clone(),
                    f.description.clone(),
                    f.provider_data.clone()
                ))
                .collect::<Vec<_>>()
        ),
        None,
    );
    if let Some(e) = mine.first() {
        r.info(
            "what a notification says",
            format!(
                "app {}, remote {}:{}, protocol {}, layer {}, direction {}",
                e.app, e.remote, e.remote_port, e.protocol, e.layer_id, e.direction
            ),
            None,
        );
        let ips_ok = mine
            .iter()
            .all(|e| e.remote == HOST_A || e.remote == HOST_B)
            && mine.iter().all(|e| e.remote_port == 443);
        r.check("remote address and port are right", ips_ok, "", None);
    }
    if !latencies.is_empty() {
        latencies.sort_by(f64::total_cmp);
        let max = latencies.last().copied().unwrap_or_default();
        let median = latencies[latencies.len() / 2];
        r.check(
            "notification latency under 250 ms",
            max < MAX_LATENCY_MS,
            format!("from drop to our callback: median {median:.1} ms, max {max:.1} ms"),
            Some(max),
        );
        // Also from the moment the app started connecting, which includes process start.
        let from_attempt: Vec<f64> = attempts
            .iter()
            .filter_map(|a| {
                mine.iter()
                    .filter(|e| e.remote == a.ip && e.received_ms >= a.start_ms)
                    .map(|e| e.received_ms - a.start_ms)
                    .reduce(f64::min)
            })
            .collect();
        r.info(
            "from starting the app to the notification",
            format!(
                "{:?} ms",
                from_attempt.iter().map(|v| v.round()).collect::<Vec<_>>()
            ),
            None,
        );
    }
    fw.remove(&rule.name)?;
    let _ = std::fs::remove_file(&exe);
    if audit_changed {
        let restored = set_audit_failure(AUDIT_FP_CONNECTION, false);
        r.info("audit setting restored", format!("{restored}"), None);
    }

    // Other drops while idle: what the default block and Windows' own filters look like.
    std::thread::sleep(Duration::from_secs(idle_secs));
    drop(subscription);
    let all = events.lock().map(|v| v.clone()).unwrap_or_default();
    let mut by_filter: BTreeMap<u64, (usize, DropEvent)> = BTreeMap::new();
    for e in all
        .iter()
        .filter(|e| !e.app.to_ascii_lowercase().ends_with("\\w4fwtest.exe"))
    {
        by_filter.entry(e.filter_id).or_insert((0, e.clone())).0 += 1;
    }
    let mut ranked: Vec<_> = by_filter.into_iter().collect();
    ranked.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
    r.info(
        "other drops recorded",
        format!(
            "{} drops by {} filters",
            all.len() - mine.len(),
            ranked.len()
        ),
        None,
    );
    for (id, (n, sample)) in ranked.iter().take(12) {
        let f = engine.filter(*id).ok();
        r.info(
            &format!("filter {id}"),
            format!(
                "{n} drops; {}; sample: {} {}:{} → local port {}, direction {}, app {}",
                f.as_ref()
                    .map(|f| format!(
                        "\"{}\" ({}, {}, {})",
                        f.name, f.provider, f.action, f.description
                    ))
                    .unwrap_or("filter not found".into()),
                sample.protocol,
                sample.remote,
                sample.remote_port,
                sample.local_port,
                sample.direction,
                if sample.app.is_empty() {
                    "(none)"
                } else {
                    &sample.app
                },
            ),
            None,
        );
    }

    // Windows Firewall's catch-all filters at outbound connect: with outbound
    // default "block", these are what a drop would name.
    let connect = engine.filters_at(FWPM_LAYER_ALE_AUTH_CONNECT_V4)?;
    let mut providers: BTreeMap<String, usize> = BTreeMap::new();
    for f in &connect {
        *providers
            .entry(if f.provider.is_empty() {
                "(none)".into()
            } else {
                f.provider.clone()
            })
            .or_default() += 1;
    }
    r.info(
        "filters at outbound connect (IPv4) by provider",
        format!("{providers:?}"),
        None,
    );
    let defaults: Vec<_> = connect
        .iter()
        .filter(|f| {
            let n = f.name.to_ascii_lowercase();
            n.contains("default") || n.contains("query user") || n.contains("boot time")
        })
        .cloned()
        .collect();
    for f in &defaults {
        r.info(
            &format!("catch-all filter {}", f.id),
            format!(
                "\"{}\" ({}, {}, {})",
                f.name, f.provider, f.action, f.description
            ),
            None,
        );
    }
    r.filters = defaults;
    r.drops = all;

    write_report(out, &r)?;
    let failed = r.checks.iter().filter(|c| c.result == "fail").count();
    println!(
        "\n{} checks, {failed} failed. Results in {}",
        r.checks.len(),
        out.display()
    );
    Ok(())
}
