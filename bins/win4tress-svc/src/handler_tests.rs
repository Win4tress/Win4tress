//! The service's handling of temporary rules, export and import, profiles and
//! ending connections, end to end through `handle`, with a stand-in for
//! Windows Firewall.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use w4_core::firewall::{
    Action, Direction, Expiry, FirewallState, Mode, NetworkCategory, Origin, ProfileState, Scope,
};
use w4_core::time::now_unix_ms;
use w4_enforce::model::{PROFILES_ALL, PROTOCOL_ANY};
use w4_enforce::{ActualRule, AddressSet, Change, EnforcementBackend, WindowsRule};
use w4_ipc::api::{
    CloseResult, ImportResult, NetworkMatch, Profile, ProfilesResult, Rule, RulesExport,
    RulesResult, method,
};
use w4_ipc::{Caller, CallerToken, Handler, RpcError};
use w4_monitor::{Monitor, Resolver};
use w4_store::{NewRule, Store};

use super::{History, SvcHandler};
use crate::enforcer::Enforcer;
use crate::usage::Usage;

/// Windows Firewall as a list: what's applied is what's listed.
#[derive(Default)]
struct FakeFirewall {
    rules: Mutex<Vec<ActualRule>>,
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

impl EnforcementBackend for FakeFirewall {
    fn group(&self) -> &str {
        "win4tress (test)"
    }
    fn list(&self) -> w4_enforce::Result<Vec<ActualRule>> {
        Ok(self.rules.lock().unwrap().clone())
    }
    fn apply(&self, change: &Change) -> w4_enforce::Result<()> {
        let mut rules = self.rules.lock().unwrap();
        match change {
            Change::Create(w) => rules.push(written(w)),
            Change::Update { name, rule } | Change::Recreate { name, rule } => {
                rules.retain(|r| &r.name != name);
                rules.push(written(rule));
            }
            Change::Delete { name } => rules.retain(|r| &r.name != name),
        }
        Ok(())
    }
    fn set_group_enabled(&self, _enabled: bool) -> w4_enforce::Result<()> {
        Ok(())
    }
    fn state(&self) -> w4_enforce::Result<FirewallState> {
        Ok(FirewallState {
            profiles: vec![ProfileState {
                name: "private".into(),
                active: true,
                firewall_on: true,
                inbound_default_block: true,
                outbound_default_block: false,
            }],
            policy_override: false,
            rule_count: 0,
        })
    }
    fn others(&self) -> w4_enforce::Result<Vec<ActualRule>> {
        Ok(Vec::new())
    }
    fn turn_on(&self, _profile: &str) -> w4_enforce::Result<()> {
        Ok(())
    }
    fn set_defaults(&self, _p: &str, _i: bool, _o: bool) -> w4_enforce::Result<()> {
        Ok(())
    }
}

struct NoResolver;

impl Resolver for NoResolver {
    fn image_path(&self, _pid: u32) -> Option<String> {
        None
    }
    fn to_win32(&self, nt_path: &str) -> String {
        nt_path.to_string()
    }
}

struct Service {
    handler: SvcHandler,
    enforcer: Arc<Enforcer>,
    firewall: Arc<FakeFirewall>,
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    usage: Arc<Usage>,
}

fn service() -> Service {
    let now = now_unix_ms();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let monitor = Arc::new(Mutex::new(Monitor::new(Box::new(NoResolver), now)));
    let firewall = Arc::new(FakeFirewall::default());
    let enforcer = Enforcer::new(
        Arc::clone(&firewall) as Arc<dyn EnforcementBackend>,
        Arc::clone(&store),
        Arc::clone(&monitor),
        Vec::new(),
    );
    let usage = Usage::new(Arc::clone(&store), Arc::clone(&monitor));
    let handler = SvcHandler {
        monitor: Arc::clone(&monitor),
        collector: w4_etw::HealthProbe::idle("win4tress-test"),
        adapters_at_start: Vec::new(),
        history: Some(History {
            store: Arc::clone(&store),
            path: PathBuf::from("memory"),
        }),
        enforcer: Some(Arc::clone(&enforcer)),
        prompter: None,
        usage: Some(Arc::clone(&usage)),
        security: None,
        reputation: None,
        cleanup: None,
        dns: None,
        autoprofile: None,
    };
    Service {
        handler,
        enforcer,
        firewall,
        store,
        monitor,
        usage,
    }
}

fn admin() -> Caller {
    Caller {
        pid: None,
        token: Some(CallerToken {
            user: "S-1-5-21-1-2-3-1001".into(),
            admin: true,
            elevated: false,
        }),
    }
}

impl Service {
    fn app(&self, path: &str) -> u32 {
        self.monitor
            .lock()
            .unwrap()
            .program_app(path, None, None, now_unix_ms())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.handler.handle(&admin(), method, params)
    }

    fn rule(&self, params: Value) -> Result<Rule, RpcError> {
        self.call(method::RULES_SET, params)
            .map(|v| serde_json::from_value(v).unwrap())
    }

    fn rules(&self) -> Vec<Rule> {
        let r: RulesResult =
            serde_json::from_value(self.call(method::RULES, Value::Null).unwrap()).unwrap();
        r.rules
    }

    fn profiles(&self) -> ProfilesResult {
        serde_json::from_value(self.call(method::PROFILES, Value::Null).unwrap()).unwrap()
    }

    /// DNS filtering on or off, with these names always allowed, and paused.
    fn set_dns(&self, enabled: bool, allow: &[&str], paused_until_ms: Option<i64>) {
        let mut settings = self.usage.settings();
        settings.dns.enabled = enabled;
        settings.dns.allow = allow.iter().map(|a| a.to_string()).collect();
        settings.dns.paused_until_ms = paused_until_ms;
        self.usage.set_settings(settings, "test").unwrap();
    }
}

/// The test's own program: running, so "until it quits" is allowed for it.
fn this_program() -> String {
    std::env::current_exe().unwrap().display().to_string()
}

#[test]
fn temporary_rules_are_checked_set_and_ended() {
    let s = service();
    let gone = s.app(r"C:\Nowhere\gone.exe");
    let me = s.app(&this_program());

    // Blocked for good, then allowed for an hour: the same rule, going back.
    s.rule(json!({ "app": gone, "direction": "out", "action": "block" }))
        .unwrap();
    let allowed = s
        .rule(json!({ "app": gone, "direction": "out", "action": "allow",
                      "lasts": { "kind": "minutes", "minutes": 60 } }))
        .unwrap();
    assert_eq!(allowed.action, Action::Allow);
    assert_eq!(allowed.revert, Some(Action::Block));
    let Some(Expiry::At { ms }) = allowed.expires else {
        panic!("{allowed:?}")
    };
    let hour = ms - now_unix_ms();
    assert!((3_590_000..=3_600_000).contains(&hour), "{hour}");

    // What's refused: until it quits for a program that isn't running, a
    // temporary rule for some hosts, and no time at all.
    let refused = |params: Value| s.rule(params).unwrap_err().message;
    assert!(
        refused(json!({ "app": gone, "direction": "out", "action": "block",
                        "lasts": { "kind": "app_quits" } }))
        .contains("isn't running")
    );
    assert!(
        refused(json!({ "app": gone, "direction": "out", "action": "block",
                        "scope": { "kind": "hosts", "hosts": ["example.com"] },
                        "lasts": { "kind": "minutes", "minutes": 5 } }))
        .contains("all of an app's connections")
    );
    assert!(
        refused(json!({ "app": gone, "direction": "out", "action": "block",
                        "lasts": { "kind": "minutes", "minutes": 0 } }))
        .contains("1 to")
    );

    // Until it quits, for a program that's running; until a restart.
    let quits = s
        .rule(json!({ "app": me, "direction": "out", "action": "block",
                      "lasts": { "kind": "app_quits" } }))
        .unwrap();
    assert_eq!(quits.expires, Some(Expiry::AppQuits));
    let restart = s
        .rule(json!({ "app": me, "direction": "in", "action": "block",
                      "lasts": { "kind": "restart" } }))
        .unwrap();
    let Some(Expiry::Restart { boot_ms }) = restart.expires else {
        panic!("{restart:?}")
    };
    assert_eq!(Some(boot_ms), w4_sys::time::boot_ms());

    // A pass: nothing is over yet, and every rule is in Windows Firewall.
    s.enforcer.sync().unwrap();
    assert_eq!(s.rules().len(), 3);
    let blocking = |app: &str| {
        s.firewall
            .rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.program.as_deref().is_some_and(|p| p.contains(app)))
            .map(|r| (r.inbound, r.block))
            .collect::<Vec<_>>()
    };
    assert_eq!(blocking("gone.exe"), [(false, false)]);

    // The hour is up (made so in history): blocked again, for good, in
    // Windows Firewall too, and audited as the service's own change.
    s.store
        .lock()
        .unwrap()
        .set_rule(
            &NewRule {
                app: gone,
                direction: Direction::Out,
                action: Action::Allow,
                scope: Scope::Any,
                origin: Origin::User,
                note: None,
                expires: Some(Expiry::At { ms: 1 }),
            },
            now_unix_ms(),
            "test",
        )
        .unwrap();
    s.enforcer.sync().unwrap();
    let back = s.rules().into_iter().find(|r| r.app.id == gone).unwrap();
    assert_eq!(
        (back.action, back.expires, back.revert),
        (Action::Block, None, None)
    );
    assert_eq!(blocking("gone.exe"), [(false, true)]);
    let audit = s.store.lock().unwrap().rule_audit(20).unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.change == "expired" && e.who == "win4tress (time up)"),
        "{audit:?}"
    );
    // This program still runs, and it's the same boot: those stay.
    assert_eq!(s.rules().iter().filter(|r| r.app.id == me).count(), 2);
}

#[test]
fn rules_and_profiles_go_to_another_pc_and_back() {
    let a = service();
    let edge = a.app(r"C:\Program Files\Edge\msedge.exe");
    let game = a.app(r"C:\Games\game.exe");
    let tool = a.app(r"C:\Tools\tool.exe");
    a.rule(json!({ "app": edge, "direction": "out", "action": "block",
                   "scope": { "kind": "hosts", "hosts": ["ads.example.com"] } }))
        .unwrap();
    let game_rule = a
        .rule(json!({ "app": game, "direction": "out", "action": "block" }))
        .unwrap();
    // Temporarily allowed: exported as the block it goes back to.
    a.rule(json!({ "app": game, "direction": "out", "action": "allow",
                   "lasts": { "kind": "minutes", "minutes": 30 } }))
        .unwrap();
    // Temporary with nothing to go back to: left out.
    a.rule(json!({ "app": tool, "direction": "out", "action": "block",
                   "lasts": { "kind": "minutes", "minutes": 30 } }))
        .unwrap();
    // DNS filtering on, with a name allowed, and paused: the pause stays here.
    a.set_dns(true, &["example.com"], Some(now_unix_ms() + 60_000));
    a.call(method::PROFILES_SAVE, json!({ "name": "Travel" }))
        .unwrap();
    a.call(
        method::PROFILES_SET_NETWORKS,
        json!({ "name": "Travel", "networks": [{ "kind": "category", "category": "public" }] }),
    )
    .unwrap();

    let export: RulesExport =
        serde_json::from_value(a.call(method::RULES_EXPORT, Value::Null).unwrap()).unwrap();
    assert_eq!(export.format, RulesExport::FORMAT);
    assert_eq!(export.rules.len(), 2, "{export:?}");
    let game_out = export
        .rules
        .iter()
        .position(|r| r.app.path.ends_with("game.exe"))
        .unwrap();
    assert_eq!(export.rules[game_out].action, Action::Block);
    assert_eq!(export.profiles.len(), 1);
    assert_eq!(export.profiles[0].rules.get(&game_out), Some(&true));
    assert_eq!(
        export.profiles[0].networks,
        [NetworkMatch::Category {
            category: NetworkCategory::Public
        }]
    );
    let dns = export.dns.clone().unwrap();
    assert_eq!(
        (dns.enabled, dns.allow.as_slice(), dns.paused_until_ms),
        (true, ["example.com".to_string()].as_slice(), None)
    );
    assert_eq!(export.profiles[0].dns.as_ref(), Some(&dns));
    // In full too: Edge's block and the game's, as it goes back to; not the
    // tool's, which goes away.
    let full = export.profiles[0].rules_on.as_ref().unwrap();
    assert_eq!(full.len(), 2, "{full:?}");
    assert!(full.iter().all(|r| r.action == Action::Block && r.enabled));
    let _ = game_rule;

    // Another PC: one of the programs is there already, with a rule of the
    // same kind that the file replaces.
    let b = service();
    let there = b.app(r"C:\Games\game.exe");
    b.rule(json!({ "app": there, "direction": "out", "action": "allow" }))
        .unwrap();
    let paused_b = Some(now_unix_ms() + 120_000);
    b.set_dns(false, &[], paused_b);
    let import = |dry_run: bool| -> ImportResult {
        serde_json::from_value(
            b.call(
                method::RULES_IMPORT,
                json!({ "export": export, "dry_run": dry_run }),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let preview = import(true);
    assert_eq!(
        (preview.added, preview.replaced, preview.unchanged),
        (1, 1, 0)
    );
    assert_eq!(b.rules().len(), 1, "a dry run changes nothing");
    assert!(preview.dns);
    assert!(!b.usage.settings().dns.enabled, "a dry run changes nothing");
    assert_eq!(preview.missing_apps.len(), 2, "{preview:?}");

    let done = import(false);
    assert_eq!((done.added, done.replaced, done.failed.len()), (1, 1, 0));
    assert_eq!(done.profiles, ["Travel"]);
    // DNS filtering as in the file, this PC's pause kept.
    assert!(done.dns);
    let dns_b = b.usage.settings().dns;
    assert_eq!(dns_b.without_pause(), dns);
    assert_eq!(dns_b.paused_until_ms, paused_b);
    let rules = b.rules();
    assert_eq!(rules.len(), 2);
    assert!(rules.iter().all(|r| r.origin == Origin::Import));
    let game_b = rules.iter().find(|r| r.app.id == there).unwrap();
    assert_eq!((game_b.action, &game_b.scope), (Action::Block, &Scope::Any));
    // The profile names the new PC's rule for it.
    let travel = b.store.lock().unwrap().profile("Travel").unwrap().unwrap();
    assert_eq!(travel.rules.len(), 2);
    assert!(
        travel
            .rules
            .iter()
            .any(|w| w.app == there && w.action == Action::Block && w.scope == Scope::Any)
    );
    assert_eq!(travel.profile.networks.len(), 1);
    assert_eq!(travel.dns, Some(dns));
    assert_eq!(travel.profile.dns_filtering, Some(true));

    // Again: nothing to do.
    let again = import(false);
    assert_eq!((again.added, again.replaced, again.unchanged), (0, 0, 2));
    assert!(!again.dns);

    // Not a rules file, or a newer one.
    let mut other = serde_json::to_value(&export).unwrap();
    other["format"] = json!("something-else");
    assert!(
        b.call(
            method::RULES_IMPORT,
            json!({ "export": other, "dry_run": true })
        )
        .is_err()
    );
    let mut newer = serde_json::to_value(&export).unwrap();
    newer["version"] = json!(RulesExport::VERSION + 1);
    assert!(
        b.call(
            method::RULES_IMPORT,
            json!({ "export": newer, "dry_run": true })
        )
        .unwrap_err()
        .message
        .contains("newer")
    );
}

#[test]
fn ending_connections_needs_an_administrator_and_skips_ipv6() {
    let s = service();
    let app = s.app(r"C:\Nowhere\gone.exe");
    // No processes seen: nothing to end.
    let r: CloseResult = serde_json::from_value(
        s.call(method::CONNECTIONS_CLOSE, json!({ "app": app }))
            .unwrap(),
    )
    .unwrap();
    assert_eq!((r.closed, r.not_closable), (0, 0));
    // IPv6 connections are counted, not ended.
    let r: CloseResult = serde_json::from_value(
        s.call(
            method::CONNECTIONS_CLOSE,
            json!({ "connections": [["[2001:db8::1]:50000", "[2001:db8::2]:443"]] }),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!((r.closed, r.not_closable), (0, 1));
    let user = Caller {
        pid: None,
        token: Some(CallerToken {
            user: "S-1-5-21-1-2-3-1002".into(),
            admin: false,
            elevated: false,
        }),
    };
    let e = s
        .handler
        .handle(&user, method::CONNECTIONS_CLOSE, json!({ "app": app }))
        .unwrap_err();
    assert_eq!(e.code, RpcError::FORBIDDEN);
}

#[test]
fn a_profile_puts_the_apps_switches_back() {
    let s = service();
    let game = s.app(r"C:\Games\game.exe");
    let tool = s.app(r"C:\Tools\tool.exe");
    let blocks = |path: &str| {
        s.firewall
            .rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                r.enabled && r.block && r.program.as_deref().is_some_and(|p| p.contains(path))
            })
            .count()
    };
    // Home blocks the game.
    let rule = s
        .rule(json!({ "app": game, "direction": "out", "action": "block" }))
        .unwrap();
    s.call(method::PROFILES_SAVE, json!({ "name": "Home" }))
        .unwrap();
    // As the Apps tab does it: the game unblocked (its rule deleted) and the
    // tool blocked. Both are changes; saved as Travel.
    s.call(method::RULES_DELETE, json!({ "id": rule.id }))
        .unwrap();
    assert!(s.profiles().changed);
    s.rule(json!({ "app": tool, "direction": "out", "action": "block" }))
        .unwrap();
    s.call(method::PROFILES_SAVE, json!({ "name": "Travel" }))
        .unwrap();
    s.enforcer.sync().unwrap();
    assert_eq!((blocks("game.exe"), blocks("tool.exe")), (0, 1));

    // Home: the game's block made again, the tool's turned off; in Windows
    // Firewall too.
    s.call(method::PROFILES_SWITCH, json!({ "name": "Home" }))
        .unwrap();
    s.enforcer.sync().unwrap();
    assert_eq!((blocks("game.exe"), blocks("tool.exe")), (1, 0));
    assert!(!s.profiles().changed);
    assert_eq!(s.rules().len(), 2, "the tool's rule is off, not deleted");

    s.call(method::PROFILES_SWITCH, json!({ "name": "Travel" }))
        .unwrap();
    s.enforcer.sync().unwrap();
    assert_eq!((blocks("game.exe"), blocks("tool.exe")), (0, 1));
    assert!(!s.profiles().changed);
}

#[test]
fn a_profile_puts_dns_filtering_back() {
    let s = service();
    // "Home": filtering off. "Travel": on, with a name allowed.
    s.call(method::PROFILES_SAVE, json!({ "name": "Home" }))
        .unwrap();
    s.set_dns(true, &["example.com"], None);
    assert!(s.profiles().changed, "DNS filtering differs from Home");
    s.call(method::PROFILES_SAVE, json!({ "name": "Travel" }))
        .unwrap();
    let travel = s.profiles();
    assert!(!travel.changed);
    let on: Vec<_> = travel.profiles.iter().map(|p| p.dns_filtering).collect();
    assert_eq!(on, [Some(false), Some(true)]);

    // Paused on Travel: a pause isn't a change, and switching keeps it.
    let paused = Some(now_unix_ms() + 60_000);
    s.set_dns(true, &["example.com"], paused);
    assert!(!s.profiles().changed);
    s.call(method::PROFILES_SWITCH, json!({ "name": "Home" }))
        .unwrap();
    let dns = s.usage.settings().dns;
    assert_eq!(
        (dns.enabled, dns.allow.len(), dns.paused_until_ms),
        (false, 0, paused)
    );
    assert!(!s.profiles().changed);
    s.call(method::PROFILES_SWITCH, json!({ "name": "Travel" }))
        .unwrap();
    let dns = s.usage.settings().dns;
    assert_eq!(
        (dns.enabled, dns.allow.as_slice()),
        (true, ["example.com".to_string()].as_slice())
    );

    // DNS filtering that can't be used here (a blocklist gone from the
    // catalogue): refused, nothing switched.
    let mut gone = dns.without_pause();
    gone.lists = vec!["no-such-list".into()];
    let elsewhere = Profile {
        name: "Elsewhere".into(),
        mode: Mode::ClickToBlock,
        rules: 0,
        enabled: 0,
        saved_ms: 0,
        networks: Vec::new(),
        dns_filtering: None,
    };
    s.store
        .lock()
        .unwrap()
        .import_profile(&elsewhere, &[], Some(&gone), 1, "test")
        .unwrap();
    let e = s
        .call(method::PROFILES_SWITCH, json!({ "name": "Elsewhere" }))
        .unwrap_err();
    assert!(e.message.contains("DNS filtering"), "{e:?}");
    assert_eq!(s.profiles().active.as_deref(), Some("Travel"));
}

#[test]
fn a_profile_is_switched_to_on_the_network_the_pc_is_on() {
    let connected = w4_sys::netlist::networks(false);
    if connected.is_empty() {
        eprintln!("no network connected: nothing to switch by");
        return;
    }
    let s = service();
    let app = s.app(r"C:\Nowhere\gone.exe");
    let rule = s
        .rule(json!({ "app": app, "direction": "out", "action": "block" }))
        .unwrap();
    // "Home" has the block on, "Here" has it off; by hand, Home.
    s.call(method::PROFILES_SAVE, json!({ "name": "Home" }))
        .unwrap();
    s.call(
        method::RULES_ENABLE,
        json!({ "id": rule.id, "enabled": false }),
    )
    .unwrap();
    s.call(method::PROFILES_SAVE, json!({ "name": "Here" }))
        .unwrap();
    s.call(method::PROFILES_SWITCH, json!({ "name": "Home" }))
        .unwrap();
    let networks: Vec<Value> = connected
        .iter()
        .map(|n| json!({ "kind": "network", "id": n.id, "name": n.name }))
        .collect();
    s.call(
        method::PROFILES_SET_NETWORKS,
        json!({ "name": "Here", "networks": networks }),
    )
    .unwrap();

    let auto = crate::autoprofile::AutoProfile::new(
        Arc::clone(&s.store),
        Arc::clone(&s.monitor),
        Arc::clone(&s.enforcer),
        None,
        Some(Arc::clone(&s.usage)),
    );
    let on = || s.rules().iter().find(|r| r.id == rule.id).unwrap().enabled;
    let active = || s.store.lock().unwrap().active_profile().unwrap();
    auto.check();
    assert_eq!(active().as_deref(), Some("Here"));
    assert!(!on());
    let last = auto.last().unwrap();
    assert_eq!(last.profile, "Here");
    let alerts = s.monitor.lock().unwrap().take_alerts();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].body.kind(), "profile_switched");

    // Switched back by hand: that stands while the networks stay the same.
    s.call(method::PROFILES_SWITCH, json!({ "name": "Home" }))
        .unwrap();
    auto.check();
    assert_eq!(active().as_deref(), Some("Home"));
    assert!(on());
    // Choosing networks again looks again.
    auto.reconsider();
    auto.check();
    assert_eq!(active().as_deref(), Some("Here"));
}

#[test]
fn a_rule_until_the_app_quits_ends_when_it_does() {
    // A program of its own, so nothing else running has its path.
    let dir = std::env::temp_dir().join(format!("w4-quit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("w4-quit-test.exe");
    std::fs::copy(r"C:\Windows\System32\PING.EXE", &exe).unwrap();
    let mut child = std::process::Command::new(&exe)
        .args(["-n", "3", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let s = service();
    let app = s.app(&exe.display().to_string());
    s.rule(json!({ "app": app, "direction": "out", "action": "block",
                   "lasts": { "kind": "app_quits" } }))
        .unwrap();
    s.enforcer.sync().unwrap();
    assert_eq!(s.rules().len(), 1, "still running");

    child.wait().unwrap();
    s.enforcer.sync().unwrap();
    assert!(s.rules().is_empty(), "it quit: the rule went with it");
    let audit = s.store.lock().unwrap().rule_audit(1).unwrap();
    assert_eq!(
        (audit[0].change.as_str(), audit[0].who.as_str()),
        ("expired", "win4tress (app quit)")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
