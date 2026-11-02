use std::net::IpAddr;

use w4_core::{Bytes, Country, TrafficType};
use w4_ipc::api::{
    AlertBody, AlertsParams, AppField, BreakdownFilter, DNS_TIMELINE_APPS, MAX_DNS_STEPS,
    StatusCount, TypeCount,
};
use w4_monitor::{AppRecord, DnsRecord, MinuteRow, PendingAlert, UsageRow, build_breakdown};

use super::*;

fn alert(ts_ms: i64, app: Option<u32>, body: AlertBody) -> PendingAlert {
    PendingAlert {
        ts_ms,
        app,
        app_name: app.map(|_| "The curl executable".into()),
        body,
        severity: None,
    }
}

#[test]
fn alerts_are_stored_filtered_and_marked() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .save(&[app(0, r"C:\Tools\curl.exe")], &[], &[])
        .unwrap();
    let version = AlertBody::AppInfoChanged {
        field: AppField::Version,
        from: "8.9.0".into(),
        to: "8.10.1".into(),
    };
    let ids = store
        .insert_alerts(&[
            alert(1_000, Some(0), version.clone()),
            alert(2_000, None, AlertBody::MonitoringInterrupted),
            alert(
                3_000,
                Some(0),
                AlertBody::FirstNetworkActivity {
                    host: None,
                    port: 443,
                },
            ),
        ])
        .unwrap();
    assert_eq!(ids.len(), 3);
    assert_eq!(store.unread_alerts().unwrap(), 3);

    let list = |p: AlertsParams, limit| store.alerts(&p, limit).unwrap();
    let (all, more) = list(AlertsParams::default(), 10);
    assert_eq!(all.len(), 3);
    assert!(!more);
    assert_eq!(all[0].id, ids[2], "newest first");
    assert_eq!(all[2].body, version);
    assert_eq!(all[2].app, Some(0));
    assert_eq!(all[2].app_name.as_deref(), Some("The curl executable"));
    assert_eq!(all[1].app_name, None);

    let (page, more) = list(AlertsParams::default(), 2);
    assert!(more);
    let older = AlertsParams {
        before_id: Some(page[1].id),
        ..Default::default()
    };
    assert_eq!(list(older, 2).0.len(), 1);

    let kinds = AlertsParams {
        kinds: vec!["monitoring_interrupted".into()],
        ..Default::default()
    };
    assert_eq!(list(kinds, 10).0.len(), 1);
    let by_app = AlertsParams {
        query: Some("CURL".into()),
        ..Default::default()
    };
    assert_eq!(list(by_app, 10).0.len(), 2);
    let by_detail = AlertsParams {
        query: Some("8.10".into()),
        ..Default::default()
    };
    assert_eq!(list(by_detail, 10).0.len(), 1);
    let wildcard_is_literal = AlertsParams {
        query: Some("%".into()),
        ..Default::default()
    };
    assert_eq!(list(wildcard_is_literal, 10).0.len(), 0);
    let recent = AlertsParams {
        since_ms: Some(2_000),
        ..Default::default()
    };
    assert_eq!(list(recent, 10).0.len(), 2);

    assert_eq!(store.mark_read(Some(&[ids[0]]), true).unwrap(), 1);
    assert_eq!(store.unread_alerts().unwrap(), 2);
    let unread = AlertsParams {
        unread_only: true,
        ..Default::default()
    };
    assert_eq!(list(unread, 10).0.len(), 2);
    assert_eq!(store.mark_read(None, true).unwrap(), 2);
    assert_eq!(store.unread_alerts().unwrap(), 0);
    assert_eq!(store.mark_read(Some(&[ids[1]]), false).unwrap(), 1);
    assert_eq!(store.unread_alerts().unwrap(), 1);

    // Kept for a year.
    store.prune(1_000 + ALERT_RETENTION_MS + 1).unwrap();
    assert_eq!(list(AlertsParams::default(), 10).0.len(), 2);
}

#[test]
fn dns_stats_count_timelines_and_top_lists() {
    let mut store = Store::open_in_memory().unwrap();
    let q = |ts_ms: i64, app: u32, name: &str, query_type: u16, status: u32| DnsRecord {
        ts_ms,
        app,
        name: name.into(),
        query_type,
        status,
        addrs: vec![],
    };
    const MIN: i64 = 60_000;
    let t0 = MINUTE * MIN; // a whole minute
    let mut dns = vec![
        q(t0, 0, "a.example", 1, 0),
        q(t0 + 1_000, 0, "a.example", 28, 0),
        q(t0 + 2_000, 1, "wpad", 1, 9003),
        q(t0 + MIN + 5, 1, "wpad", 1, 9003),
        q(t0 + 2 * MIN, 2, "b.example", 65, 0),
    ];
    // Six more apps, one lookup each: more than get their own timeline.
    dns.extend((3..9).map(|app| q(t0 + 3 * MIN, app, "c.example", 1, 1460)));
    store.save(&[], &[], &dns).unwrap();

    let s = store.dns_stats(t0, t0 + 4 * MIN - 1, MIN, 3).unwrap();
    assert_eq!((s.lookups, s.failed, s.domains, s.apps), (11, 8, 4, 9));
    assert_eq!((s.start_ms, s.step_ms), (t0, MIN));
    assert_eq!(s.timeline, vec![[2, 1], [0, 1], [1, 0], [0, 6]]);
    assert_eq!(s.app_timeline.len(), DNS_TIMELINE_APPS);
    assert_eq!(s.app_timeline[0], (0, vec![2, 0, 0, 0]));
    assert_eq!(s.app_timeline[1], (1, vec![1, 1, 0, 0]));
    // Every lookup is in exactly one app line.
    let per_step: Vec<u64> = (0..4)
        .map(|i| s.app_timeline.iter().map(|(_, c)| c[i]).sum::<u64>() + s.other_timeline[i])
        .collect();
    assert_eq!(per_step, vec![3, 1, 1, 6]);
    assert_eq!(
        s.query_types[0],
        TypeCount {
            query_type: 1,
            count: 9
        }
    );
    assert_eq!(
        s.results[0],
        StatusCount {
            status: 1460,
            count: 6
        }
    );
    assert_eq!(s.top_domains[0].name, "c.example");
    assert_eq!(s.top_failed.len(), 2);
    assert_eq!(s.top_failed[0].name, "c.example");
    assert_eq!(s.top_apps.len(), 3);
    assert_eq!(s.top_apps[0], (0, 2, 0));

    // A month in one-minute steps is made coarser.
    let month = store
        .dns_stats(t0, t0 + 30 * 24 * 60 * MIN, MIN, 3)
        .unwrap();
    assert!(month.timeline.len() as i64 <= MAX_DNS_STEPS + 1);
}

#[test]
fn rules_toggle_update_delete_and_audit() {
    use w4_core::firewall::{Action, Direction, Origin, Scope};
    let mut store = Store::open_in_memory().unwrap();
    let new = |action| NewRule {
        app: 3,
        direction: Direction::Out,
        action,
        scope: Scope::Any,
        origin: Origin::User,
        note: None,
        expires: None,
    };

    let block = store
        .set_rule(&new(Action::Block), 1_000, "admin (pid 1)")
        .unwrap();
    assert_eq!(
        (block.app, block.action, block.enabled),
        (3, Action::Block, true)
    );
    // Setting it again updates the same rule.
    let again = store
        .set_rule(&new(Action::Block), 2_000, "admin (pid 1)")
        .unwrap();
    assert_eq!(again.id, block.id);
    assert_eq!((again.created_ms, again.updated_ms), (1_000, 2_000));
    // Inbound is a separate rule.
    let mut inbound = new(Action::Block);
    inbound.direction = Direction::In;
    store.set_rule(&inbound, 2_500, "admin (pid 1)").unwrap();
    assert_eq!(store.rules().unwrap().len(), 2);

    // Allow replaces the outbound block: one verdict per direction.
    let allow = store
        .set_rule(&new(Action::Allow), 3_000, "admin (pid 1)")
        .unwrap();
    let rules = store.rules().unwrap();
    assert_eq!(rules.len(), 2);
    assert!(rules.iter().all(|r| r.id != block.id));
    assert_eq!(store.rule(allow.id).unwrap().unwrap().action, Action::Allow);

    assert_eq!(
        store
            .delete_rule(allow.id, 4_000, "admin (pid 2)", "deleted")
            .unwrap(),
        Some(allow.clone())
    );
    assert_eq!(
        store
            .delete_rule(allow.id, 4_000, "admin (pid 2)", "deleted")
            .unwrap(),
        None
    );
    // Ids are never reused, even the highest one after it's deleted.
    let next = store
        .set_rule(&new(Action::Allow), 4_500, "admin (pid 2)")
        .unwrap();
    assert!(next.id > allow.id, "{} reused", next.id);
    store
        .delete_rule(next.id, 4_600, "admin (pid 2)", "deleted")
        .unwrap();
    store.audit_repair(&rules[0], 5_000).unwrap();

    let log = store.rule_audit(20).unwrap();
    let changes: Vec<&str> = log.iter().map(|e| e.change.as_str()).collect();
    assert_eq!(
        changes,
        [
            "repaired", "deleted", "created", "deleted", "created", "deleted", "created",
            "updated", "created"
        ]
    );
    assert_eq!(log[3].who, "admin (pid 2)");
    assert!(log[3].rule.contains("\"allow\""));
}

#[test]
fn temporary_rules_stand_in_and_go_back() {
    use w4_core::firewall::{Action, Direction, Expiry, Origin, Scope};
    let mut store = Store::open_in_memory().unwrap();
    let new = |action, expires| NewRule {
        app: 3,
        direction: Direction::Out,
        action,
        scope: Scope::Any,
        origin: Origin::User,
        note: None,
        expires,
    };
    let hour = Some(Expiry::At { ms: 3_600_000 });

    // Allowed for an hour on top of a block: the same rule, going back.
    let block = store.set_rule(&new(Action::Block, None), 1, "t").unwrap();
    let allow = store.set_rule(&new(Action::Allow, hour), 2, "t").unwrap();
    assert_eq!(allow.id, block.id);
    assert_eq!(
        (allow.action, allow.expires, allow.revert),
        (Action::Allow, hour, Some(Action::Block))
    );
    // Longer: still going back to the block.
    let day = Some(Expiry::At { ms: 86_400_000 });
    let longer = store.set_rule(&new(Action::Allow, day), 3, "t").unwrap();
    assert_eq!(
        (longer.id, longer.expires, longer.revert),
        (block.id, day, Some(Action::Block))
    );
    // Its end: blocked again, for good, and audited.
    let ended = store
        .expire_rule(block.id, 4, "win4tress (time up)")
        .unwrap();
    assert_eq!(ended.map(|r| r.action), Some(Action::Allow));
    let back = store.rule(block.id).unwrap().unwrap();
    assert_eq!(
        (back.action, back.expires, back.revert),
        (Action::Block, None, None)
    );
    assert_eq!(store.rule_audit(1).unwrap()[0].change, "expired");

    // Blocked for good, then "block for an hour": stays for good.
    let same = store.set_rule(&new(Action::Block, hour), 5, "t").unwrap();
    assert_eq!((same.expires, same.revert), (None, None));

    // Temporarily allowed, then blocked temporarily: what's for good is the
    // block, so that's simply it.
    store.set_rule(&new(Action::Allow, hour), 6, "t").unwrap();
    let blocked = store.set_rule(&new(Action::Block, hour), 7, "t").unwrap();
    assert_eq!(
        (blocked.action, blocked.expires, blocked.revert),
        (Action::Block, None, None)
    );

    // No rule before: a temporary one is deleted at its end.
    let mut other = new(Action::Allow, Some(Expiry::AppQuits));
    other.app = 4;
    let temp = store.set_rule(&other, 8, "t").unwrap();
    assert_eq!(temp.revert, None);
    store.expire_rule(temp.id, 9, "t").unwrap();
    assert_eq!(store.rule(temp.id).unwrap(), None);

    // For good replaces temporary.
    store.set_rule(&new(Action::Allow, hour), 10, "t").unwrap();
    let kept = store.set_rule(&new(Action::Allow, None), 11, "t").unwrap();
    assert_eq!((kept.expires, kept.revert), (None, None));
    // And a toggle of a temporary rule is for good too.
    store.set_rule(&new(Action::Block, None), 12, "t").unwrap();
    let t = store.set_rule(&new(Action::Allow, hour), 13, "t").unwrap();
    let flipped = store
        .edit_rule(
            t.id,
            RuleEdit {
                action: Some(Action::Block),
                ..Default::default()
            },
            14,
            "t",
            "updated",
        )
        .unwrap()
        .unwrap();
    assert_eq!((flipped.expires, flipped.revert), (None, None));
}

#[test]
fn rules_are_edited_to_keep_outside_changes() {
    use w4_core::firewall::{Action, Direction, Origin, Scope};
    let mut store = Store::open_in_memory().unwrap();
    let new = |direction, action| NewRule {
        app: 3,
        direction,
        action,
        scope: Scope::Any,
        origin: Origin::User,
        note: None,
        expires: None,
    };
    let out = store
        .set_rule(&new(Direction::Out, Action::Block), 1_000, "admin")
        .unwrap();
    let off = RuleEdit {
        enabled: Some(false),
        ..Default::default()
    };
    let edited = store
        .edit_rule(out.id, off, 2_000, "admin", "kept outside change")
        .unwrap()
        .unwrap();
    assert_eq!(
        (edited.enabled, edited.action, edited.updated_ms),
        (false, Action::Block, 2_000)
    );
    // Setting the verdict again turns it back on.
    assert!(
        store
            .set_rule(&new(Direction::Out, Action::Block), 2_500, "admin")
            .unwrap()
            .enabled
    );

    // Switching the action keeps the id; an inbound rule is untouched.
    let inbound = store
        .set_rule(&new(Direction::In, Action::Allow), 3_000, "admin")
        .unwrap();
    let allow = RuleEdit {
        action: Some(Action::Allow),
        ..Default::default()
    };
    let switched = store
        .edit_rule(out.id, allow, 4_000, "admin", "kept outside change")
        .unwrap()
        .unwrap();
    assert_eq!((switched.id, switched.action), (out.id, Action::Allow));
    assert_eq!(store.rules().unwrap().len(), 2);
    assert_eq!(store.rule(inbound.id).unwrap(), Some(inbound.clone()));

    // An app's other rule with the new action gives way (one verdict per direction).
    let block_in = RuleEdit {
        action: Some(Action::Block),
        ..Default::default()
    };
    store
        .set_rule(&new(Direction::Out, Action::Block), 5_000, "admin")
        .unwrap(); // replaces the outbound allow
    let rules = store.rules().unwrap();
    assert_eq!(rules.len(), 2);
    let out_block = rules
        .iter()
        .find(|r| r.direction == Direction::Out)
        .unwrap();
    store
        .edit_rule(inbound.id, block_in, 6_000, "admin", "kept outside change")
        .unwrap();
    assert_eq!(
        store.rule(out_block.id).unwrap().unwrap().action,
        Action::Block
    );
    assert_eq!(
        store.rule(inbound.id).unwrap().unwrap().action,
        Action::Block
    );

    assert_eq!(
        store.edit_rule(999, off, 7_000, "admin", "x").unwrap(),
        None
    );
    let log = store.rule_audit(3).unwrap();
    assert_eq!(log[0].change, "kept outside change");
}

#[test]
fn mode_is_kept_audited_and_reset() {
    use w4_core::firewall::{Action, Direction, Mode, Origin, Scope};
    let mut store = Store::open_in_memory().unwrap();
    assert_eq!(store.firewall_mode().unwrap(), Mode::ClickToBlock);
    assert!(store.set_firewall_mode(Mode::Off, 1_000, "admin").unwrap());
    assert!(!store.set_firewall_mode(Mode::Off, 1_500, "admin").unwrap());
    assert_eq!(store.firewall_mode().unwrap(), Mode::Off);
    let log = store.rule_audit(5).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].change.as_str(), log[0].rule_id, log[0].rule.as_str()),
        ("mode", None, "{\"mode\":\"off\"}")
    );

    for app in [3, 4] {
        let new = NewRule {
            app,
            direction: Direction::Out,
            action: Action::Block,
            scope: Scope::Any,
            origin: Origin::User,
            note: None,
            expires: None,
        };
        store.set_rule(&new, 2_000, "admin").unwrap();
    }
    assert_eq!(store.reset_rules(3_000, "elevated admin").unwrap(), 2);
    assert!(store.rules().unwrap().is_empty());
    assert_eq!(store.firewall_mode().unwrap(), Mode::ClickToBlock);
    let changes: Vec<String> = store
        .rule_audit(3)
        .unwrap()
        .into_iter()
        .map(|e| e.change)
        .collect();
    assert_eq!(changes, ["mode", "reset", "reset"]);
    // Nothing to do the second time, and nothing audited.
    assert_eq!(store.reset_rules(4_000, "elevated admin").unwrap(), 0);
    assert_eq!(store.rule_audit(10).unwrap().len(), 6);
}

#[test]
fn alert_is_found_and_its_body_replaced() {
    let mut store = Store::open_in_memory().unwrap();
    let body = AlertBody::FirewallChanged {
        repaired: 1,
        changes: Vec::new(),
        kept_ms: None,
    };
    let ids = store
        .insert_alerts(&[alert(1_000, None, body.clone())])
        .unwrap();
    let found = store.alert(ids[0]).unwrap().unwrap();
    assert_eq!(found.body, body);
    let kept = AlertBody::FirewallChanged {
        repaired: 1,
        changes: Vec::new(),
        kept_ms: Some(2_000),
    };
    assert!(store.set_alert_body(ids[0], &kept).unwrap());
    assert_eq!(store.alert(ids[0]).unwrap().unwrap().body, kept);
    // A body of another kind isn't written over an alert.
    assert!(
        !store
            .set_alert_body(ids[0], &AlertBody::MonitoringInterrupted)
            .unwrap()
    );
    assert_eq!(store.alert(ids[0] + 1).unwrap(), None);
}

#[test]
fn upgrade_to_autoincrement_keeps_rules_and_skips_used_ids() {
    use w4_core::firewall::{Action, Direction, Origin, Scope};
    let conn = Connection::open_in_memory().unwrap();
    for m in &MIGRATIONS[..6] {
        conn.execute_batch(m).unwrap();
    }
    conn.pragma_update(None, "user_version", 6).unwrap();
    conn.execute_batch(
        "INSERT INTO rules VALUES (2, 3, 'out', 'block', 'any', '{\"kind\":\"any\"}', 1, 'user', NULL, 1, 1);
         INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule) VALUES (1, 7, 'deleted', 'x', '{}');",
    )
    .unwrap();
    let mut store = Store::init(conn).unwrap();
    assert_eq!(store.rules().unwrap().len(), 1);
    let new = NewRule {
        app: 4,
        direction: Direction::Out,
        action: Action::Block,
        scope: Scope::Any,
        origin: Origin::User,
        note: None,
        expires: None,
    };
    // Rule 7 existed once (the audit trail says so): the next id is above it.
    assert_eq!(store.set_rule(&new, 2, "x").unwrap().id, 8);
}

#[test]
fn first_run_is_recorded_once() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.first_run_ms(5_000).unwrap(), 5_000);
    assert_eq!(store.first_run_ms(9_000).unwrap(), 5_000);
}

#[test]
fn upgrade_drops_dns_rows_recorded_by_mistake() {
    let conn = Connection::open_in_memory().unwrap();
    for m in &MIGRATIONS[..4] {
        conn.execute_batch(m).unwrap();
    }
    conn.pragma_update(None, "user_version", 4).unwrap();
    conn.execute_batch(
        r"INSERT INTO apps (id, key, path, first_seen_ms, last_seen_ms)
              VALUES (0, 'svc', 'C:\Bin\win4tress-svc.exe', 1, 2), (1, 'b', 'C:\b.exe', 1, 2);
          INSERT INTO dns_queries VALUES
              (1, 1, 'example.com', 1, 87, ''),
              (2, 1, 'example.com', 28, 0, '1.2.3.4'),
              (3, 0, '4.3.2.1.in-addr.arpa.', 12, 0, ''),
              (4, 1, '4.3.2.1.in-addr.arpa.', 12, 9003, ''),
              (5, 1, 'odd.example', 1, 87, '5.6.7.8');",
    )
    .unwrap();
    let store = Store::init(conn).unwrap();
    let names: Vec<(String, i64)> = store
        .conn
        .prepare("SELECT name, status FROM dns_queries ORDER BY ts_ms")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        names,
        vec![
            ("example.com".into(), 0),
            ("4.3.2.1.in-addr.arpa".into(), 9003), // another app's lookup stays
            ("odd.example".into(), 87),            // an 87 with addresses stays
        ]
    );
}

#[test]
fn upgrade_marks_apps_with_traffic_as_network_users() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.execute_batch(SCHEMA_V2).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    conn.execute_batch(
        "INSERT INTO apps (id, key, path, first_seen_ms, last_seen_ms)
             VALUES (0, 'a', 'C:\\a.exe', 1, 2), (1, 'b', 'C:\\b.exe', 1, 2);
         INSERT INTO traffic_min VALUES (100, 0, 0, 'https', 10, 0), (99, 0, 0, 'https', 5, 0);",
    )
    .unwrap();
    let apps = Store::init(conn).unwrap().load_apps().unwrap();
    assert_eq!(apps[0].net_first_seen_ms, Some(99 * 60_000));
    assert_eq!(apps[1].net_first_seen_ms, None);
}

const MINUTE: i64 = 29_881_440; // 2026-10-25 00:00 UTC, in Unix minutes

fn app(id: u32, path: &str) -> AppRecord {
    AppRecord {
        id,
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
fn trust_and_own_dns_round_trip() {
    use w4_core::trust::{DownloadOrigin, Signature, Trust};
    let mut store = Store::open_in_memory().unwrap();
    let mut a = app(0, r"C:\Users\Sam\Downloads\tool.exe");
    a.trust = Trust {
        signature: Some(Signature::Signed),
        signer: Some("Example Ltd".into()),
        sha256: Some("ab".repeat(32)),
        origin: Some(DownloadOrigin {
            zone: 3,
            host_url: Some("https://example.com/tool.exe".into()),
            referrer_url: None,
        }),
    };
    a.own_dns_ms = Some(5_000);
    store.save(std::slice::from_ref(&a), &[], &[]).unwrap();
    assert_eq!(store.load_apps().unwrap(), [a.clone()]);
    // A later save without the sighting keeps the earliest one.
    let mut later = a.clone();
    later.own_dns_ms = None;
    store.save(&[later], &[], &[]).unwrap();
    assert_eq!(store.load_apps().unwrap()[0].own_dns_ms, Some(5_000));
}

#[test]
fn firewall_settings_are_kept_and_audited() {
    use w4_core::firewall::{BlockAll, ProfileState};
    let mut store = Store::open_in_memory().unwrap();
    assert_eq!(store.block_all().unwrap(), None);
    let on = BlockAll {
        since_ms: 1_000,
        until_ms: Some(61_000),
    };
    store.set_block_all(Some(on), 1_000, "admin").unwrap();
    assert_eq!(store.block_all().unwrap(), Some(on));
    assert!(on.active(60_999) && !on.active(61_000));
    store.set_block_all(None, 2_000, "win4tress").unwrap();
    assert_eq!(store.block_all().unwrap(), None);

    assert!(!store.require_elevation().unwrap());
    store.set_require_elevation(true, 3_000, "admin").unwrap();
    assert!(store.require_elevation().unwrap());

    let profiles = vec![ProfileState {
        name: "private".into(),
        active: true,
        firewall_on: true,
        inbound_default_block: true,
        outbound_default_block: false,
    }];
    assert!(store.save_profile_originals(&profiles, 4_000).unwrap());
    let mut changed = profiles.clone();
    changed[0].outbound_default_block = true;
    // The first record stays.
    assert!(!store.save_profile_originals(&changed, 5_000).unwrap());
    assert_eq!(store.profile_originals().unwrap(), Some(profiles));
    store.clear_profile_originals(6_000, "admin").unwrap();
    assert_eq!(store.profile_originals().unwrap(), None);

    let changes: Vec<String> = store
        .rule_audit(10)
        .unwrap()
        .into_iter()
        .map(|e| e.change)
        .collect();
    assert_eq!(
        changes,
        [
            "restored profile settings",
            "saved profile settings",
            "require elevation",
            "block all",
            "block all"
        ]
    );
}

#[test]
fn dns_addresses_for_host_rules() {
    let mut store = Store::open_in_memory().unwrap();
    let q = |app: u32, name: &str, status: u32, addrs: &[&str]| DnsRecord {
        ts_ms: 1_000,
        app,
        name: name.into(),
        query_type: 1,
        status,
        addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
    };
    store
        .save(
            &[],
            &[],
            &[
                q(1, "ads.example.com", 0, &["203.0.113.5", "203.0.113.6"]),
                q(1, "ads.example.com", 0, &["203.0.113.6"]),
                q(1, "cdn.ads.example.com", 0, &["203.0.113.9"]),
                q(1, "example.com", 9003, &[]),
                q(2, "ads.example.com", 0, &["198.51.100.1"]),
            ],
        )
        .unwrap();
    let ips = |app, pattern| -> Vec<String> {
        store
            .dns_addresses(app, pattern)
            .unwrap()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect()
    };
    // Only this app's answers, for this name.
    assert_eq!(ips(1, "ADS.example.com."), ["203.0.113.5", "203.0.113.6"]);
    assert_eq!(
        ips(1, "*.ads.example.com"),
        ["203.0.113.5", "203.0.113.6", "203.0.113.9"]
    );
    assert!(ips(1, "other.example.com").is_empty());
}

#[test]
fn blocks_are_combined_across_minutes() {
    use w4_core::firewall::{BlockedBy, BlockedByKind};
    use w4_monitor::blocks::{BlockKey, BlockRow};
    let mut store = Store::open_in_memory().unwrap();
    let key = |port| BlockKey {
        app: 3,
        inbound: false,
        ip: "1.1.1.1".parse().unwrap(),
        port,
        by: BlockedBy {
            kind: BlockedByKind::Win4tress,
            name: "win4tress: curl (Out, Block) #1".into(),
        },
    };
    let row = |minute, port, count| BlockRow {
        minute,
        key: key(port),
        count,
    };
    store
        .save_blocks(&[
            row(MINUTE, 443, 2),
            row(MINUTE + 1, 443, 1),
            row(MINUTE + 1, 80, 4),
        ])
        .unwrap();
    store.save_blocks(&[row(MINUTE + 1, 443, 1)]).unwrap();
    let found = store.blocks(Some(3), MINUTE * 60_000, 10).unwrap();
    assert_eq!(found.len(), 2);
    let https = found.iter().find(|(k, _)| k.port == 443).unwrap();
    assert_eq!(https.1.count, 4);
    assert_eq!(https.1.first_ms, MINUTE * 60_000);
    assert!(store.blocks(Some(4), 0, 10).unwrap().is_empty());
    // Pruned after the retention.
    store
        .prune((MINUTE + 2) * 60_000 + BLOCK_RETENTION_MS)
        .unwrap();
    assert!(store.blocks(None, 0, 10).unwrap().is_empty());
}

fn row(minute: i64, app: u32, ip: &str, name: Option<&str>, recv: u64) -> MinuteRow {
    MinuteRow {
        minute,
        row: UsageRow {
            app,
            ip: ip.parse().unwrap(),
            name: name.map(str::to_string),
            country: Country {
                code: "US".into(),
                name: "United States".into(),
            },
            traffic_type: TrafficType::Https,
            bytes: Bytes { recv, sent: 1 },
        },
    }
}

#[test]
fn apps_round_trip_and_update() {
    let mut store = Store::open_in_memory().unwrap();
    let mut curl = app(0, r"C:\Tools\curl.exe");
    store
        .save(&[curl.clone(), app(1, r"C:\x.exe")], &[], &[])
        .unwrap();
    curl.description = Some("The curl executable".into());
    curl.version = Some("8.9.1.0".into());
    curl.last_seen_ms = 99;
    store.save(&[curl.clone()], &[], &[]).unwrap();

    let loaded = store.load_apps().unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0], curl);
}

#[test]
fn schema_1_database_is_upgraded_in_place() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    conn.execute(
        "INSERT INTO apps (id, key, path, first_seen_ms, last_seen_ms)
         VALUES (0, 'c:\\tools\\curl.exe', 'C:\\Tools\\curl.exe', 1, 2)",
        [],
    )
    .unwrap();

    let store = Store::init(conn).unwrap();
    let apps = store.load_apps().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].version, None);
    let version: i32 = store
        .conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
}

#[test]
fn minutes_accumulate_and_feed_history_and_usage() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .save(&[app(0, r"C:\a.exe"), app(1, r"C:\b.exe")], &[], &[])
        .unwrap();
    store
        .save(
            &[],
            &[
                row(MINUTE, 0, "1.2.3.4", None, 100),
                row(MINUTE, 1, "1.2.3.4", Some("cdn.example"), 50),
                row(MINUTE + 2, 0, "5.6.7.8", None, 7),
            ],
            &[],
        )
        .unwrap();
    // The same minute arriving twice adds up rather than failing.
    store
        .save(&[], &[row(MINUTE, 0, "1.2.3.4", None, 10)], &[])
        .unwrap();

    let history = store.history(MINUTE, MINUTE + 5).unwrap();
    assert_eq!(
        history,
        vec![
            (MINUTE, Bytes { recv: 160, sent: 3 }),
            (MINUTE + 2, Bytes { recv: 7, sent: 1 }),
        ]
    );

    let usage = store.usage(MINUTE, MINUTE + 5).unwrap();
    assert_eq!(usage.len(), 3);
    let b = build_breakdown(
        usage,
        &BreakdownFilter::default(),
        10,
        |id| w4_ipc::api::AppRef {
            id,
            name: format!("app {id}"),
            path: String::new(),
        },
        |_| None,
    );
    assert_eq!(b.total, Bytes { recv: 167, sent: 4 });
    let shared = b
        .hosts
        .iter()
        .find(|h| h.ip == "1.2.3.4".parse::<IpAddr>().unwrap())
        .unwrap();
    assert_eq!(shared.app_count, 2);
    // The host's name was learned later and stored once for the address.
    assert_eq!(shared.name.as_deref(), Some("cdn.example"));
    assert_eq!(b.traffic_types[0].traffic_type, TrafficType::Https);
    assert_eq!(b.countries[0].country.code, "US");

    assert_eq!(store.oldest_minute().unwrap(), Some(MINUTE));
}

#[test]
fn prune_removes_expired_rows() {
    let mut store = Store::open_in_memory().unwrap();
    let now_ms = (MINUTE + 3 * 24 * 60) * 60_000; // three days later
    let dns = |ts_ms| DnsRecord {
        ts_ms,
        app: 0,
        name: "x.example".into(),
        query_type: 1,
        status: 0,
        addrs: vec![],
    };
    store
        .save(
            &[app(0, r"C:\a.exe")],
            &[
                row(MINUTE, 0, "1.2.3.4", None, 1),
                row(now_ms / 60_000 - 1, 0, "1.2.3.4", None, 1),
            ],
            &[dns(now_ms - 40 * 24 * 3600 * 1000), dns(now_ms - 1000)],
        )
        .unwrap();
    assert_eq!(store.prune(now_ms).unwrap(), 2);
    assert_eq!(store.history(0, i64::MAX).unwrap().len(), 1);
    assert_eq!(store.dns_top(0, i64::MAX, None, 10).unwrap()[0].queries, 1);
}

#[test]
fn dns_top_counts_failures_and_apps() {
    let mut store = Store::open_in_memory().unwrap();
    let q = |app, name: &str, status| DnsRecord {
        ts_ms: 1_000,
        app,
        name: name.into(),
        query_type: 1,
        status,
        addrs: vec!["1.1.1.1".parse().unwrap()],
    };
    store
        .save(
            &[],
            &[],
            &[
                q(0, "a.example", 0),
                q(1, "a.example", 9003),
                q(0, "b.example", 0),
            ],
        )
        .unwrap();
    let top = store.dns_top(0, 2_000, None, 10).unwrap();
    assert_eq!(top[0].name, "a.example");
    assert_eq!((top[0].queries, top[0].failed, top[0].apps), (2, 1, 2));
    assert_eq!(store.dns_top(0, 2_000, Some(1), 10).unwrap().len(), 1);
}

#[test]
fn reopening_a_file_keeps_data() {
    let dir = std::env::temp_dir().join(format!("w4-store-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("history.db");
    {
        let mut store = Store::open(&path).unwrap();
        store
            .save(
                &[app(0, r"C:\a.exe")],
                &[row(MINUTE, 0, "1.2.3.4", None, 5)],
                &[],
            )
            .unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.load_apps().unwrap().len(), 1);
    assert_eq!(store.history(MINUTE, MINUTE).unwrap().len(), 1);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
