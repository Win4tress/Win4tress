use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use w4_ipc::api::Severity;

use super::*;

/// pid 300 is a svchost hosting TermService once `services` is filled in.
#[derive(Default)]
struct FakeResolver {
    paths: HashMap<u32, String>,
    services: Arc<Mutex<HashMap<u32, Vec<ServiceInfo>>>>,
}

impl Resolver for FakeResolver {
    fn image_path(&self, pid: u32) -> Option<String> {
        self.paths.get(&pid).cloned()
    }
    fn services(&self, pid: u32) -> Option<Vec<ServiceInfo>> {
        self.services.lock().unwrap().get(&pid).cloned()
    }
    /// 192.168.1.10 is this PC.
    fn is_own_address(&self, ip: IpAddr) -> bool {
        ip == "192.168.1.10".parse::<IpAddr>().unwrap()
    }
    fn to_win32(&self, nt_path: &str) -> String {
        nt_path.replace(r"\Device\HarddiskVolume3", "C:")
    }
    /// 1.x.x.x is "Australia", everything else unknown.
    fn country(&self, ip: IpAddr) -> Option<Country> {
        match ip {
            IpAddr::V4(v4) if v4.octets()[0] == 1 => Some(Country {
                code: "AU".into(),
                name: "Australia".into(),
            }),
            _ => None,
        }
    }
    /// Any public address belongs to "Example Net".
    fn network_owner(&self, _ip: IpAddr) -> Option<NetworkOwner> {
        Some(NetworkOwner {
            asn: 64500,
            name: "Example Net".into(),
        })
    }
}

const T0: i64 = 1_792_886_400_000; // a whole second, in ms

fn resolver() -> FakeResolver {
    FakeResolver {
        paths: HashMap::from([
            (100, r"C:\Tools\curl.exe".to_string()),
            (200, r"C:\Program Files\App\app.exe".to_string()),
            (300, r"C:\Windows\System32\svchost.exe".to_string()),
        ]),
        ..Default::default()
    }
}

fn monitor() -> Monitor {
    Monitor::new(Box::new(resolver()), T0)
}

fn dns(ts_ms: i64, pid: u32, name: &str, addrs: &[&str]) -> NetEvent {
    NetEvent::DnsQuery {
        ts_ms,
        pid,
        name: name.into(),
        query_type: 1,
        status: 0,
        addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
    }
}

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn traffic(ts_ms: i64, pid: u32, dir: Direction, bytes: u32, remote: &str) -> NetEvent {
    NetEvent::Traffic {
        ts_ms,
        pid,
        proto: Protocol::Tcp,
        dir,
        bytes,
        local: sock("192.168.1.10:50000"),
        remote: sock(remote),
    }
}

fn app_named(m: &Monitor, now: i64, file: &str) -> AppSummary {
    m.apps(now)
        .into_iter()
        .find(|a| a.path.ends_with(file))
        .unwrap_or_else(|| panic!("{file} not listed"))
}

#[test]
fn attributes_bytes_to_apps_and_hosts() {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 1000, "1.2.3.4:443"), T0);
    m.on_event(traffic(T0, 100, Direction::Out, 50, "1.2.3.4:443"), T0);
    m.on_event(traffic(T0, 200, Direction::In, 10, "192.168.1.1:53"), T0);

    let curl = app_named(&m, T0, "curl.exe");
    assert_eq!(
        curl.total,
        Bytes {
            recv: 1000,
            sent: 50
        }
    );
    assert_eq!(curl.name, "curl.exe");
    assert_eq!(curl.host_count, 1);

    let hosts = m.hosts(curl.id).unwrap().hosts;
    assert_eq!(hosts[0].traffic_type, TrafficType::Https);
    assert_eq!(hosts[0].locality, Locality::Internet);

    let (total, local) = m.totals();
    assert_eq!(
        total,
        Bytes {
            recv: 1010,
            sent: 50
        }
    );
    assert_eq!(local, Bytes { recv: 10, sent: 0 });
}

#[test]
fn loopback_is_ignored() {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 999, "127.0.0.1:8080"), T0);
    assert_eq!(m.totals().0, Bytes::default());
    assert!(m.apps(T0).is_empty());
}

#[test]
fn system_and_unknown_processes() {
    let mut m = monitor();
    m.on_event(traffic(T0, 4, Direction::In, 5, "1.1.1.1:445"), T0);
    m.on_event(traffic(T0, 999, Direction::In, 7, "1.1.1.1:443"), T0);
    let names: Vec<_> = m.apps(T0).into_iter().map(|a| a.name).collect();
    assert!(names.contains(&SYSTEM_APP.to_string()));
    assert!(names.contains(&UNKNOWN_APP.to_string()));
}

#[test]
fn process_start_maps_nt_path_and_handles_pid_reuse() {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 1, "1.1.1.1:443"), T0);
    // PID 100 is reused by a different program.
    m.on_event(
        NetEvent::ProcessStart {
            ts_ms: T0 + 10,
            pid: 100,
            sequence: 42,
            image: r"\Device\HarddiskVolume3\Games\game.exe".into(),
            package: None,
        },
        T0,
    );
    m.on_event(traffic(T0 + 20, 100, Direction::In, 500, "1.1.1.1:443"), T0);

    assert_eq!(app_named(&m, T0, "curl.exe").total.recv, 1);
    let game = app_named(&m, T0, "game.exe");
    assert_eq!(game.path, r"C:\Games\game.exe");
    assert_eq!(game.total.recv, 500);
}

#[test]
fn version_info_supplies_display_name() {
    let mut m = monitor();
    m.on_event(traffic(T0, 200, Direction::In, 1, "1.2.3.4:443"), T0);
    let pending = m.take_pending_info();
    assert_eq!(pending.len(), 1);
    let info = AppInfo {
        description: Some("Example App".into()),
        company: Some("Example Corp".into()),
        version: Some("1.2.3.4".into()),
        trust: Trust::default(),
    };
    m.set_app_info(pending[0].0, info.clone(), T0);
    let app = app_named(&m, T0, "app.exe");
    assert_eq!(app.name, "Example App");
    assert_eq!(app.company.as_deref(), Some("Example Corp"));
    assert_eq!(app.version.as_deref(), Some("1.2.3.4"));
    assert!(m.take_pending_info().is_empty());
    // A first reading isn't a change.
    assert!(m.take_alerts().is_empty());

    // Unchanged info isn't written to history again.
    m.take_dirty_apps();
    m.set_app_info(pending[0].0, info, T0);
    assert!(m.take_dirty_apps().is_empty());
}

#[test]
fn version_and_publisher_changes_raise_one_alert_each() {
    let mut m = monitor();
    m.on_event(traffic(T0, 200, Direction::In, 1, "1.2.3.4:443"), T0);
    let id = m.take_pending_info()[0].0;
    let info = |version: &str, company: &str, description: &str| AppInfo {
        description: Some(description.into()),
        company: Some(company.into()),
        version: Some(version.into()),
        trust: Trust::default(),
    };
    m.set_app_info(id, info("1.0.0.0", "Example Corp", "Example App"), T0);
    // The update also renames the app: the alert keeps the name it had.
    m.set_app_info(id, info("1.1.0.0", "Example Corp", "Example App 2"), T0 + 1);
    m.set_app_info(id, info("1.1.0.0", "Someone Else", "Example App 2"), T0 + 2);
    let alerts = m.take_alerts();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].app, Some(id));
    assert_eq!(alerts[0].app_name.as_deref(), Some("Example App"));
    assert_eq!(alerts[1].app_name.as_deref(), Some("Example App 2"));
    assert_eq!(
        alerts[0].body,
        AlertBody::AppInfoChanged {
            field: AppField::Version,
            from: "1.0.0.0".into(),
            to: "1.1.0.0".into(),
        }
    );
    assert_eq!(alerts[1].body.severity(), Severity::Warning); // publisher
    assert!(m.take_alerts().is_empty());
}

#[test]
fn trust_changes_raise_alerts() {
    use w4_core::trust::Signature::{Signed, Unsigned};
    let mut m = monitor();
    m.on_event(traffic(T0, 200, Direction::In, 1, "1.2.3.4:443"), T0);
    let id = m.take_pending_info()[0].0;
    let info = |signature, signer: Option<&str>, hash: &str| AppInfo {
        description: None,
        company: None,
        version: Some("1.0".into()),
        trust: Trust {
            signature: Some(signature),
            signer: signer.map(Into::into),
            sha256: Some(hash.repeat(64)),
            origin: None,
        },
    };
    m.set_app_info(id, info(Signed, Some("Example Corp"), "a"), T0);
    assert!(m.take_alerts().is_empty());
    m.set_app_info(id, info(Signed, Some("Example Corp"), "b"), T0 + 1); // same version, other bytes
    m.set_app_info(id, info(Signed, Some("Someone Else"), "b"), T0 + 2); // another signer
    m.set_app_info(id, info(Unsigned, None, "c"), T0 + 3); // replaced by an unsigned file
    let alerts: Vec<(AppField, Severity)> = m
        .take_alerts()
        .iter()
        .map(|a| match &a.body {
            AlertBody::AppInfoChanged { field, .. } => (*field, a.body.severity()),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        alerts,
        [
            (AppField::File, Severity::Warning),
            (AppField::Signer, Severity::Warning),
            (AppField::Signature, Severity::Critical),
            (AppField::File, Severity::Warning),
        ]
    );
    let app = app_named(&m, T0 + 3, "app.exe");
    assert_eq!(app.trust.signature, Some(Unsigned));
    assert_eq!(app.trust.signer, None);
}

#[test]
fn own_dns_is_alerted_once_per_app_but_not_for_the_dns_client() {
    let services = Arc::new(Mutex::new(HashMap::from([(
        300,
        vec![ServiceInfo {
            name: "Dnscache".into(),
            display_name: "DNS Client".into(),
        }],
    )])));
    let mut m = Monitor::new(
        Box::new(FakeResolver {
            services,
            ..resolver()
        }),
        T0,
    );
    m.on_event(traffic(T0, 100, Direction::Out, 40, "8.8.8.8:53"), T0);
    m.on_event(
        traffic(T0 + 1, 100, Direction::Out, 40, "8.8.4.4:853"),
        T0 + 1,
    );
    let alerts = m.take_alerts();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(alerts[0].body, AlertBody::OwnDns { port: 53, .. }));
    assert!(app_named(&m, T0 + 1, "curl.exe").own_dns_ms.is_some());
    // HTTPS counts only to a known DNS-over-HTTPS server.
    m.on_event(traffic(T0, 200, Direction::Out, 40, "1.2.3.4:443"), T0);
    assert!(m.take_alerts().is_empty());
    m.on_event(traffic(T0, 200, Direction::Out, 40, "9.9.9.9:443"), T0);
    assert_eq!(m.take_alerts().len(), 1);
    // Windows' DNS Client is expected to.
    m.on_event(traffic(T0, 300, Direction::Out, 40, "8.8.8.8:53"), T0);
    assert!(m.take_alerts().is_empty());
}

#[test]
fn own_dns_is_not_alerted_for_win4tress_s_resolver() {
    let mut m = Monitor::new(Box::new(resolver()), T0);
    m.set_own_resolvers([r"c:\tools\CURL.exe".to_string()]);
    m.on_event(traffic(T0, 100, Direction::Out, 40, "8.8.8.8:53"), T0);
    assert!(m.take_alerts().is_empty());
}

#[test]
fn dns_answers_resolve_host_patterns() {
    let mut m = monitor();
    m.on_event(dns(T0, 100, "ads.example.com", &["203.0.113.5"]), T0);
    m.on_event(dns(T0, 100, "cdn.ads.example.com", &["203.0.113.9"]), T0);
    m.on_event(dns(T0, 200, "ads.example.com", &["198.51.100.1"]), T0);
    assert_eq!(m.dns_generation(), 3);
    let curl = m
        .known_apps()
        .into_iter()
        .find(|a| a.path.ends_with("curl.exe"))
        .unwrap()
        .id;
    let ips = |pattern| -> Vec<String> {
        m.dns_addresses(curl, pattern)
            .into_iter()
            .map(|ip| ip.to_string())
            .collect()
    };
    assert_eq!(ips("ads.example.com"), ["203.0.113.5"]);
    assert_eq!(ips("*.ads.example.com"), ["203.0.113.5", "203.0.113.9"]);
}

#[test]
fn blocks_are_recorded_by_app() {
    use w4_core::firewall::{BlockedBy, BlockedByKind};
    let mut m = monitor();
    let by = BlockedBy {
        kind: BlockedByKind::WindowsDefault,
        name: "Default Outbound".into(),
    };
    let curl = r"C:\Tools\curl.exe";
    let first = m.record_block(T0, curl, 0, false, sock("1.2.3.4:443"), by.clone(), T0);
    assert!(first.is_some());
    m.record_block(
        T0 + 5,
        curl,
        0,
        false,
        sock("1.2.3.4:443"),
        by.clone(),
        T0 + 5,
    );
    // No app (a packet to a closed port), and this PC itself: not recorded.
    assert_eq!(
        m.record_block(T0, "", 0, true, sock("1.2.3.4:137"), by.clone(), T0),
        None
    );
    assert_eq!(
        m.record_block(T0, "NULL", 0, true, sock("1.2.3.4:137"), by.clone(), T0),
        None
    );
    m.record_block(T0, curl, 0, false, sock("127.0.0.1:80"), by, T0);
    let blocks = m.blocks(None, 10);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].count, 2);
    assert_eq!(blocks[0].app.name, "curl.exe");
    assert_eq!(m.take_unsaved_blocks().len(), 1);
}

#[test]
fn blocks_in_svchost_go_to_the_service_by_process() {
    use w4_core::firewall::{BlockedBy, BlockedByKind};
    let r = resolver();
    r.services.lock().unwrap().insert(
        300,
        vec![ServiceInfo {
            name: "TermService".into(),
            display_name: "Remote Desktop Services".into(),
        }],
    );
    let mut m = Monitor::new(Box::new(r), T0);
    let by = BlockedBy {
        kind: BlockedByKind::WindowsDefault,
        name: "Default Outbound".into(),
    };
    let svchost = r"\Device\HarddiskVolume3\Windows\System32\svchost.exe";
    let rdp = m
        .record_block(T0, svchost, 300, false, sock("1.2.3.4:443"), by.clone(), T0)
        .unwrap();
    assert_eq!(
        m.app_record(rdp).unwrap().service.as_deref(),
        Some("TermService")
    );
    // Seen in a process running something else (an incoming drop): by path only.
    let plain = m
        .record_block(T0, svchost, 100, true, sock("1.2.3.4:443"), by, T0)
        .unwrap();
    assert_ne!(plain, rdp);
    assert_eq!(m.app_record(plain).unwrap().service, None);
}

#[test]
fn first_network_activity_alerts_after_learning() {
    let mut m = monitor();
    // Off until the service turns it on (it needs history to know old apps).
    m.on_event(traffic(T0, 100, Direction::Out, 10, "1.2.3.4:443"), T0);
    assert!(m.take_alerts().is_empty());

    m.set_first_activity_alerts_from(T0);
    m.on_event(
        traffic(T0 + 5, 200, Direction::Out, 10, "1.2.3.4:443"),
        T0 + 5,
    );
    m.on_event(
        traffic(T0 + 6, 200, Direction::Out, 10, "1.2.3.4:443"),
        T0 + 6,
    );
    // curl was seen before alerts were on: still nothing for it.
    m.on_event(
        traffic(T0 + 7, 100, Direction::Out, 10, "5.6.7.8:443"),
        T0 + 7,
    );
    let alerts = m.take_alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    let AlertBody::FirstNetworkActivity { host, port } = &alerts[0].body else {
        panic!("{:?}", alerts[0]);
    };
    assert_eq!(*port, 443);
    assert_eq!(host.as_ref().unwrap().country.code, "AU");
    assert_eq!(alerts[0].app, Some(app_named(&m, T0, "app.exe").id));
}

#[test]
fn rdp_connections_alert_once_per_address() {
    let mut m = monitor();
    let rdp = |ts_ms: i64, remote: &str| NetEvent::Connect {
        ts_ms,
        pid: 100,
        local: sock("192.168.1.10:3389"),
        remote: sock(remote),
        inbound: true,
    };
    m.on_event(rdp(T0, "192.168.1.50:50001"), T0);
    m.on_event(rdp(T0 + 1_000, "192.168.1.50:50002"), T0 + 1_000);
    m.on_event(rdp(T0 + 2_000, "192.168.1.51:50003"), T0 + 2_000);
    // An outbound connection to someone else's RDP port isn't one.
    m.on_event(
        NetEvent::Connect {
            ts_ms: T0,
            pid: 100,
            local: sock("192.168.1.10:50010"),
            remote: sock("192.168.1.60:3389"),
            inbound: false,
        },
        T0,
    );
    assert_eq!(m.take_alerts().len(), 2);
    let later = T0 + 13 * 3600 * 1000;
    m.on_event(rdp(later, "192.168.1.50:50004"), later);
    assert_eq!(m.take_alerts().len(), 1);
}

#[test]
fn live_samples_use_event_time_and_close_after_lag() {
    let mut m = monitor();
    let now = T0 + 10_000;
    // Traffic in second T0+5, delivered late at T0+10.
    m.on_event(
        traffic(T0 + 5_400, 100, Direction::In, 300, "1.1.1.1:443"),
        now,
    );
    let samples = m.live(10, now);
    let sec = (T0 + 5_000) / 1000;
    let s = samples.iter().find(|s| s.t == sec).expect("second present");
    assert_eq!(s.recv, 300);
    // The newest returned second has closed: now - lag - 1 s.
    assert_eq!(samples.last().unwrap().t, closed_until(now));
}

#[test]
fn take_new_samples_publishes_each_second_once() {
    let mut m = monitor();
    m.on_event(
        traffic(T0 + 500, 100, Direction::In, 10, "1.1.1.1:443"),
        T0 + 500,
    );
    let first = m.take_new_samples(T0 + 3_000);
    assert!(!first.is_empty());
    assert!(m.take_new_samples(T0 + 3_000).is_empty(), "nothing new yet");
    let second = m.take_new_samples(T0 + 4_000);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].t, first.last().unwrap().t + 1);
}

#[test]
fn breakdown_ranks_apps_and_hosts_with_names() {
    let mut m = monitor();
    m.on_event(dns(T0, 100, "speed.example.com", &["1.2.3.4"]), T0);
    m.on_event(traffic(T0, 100, Direction::In, 5000, "1.2.3.4:443"), T0);
    m.on_event(traffic(T0, 200, Direction::In, 100, "5.6.7.8:443"), T0);
    let sec = T0 / 1000;
    let b = m.breakdown(sec, sec, &BreakdownFilter::default(), 10);
    assert!(b.apps[0].app.name.contains("curl"));
    assert_eq!(b.hosts[0].name.as_deref(), Some("speed.example.com"));
    assert_eq!(b.hosts[1].name, None);
}

#[test]
fn per_app_dns_name_beats_global() {
    let mut m = monitor();
    for (pid, name) in [(100, "a.example"), (200, "b.example")] {
        m.on_event(dns(T0, pid, name, &["9.9.9.9"]), T0);
        m.on_event(traffic(T0, pid, Direction::In, 1, "9.9.9.9:443"), T0);
    }
    let curl = app_named(&m, T0, "curl.exe");
    assert_eq!(
        m.hosts(curl.id).unwrap().hosts[0].name.as_deref(),
        Some("a.example")
    );
}

#[test]
fn old_seconds_are_evicted_but_totals_kept() {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 10, "1.1.1.1:443"), T0);
    let later = T0 + (LIVE_SECONDS + 5) * 1000;
    m.evict(later);
    let sec = T0 / 1000;
    assert!(
        m.breakdown(sec, sec, &BreakdownFilter::default(), 10)
            .apps
            .is_empty()
    );
    assert_eq!(m.totals().0.recv, 10);
}

#[test]
fn inbound_service_is_typed_by_local_port() {
    let mut m = monitor();
    // A remote desktop client connecting to this PC: our port is 3389, theirs is random.
    m.on_event(
        NetEvent::Traffic {
            ts_ms: T0,
            pid: 100,
            proto: Protocol::Udp,
            dir: Direction::Out,
            bytes: 1200,
            local: sock("192.168.1.135:3389"),
            remote: sock("192.168.1.229:59561"),
        },
        T0,
    );
    let curl = app_named(&m, T0, "curl.exe");
    let host = &m.hosts(curl.id).unwrap().hosts[0];
    assert_eq!(host.traffic_type, TrafficType::Rdp);
    assert_eq!(host.ports, vec![59561]);
}

fn breakdown_fixture() -> Monitor {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 5000, "1.2.3.4:443"), T0); // curl, AU, HTTPS
    m.on_event(traffic(T0, 200, Direction::In, 300, "1.2.3.4:443"), T0); // app, AU, HTTPS
    m.on_event(traffic(T0, 200, Direction::Out, 40, "9.9.9.9:53"), T0); // app, ??, DNS
    m.on_event(traffic(T0, 200, Direction::In, 70, "192.168.1.1:53"), T0); // app, LAN, DNS
    m
}

#[test]
fn breakdown_groups_by_every_dimension() {
    let m = breakdown_fixture();
    let sec = T0 / 1000;
    let b = m.breakdown(sec, sec, &BreakdownFilter::default(), 10);

    assert_eq!(
        b.total,
        Bytes {
            recv: 5370,
            sent: 40
        }
    );
    assert_eq!(b.local, Bytes { recv: 70, sent: 0 });
    assert_eq!(
        b.internet,
        Bytes {
            recv: 5300,
            sent: 40
        }
    );
    assert!(b.apps[0].app.path.ends_with("curl.exe"));

    // One host row per IP, across apps, credited to the busiest app.
    let shared = b
        .hosts
        .iter()
        .find(|h| h.ip.to_string() == "1.2.3.4")
        .unwrap();
    assert_eq!(shared.bytes.recv, 5300);
    assert_eq!(shared.app_count, 2);
    assert!(shared.top_app.path.ends_with("curl.exe"));
    assert_eq!(shared.country.code, "AU");

    let types: Vec<_> = b.traffic_types.iter().map(|t| t.traffic_type).collect();
    assert_eq!(types, vec![TrafficType::Https, TrafficType::Dns]);
    let codes: Vec<_> = b
        .countries
        .iter()
        .map(|c| c.country.code.as_str())
        .collect();
    assert_eq!(codes, vec!["AU", Country::LOCAL, Country::UNKNOWN]);
}

#[test]
fn breakdown_filters_cross_columns() {
    let m = breakdown_fixture();
    let sec = T0 / 1000;
    let dns_only = BreakdownFilter {
        traffic_type: Some(TrafficType::Dns),
        ..Default::default()
    };
    let b = m.breakdown(sec, sec, &dns_only, 10);
    assert_eq!(b.total, Bytes { recv: 70, sent: 40 });
    assert_eq!(b.apps.len(), 1);
    assert!(b.apps[0].app.path.ends_with("app.exe"));

    let lan = BreakdownFilter {
        country: Some(Country::LOCAL.into()),
        ..Default::default()
    };
    assert_eq!(
        m.breakdown(sec, sec, &lan, 10).total,
        Bytes { recv: 70, sent: 0 }
    );
}

#[test]
fn breakdown_limit_reports_the_rest() {
    let m = breakdown_fixture();
    let sec = T0 / 1000;
    let b = m.breakdown(sec, sec, &BreakdownFilter::default(), 1);
    assert_eq!(b.apps.len(), 1);
    assert_eq!(b.apps_more, 1);
    assert_eq!(b.hosts_more, 2);
}

#[test]
fn connect_counts_and_ports_are_tracked() {
    let mut m = monitor();
    for port in [443, 8443, 443] {
        m.on_event(
            NetEvent::Connect {
                ts_ms: T0,
                pid: 100,
                local: sock("192.168.1.10:50000"),
                remote: SocketAddr::new("1.1.1.1".parse().unwrap(), port),
                inbound: false,
            },
            T0,
        );
    }
    m.on_event(traffic(T0, 100, Direction::In, 1, "1.1.1.1:443"), T0);
    let curl = app_named(&m, T0, "curl.exe");
    let host = &m.hosts(curl.id).unwrap().hosts[0];
    assert_eq!(host.connects, 3);
    assert_eq!(host.ports, vec![443, 8443]);
}

#[test]
fn own_addresses_are_ignored() {
    let mut m = monitor();
    // Multicast looped back to us arrives "from" our own address.
    m.on_event(
        traffic(T0, 100, Direction::In, 500, "192.168.1.10:5353"),
        T0,
    );
    assert_eq!(m.totals().0, Bytes::default());
    assert!(m.connections(None, 10).is_empty());
}

#[test]
fn svchost_is_split_by_service_once_registered() {
    let r = resolver();
    let services = Arc::clone(&r.services);
    let mut m = Monitor::new(Box::new(r), T0);
    m.on_event(
        NetEvent::ProcessStart {
            ts_ms: T0,
            pid: 300,
            sequence: 7,
            image: r"\Device\HarddiskVolume3\Windows\System32\svchost.exe".into(),
            package: None,
        },
        T0,
    );
    // Services not registered yet: counted as plain svchost.
    m.on_event(
        traffic(T0, 300, Direction::Out, 10, "192.168.1.229:59561"),
        T0,
    );
    services.lock().unwrap().insert(
        300,
        vec![ServiceInfo {
            name: "TermService".into(),
            display_name: "Remote Desktop Services".into(),
        }],
    );
    m.on_event(
        traffic(T0, 300, Direction::Out, 1000, "192.168.1.229:59561"),
        T0,
    );

    let apps = m.apps(T0);
    let rdp = apps
        .iter()
        .find(|a| a.service.as_deref() == Some("TermService"))
        .unwrap();
    assert_eq!(rdp.name, "Remote Desktop Services");
    assert_eq!(rdp.total.sent, 1000);
    assert!(rdp.path.ends_with("svchost.exe"));
    let plain = apps
        .iter()
        .find(|a| a.service.is_none() && a.path.ends_with("svchost.exe"))
        .unwrap();
    assert_eq!(plain.total.sent, 10);
}

#[test]
fn connections_open_close_and_seed() {
    let mut m = monitor();
    let local = sock("192.168.1.10:50000");
    let remote = sock("1.2.3.4:443");
    m.seed_connections(
        &[(200, sock("192.168.1.10:51000"), sock("5.6.7.8:443"))],
        T0,
    );
    m.on_event(
        NetEvent::Connect {
            ts_ms: T0,
            pid: 100,
            local,
            remote,
            inbound: false,
        },
        T0,
    );
    m.on_event(
        traffic(T0 + 10, 100, Direction::In, 700, "1.2.3.4:443"),
        T0 + 10,
    );

    let open = m.connections(None, 10);
    assert_eq!(open.len(), 2);
    let curl = open.iter().find(|c| c.remote == remote).unwrap();
    assert_eq!(curl.state, ConnectionState::Open);
    assert_eq!(curl.inbound, Some(false));
    assert_eq!(curl.bytes.recv, 700);
    assert_eq!(curl.traffic_type, TrafficType::Https);
    let seeded = open
        .iter()
        .find(|c| c.remote.port() == 443 && c.remote != remote)
        .unwrap();
    assert_eq!(seeded.inbound, None);

    m.on_event(
        NetEvent::Disconnect {
            ts_ms: T0 + 20,
            pid: 100,
            local,
            remote,
        },
        T0 + 20,
    );
    let curl = m.connections(Some(curl.app.id), 10).remove(0);
    assert_eq!(curl.state, ConnectionState::Closed);

    // Closed connections drop off after a minute.
    m.evict(T0 + 120_000);
    assert!(m.connections(None, 10).iter().all(|c| c.remote != remote));
}

#[test]
fn app_summary_has_rate_activity_hosts_and_processes() {
    let mut m = monitor();
    let t = T0 + 30_000;
    m.on_event(traffic(t, 100, Direction::In, 3_000, "1.2.3.4:443"), t);
    m.on_event(traffic(t, 100, Direction::Out, 300, "1.2.3.4:443"), t);
    m.on_event(traffic(t, 100, Direction::In, 600, "5.6.7.8:443"), t);
    m.on_event(
        NetEvent::Connect {
            ts_ms: t,
            pid: 100,
            local: sock("192.168.1.10:50000"),
            remote: sock("1.2.3.4:443"),
            inbound: false,
        },
        t,
    );
    // Once its second has closed, the traffic is the latest in the rate window.
    let now = t + 2_500;
    let curl = app_named(&m, now, "curl.exe");
    assert_eq!(curl.rate.recv, 3_600 / 3);
    assert_eq!(curl.rate.sent, 300 / 3);
    assert_eq!(curl.recent_hosts, 2);
    let top = curl.top_host.unwrap();
    assert_eq!(top.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    assert_eq!(top.country.code, "AU");
    assert_eq!(curl.connections, 2); // traffic alone opens a flow too
    assert_eq!(curl.pids, vec![100]);
    assert_eq!(curl.activity.len(), 30);
    assert_eq!(curl.activity.last(), Some(&[3_600, 300]));

    // After a minute it's no longer active; after a stop event the PID is gone.
    m.on_event(
        NetEvent::ProcessStop {
            ts_ms: now,
            pid: 100,
        },
        now,
    );
    let later = app_named(&m, now + 61_000, "curl.exe");
    assert_eq!(later.rate, Bytes::default());
    assert!(later.activity.is_empty());
    assert_eq!(later.top_host, None);
    assert!(later.pids.is_empty());
}

#[test]
fn internet_hosts_have_a_network_owner() {
    let mut m = monitor();
    m.on_event(traffic(T0, 100, Direction::In, 10, "1.2.3.4:443"), T0);
    m.on_event(traffic(T0, 100, Direction::In, 10, "192.168.1.1:80"), T0);
    let curl = app_named(&m, T0, "curl.exe").id;
    let hosts = m.hosts(curl).unwrap().hosts;
    let owner = |ip: &str| {
        hosts
            .iter()
            .find(|h| h.ip == ip.parse::<IpAddr>().unwrap())
            .unwrap()
            .owner
            .clone()
    };
    assert_eq!(owner("1.2.3.4").map(|o| o.asn), Some(64500));
    assert_eq!(owner("192.168.1.1"), None); // local network: not looked up
    let conn = m.connections(None, 10);
    let public = conn
        .iter()
        .find(|c| c.remote == sock("1.2.3.4:443"))
        .unwrap();
    assert_eq!(
        public.owner.as_ref().map(|o| o.name.as_str()),
        Some("Example Net")
    );
}

#[test]
fn udp_queries_expire_sooner_than_other_udp() {
    let mut m = monitor();
    let udp = |remote: &str| NetEvent::Traffic {
        ts_ms: T0,
        pid: 100,
        proto: Protocol::Udp,
        dir: Direction::Out,
        bytes: 60,
        local: sock("192.168.1.10:50000"),
        remote: sock(remote),
    };
    m.on_event(udp("192.168.1.1:53"), T0);
    m.on_event(udp("1.2.3.4:3478"), T0);
    assert_eq!(m.connections(None, 10).len(), 2);

    m.evict(T0 + 20_000);
    let left = m.connections(None, 10);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].remote, sock("1.2.3.4:3478"));

    m.evict(T0 + 130_000);
    assert!(m.connections(None, 10).is_empty());
}

#[test]
fn dns_log_keeps_failures_and_filters() {
    let mut m = monitor();
    m.on_event(dns(T0, 100, "ok.example", &["1.2.3.4"]), T0);
    m.on_event(
        NetEvent::DnsQuery {
            ts_ms: T0 + 1,
            pid: 200,
            name: "missing.example".into(),
            query_type: 28,
            status: 9003,
            addrs: vec![],
        },
        T0,
    );
    let log = m.dns_log(10, None, None);
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].name, "missing.example"); // newest first
    assert_eq!(log[0].status, 9003);
    assert_eq!(m.dns_log(10, None, Some("OK.")).len(), 1);
    let curl = m.dns_log(1, None, Some("ok")).remove(0).app.id;
    assert_eq!(m.dns_log(10, Some(curl), None).len(), 1);

    let top = m.dns_top(T0, T0 + 10, None, 10);
    assert_eq!(top.len(), 2);
    assert_eq!(
        top.iter()
            .find(|d| d.name == "missing.example")
            .unwrap()
            .failed,
        1
    );
    assert_eq!(m.take_unsaved_dns().len(), 2);
    assert!(m.take_unsaved_dns().is_empty());
}

#[test]
fn dual_lookup_echo_is_not_a_failure() {
    let mut m = monitor();
    m.on_event(
        dns(T0, 100, "host.example", &["1.2.3.4", "2001:db8::1"]),
        T0,
    );
    m.on_event(
        NetEvent::DnsQuery {
            ts_ms: T0,
            pid: 100,
            name: "host.example".into(),
            query_type: 1,
            status: 87,
            addrs: vec![],
        },
        T0,
    );
    assert_eq!(m.dns_log(10, None, None).len(), 1);
    assert_eq!(m.dns_top(T0, T0 + 10, None, 10)[0].failed, 0);
}

#[test]
fn reverse_dns_is_queued_once_and_ranks_below_dns() {
    let mut m = monitor();
    m.on_event(dns(T0, 100, "named.example", &["1.2.3.4"]), T0);
    m.on_event(traffic(T0, 100, Direction::In, 1, "1.2.3.4:443"), T0); // has a DNS name
    m.on_event(traffic(T0, 100, Direction::In, 1, "5.6.7.8:443"), T0);
    m.on_event(traffic(T0, 200, Direction::In, 1, "5.6.7.8:443"), T0); // same IP, other app
    m.on_event(traffic(T0, 100, Direction::In, 1, "224.0.0.251:5353"), T0); // multicast

    let queued = m.take_reverse_lookups(10);
    assert_eq!(queued, vec!["5.6.7.8".parse::<IpAddr>().unwrap()]);
    m.set_reverse_name(queued[0], "ptr.example");
    m.set_reverse_name("1.2.3.4".parse().unwrap(), "ignored.ptr");

    let curl = app_named(&m, T0, "curl.exe");
    let hosts = m.hosts(curl.id).unwrap().hosts;
    let name = |ip: &str| {
        hosts
            .iter()
            .find(|h| h.ip.to_string() == ip)
            .unwrap()
            .name
            .clone()
    };
    assert_eq!(name("5.6.7.8").as_deref(), Some("ptr.example"));
    assert_eq!(name("1.2.3.4").as_deref(), Some("named.example"));
}

#[test]
fn closed_minutes_are_handed_over_once() {
    let mut m = monitor();
    m.on_event(
        traffic(T0 + 5_000, 100, Direction::In, 300, "1.2.3.4:443"),
        T0 + 5_000,
    );
    m.on_event(
        traffic(T0 + 65_000, 100, Direction::In, 40, "1.2.3.4:443"),
        T0 + 65_000,
    );

    // The first minute isn't closed until its last second plus the delivery lag.
    assert!(m.take_closed_minutes(T0 + 59_000).is_empty());
    let first = m.take_closed_minutes(T0 + 62_000);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].minute, T0 / 60_000);
    assert_eq!(first[0].row.bytes.recv, 300);
    assert_eq!(first[0].row.traffic_type, TrafficType::Https);
    assert_eq!(first[0].row.country.code, "AU");
    assert!(m.take_closed_minutes(T0 + 62_000).is_empty());

    let second = m.take_closed_minutes(T0 + 125_000);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].row.bytes.recv, 40);
}

#[test]
fn saved_apps_keep_their_ids() {
    let mut m = monitor();
    m.on_event(traffic(T0, 200, Direction::In, 1, "1.2.3.4:443"), T0);
    m.on_event(traffic(T0, 100, Direction::In, 1, "1.2.3.4:443"), T0);
    let saved = m.take_dirty_apps();
    assert_eq!(saved.len(), 2);
    assert!(m.take_dirty_apps().is_empty());

    // A new run loads them; the same executable gets the same id.
    let mut next = monitor();
    next.load_apps(saved.clone());
    next.on_event(traffic(T0, 100, Direction::In, 1, "1.2.3.4:443"), T0);
    let curl_before = saved
        .iter()
        .find(|r| r.path.ends_with("curl.exe"))
        .unwrap()
        .id;
    assert_eq!(app_named(&next, T0, "curl.exe").id, curl_before);
    assert_eq!(next.app_ref(curl_before).path, r"C:\Tools\curl.exe");
}

mod properties {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;

    fn ip() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(IpAddr::from),
            any::<[u8; 16]>().prop_map(IpAddr::from),
            Just("192.168.1.10".parse().unwrap()), // this PC
            Just("127.0.0.1".parse().unwrap()),
        ]
    }

    fn sock() -> impl Strategy<Value = SocketAddr> {
        (ip(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::new(ip, port))
    }

    fn event() -> impl Strategy<Value = NetEvent> {
        let ts = (0i64..120_000).prop_map(|t| T0 + t);
        let pid = 0u32..8;
        prop_oneof![
            4 => (ts.clone(), pid.clone(), any::<bool>(), any::<bool>(), 0u32..100_000, sock(), sock())
                .prop_map(|(ts_ms, pid, udp, inbound, bytes, local, remote)| NetEvent::Traffic {
                    ts_ms,
                    pid,
                    proto: if udp { Protocol::Udp } else { Protocol::Tcp },
                    dir: if inbound { Direction::In } else { Direction::Out },
                    bytes,
                    local,
                    remote,
                }),
            1 => (ts.clone(), pid.clone(), sock(), sock(), any::<bool>())
                .prop_map(|(ts_ms, pid, local, remote, inbound)| NetEvent::Connect { ts_ms, pid, local, remote, inbound }),
            1 => (ts.clone(), pid.clone(), sock(), sock())
                .prop_map(|(ts_ms, pid, local, remote)| NetEvent::Disconnect { ts_ms, pid, local, remote }),
            1 => (ts.clone(), pid.clone(), "\\PC{0,30}", any::<u16>(), any::<u32>(), vec(ip(), 0..3))
                .prop_map(|(ts_ms, pid, name, query_type, status, addrs)| NetEvent::DnsQuery {
                    ts_ms, pid, name, query_type, status, addrs,
                }),
            1 => (ts, pid, "[a-zA-Z]{1,12}", prop_oneof![Just(false), Just(true)])
                .prop_map(|(ts_ms, pid, name, svchost)| NetEvent::ProcessStart {
                    ts_ms,
                    pid,
                    sequence: 1,
                    image: if svchost {
                        r"\Device\HarddiskVolume3\Windows\System32\svchost.exe".into()
                    } else {
                        format!(r"\Device\HarddiskVolume3\Apps\{name}.exe")
                    },
                    package: None,
                }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Any sequence of events: no panics, and every view of the traffic agrees.
        #[test]
        fn random_events_keep_totals_consistent(events in vec(event(), 0..200)) {
            let mut m = monitor();
            let now = T0 + 130_000;
            for e in events {
                m.on_event(e, now);
            }
            let (total, _) = m.totals();

            let per_app = m.apps(now).iter().fold(Bytes::default(), |acc, a| acc.plus(a.total));
            prop_assert_eq!(per_app, total);

            // All events fall inside the live window here, so a breakdown sees everything.
            let b = m.breakdown(i64::MIN, i64::MAX, &BreakdownFilter::default(), 10_000);
            prop_assert_eq!(b.total, total);
            prop_assert_eq!(b.internet.plus(b.local), total);

            // So does history: the minutes handed over add up to the same.
            let minutes = m.take_closed_minutes(now + 61_000);
            let saved = minutes.iter().fold(Bytes::default(), |acc, r| acc.plus(r.row.bytes));
            prop_assert_eq!(saved, total);

            // Listing everything else must not panic either.
            let _ = m.connections(None, 10_000);
            let _ = m.dns_log(10_000, None, Some("a"));
            let _ = m.take_dirty_apps();
        }
    }
}
