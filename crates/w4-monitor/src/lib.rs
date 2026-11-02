//! In-memory traffic model. Traffic is placed in per-second buckets by *event*
//! timestamp (ETW delivers late), apps are keyed by executable path (plus the
//! hosted services for svchost), and hosts by (app, remote IP). Closed minutes are
//! handed to the history store; this crate does no I/O itself.

pub mod blocks;
mod dnslog;
mod flows;
mod names;
pub mod usage;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use w4_core::firewall::BlockedBy;
use w4_core::trust::{PathClass, Signature, Trust};
use w4_core::{
    Bytes, Country, Direction, Locality, NetEvent, NetworkOwner, Protocol, TrafficType, locality,
};
use w4_ipc::api::{
    ACTIVITY_STEP, AlertBody, AppField, AppId, AppRef, AppSummary, BlockedConnection, Breakdown,
    BreakdownFilter, Connection, ConnectionState, DnsEntry, DomainCount, HostRef, HostSummary,
    HostsResult, KnownApp, Sample,
};

pub use dnslog::{DnsRecord, top_domains};
use flows::{FlowKey, Flows};
use names::Names;
pub use usage::{UsageRow, build_breakdown};

/// Seconds of per-second detail kept in memory.
pub const LIVE_SECONDS: i64 = 600;
/// A second is final once this long has passed after it ended (ETW delivery delay).
pub const CLOSE_LAG_MS: i64 = 1_000;
const RECENT_SECONDS: i64 = 60;
/// An app's current rate is its average over this many closed seconds.
const RATE_SECONDS: i64 = 3;
const MAX_HOSTS: usize = 100_000;
const MAX_PORTS: usize = 8;
/// Events stamped further in the future than this are treated as "now".
const MAX_CLOCK_SKEW_MS: i64 = 2_000;
/// Addresses queued for reverse DNS, at most.
const MAX_REVERSE_QUEUE: usize = 1_000;
/// Win32 ERROR_INVALID_PARAMETER, as a DNS-Client query status.
const DNS_INVALID_PARAMETER: u32 = 87;
const RDP_PORT: u16 = 3389;
/// One RDP alert per remote address in this long.
const RDP_REALERT_MS: i64 = 12 * 3600 * 1000;
/// Alerts not yet collected by the service, at most (it collects every second).
const MAX_PENDING_ALERTS: usize = 1_000;

pub const SYSTEM_APP: &str = "System";
pub const UNKNOWN_APP: &str = "Unknown";

/// A Windows service hosted by a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
}

/// System lookups. The service implements this with Win32 calls; tests fake it.
pub trait Resolver: Send {
    /// Win32 path of a running process's executable.
    fn image_path(&self, pid: u32) -> Option<String>;
    /// NT device path (from Kernel-Process events) to a Win32 path.
    fn to_win32(&self, nt_path: &str) -> String;
    /// Country of a public address; `None` without a database or entry.
    fn country(&self, _ip: IpAddr) -> Option<Country> {
        None
    }
    /// Network owner (ASN) of a public address; `None` without a database or entry.
    fn network_owner(&self, _ip: IpAddr) -> Option<NetworkOwner> {
        None
    }
    /// Services running in a process; `None` or empty if none are registered yet.
    fn services(&self, _pid: u32) -> Option<Vec<ServiceInfo>> {
        None
    }
    /// One of this PC's own addresses: traffic to it never leaves the machine.
    fn is_own_address(&self, _ip: IpAddr) -> bool {
        false
    }
    /// Where an executable lives, by who can write there.
    fn path_class(&self, _path: &str) -> Option<PathClass> {
        None
    }
}

/// An app as stored in history; ids are stable across restarts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRecord {
    pub id: AppId,
    /// Identity: lower-case path, plus `|services` for svchost instances.
    pub key: String,
    pub path: String,
    pub description: Option<String>,
    pub company: Option<String>,
    pub version: Option<String>,
    pub package: Option<String>,
    pub service: Option<String>,
    pub service_display: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// When the app first sent or received anything; `None` if it never has.
    pub net_first_seen_ms: Option<i64>,
    pub trust: Trust,
    /// When the app was first seen doing its own DNS (SPEC §7.11).
    pub own_dns_ms: Option<i64>,
}

/// An alert the monitor raised; the service stores it and assigns an id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAlert {
    pub ts_ms: i64,
    pub app: Option<AppId>,
    /// The app's name when the alert was raised. An update can change it (the
    /// name comes from the file's description), and the alert should say what
    /// the app was called at the time.
    pub app_name: Option<String>,
    pub body: AlertBody,
    /// Instead of the body's own severity (the user's monitor settings).
    pub severity: Option<w4_ipc::api::Severity>,
}

/// An app's executable as read: version resource and trust details.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppInfo {
    pub description: Option<String>,
    pub company: Option<String>,
    pub version: Option<String>,
    pub trust: Trust,
}

/// One minute of traffic between an app and a remote address, for history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinuteRow {
    /// Unix minute (Unix seconds / 60).
    pub minute: i64,
    pub row: UsageRow,
}

struct App {
    key: String,
    path: String,
    file_name: String,
    description: Option<String>,
    company: Option<String>,
    version: Option<String>,
    package: Option<String>,
    service: Option<String>,
    service_display: Option<String>,
    first_seen_ms: i64,
    last_seen_ms: i64,
    net_first_seen_ms: Option<i64>,
    trust: Trust,
    own_dns_ms: Option<i64>,
    total: Bytes,
    local: Bytes,
}

impl App {
    /// Windows' DNS Client service: the one app expected to talk DNS itself.
    fn is_dns_client(&self) -> bool {
        self.service
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().split(", ").any(|n| n == "dnscache"))
    }

    fn display_name(&self) -> String {
        self.service_display
            .clone()
            .or_else(|| self.description.clone())
            .unwrap_or_else(|| self.file_name.clone())
    }

    fn record(&self, id: AppId) -> AppRecord {
        AppRecord {
            id,
            key: self.key.clone(),
            path: self.path.clone(),
            description: self.description.clone(),
            company: self.company.clone(),
            version: self.version.clone(),
            package: self.package.clone(),
            service: self.service.clone(),
            service_display: self.service_display.clone(),
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            net_first_seen_ms: self.net_first_seen_ms,
            trust: self.trust.clone(),
            own_dns_ms: self.own_dns_ms,
        }
    }
}

struct Host {
    locality: Locality,
    country: Country,
    owner: Option<NetworkOwner>,
    traffic_type: TrafficType,
    ports: Vec<u16>,
    total: Bytes,
    connects: u32,
    first_seen_ms: i64,
    last_seen_ms: i64,
}

impl Host {
    fn touch(&mut self, port: u16, ts_ms: i64) {
        self.last_seen_ms = self.last_seen_ms.max(ts_ms);
        if self.ports.len() < MAX_PORTS && !self.ports.contains(&port) {
            self.ports.push(port);
        }
    }
}

/// The service port is usually the remote one; for connections *to* this PC
/// (RDP, SMB, a local web server) it's ours, so fall back to the local port.
fn classify(proto: Protocol, remote_port: u16, local_port: u16) -> TrafficType {
    match TrafficType::classify(proto, remote_port) {
        TrafficType::Other => TrafficType::classify(proto, local_port),
        known => known,
    }
}

fn is_svchost(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with("\\svchost.exe")
}

/// Worth a PTR query: unicast and not link-local.
fn reverse_eligible(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_multicast() || v6.is_unspecified() || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[derive(Default)]
struct Bucket {
    total: Bytes,
    apps: HashMap<AppId, Bytes>,
    hosts: HashMap<(AppId, IpAddr), Bytes>,
}

pub struct Monitor {
    started_ms: i64,
    resolver: Box<dyn Resolver>,
    apps: Vec<App>,
    app_index: HashMap<String, AppId>,
    /// Current app for each PID. A ProcessStart for a reused PID replaces it.
    procs: HashMap<u32, AppId>,
    /// The subset of `procs` that hasn't exited. `procs` keeps exited PIDs, since
    /// their last events can arrive after the stop event.
    running: HashMap<u32, AppId>,
    /// svchost processes whose services weren't registered yet when last checked.
    svchost_pids: HashMap<u32, String>,
    hosts: HashMap<(AppId, IpAddr), Host>,
    names: Names,
    live: BTreeMap<i64, Bucket>,
    /// Left out of the live totals (VPN clients, when the user says so).
    excluded: Vec<AppId>,
    /// Threat lists new hosts are checked against (SPEC §11 "Suspicious host").
    threats: Option<std::sync::Arc<w4_core::threats::ThreatLists>>,
    /// (app, address) pairs already reported as suspicious.
    suspicious_seen: HashSet<(AppId, IpAddr)>,
    flows: Flows,
    dns: dnslog::DnsLog,
    totals: Bytes,
    local: Bytes,
    pending_info: Vec<AppId>,
    dirty_apps: HashSet<AppId>,
    reverse_queue: VecDeque<IpAddr>,
    reverse_requested: HashSet<IpAddr>,
    published_until: i64,
    /// The first minute not yet handed to history.
    next_minute: i64,
    alerts: Vec<PendingAlert>,
    /// First-network-activity alerts start here; `None` keeps them off (no history
    /// to tell new apps from known ones, or still learning what's normal).
    first_activity_from_ms: Option<i64>,
    /// Last RDP alert per remote address.
    rdp_alerted: HashMap<IpAddr, i64>,
    /// (lower-case path, field, new value) already alerted: svchost instances
    /// share one file, and one update shouldn't raise an alert per service.
    info_alerted: HashSet<(String, AppField, String)>,
    /// Public DNS-over-HTTPS resolvers.
    doh: HashSet<IpAddr>,
    /// win4tress's own DNS resolver (lower-case paths): doing DNS is its job.
    own_resolvers: HashSet<String>,
    dns_generation: u64,
    blocks: blocks::Blocks,
}

impl Monitor {
    pub fn new(resolver: Box<dyn Resolver>, now_ms: i64) -> Self {
        Monitor {
            started_ms: now_ms,
            resolver,
            apps: Vec::new(),
            app_index: HashMap::new(),
            procs: HashMap::new(),
            running: HashMap::new(),
            svchost_pids: HashMap::new(),
            hosts: HashMap::new(),
            names: Names::default(),
            live: BTreeMap::new(),
            excluded: Vec::new(),
            threats: None,
            suspicious_seen: HashSet::new(),
            flows: Flows::default(),
            dns: dnslog::DnsLog::default(),
            totals: Bytes::default(),
            local: Bytes::default(),
            pending_info: Vec::new(),
            dirty_apps: HashSet::new(),
            reverse_queue: VecDeque::new(),
            reverse_requested: HashSet::new(),
            published_until: closed_until(now_ms),
            next_minute: now_ms.div_euclid(60_000),
            alerts: Vec::new(),
            first_activity_from_ms: None,
            rdp_alerted: HashMap::new(),
            info_alerted: HashSet::new(),
            doh: w4_core::net::doh_servers().into_iter().collect(),
            own_resolvers: HashSet::new(),
            dns_generation: 0,
            blocks: blocks::Blocks::default(),
        }
    }

    /// A connection attempt WFP dropped. `app` is the drop's app: an NT device
    /// path, a Win32 path, or "System"; drops with no app (unsolicited packets
    /// to a closed port, which WFP reports as empty or "NULL") aren't recorded.
    /// `pid`, the process the drop was seen in, tells svchost's services apart
    /// when it's running `app`. Returns the app, if recorded.
    #[allow(clippy::too_many_arguments)]
    pub fn record_block(
        &mut self,
        ts_ms: i64,
        app: &str,
        pid: u32,
        inbound: bool,
        remote: SocketAddr,
        by: BlockedBy,
        now_ms: i64,
    ) -> Option<AppId> {
        if self.ignored(remote.ip()) {
            return None;
        }
        let converted;
        let path = if app.starts_with('\\') {
            converted = self.resolver.to_win32(app);
            converted.as_str()
        } else if app.eq_ignore_ascii_case(SYSTEM_APP) {
            SYSTEM_APP
        } else if app.contains(":\\") {
            app
        } else {
            return None;
        };
        let ts_ms = clamp_ts(ts_ms, now_ms);
        // A drop names the executable only; the process it was seen in tells
        // svchost's services apart, if it's running that executable.
        let by_pid = (pid > 4)
            .then(|| self.app_for_pid(pid, ts_ms))
            .filter(|&id| {
                self.apps
                    .get(id as usize)
                    .is_some_and(|a| a.path.eq_ignore_ascii_case(path))
            });
        let app = match by_pid {
            Some(id) => id,
            None => self.app_id(path, None, ts_ms),
        };
        self.blocks.record(
            blocks::BlockKey {
                app,
                inbound,
                ip: remote.ip(),
                port: remote.port(),
                by,
            },
            ts_ms,
        );
        Some(app)
    }

    /// Recent blocked attempts since the service started, most recent first.
    pub fn blocks(&self, app: Option<AppId>, limit: usize) -> Vec<BlockedConnection> {
        self.blocks
            .recent(app, limit)
            .into_iter()
            .map(|(k, c)| BlockedConnection {
                app: self.app_ref(k.app),
                inbound: k.inbound,
                remote: SocketAddr::new(k.ip, k.port),
                name: self.names.get(k.app, k.ip).map(str::to_string),
                by: k.by,
                count: c.count,
                first_ms: c.first_ms,
                last_ms: c.last_ms,
            })
            .collect()
    }

    /// The name this app knows an address by, if any.
    pub fn host_name(&self, app: AppId, ip: IpAddr) -> Option<String> {
        self.names.get(app, ip).map(str::to_string)
    }

    pub fn take_unsaved_blocks(&mut self) -> Vec<blocks::BlockRow> {
        self.blocks.take_unsaved()
    }

    /// Every app with a program a rule can name (System included), from history
    /// and this run, most recently seen first.
    pub fn known_apps(&self) -> Vec<KnownApp> {
        let mut out: Vec<KnownApp> = self
            .apps
            .iter()
            .enumerate()
            .filter(|(_, a)| a.path == SYSTEM_APP || a.path.contains('\\'))
            .map(|(i, a)| KnownApp {
                id: i as AppId,
                name: a.display_name(),
                path: a.path.clone(),
                service: a.service.clone(),
                company: a.company.clone(),
                version: a.version.clone(),
                first_seen_ms: a.first_seen_ms,
                last_seen_ms: a.last_seen_ms,
                net_first_seen_ms: a.net_first_seen_ms,
                trust: a.trust.clone(),
                path_class: self.resolver.path_class(&a.path),
                own_dns_ms: a.own_dns_ms,
                vpn: w4_core::net::is_vpn_client(&a.path),
                reputation: None,
                incognito: false,
            })
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.last_seen_ms));
        out
    }

    /// Automatic cleanup removed an app's rules: if it comes back, it's new
    /// again, with a "first network activity" alert (SPEC §7.10).
    pub fn forget_first_activity(&mut self, app: AppId) {
        if let Some(a) = self.apps.get_mut(app as usize) {
            a.net_first_seen_ms = None;
        }
    }

    /// Every known app's record (System and placeholders included).
    pub fn app_records(&self) -> Vec<AppRecord> {
        self.apps
            .iter()
            .enumerate()
            .map(|(i, a)| a.record(i as AppId))
            .collect()
    }

    pub fn started_ms(&self) -> i64 {
        self.started_ms
    }

    /// Restores apps saved by an earlier run, so ids and names stay stable.
    /// Call before any events. Gaps in the ids are filled with placeholders.
    pub fn load_apps(&mut self, mut records: Vec<AppRecord>) {
        records.sort_by_key(|r| r.id);
        for r in records {
            while (self.apps.len() as AppId) < r.id {
                let gap = self.apps.len();
                self.push_app(format!("#{gap}"), UNKNOWN_APP.into(), None, 0);
            }
            if self.apps.len() as AppId != r.id || self.app_index.contains_key(&r.key) {
                continue; // duplicate id or key: keep the first
            }
            let id = self.push_app(r.key, r.path, None, r.first_seen_ms);
            let app = &mut self.apps[id as usize];
            app.description = r.description;
            app.company = r.company;
            app.version = r.version;
            app.package = r.package;
            app.service = r.service;
            app.service_display = r.service_display;
            app.last_seen_ms = r.last_seen_ms;
            app.net_first_seen_ms = r.net_first_seen_ms;
            app.trust = r.trust;
            app.own_dns_ms = r.own_dns_ms;
            // Read the version info again: the app may have been updated since.
            if app.path.contains('\\') {
                self.pending_info.push(id);
            }
        }
        self.dirty_apps.clear();
    }

    pub fn on_event(&mut self, event: NetEvent, now_ms: i64) {
        match event {
            NetEvent::Traffic {
                ts_ms,
                pid,
                proto,
                dir,
                bytes,
                local,
                remote,
            } => {
                let ts_ms = clamp_ts(ts_ms, now_ms);
                self.on_traffic(
                    ts_ms,
                    pid,
                    proto,
                    dir,
                    u64::from(bytes),
                    local,
                    remote,
                    now_ms,
                )
            }
            NetEvent::Connect {
                ts_ms,
                pid,
                local,
                remote,
                inbound,
            } => {
                if self.ignored(remote.ip()) {
                    return;
                }
                let ts_ms = clamp_ts(ts_ms, now_ms);
                let app = self.app_for_pid(pid, ts_ms);
                let host = self.host(app, remote, local.port(), Protocol::Tcp, ts_ms);
                host.connects += 1;
                let key = FlowKey {
                    pid,
                    proto: Protocol::Tcp,
                    local,
                    remote,
                };
                self.flows.connect(key, app, inbound, ts_ms);
                if inbound && local.port() == RDP_PORT {
                    self.rdp_connection(app, remote.ip(), ts_ms);
                }
            }
            NetEvent::Disconnect {
                ts_ms,
                pid,
                local,
                remote,
            } => {
                let key = FlowKey {
                    pid,
                    proto: Protocol::Tcp,
                    local,
                    remote,
                };
                self.flows.disconnect(&key, clamp_ts(ts_ms, now_ms));
            }
            NetEvent::ProcessStart {
                ts_ms,
                pid,
                image,
                package,
                ..
            } => {
                let path = self.resolver.to_win32(&image);
                if is_svchost(&path) {
                    // Its services register after the process starts; resolve on first traffic.
                    self.procs.remove(&pid);
                    self.running.remove(&pid);
                    self.svchost_pids.insert(pid, path);
                } else {
                    self.svchost_pids.remove(&pid);
                    let app = self.app_id(&path, None, ts_ms);
                    if package.is_some() && self.apps[app as usize].package != package {
                        self.apps[app as usize].package = package;
                        self.dirty_apps.insert(app);
                    }
                    self.procs.insert(pid, app);
                    self.running.insert(pid, app);
                }
            }
            // Keep the `procs` mapping: events for an exited process can still arrive.
            NetEvent::ProcessStop { pid, .. } => {
                self.running.remove(&pid);
            }
            // A combined A+AAAA lookup is logged twice: the AAAA event carries every
            // address and the A event fails with ERROR_INVALID_PARAMETER. That second
            // event says nothing and would count as a failed lookup.
            NetEvent::DnsQuery {
                status: DNS_INVALID_PARAMETER,
                ref addrs,
                ..
            } if addrs.is_empty() => {}
            NetEvent::DnsQuery {
                ts_ms,
                pid,
                name,
                query_type,
                status,
                addrs,
            } => {
                let app = self.app_for_pid(pid, ts_ms);
                for ip in &addrs {
                    self.names.insert(app, *ip, &name);
                }
                if !addrs.is_empty() {
                    self.dns_generation += 1;
                }
                self.dns.push(DnsRecord {
                    ts_ms,
                    app,
                    name,
                    query_type,
                    status,
                    addrs,
                });
            }
        }
        self.evict(now_ms);
    }

    /// Loopback and this PC's own addresses: traffic that never leaves the machine.
    fn ignored(&self, ip: IpAddr) -> bool {
        locality(ip) == Locality::Loopback || self.resolver.is_own_address(ip)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_traffic(
        &mut self,
        ts_ms: i64,
        pid: u32,
        proto: Protocol,
        dir: Direction,
        n: u64,
        local: SocketAddr,
        remote: SocketAddr,
        now_ms: i64,
    ) {
        let ip = remote.ip();
        if self.ignored(ip) {
            return;
        }
        let app = self.app_for_pid(pid, ts_ms);
        let loc = locality(ip);

        self.totals.add(dir, n);
        let entry = &mut self.apps[app as usize];
        entry.total.add(dir, n);
        if ts_ms > entry.last_seen_ms {
            entry.last_seen_ms = ts_ms;
            self.dirty_apps.insert(app);
        }
        let first_ever = entry.net_first_seen_ms.is_none();
        if first_ever {
            entry.net_first_seen_ms = Some(ts_ms);
            self.dirty_apps.insert(app);
        }
        if loc == Locality::Local {
            self.local.add(dir, n);
            entry.local.add(dir, n);
        }

        self.host(app, remote, local.port(), proto, ts_ms)
            .total
            .add(dir, n);
        if first_ever {
            self.first_network_activity(app, remote, ts_ms);
        }
        self.own_dns(app, remote, ts_ms);
        let key = FlowKey {
            pid,
            proto,
            local,
            remote,
        };
        self.flows.traffic(key, app, dir, n, ts_ms);

        let sec = ts_ms.div_euclid(1000);
        if sec > now_ms.div_euclid(1000) - LIVE_SECONDS {
            let bucket = self.live.entry(sec).or_default();
            bucket.total.add(dir, n);
            bucket.apps.entry(app).or_default().add(dir, n);
            bucket.hosts.entry((app, ip)).or_default().add(dir, n);
        }
    }

    /// The (app, host) entry, created on first sight. New addresses without a
    /// name are queued for reverse DNS.
    fn host(
        &mut self,
        app: AppId,
        remote: SocketAddr,
        local_port: u16,
        proto: Protocol,
        ts_ms: i64,
    ) -> &mut Host {
        let ip = remote.ip();
        if !self.hosts.contains_key(&(app, ip)) {
            let loc = locality(ip);
            let (country, owner) = match loc {
                Locality::Internet => (
                    self.resolver.country(ip).unwrap_or_else(Country::unknown),
                    self.resolver.network_owner(ip),
                ),
                _ => (Country::local(), None),
            };
            self.hosts.insert(
                (app, ip),
                Host {
                    locality: loc,
                    country,
                    owner,
                    traffic_type: classify(proto, remote.port(), local_port),
                    ports: Vec::new(),
                    total: Bytes::default(),
                    connects: 0,
                    first_seen_ms: ts_ms,
                    last_seen_ms: ts_ms,
                },
            );
            if !self.names.has_any(ip)
                && reverse_eligible(ip)
                && self.reverse_queue.len() < MAX_REVERSE_QUEUE
                && self.reverse_requested.insert(ip)
            {
                self.reverse_queue.push_back(ip);
            }
            self.check_threats(app, remote, ts_ms);
        }
        let host = self.hosts.get_mut(&(app, ip)).expect("inserted above");
        host.touch(remote.port(), ts_ms);
        host
    }

    fn app_for_pid(&mut self, pid: u32, ts_ms: i64) -> AppId {
        if let Some(&app) = self.procs.get(&pid) {
            return app;
        }
        let path = match pid {
            0 | 4 => SYSTEM_APP.to_string(),
            _ => self
                .svchost_pids
                .get(&pid)
                .cloned()
                .or_else(|| self.resolver.image_path(pid))
                // Cached even when unknown, so a dead PID isn't looked up on every event.
                .unwrap_or_else(|| UNKNOWN_APP.to_string()),
        };
        if is_svchost(&path) {
            match self.resolver.services(pid).filter(|s| !s.is_empty()) {
                Some(services) => {
                    let app = self.app_id(&path, Some(&services), ts_ms);
                    self.svchost_pids.remove(&pid);
                    self.procs.insert(pid, app);
                    self.running.insert(pid, app);
                    return app;
                }
                None => {
                    // Not registered yet: count it as plain svchost, and look again next time.
                    self.svchost_pids.insert(pid, path.clone());
                    return self.app_id(&path, None, ts_ms);
                }
            }
        }
        let known = path != UNKNOWN_APP;
        let app = self.app_id(&path, None, ts_ms);
        self.procs.insert(pid, app);
        // No path means the process is already gone (or hidden from us).
        if known {
            self.running.insert(pid, app);
        }
        app
    }

    fn app_id(&mut self, path: &str, services: Option<&[ServiceInfo]>, ts_ms: i64) -> AppId {
        let key = match services {
            Some(services) => {
                let mut names: Vec<String> = services
                    .iter()
                    .map(|s| s.name.to_ascii_lowercase())
                    .collect();
                names.sort_unstable();
                format!("{}|{}", path.to_lowercase(), names.join(","))
            }
            None => path.to_lowercase(),
        };
        if let Some(&id) = self.app_index.get(&key) {
            return id;
        }
        let id = self.push_app(key, path.to_string(), services, ts_ms);
        if path.contains('\\') {
            self.pending_info.push(id);
        }
        id
    }

    fn push_app(
        &mut self,
        key: String,
        path: String,
        services: Option<&[ServiceInfo]>,
        ts_ms: i64,
    ) -> AppId {
        let id = self.apps.len() as AppId;
        let file_name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string();
        let (service, service_display) = match services {
            Some(services) if !services.is_empty() => {
                let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
                let display = match services.len() {
                    1 => services[0].display_name.clone(),
                    n => format!("{} (+{} more)", services[0].display_name, n - 1),
                };
                (Some(names.join(", ")), Some(display))
            }
            _ => (None, None),
        };
        self.app_index.insert(key.clone(), id);
        self.apps.push(App {
            key,
            path,
            file_name,
            description: None,
            company: None,
            version: None,
            package: None,
            service,
            service_display,
            first_seen_ms: ts_ms,
            last_seen_ms: ts_ms,
            net_first_seen_ms: None,
            trust: Trust::default(),
            own_dns_ms: None,
            total: Bytes::default(),
            local: Bytes::default(),
        });
        self.dirty_apps.insert(id);
        id
    }

    /// The app for a program named elsewhere (a rules export, SPEC §7.2):
    /// the one this PC knows, or a new one that hasn't run yet. `services` are
    /// svchost's, comma-separated.
    pub fn program_app(
        &mut self,
        path: &str,
        services: Option<&str>,
        package: Option<&str>,
        now_ms: i64,
    ) -> AppId {
        let services: Option<Vec<ServiceInfo>> = services.map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(|n| ServiceInfo {
                    name: n.to_string(),
                    display_name: n.to_string(),
                })
                .collect()
        });
        let services = services.filter(|s| !s.is_empty());
        let app = self.app_id(path, services.as_deref(), now_ms);
        if let Some(package) = package
            && self.apps[app as usize].package.is_none()
        {
            self.apps[app as usize].package = Some(package.to_string());
            self.dirty_apps.insert(app);
        }
        app
    }

    /// The app's processes running now, as far as the monitor has seen them.
    pub fn pids_of(&self, app: AppId) -> Vec<u32> {
        self.running
            .iter()
            .filter(|(_, a)| **a == app)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Connections already open when the service started, from the TCP table.
    pub fn seed_connections(&mut self, connections: &[(u32, SocketAddr, SocketAddr)], now_ms: i64) {
        for &(pid, local, remote) in connections {
            if self.ignored(remote.ip()) {
                continue;
            }
            let app = self.app_for_pid(pid, now_ms);
            self.host(app, remote, local.port(), Protocol::Tcp, now_ms);
            let key = FlowKey {
                pid,
                proto: Protocol::Tcp,
                local,
                remote,
            };
            self.flows.seed(key, app, now_ms);
        }
    }

    /// Drops per-second detail older than the live window, stale connections,
    /// and caps the host table.
    pub fn evict(&mut self, now_ms: i64) {
        let cutoff = now_ms.div_euclid(1000) - LIVE_SECONDS;
        while self
            .live
            .first_key_value()
            .is_some_and(|(&sec, _)| sec <= cutoff)
        {
            self.live.pop_first();
        }
        self.flows.evict(now_ms);
        if self.hosts.len() > MAX_HOSTS {
            let mut by_age: Vec<_> = self
                .hosts
                .iter()
                .map(|(k, h)| (h.last_seen_ms, *k))
                .collect();
            by_age.sort_unstable();
            for (_, key) in by_age.into_iter().take(MAX_HOSTS / 10) {
                self.hosts.remove(&key);
            }
        }
    }

    /// Apps whose version info (friendly name, publisher, version) needs reading.
    pub fn take_pending_info(&mut self) -> Vec<(AppId, String)> {
        std::mem::take(&mut self.pending_info)
            .into_iter()
            .map(|id| (id, self.apps[id as usize].path.clone()))
            .collect()
    }

    /// Records a fresh reading of the executable. Against a known earlier one
    /// (a first reading never alerts), these raise an alert:
    /// - version: info;
    /// - publisher, signer, or the file changing without a version change: warning;
    /// - a signed file that's now unsigned or doesn't verify: critical.
    pub fn set_app_info(&mut self, id: AppId, info: AppInfo, now_ms: i64) {
        let Some(app) = self.apps.get(id as usize) else {
            return;
        };
        let current = AppInfo {
            description: app.description.clone(),
            company: app.company.clone(),
            version: app.version.clone(),
            trust: app.trust.clone(),
        };
        if current == info {
            return;
        }
        let path = app.path.to_lowercase();
        let signature_text = |t: &Trust| -> Option<String> {
            Some(match t.signature? {
                Signature::Signed => match &t.signer {
                    Some(s) => format!("signed by {s}"),
                    None => "signed".into(),
                },
                Signature::Unsigned => "unsigned".into(),
                Signature::Invalid => "a signature that doesn't verify".into(),
            })
        };
        let short = |h: &Option<String>| h.as_ref().map(|h| h.chars().take(12).collect::<String>());
        let mut changes = vec![
            (
                AppField::Version,
                current.version.clone(),
                info.version.clone(),
            ),
            (
                AppField::Publisher,
                current.company.clone(),
                info.company.clone(),
            ),
            (
                AppField::Signer,
                current.trust.signer.clone(),
                info.trust.signer.clone(),
            ),
        ];
        let was_signed = current.trust.signature == Some(Signature::Signed);
        let now_unsigned = matches!(
            info.trust.signature,
            Some(Signature::Unsigned | Signature::Invalid)
        );
        if was_signed && now_unsigned {
            changes.push((
                AppField::Signature,
                signature_text(&current.trust),
                signature_text(&info.trust),
            ));
        }
        // An update changes the version too; the same version with other bytes doesn't.
        if current.version == info.version {
            changes.push((
                AppField::File,
                short(&current.trust.sha256),
                short(&info.trust.sha256),
            ));
        }
        for (field, from, to) in changes {
            if let (Some(from), Some(to)) = (from, to)
                && from != to
                && self.info_alerted.insert((path.clone(), field, to.clone()))
            {
                self.raise(
                    now_ms,
                    Some(id),
                    AlertBody::AppInfoChanged { field, from, to },
                );
            }
        }
        let app = &mut self.apps[id as usize];
        app.description = info.description;
        app.company = info.company;
        app.version = info.version;
        // Keep what's known when a reading couldn't get it (file locked, say).
        let t = info.trust;
        app.trust = Trust {
            signature: t.signature.or(app.trust.signature),
            signer: if t.signature.is_some() {
                t.signer
            } else {
                app.trust.signer.take()
            },
            sha256: t.sha256.or(app.trust.sha256.take()),
            origin: t.origin,
        };
        self.dirty_apps.insert(id);
    }

    /// Turns on first-network-activity alerts from this time. Until then, apps
    /// using the network are recorded silently: that's how win4tress learns what
    /// normally runs.
    pub fn set_first_activity_alerts_from(&mut self, from_ms: i64) {
        self.first_activity_from_ms = Some(from_ms);
    }

    /// win4tress's own DNS resolver, by full path: never "uses its own DNS".
    pub fn set_own_resolvers(&mut self, paths: impl IntoIterator<Item = String>) {
        self.own_resolvers = paths.into_iter().map(|p| p.to_ascii_lowercase()).collect();
    }

    /// Queues an alert for the service to store and announce.
    pub fn raise(&mut self, ts_ms: i64, app: Option<AppId>, body: AlertBody) {
        if self.alerts.len() < MAX_PENDING_ALERTS {
            let app_name = app
                .and_then(|id| self.apps.get(id as usize))
                .map(App::display_name);
            self.alerts.push(PendingAlert {
                ts_ms,
                app,
                app_name,
                body,
                severity: None,
            });
        }
    }

    pub fn take_alerts(&mut self) -> Vec<PendingAlert> {
        std::mem::take(&mut self.alerts)
    }

    fn first_network_activity(&mut self, app: AppId, remote: SocketAddr, ts_ms: i64) {
        let alerting = self
            .first_activity_from_ms
            .is_some_and(|from| ts_ms >= from);
        // System and Unknown aren't programs a user could recognise or block.
        if !alerting || !self.apps[app as usize].path.contains('\\') {
            return;
        }
        let body = AlertBody::FirstNetworkActivity {
            host: Some(self.host_ref(app, remote.ip())),
            port: remote.port(),
        };
        self.raise(ts_ms, Some(app), body);
    }

    /// An app doing DNS itself (port 53 or 853, or a DNS-over-HTTPS server):
    /// alerts once per app, ever (SPEC §7.11). Windows' DNS Client and
    /// win4tress's resolver are expected to; System and unknown processes
    /// can't be given a rule.
    fn own_dns(&mut self, app: AppId, remote: SocketAddr, ts_ms: i64) {
        let entry = &self.apps[app as usize];
        if entry.own_dns_ms.is_some()
            || entry.is_dns_client()
            || !entry.path.contains('\\')
            || self
                .own_resolvers
                .contains(&entry.path.to_ascii_lowercase())
        {
            return;
        }
        let dns = w4_core::net::is_dns_port(remote.port())
            || (remote.port() == 443 && self.doh.contains(&remote.ip()));
        if !dns {
            return;
        }
        self.apps[app as usize].own_dns_ms = Some(ts_ms);
        self.dirty_apps.insert(app);
        let body = AlertBody::OwnDns {
            host: self.host_ref(app, remote.ip()),
            port: remote.port(),
        };
        self.raise(ts_ms, Some(app), body);
    }

    /// Addresses `app` received from DNS for names `pattern` covers (`name`, or
    /// `*.name` for it and its subdomains), from the queries kept in memory.
    pub fn dns_addresses(&self, app: AppId, pattern: &str) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .dns
            .query(Some(app), None)
            .filter(|r| r.status == 0 && w4_core::net::name_matches(pattern, &r.name))
            .flat_map(|r| r.addrs.iter().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Bumped by every DNS answer: host rules may need their addresses again.
    pub fn dns_generation(&self) -> u64 {
        self.dns_generation
    }

    fn rdp_connection(&mut self, app: AppId, ip: IpAddr, ts_ms: i64) {
        if self
            .rdp_alerted
            .get(&ip)
            .is_some_and(|&last| ts_ms - last < RDP_REALERT_MS)
        {
            return;
        }
        self.rdp_alerted.insert(ip, ts_ms);
        let body = AlertBody::RdpConnection {
            remote: self.host_ref(app, ip),
        };
        self.raise(ts_ms, Some(app), body);
    }

    /// Addresses to look up with reverse DNS, at most `max`.
    pub fn take_reverse_lookups(&mut self, max: usize) -> Vec<IpAddr> {
        let n = max.min(self.reverse_queue.len());
        self.reverse_queue.drain(..n).collect()
    }

    pub fn set_reverse_name(&mut self, ip: IpAddr, name: &str) {
        self.names.insert_reverse(ip, name);
    }

    /// Apps created or changed since the last call, for history.
    pub fn take_dirty_apps(&mut self) -> Vec<AppRecord> {
        let mut ids: Vec<AppId> = self.dirty_apps.drain().collect();
        ids.sort_unstable();
        ids.into_iter()
            .map(|id| self.apps[id as usize].record(id))
            .collect()
    }

    /// Minutes that have closed since the last call, as (minute, app, host) rows.
    pub fn take_closed_minutes(&mut self, now_ms: i64) -> Vec<MinuteRow> {
        let last_closed_sec = closed_until(now_ms);
        // Minutes older than the live window are no longer in memory.
        let oldest_kept = (last_closed_sec - LIVE_SECONDS).div_euclid(60) + 1;
        self.next_minute = self.next_minute.max(oldest_kept);

        let mut rows = Vec::new();
        while (self.next_minute + 1) * 60 - 1 <= last_closed_sec {
            let minute = self.next_minute;
            let mut agg: HashMap<(AppId, IpAddr), Bytes> = HashMap::new();
            for (_, bucket) in self.live.range(minute * 60..=minute * 60 + 59) {
                for (&key, &bytes) in &bucket.hosts {
                    *agg.entry(key).or_default() += bytes;
                }
            }
            rows.extend(agg.into_iter().map(|((app, ip), bytes)| MinuteRow {
                minute,
                row: self.usage_row(app, ip, bytes),
            }));
            self.next_minute += 1;
        }
        rows
    }

    pub fn take_unsaved_dns(&mut self) -> Vec<DnsRecord> {
        self.dns.take_unsaved()
    }

    fn usage_row(&self, app: AppId, ip: IpAddr, bytes: Bytes) -> UsageRow {
        // The host entry can be missing if the table was trimmed.
        let host = self.hosts.get(&(app, ip));
        UsageRow {
            app,
            ip,
            name: self.names.get(app, ip).map(str::to_string),
            country: host.map_or_else(Country::unknown, |h| h.country.clone()),
            traffic_type: host.map_or(TrafficType::Other, |h| h.traffic_type),
            bytes,
        }
    }

    pub fn totals(&self) -> (Bytes, Bytes) {
        (self.totals, self.local)
    }

    pub fn app_count(&self) -> usize {
        self.apps.iter().filter(|a| a.total.total() > 0).count()
    }

    /// Start of the oldest second still held in memory.
    pub fn live_start(&self, now_ms: i64) -> i64 {
        closed_until(now_ms) - LIVE_SECONDS + 1
    }

    /// The last `seconds` closed seconds, oldest first, with zeros for quiet seconds.
    pub fn live(&self, seconds: u32, now_ms: i64) -> Vec<Sample> {
        let end = closed_until(now_ms);
        let start = end - i64::from(seconds).clamp(1, LIVE_SECONDS) + 1;
        self.samples(start, end)
    }

    /// Seconds that closed since the last call, for the push stream.
    pub fn take_new_samples(&mut self, now_ms: i64) -> Vec<Sample> {
        let end = closed_until(now_ms);
        if end <= self.published_until {
            return Vec::new();
        }
        let start = (self.published_until + 1).max(end - LIVE_SECONDS + 1);
        self.published_until = end;
        self.samples(start, end)
    }

    /// The threat lists to check new hosts against; `None` stops checking.
    pub fn set_threats(&mut self, lists: Option<std::sync::Arc<w4_core::threats::ThreatLists>>) {
        self.threats = lists;
    }

    /// A first connection between an app and an address on a threat list, by
    /// address or by the name the app looked up for it: an alert, once.
    fn check_threats(&mut self, app: AppId, remote: SocketAddr, ts_ms: i64) {
        let Some(lists) = &self.threats else { return };
        let ip = remote.ip();
        let name = self.names.get(app, ip).map(str::to_string);
        let source = lists
            .ip(ip)
            .or_else(|| name.as_deref().and_then(|n| lists.name(n)));
        let Some(source) = source else { return };
        if !self.suspicious_seen.insert((app, ip)) {
            return;
        }
        let host = self.host_ref(app, ip);
        self.raise(
            ts_ms,
            Some(app),
            AlertBody::SuspiciousHost {
                host,
                port: remote.port(),
                list: source.label().to_string(),
            },
        );
    }

    /// Apps left out of the live totals ("exclude VPN clients from totals").
    pub fn set_excluded(&mut self, apps: Vec<AppId>) {
        self.excluded = apps;
    }

    /// Apps that are known VPN clients.
    pub fn vpn_apps(&self) -> Vec<AppId> {
        self.apps
            .iter()
            .enumerate()
            .filter(|(_, a)| w4_core::net::is_vpn_client(&a.path))
            .map(|(id, _)| id as AppId)
            .collect()
    }

    fn samples(&self, start: i64, end: i64) -> Vec<Sample> {
        (start..=end)
            .map(|t| {
                let total = self
                    .live
                    .get(&t)
                    .map(|b| {
                        let mut total = b.total;
                        for app in &self.excluded {
                            if let Some(x) = b.apps.get(app) {
                                total.recv = total.recv.saturating_sub(x.recv);
                                total.sent = total.sent.saturating_sub(x.sent);
                            }
                        }
                        total
                    })
                    .unwrap_or_default();
                Sample {
                    t,
                    recv: total.recv,
                    sent: total.sent,
                }
            })
            .collect()
    }

    /// Usage within [from, to] (Unix seconds, inclusive) from the live buckets.
    pub fn breakdown(
        &self,
        from: i64,
        to: i64,
        filter: &BreakdownFilter,
        limit: usize,
    ) -> Breakdown {
        let mut agg: HashMap<(AppId, IpAddr), Bytes> = HashMap::new();
        for (_, bucket) in self.live.range(from..=to) {
            for (&key, &bytes) in &bucket.hosts {
                *agg.entry(key).or_default() += bytes;
            }
        }
        let rows = agg
            .into_iter()
            .map(|((app, ip), bytes)| self.usage_row(app, ip, bytes));
        build_breakdown(
            rows,
            filter,
            limit,
            |id| self.app_ref(id),
            |id| self.publisher(id),
        )
    }

    /// Apps that have sent or received anything since the service started, busiest first.
    pub fn apps(&self, now_ms: i64) -> Vec<AppSummary> {
        let end = closed_until(now_ms);
        let start = end - RECENT_SECONDS + 1;
        let steps = (RECENT_SECONDS / ACTIVITY_STEP) as usize;
        let mut recent: HashMap<AppId, Bytes> = HashMap::new();
        let mut rate: HashMap<AppId, Bytes> = HashMap::new();
        let mut activity: HashMap<AppId, Vec<[u64; 2]>> = HashMap::new();
        let mut recent_hosts: HashMap<(AppId, IpAddr), u64> = HashMap::new();
        for (&sec, bucket) in self.live.range(start..=end) {
            let step = ((sec - start) / ACTIVITY_STEP) as usize;
            for (&app, &b) in &bucket.apps {
                *recent.entry(app).or_default() += b;
                if sec > end - RATE_SECONDS {
                    *rate.entry(app).or_default() += b;
                }
                let series = activity.entry(app).or_insert_with(|| vec![[0, 0]; steps]);
                series[step][0] += b.recv;
                series[step][1] += b.sent;
            }
            for (&key, b) in &bucket.hosts {
                *recent_hosts.entry(key).or_default() += b.total();
            }
        }
        // Per app: how many hosts were active, and the busiest one.
        let mut top: HashMap<AppId, (usize, IpAddr, u64)> = HashMap::new();
        for (&(app, ip), &bytes) in &recent_hosts {
            let e = top.entry(app).or_insert((0, ip, bytes));
            e.0 += 1;
            if (bytes, ip) > (e.2, e.1) {
                (e.1, e.2) = (ip, bytes);
            }
        }
        let mut host_counts: HashMap<AppId, usize> = HashMap::new();
        for (app, _) in self.hosts.keys() {
            *host_counts.entry(*app).or_default() += 1;
        }
        let mut connections: HashMap<AppId, usize> = HashMap::new();
        for (_, flow) in self.flows.iter().filter(|(_, f)| f.open) {
            *connections.entry(flow.app).or_default() += 1;
        }
        let mut pids: HashMap<AppId, Vec<u32>> = HashMap::new();
        for (&pid, &app) in &self.running {
            pids.entry(app).or_default().push(pid);
        }

        let mut list: Vec<AppSummary> = self
            .apps
            .iter()
            .enumerate()
            .filter(|(_, a)| a.total.total() > 0)
            .map(|(i, a)| {
                let id = i as AppId;
                let rate = rate.get(&id).copied().unwrap_or_default();
                let (recent_hosts, top_host) = match top.get(&id) {
                    Some(&(count, ip, _)) => (count, Some(self.host_ref(id, ip))),
                    None => (0, None),
                };
                let mut pids = pids.remove(&id).unwrap_or_default();
                pids.sort_unstable();
                AppSummary {
                    id,
                    name: a.display_name(),
                    path: a.path.clone(),
                    service: a.service.clone(),
                    company: a.company.clone(),
                    version: a.version.clone(),
                    pids,
                    first_seen_ms: a.first_seen_ms,
                    last_seen_ms: a.last_seen_ms,
                    total: a.total,
                    local: a.local,
                    recent: recent.get(&id).copied().unwrap_or_default(),
                    rate: Bytes {
                        recv: rate.recv / RATE_SECONDS as u64,
                        sent: rate.sent / RATE_SECONDS as u64,
                    },
                    host_count: host_counts.get(&id).copied().unwrap_or_default(),
                    recent_hosts,
                    top_host,
                    connections: connections.get(&id).copied().unwrap_or_default(),
                    activity: activity.remove(&id).unwrap_or_default(),
                    trust: a.trust.clone(),
                    path_class: self.resolver.path_class(&a.path),
                    own_dns_ms: a.own_dns_ms,
                    vpn: w4_core::net::is_vpn_client(&a.path),
                }
            })
            .collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.total.total()));
        list
    }

    /// A remote address as a prompt shows it (SPEC §7.4): the name this app
    /// looked up for it, its country and network owner. Blocked attempts carry
    /// no traffic, so the address may be new to the monitor.
    pub fn remote(&self, app: AppId, ip: IpAddr) -> (HostRef, Option<NetworkOwner>) {
        let (country, owner) = match locality(ip) {
            Locality::Internet => (
                self.resolver.country(ip).unwrap_or_else(Country::unknown),
                self.resolver.network_owner(ip),
            ),
            _ => (Country::local(), None),
        };
        let name = self.names.get(app, ip).map(str::to_string);
        (HostRef { ip, name, country }, owner)
    }

    fn host_ref(&self, app: AppId, ip: IpAddr) -> HostRef {
        HostRef {
            ip,
            name: self.names.get(app, ip).map(str::to_string),
            country: self
                .hosts
                .get(&(app, ip))
                .map_or_else(Country::unknown, |h| h.country.clone()),
        }
    }

    pub fn hosts(&self, app: AppId) -> Option<HostsResult> {
        self.apps.get(app as usize)?;
        let mut hosts: Vec<HostSummary> = self
            .hosts
            .iter()
            .filter(|((a, _), _)| *a == app)
            .map(|((_, ip), h)| HostSummary {
                ip: *ip,
                name: self.names.get(app, *ip).map(str::to_string),
                locality: h.locality,
                country: h.country.clone(),
                owner: h.owner.clone(),
                traffic_type: h.traffic_type,
                ports: h.ports.clone(),
                total: h.total,
                connects: h.connects,
                first_seen_ms: h.first_seen_ms,
                last_seen_ms: h.last_seen_ms,
            })
            .collect();
        hosts.sort_by_key(|h| std::cmp::Reverse(h.total.total()));
        Some(HostsResult {
            app: self.app_ref(app),
            hosts,
        })
    }

    /// Open connections first, then by latest activity.
    pub fn connections(&self, app: Option<AppId>, limit: usize) -> Vec<Connection> {
        let mut list: Vec<Connection> = self
            .flows
            .iter()
            .filter(|(_, f)| app.is_none_or(|a| a == f.app))
            .map(|(key, f)| {
                let ip = key.remote.ip();
                let host = self.hosts.get(&(f.app, ip));
                Connection {
                    app: self.app_ref(f.app),
                    pid: key.pid,
                    protocol: key.proto,
                    local: key.local,
                    remote: key.remote,
                    name: self.names.get(f.app, ip).map(str::to_string),
                    country: host.map_or_else(Country::unknown, |h| h.country.clone()),
                    owner: host.and_then(|h| h.owner.clone()),
                    locality: locality(ip),
                    traffic_type: host.map_or_else(
                        || classify(key.proto, key.remote.port(), key.local.port()),
                        |h| h.traffic_type,
                    ),
                    state: if f.open {
                        ConnectionState::Open
                    } else {
                        ConnectionState::Closed
                    },
                    inbound: f.inbound,
                    first_seen_ms: f.first_seen_ms,
                    last_seen_ms: f.last_seen_ms,
                    bytes: f.bytes,
                }
            })
            .collect();
        list.sort_by(|a, b| {
            (b.state == ConnectionState::Open)
                .cmp(&(a.state == ConnectionState::Open))
                .then(b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        list.truncate(limit);
        list
    }

    pub fn connection_count(&self) -> usize {
        self.flows.len()
    }

    /// Recent DNS queries, newest first.
    pub fn dns_log(&self, limit: usize, app: Option<AppId>, query: Option<&str>) -> Vec<DnsEntry> {
        self.dns
            .query(app, query)
            .take(limit)
            .map(|r| DnsEntry {
                ts_ms: r.ts_ms,
                app: self.app_ref(r.app),
                name: r.name.clone(),
                query_type: r.query_type,
                status: r.status,
                addrs: r.addrs.clone(),
                blocked_by: None,
            })
            .collect()
    }

    /// Most-queried names among recent queries; history has the longer view.
    pub fn dns_top(
        &self,
        from_ms: i64,
        to_ms: i64,
        app: Option<AppId>,
        limit: usize,
    ) -> Vec<DomainCount> {
        self.dns.top(from_ms, to_ms, app, limit)
    }

    /// An app as it would be stored: path, services, package. `None` for an
    /// unknown id.
    pub fn app_record(&self, id: AppId) -> Option<AppRecord> {
        self.apps.get(id as usize).map(|a| a.record(id))
    }

    /// The app's publisher (company), from its version info.
    pub fn publisher(&self, id: AppId) -> Option<String> {
        self.apps.get(id as usize).and_then(|a| a.company.clone())
    }

    /// Apps by a publisher (for filtering history by it).
    pub fn apps_by_publisher(&self, publisher: &str) -> Vec<AppId> {
        self.apps
            .iter()
            .enumerate()
            .filter(|(_, a)| a.company.as_deref() == Some(publisher))
            .map(|(id, _)| id as AppId)
            .collect()
    }

    pub fn app_ref(&self, id: AppId) -> AppRef {
        let app = self.apps.get(id as usize);
        AppRef {
            id,
            name: app.map(App::display_name).unwrap_or_default(),
            path: app.map(|a| a.path.clone()).unwrap_or_default(),
        }
    }
}

fn clamp_ts(ts_ms: i64, now_ms: i64) -> i64 {
    if ts_ms > now_ms + MAX_CLOCK_SKEW_MS {
        now_ms
    } else {
        ts_ms
    }
}

/// The last second whose traffic is considered complete.
pub fn closed_until(now_ms: i64) -> i64 {
    (now_ms - CLOSE_LAG_MS).div_euclid(1000) - 1
}

#[cfg(test)]
mod tests;
