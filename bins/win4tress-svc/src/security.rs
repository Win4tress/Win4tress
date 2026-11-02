//! The security monitors (SPEC §11) and the network scanner (SPEC §10.2):
//! a loop that looks at system files, adapters and DNS servers, the ARP
//! table, Wi-Fi, proxy settings and internet access, keeps the threat lists
//! current, and scans the local network when asked or set to. What each has
//! seen is kept in history, so a restart doesn't re-learn it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use w4_core::threats::{ThreatLists, parse_ip_list, parse_local_list};
use w4_core::time::now_unix_ms;
use w4_ipc::api::{AlertBody, Device, DevicesResult, ProxyScope, ThreatStatus};
use w4_monitor::Monitor;
use w4_monitors::oui::Vendors;
use w4_monitors::{arp, files, network, scanner, wifi};
use w4_store::Store;

use crate::usage::Usage;

/// How often the monitors look.
const CHECK_EVERY: Duration = Duration::from_secs(30);
/// Threat lists are downloaded this often (not on metered connections).
const FEEDS_EVERY_MS: i64 = 24 * 3600 * 1000;
/// With automatic scans on, the network is scanned this often.
const SCAN_EVERY_MS: i64 = 30 * 60 * 1000;
const FEODO_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
/// The user's own list of addresses and names, in the data folder.
pub const LOCAL_LIST: &str = "threats-local.txt";
const FEED_MAX_BYTES: usize = 8 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Default)]
struct State {
    files: Option<files::Hashes>,
    network: network::Memory,
    arp: arp::Memory,
    wifi: wifi::Memory,
    machine_proxy: Option<String>,
    user_proxy: Option<String>,
    internet: Option<bool>,
    feodo: std::collections::HashSet<std::net::IpAddr>,
    feeds_ms: Option<i64>,
    local_modified: Option<std::time::SystemTime>,
    local: (
        std::collections::HashSet<std::net::IpAddr>,
        std::collections::HashSet<String>,
    ),
    threats: ThreatStatus,
    scanning: bool,
    last_scan_ms: Option<i64>,
    /// The first scan learns the network without new-device alerts.
    devices_learned: bool,
}

pub struct Security {
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    usage: Arc<Usage>,
    data_dir: PathBuf,
    vendors: Vendors,
    state: Mutex<State>,
}

impl Security {
    pub fn new(
        store: Arc<Mutex<Store>>,
        monitor: Arc<Mutex<Monitor>>,
        usage: Arc<Usage>,
        data_dir: PathBuf,
    ) -> Arc<Security> {
        let vendors = match w4_monitors::oui::find().and_then(|p| Vendors::load(&p)) {
            Some(v) => {
                tracing::info!(
                    vendors = v.len(),
                    "device manufacturer registry loaded (IEEE)"
                );
                v
            }
            None => {
                tracing::warn!(
                    "no oui.csv found; device makers will show as unknown (run tools/dev/fetch-oui.ps1)"
                );
                Vendors::default()
            }
        };
        let security = Arc::new(Security {
            store,
            monitor,
            usage,
            data_dir,
            vendors,
            state: Mutex::new(State::default()),
        });
        security.load_memory();
        security
    }

    fn remembered<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        let json = lock(&self.store).monitor_state(name).ok().flatten()?;
        serde_json::from_str(&json).ok()
    }

    fn remember<T: Serialize>(&self, name: &str, value: &T) {
        if let Ok(json) = serde_json::to_string(value) {
            let _ = lock(&self.store).set_monitor_state(name, &json);
        }
    }

    fn load_memory(&self) {
        let mut s = lock(&self.state);
        s.files = self.remembered("files");
        s.network = self.remembered("network").unwrap_or_default();
        s.arp = self.remembered("arp").unwrap_or_default();
        s.wifi = self.remembered("wifi").unwrap_or_default();
        s.machine_proxy = self.remembered("machine_proxy");
        s.user_proxy = self.remembered("user_proxy");
        s.devices_learned = self.remembered("devices_learned").unwrap_or(false);
        s.last_scan_ms = self.remembered("last_scan_ms");
        s.threats.local_path = self.data_dir.join(LOCAL_LIST).display().to_string();
    }

    fn raise(&self, now_ms: i64, alerts: Vec<AlertBody>) {
        if alerts.is_empty() {
            return;
        }
        let mut monitor = lock(&self.monitor);
        for a in alerts {
            tracing::info!(alert = ?a, "security monitor");
            monitor.raise(now_ms, None, a);
        }
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            let _ = tokio::task::spawn_blocking(move || this.check(now_unix_ms())).await;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(CHECK_EVERY) => {}
            }
        }
    }

    /// One look by every monitor.
    fn check(self: &Arc<Self>, now_ms: i64) {
        self.check_files(now_ms);
        self.check_network(now_ms);
        self.check_proxy(now_ms);
        self.check_internet(now_ms);
        self.update_threats(now_ms);
        self.watch_devices(now_ms);
    }

    fn check_files(&self, now_ms: i64) {
        let dir = files::etc_dir();
        let now = files::read(&dir);
        if now.is_empty() {
            return;
        }
        let alerts = {
            let mut s = lock(&self.state);
            let alerts = match &s.files {
                Some(before) => files::changes(&dir, before, &now),
                None => Vec::new(),
            };
            let changed = s.files.as_ref() != Some(&now);
            s.files = Some(now.clone());
            if changed {
                drop(s);
                self.remember("files", &now);
            }
            alerts
        };
        self.raise(now_ms, alerts);
    }

    fn check_network(&self, now_ms: i64) {
        let adapters = w4_sys::netinfo::adapters();
        let neighbors = w4_sys::netinfo::neighbors();
        let wifi = w4_sys::wifi::state();
        let gateway_mac = |ip: std::net::IpAddr| match ip {
            std::net::IpAddr::V4(v4) => {
                neighbors.iter().find(|n| n.ip == v4).map(|n| n.mac.clone())
            }
            std::net::IpAddr::V6(_) => None,
        };
        let ssid_of = |adapter: &str| {
            wifi.connected
                .iter()
                .find(|c| {
                    c.interface
                        .as_deref()
                        .is_some_and(|i| i.eq_ignore_ascii_case(adapter))
                })
                .map(|c| c.ssid.clone())
        };
        let (alerts, network, arp, wifi_memory) = {
            let mut s = lock(&self.state);
            let mut alerts = network::check(&mut s.network, &adapters, &gateway_mac);
            alerts.extend(arp::check(&mut s.arp, &adapters, &neighbors, &ssid_of));
            alerts.extend(wifi::check(&mut s.wifi, &wifi));
            (alerts, s.network.clone(), s.arp.clone(), s.wifi.clone())
        };
        self.remember("network", &network);
        self.remember("arp", &arp);
        self.remember("wifi", &wifi_memory);
        self.raise(now_ms, alerts);
    }

    fn check_proxy(&self, now_ms: i64) {
        if let Some(now) = w4_sys::proxy::machine() {
            self.proxy_seen(ProxyScope::Machine, now, now_ms);
        }
    }

    /// From the app: the signed-in user's proxy settings.
    pub fn report_user_proxy(&self, proxy: String) {
        self.proxy_seen(ProxyScope::User, proxy, now_unix_ms());
    }

    fn proxy_seen(&self, scope: ProxyScope, now: String, now_ms: i64) {
        let (key, before) = {
            let mut s = lock(&self.state);
            let slot = match scope {
                ProxyScope::Machine => &mut s.machine_proxy,
                ProxyScope::User => &mut s.user_proxy,
            };
            let before = slot.replace(now.clone());
            let key = match scope {
                ProxyScope::Machine => "machine_proxy",
                ProxyScope::User => "user_proxy",
            };
            (key, before)
        };
        if before.as_deref() == Some(now.as_str()) {
            return;
        }
        self.remember(key, &now);
        // The first reading is learning.
        if let Some(from) = before {
            self.raise(
                now_ms,
                vec![AlertBody::ProxyChanged {
                    scope,
                    from,
                    to: now,
                }],
            );
        }
    }

    fn check_internet(&self, now_ms: i64) {
        let Some(now) = w4_sys::netinfo::internet() else {
            return;
        };
        let before = lock(&self.state).internet.replace(now);
        if before.is_some_and(|b| b != now) {
            self.raise(
                now_ms,
                vec![AlertBody::InternetAccessChanged { connected: now }],
            );
        }
    }

    /// Feodo Tracker daily (not on metered connections), and the user's own
    /// list whenever its file changes; then the traffic monitor gets them.
    fn update_threats(&self, now_ms: i64) {
        let settings = self.usage.settings();
        let mut changed = false;
        let due = lock(&self.state)
            .feeds_ms
            .is_none_or(|t| now_ms - t >= FEEDS_EVERY_MS);
        let metered = self.usage.save_context().metered;
        if settings.threat_feeds && due && !metered {
            let result = w4_sys::http::get(FEODO_URL, FEED_MAX_BYTES, Duration::from_secs(30));
            let mut s = lock(&self.state);
            s.feeds_ms = Some(now_ms);
            match result {
                Ok(body) => {
                    s.feodo = parse_ip_list(&String::from_utf8_lossy(&body));
                    s.threats.feodo = s.feodo.len();
                    s.threats.feodo_updated_ms = Some(now_ms);
                    s.threats.feodo_error = None;
                    tracing::info!(addresses = s.feodo.len(), "Feodo Tracker list updated");
                }
                Err(e) => {
                    tracing::warn!("Feodo Tracker list not updated: {e}");
                    s.threats.feodo_error = Some(e);
                }
            }
            changed = true;
        }
        if !settings.threat_feeds && !lock(&self.state).feodo.is_empty() {
            let mut s = lock(&self.state);
            s.feodo.clear();
            s.threats.feodo = 0;
            changed = true;
        }
        let path = self.data_dir.join(LOCAL_LIST);
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        {
            let mut s = lock(&self.state);
            if modified != s.local_modified {
                s.local_modified = modified;
                s.local = std::fs::read_to_string(&path)
                    .map(|t| parse_local_list(&t))
                    .unwrap_or_default();
                s.threats.local = s.local.0.len() + s.local.1.len();
                tracing::info!(entries = s.threats.local, path = %path.display(), "own threat list read");
                changed = true;
            }
        }
        if changed {
            let lists = {
                let s = lock(&self.state);
                ThreatLists {
                    feodo: s.feodo.clone(),
                    urlhaus: Default::default(),
                    local_ips: s.local.0.clone(),
                    local_names: s.local.1.clone(),
                }
            };
            let lists = (!lists.is_empty()).then(|| Arc::new(lists));
            lock(&self.monitor).set_threats(lists);
        }
    }

    pub fn threat_status(&self) -> ThreatStatus {
        lock(&self.state).threats.clone()
    }

    /// With automatic scans on: the ARP table every look (cheap, and it sees
    /// devices as they talk), and a scan when it's time.
    fn watch_devices(self: &Arc<Self>, now_ms: i64) {
        if !self.usage.settings().scanner {
            return;
        }
        let scanned: std::collections::HashSet<_> = scanner::targets(&w4_sys::netinfo::adapters())
            .into_iter()
            .flat_map(|t| t.hosts)
            .collect();
        let found: Vec<_> = w4_sys::netinfo::neighbors()
            .into_iter()
            .filter(|n| scanned.contains(&n.ip))
            .map(|n| (n.ip, n.mac))
            .collect();
        self.record_devices(&found, now_ms, true, false);
        let due = lock(&self.state)
            .last_scan_ms
            .is_none_or(|t| now_ms - t >= SCAN_EVERY_MS);
        if due {
            self.scan_now();
        }
    }

    /// Scans the local network now, in the background. Returns false if a
    /// scan is already running. Shows as scanning from the moment it returns.
    pub fn scan_now(self: &Arc<Self>) -> bool {
        {
            let mut s = lock(&self.state);
            if s.scanning {
                return false;
            }
            s.scanning = true;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || this.scan(this.usage.settings().scanner));
        true
    }

    /// With `scanning` set by [`Self::scan_now`].
    fn scan(&self, alert: bool) {
        let started = now_unix_ms();
        let targets = scanner::targets(&w4_sys::netinfo::adapters());
        let mut found = Vec::new();
        for t in &targets {
            tracing::info!(network = %t.network, addresses = t.hosts.len(), "scanning the local network");
            found.extend(scanner::probe(&t.hosts, scanner::WORKERS));
        }
        let now_ms = now_unix_ms();
        self.record_devices(&found, now_ms, alert, true);
        tracing::info!(
            devices = found.len(),
            probe_ms = now_ms - started,
            ms = now_unix_ms() - started,
            "network scan done"
        );
        let mut s = lock(&self.state);
        s.scanning = false;
        s.last_scan_ms = Some(now_ms);
        let first = !s.devices_learned;
        s.devices_learned = true;
        drop(s);
        self.remember("last_scan_ms", &now_ms);
        if first {
            self.remember("devices_learned", &true);
        }
    }

    /// Adds or refreshes devices; new ones raise "New device on network" once
    /// the network has been learned (by a first scan). Names are looked up for
    /// new devices, and for all on a scan.
    fn record_devices(
        &self,
        found: &[(std::net::Ipv4Addr, String)],
        now_ms: i64,
        alert: bool,
        scan: bool,
    ) {
        let learned = lock(&self.state).devices_learned;
        let seen: std::collections::HashSet<String> = lock(&self.store)
            .devices()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.mac)
            .collect();
        let found: Vec<_> = found
            .iter()
            .filter(|(_, mac)| w4_monitors::oui::unicast(mac))
            .collect();
        let unnamed: Vec<_> = found
            .iter()
            .filter(|(_, mac)| scan || !seen.contains(mac))
            .map(|(ip, _)| *ip)
            .collect();
        let names: std::collections::HashMap<_, _> = scanner::names_of(&unnamed, scanner::WORKERS)
            .into_iter()
            .collect();
        let mut alerts = Vec::new();
        for (ip, mac) in found {
            let vendor = self.vendors.lookup(mac);
            let name = names.get(ip).cloned();
            let device = Device {
                mac: mac.clone(),
                ip: std::net::IpAddr::V4(*ip),
                name: name.clone(),
                vendor: vendor.clone(),
                randomized: w4_monitors::oui::randomized(mac),
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                known: false,
            };
            let new = lock(&self.store).saw_device(&device).unwrap_or(false);
            if new && alert && learned {
                alerts.push(AlertBody::NewDevice {
                    ip: device.ip,
                    mac: mac.clone(),
                    vendor,
                    name,
                });
            }
        }
        self.raise(now_ms, alerts);
    }

    pub fn devices(&self) -> DevicesResult {
        let devices = lock(&self.store).devices().unwrap_or_default();
        let s = lock(&self.state);
        DevicesResult {
            devices,
            scanning: s.scanning,
            last_scan_ms: s.last_scan_ms,
            networks: scanner::targets(&w4_sys::netinfo::adapters())
                .into_iter()
                .map(|t| t.network)
                .collect(),
        }
    }
}
