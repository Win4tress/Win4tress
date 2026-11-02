//! Methods, parameters and results. Times are Unix milliseconds unless the field
//! says seconds. Protocol version: [`crate::PROTOCOL_VERSION`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use w4_core::firewall::{
    Action, BlockAll, BlockedBy, Direction, Environment, Expiry, FirewallState, Mode,
    NetworkCategory, Origin, RuleId, RuleRecord, Scope, Verdict,
};
use w4_core::trust::{PathClass, Trust};
use w4_core::{Bytes, Country, Locality, NetworkOwner, Protocol, TrafficType};

pub mod method {
    pub const HELLO: &str = "hello";
    pub const STATUS: &str = "status";
    pub const LIVE: &str = "traffic.live";
    /// Per-minute totals from history, for ranges beyond the live window.
    pub const HISTORY: &str = "traffic.history";
    /// Served from memory for recent ranges and from history for older ones.
    pub const BREAKDOWN: &str = "traffic.breakdown";
    pub const APPS: &str = "apps.list";
    pub const HOSTS: &str = "apps.hosts";
    pub const CONNECTIONS: &str = "connections.list";
    pub const DNS_LOG: &str = "dns.log";
    pub const DNS_TOP: &str = "dns.top";
    /// The DNS dashboard, from history.
    pub const DNS_STATS: &str = "dns.stats";
    pub const ALERTS: &str = "alerts.list";
    /// Changes only the read flag, which all users of this PC share.
    pub const ALERTS_MARK_READ: &str = "alerts.mark_read";
    /// Windows Firewall and enforcement state.
    pub const FIREWALL: &str = "firewall.status";
    pub const RULES: &str = "rules.list";
    /// Change (Administrators): sets an app's verdict for one direction.
    pub const RULES_SET: &str = "rules.set";
    /// Change (Administrators).
    pub const RULES_DELETE: &str = "rules.delete";
    /// Change (Administrators): the enforcement mode. Returns [`super::FirewallStatus`].
    pub const FIREWALL_SET_MODE: &str = "firewall.set_mode";
    /// Change (Administrators): adopt the outside changes a "firewall changed"
    /// alert reported, instead of the restored rules.
    pub const FIREWALL_KEEP_CHANGES: &str = "firewall.keep_changes";
    /// Elevated callers only: deletes every win4tress rule, from history and
    /// from Windows Firewall, and returns to the default mode.
    pub const FIREWALL_RESET: &str = "firewall.reset";
    /// Whether each app is allowed or blocked per direction, and by what:
    /// win4tress, a Windows Firewall rule, or the default. Read.
    pub const FIREWALL_VERDICTS: &str = "firewall.verdicts";
    /// Change (Administrators): Block All on (with a duration) or off.
    pub const FIREWALL_BLOCK_ALL: &str = "firewall.block_all";
    /// Change (Administrators): turn Windows Firewall on where it's off. win4tress
    /// never turns it off.
    pub const FIREWALL_TURN_ON: &str = "firewall.turn_on";
    /// Windows Firewall's own rules that name an app (read-only).
    pub const FIREWALL_APP_RULES: &str = "firewall.app_rules";
    /// Connection attempts that were blocked, and by what (SPEC §7.9). Read.
    pub const FIREWALL_BLOCKS: &str = "firewall.blocks";
    /// Change (Administrators): several rule changes at once, one audit entry
    /// each, applied to Windows Firewall together.
    pub const RULES_APPLY: &str = "rules.apply";
    /// Every app win4tress has seen, from history. Read.
    pub const APPS_ALL: &str = "apps.all";
    /// Elevated callers only: changes then need an elevated caller too (SPEC §4.3).
    pub const SETTINGS_REQUIRE_ELEVATION: &str = "settings.require_elevation";
    /// Connections waiting for a decision in Ask to Connect (SPEC §7.4). Read.
    pub const PROMPTS: &str = "prompts.list";
    /// Change (Administrators): answer a prompt with a rule, or later.
    pub const PROMPTS_DECIDE: &str = "prompts.decide";
    /// Read: [`super::Settings`].
    pub const SETTINGS: &str = "settings.get";
    /// Change (Administrators): [`super::Settings`], all of it.
    pub const SETTINGS_SET: &str = "settings.set";
    /// Read: the data plan's period and usage, or null without a plan.
    pub const PLAN_STATUS: &str = "usage.plan";
    /// Any client: the user's last input, for idle shading (SPEC §8.4).
    pub const SESSION_INPUT: &str = "session.input";
    /// Any client: the signed-in user's proxy settings ("Proxy changed").
    pub const SESSION_PROXY: &str = "session.proxy";
    /// Read: the security monitors and their settings.
    pub const MONITORS: &str = "monitors.list";
    /// Read: devices on the local network.
    pub const DEVICES: &str = "devices.list";
    /// Change (Administrators): scan the local network now.
    pub const DEVICES_SCAN: &str = "devices.scan";
    /// Change (Administrators): mark a device known or not.
    pub const DEVICES_SET_KNOWN: &str = "devices.set_known";
    /// Change (Administrators): turn one rule on or off, keeping it.
    pub const RULES_ENABLE: &str = "rules.enable";
    /// Read: the firewall profiles, and which is active.
    pub const PROFILES: &str = "profiles.list";
    /// Change (Administrators): save the mode, the rules on and DNS filtering as a profile.
    pub const PROFILES_SAVE: &str = "profiles.save";
    /// Change (Administrators): switch to a profile.
    pub const PROFILES_SWITCH: &str = "profiles.switch";
    /// Change (Administrators): delete a profile.
    pub const PROFILES_DELETE: &str = "profiles.delete";
    /// Change (Administrators): the networks a profile is switched to on.
    pub const PROFILES_SET_NETWORKS: &str = "profiles.set_networks";
    /// Read: the networks Windows knows, and the profile each switches to.
    pub const NETWORKS: &str = "networks.list";
    /// Read: every rule and profile, to set up another PC (SPEC §7.2).
    pub const RULES_EXPORT: &str = "rules.export";
    /// Change (Administrators): rules and profiles from an export.
    pub const RULES_IMPORT: &str = "rules.import";
    /// Change (Administrators): end an app's TCP connections, or some of them.
    pub const CONNECTIONS_CLOSE: &str = "connections.close";
    /// Read: what automatic cleanup would remove, and what it removed last.
    pub const CLEANUP: &str = "cleanup.status";
    /// Change (Administrators): run automatic cleanup now.
    pub const CLEANUP_RUN: &str = "cleanup.run";
    /// Read: hash reputation lookups' state (SPEC §12).
    pub const REPUTATION: &str = "reputation.status";
    /// Read: every reputation answer for an app's file.
    pub const REPUTATION_APP: &str = "reputation.app";
    /// Change (Administrators): an API key, stored encrypted; never read back.
    pub const REPUTATION_SET_KEY: &str = "reputation.set_key";
    /// Change (Administrators): look an app up now, ahead of the queue.
    pub const REPUTATION_CHECK: &str = "reputation.check";
    /// Change (Administrators): scan an app's file with the installed antivirus.
    pub const REPUTATION_SCAN: &str = "reputation.scan";
    /// Change (Administrators): upload an app's file to VirusTotal (confirmed).
    pub const REPUTATION_UPLOAD: &str = "reputation.upload";
    /// Read: DNS filtering's state, its lists and the resolver's counters.
    pub const DNS_FILTER: &str = "dnsfilter.status";
    /// Change (Administrators): download the chosen lists now.
    pub const DNS_FILTER_UPDATE: &str = "dnsfilter.update";
    /// Change (Administrators): pause blocking for some minutes, or resume.
    pub const DNS_FILTER_PAUSE: &str = "dnsfilter.pause";
    /// Read: the resolver's recent lookups with what blocked them.
    pub const DNS_FILTER_LOG: &str = "dnsfilter.log";
    /// Handled by the server itself: starts the notification stream.
    pub const SUBSCRIBE: &str = "subscribe";
}

pub mod notification {
    /// Params: [`super::SamplesNotification`].
    pub const SAMPLES: &str = "traffic.samples";
    /// Params: [`super::AlertsNotification`]. Sent when alerts are raised.
    pub const ALERTS: &str = "alerts.new";
    /// Params: [`super::PromptsResult`], all of them. Sent when prompts come,
    /// go or change state.
    pub const PROMPTS: &str = "prompts.changed";
}

pub type AppId = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloParams {
    pub protocol: u32,
    pub client: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloResult {
    pub protocol: u32,
    pub server_version: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub started_ms: i64,
    pub now_ms: i64,
    pub collector: CollectorHealth,
    /// Payload attributed to apps (excludes loopback).
    pub apps_bytes: Bytes,
    /// The part of `apps_bytes` that stayed on the local network.
    pub local_bytes: Bytes,
    /// Whole frames on physical adapters since start. Minus `apps_bytes`,
    /// this is protocol overhead and other unattributed traffic.
    pub adapter_bytes: Bytes,
    pub app_count: usize,
    #[serde(default)]
    pub process: ProcessUsage,
    #[serde(default)]
    pub history: HistoryStatus,
    #[serde(default)]
    pub unread_alerts: u64,
}

/// The service's own resource use.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessUsage {
    pub working_set: u64,
    pub cpu_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistoryStatus {
    /// False when the database couldn't be opened; only live data is available.
    pub enabled: bool,
    pub path: Option<String>,
    pub size_bytes: u64,
    /// Start of the oldest stored minute (Unix seconds).
    pub oldest: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryParams {
    /// First and last Unix second, inclusive; rounded to the step.
    pub from: i64,
    pub to: i64,
    /// Seconds per sample: at least the stored resolution of the range (a
    /// minute for 35 days, an hour for 2 years). Default: a minute.
    #[serde(default)]
    pub step: Option<u32>,
    /// Only matching traffic (`host` isn't supported here).
    #[serde(default)]
    pub filter: BreakdownFilter,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistoryResult {
    /// Seconds per sample.
    pub step: u32,
    /// Bytes per step (not per second), oldest first, zeros for quiet steps.
    pub samples: Vec<Sample>,
    /// When nobody used the PC (SPEC §8.4), overlapping the range.
    #[serde(default)]
    pub idle: Vec<IdleSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleSpan {
    pub start_ms: i64,
    pub end_ms: i64,
}

/// From the app: when the signed-in user last touched the keyboard or mouse.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputParams {
    pub last_input_ms: i64,
}

/// A monthly data plan (SPEC §10.2 Usage).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataPlan {
    /// Bytes a period, downloads and uploads together.
    pub limit_bytes: u64,
    /// The day of the month a period starts (1–28), at local midnight.
    pub reset_day: u8,
    /// Alerts when usage passes these percentages of the limit.
    #[serde(default = "default_warn_at")]
    pub warn_at: Vec<u8>,
    /// Count only traffic while on a metered connection.
    #[serde(default)]
    pub metered_only: bool,
}

fn default_warn_at() -> Vec<u8> {
    vec![75, 90, 100]
}

/// Settings the service keeps. A field missing from stored or sent settings
/// takes its default, so older settings keep working.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub data_plan: Option<DataPlan>,
    /// Leave known VPN clients out of traffic totals: their traffic is other
    /// apps' traffic again (SPEC §19).
    #[serde(default)]
    pub exclude_vpn: bool,
    /// Per alert kind (see [`MONITORS`]): on or off, and a different severity.
    /// Kinds not listed use their defaults.
    #[serde(default)]
    pub monitors: BTreeMap<String, MonitorSetting>,
    /// Copy alerts to the Windows Event Log (Application, source "win4tress").
    #[serde(default)]
    pub event_log: bool,
    /// Scan the local network now and then, and alert on new devices.
    #[serde(default)]
    pub scanner: bool,
    /// Download abuse.ch's threat lists daily (not on metered connections).
    #[serde(default = "yes")]
    pub threat_feeds: bool,
    /// Write no traffic or DNS lookups to history at all (SPEC §8.4).
    /// Enforcement and alerts carry on.
    #[serde(default)]
    pub incognito: bool,
    /// Apps whose traffic and lookups aren't written to history.
    #[serde(default)]
    pub incognito_apps: BTreeSet<AppId>,
    #[serde(default)]
    pub cleanup: CleanupSettings,
    #[serde(default)]
    pub reputation: ReputationSettings,
    #[serde(default)]
    pub dns: DnsSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            data_plan: None,
            exclude_vpn: false,
            monitors: BTreeMap::new(),
            event_log: false,
            scanner: false,
            threat_feeds: true,
            incognito: false,
            incognito_apps: BTreeSet::new(),
            cleanup: CleanupSettings::default(),
            reputation: ReputationSettings::default(),
            dns: DnsSettings::default(),
        }
    }
}

/// DNS filtering (SPEC §13), off by default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default)]
    pub enabled: bool,
    /// Catalogue ids of the chosen blocklists.
    #[serde(default = "default_dns_lists")]
    pub lists: Vec<String>,
    #[serde(default)]
    pub custom_lists: Vec<CustomList>,
    #[serde(default)]
    pub upstream: DnsUpstream,
    /// Answer blocked names with NXDOMAIN rather than 0.0.0.0 / ::.
    #[serde(default)]
    pub nxdomain: bool,
    #[serde(default)]
    pub observe: DnsObserve,
    /// Always allowed (with subdomains).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Always blocked (with subdomains).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Blocked when they match (linear-time regex, at most 1,000 in all).
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub local_records: Vec<DnsLocalRecord>,
    /// Blocking paused until then.
    #[serde(default)]
    pub paused_until_ms: Option<i64>,
}

fn default_dns_lists() -> Vec<String> {
    vec!["hagezi-normal".into()]
}

impl Default for DnsSettings {
    fn default() -> Self {
        DnsSettings {
            enabled: false,
            lists: default_dns_lists(),
            custom_lists: Vec::new(),
            upstream: DnsUpstream::default(),
            nxdomain: false,
            observe: DnsObserve::default(),
            allow: Vec::new(),
            deny: Vec::new(),
            regex: Vec::new(),
            local_records: Vec::new(),
            paused_until_ms: None,
        }
    }
}

impl DnsSettings {
    /// The settings without a pause: what a profile or an export holds.
    pub fn without_pause(&self) -> DnsSettings {
        DnsSettings {
            paused_until_ms: None,
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomList {
    pub name: String,
    /// https:// only.
    pub url: String,
    /// One regex per line, rather than hosts, domains or Adblock rules.
    #[serde(default)]
    pub regex: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsUpstream {
    /// The network's own DNS servers (keeps company and sign-in-page behaviour).
    #[default]
    System,
    /// DNS over HTTPS, e.g. https://cloudflare-dns.com/dns-query.
    Doh { url: String },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsObserve {
    /// Only observe when the network's DNS already blocks (an ad-blocking DNS server).
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLocalRecord {
    pub name: String,
    pub addrs: Vec<IpAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFilterState {
    Off,
    /// Lists downloading or the resolver starting; Windows' DNS as usual.
    Starting,
    /// Lookups go through the resolver and are filtered.
    On,
    /// Through the resolver, nothing blocked: paused, observing, or a
    /// sign-in page.
    Passing,
    /// The resolver isn't answering; Windows' DNS was put back.
    Failed,
}

/// A blocklist as the service holds it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsListState {
    pub id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub homepage: String,
    pub licence: String,
    pub licence_url: String,
    pub enabled: bool,
    pub custom: bool,
    /// Domains (or regex rules) in the last download.
    pub entries: Option<u32>,
    pub updated_ms: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsFilterStatus {
    pub state: Option<DnsFilterState>,
    /// Why, when not plainly on or off.
    pub message: Option<String>,
    /// Windows routes lookups to the resolver (the NRPT rule is in place).
    pub routed: bool,
    pub lists: Vec<DnsListState>,
    /// Different domains in the compiled blocklist.
    pub blocked_domains: usize,
    pub upstream: String,
    /// The network's DNS servers the resolver asks.
    pub system_servers: Vec<String>,
    pub upstream_blocks: Option<bool>,
    pub queries: u64,
    pub blocked: u64,
    pub cached: u64,
    pub top_blocked: Vec<(String, u64)>,
    pub problems: Vec<String>,
    /// Times the watchdog put Windows' DNS back since the service started.
    pub restores: u32,
    /// The account the resolver runs as: "LocalService" when the service is
    /// installed, "the service's account" in console runs; none when stopped.
    #[serde(default)]
    pub resolver_account: Option<String>,
    pub last_update_ms: Option<i64>,
    pub paused_until_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsPauseParams {
    /// `None` resumes.
    pub minutes: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsFilterLogParams {
    #[serde(default)]
    pub after: u64,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One lookup the resolver handled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsFilterLogEntry {
    pub id: u64,
    pub ts_ms: i64,
    pub name: String,
    pub qtype: u16,
    /// "answered", "cached", "blocked", "would_block", "allowed",
    /// "blocked_upstream", "local", "passed", "failed".
    pub outcome: String,
    pub reason: Option<String>,
    pub upstream_ms: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsFilterLogResult {
    pub entries: Vec<DnsFilterLogEntry>,
}

fn yes() -> bool {
    true
}

/// Automatic cleanup of rules (SPEC §7.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupSettings {
    /// Remove the rules of apps whose program has been gone for 7 days.
    #[serde(default = "yes")]
    pub uninstalled: bool,
    /// Remove the rules of apps that haven't used the network, or tried to,
    /// for this many days. Off when `None`.
    #[serde(default)]
    pub inactive_days: Option<u32>,
}

impl Default for CleanupSettings {
    fn default() -> Self {
        CleanupSettings {
            uninstalled: true,
            inactive_days: None,
        }
    }
}

/// Hash reputation (SPEC §12 tier 2). Off by default: it sends file hashes out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationSettings {
    /// Look apps' hashes up: CIRCL hashlookup, then VirusTotal with the
    /// user's key.
    #[serde(default)]
    pub enabled: bool,
    /// Also ask abuse.ch MalwareBazaar (needs an abuse.ch key).
    #[serde(default)]
    pub malwarebazaar: bool,
    /// Alert when this many engines flag a file.
    #[serde(default = "default_alert_at")]
    pub alert_at: u32,
    /// Block an app both ways when `block_at` engines flag its file.
    #[serde(default)]
    pub auto_block: bool,
    #[serde(default = "default_block_at")]
    pub block_at: u32,
}

fn default_alert_at() -> u32 {
    3
}

fn default_block_at() -> u32 {
    5
}

impl Default for ReputationSettings {
    fn default() -> Self {
        ReputationSettings {
            enabled: false,
            malwarebazaar: false,
            alert_at: default_alert_at(),
            auto_block: false,
            block_at: default_block_at(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorSetting {
    pub enabled: bool,
    /// Instead of the alert's own severity.
    #[serde(default)]
    pub severity: Option<Severity>,
}

/// A security monitor, by the alert kind it raises.
#[derive(Clone, Copy, Debug)]
pub struct MonitorInfo {
    pub kind: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub enabled_by_default: bool,
}

/// The monitors the user can switch on and off (SPEC §11).
pub const MONITORS: &[MonitorInfo] = &[
    MonitorInfo {
        kind: "app_info_changed",
        label: "App info changed",
        description: "An app's version, publisher, signer or file changes",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "first_network_activity",
        label: "First network activity",
        description: "An app uses the network for the first time",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "firewall_changed",
        label: "Firewall changed",
        description: "Something else changes win4tress's firewall rules or settings",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "own_dns",
        label: "App uses its own DNS",
        description: "An app looks up names itself instead of through Windows",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "data_plan",
        label: "Data plan",
        description: "Usage passes 75, 90 and 100% of the plan",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "system_file_changed",
        label: "System files",
        description: "A file under drivers\\etc changes, such as hosts",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "adapter_added",
        label: "Network adapters",
        description: "A network adapter appears that wasn't seen before",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "dns_servers_changed",
        label: "DNS servers",
        description: "An adapter's DNS servers change on the same network",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "proxy_changed",
        label: "Proxy settings",
        description: "The machine's or your proxy settings change",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "internet_access_changed",
        label: "Internet access",
        description: "Internet access comes or goes (noisy on laptops)",
        enabled_by_default: false,
    },
    MonitorInfo {
        kind: "arp_spoofing",
        label: "ARP spoofing",
        description: "The gateway's hardware address changes or is claimed twice",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "wifi_evil_twin",
        label: "Wi-Fi evil twin",
        description: "A network with your Wi-Fi's name but weaker security",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "suspicious_host",
        label: "Suspicious hosts",
        description: "An app talks to a host on a threat list",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "rdp_connection",
        label: "Remote Desktop",
        description: "Someone connects to this PC with Remote Desktop",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "monitoring_interrupted",
        label: "Monitoring interrupted",
        description: "Something stops win4tress's traffic monitoring",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "while_away",
        label: "While you were away",
        description: "A summary when you come back after half an hour or more",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "new_device",
        label: "New device on the network",
        description: "The scanner finds a device it hadn't seen (with automatic scans on)",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "reputation",
        label: "Reputation",
        description: "A hash lookup or antivirus scan finds an app's file is malicious",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "dns_filter",
        label: "DNS filtering",
        description: "The DNS filter stops answering and Windows' own DNS is put back",
        enabled_by_default: true,
    },
    MonitorInfo {
        kind: "profile_switched",
        label: "Profile switched",
        description: "The firewall profile changes by itself because you joined another network",
        enabled_by_default: true,
    },
];

impl MonitorInfo {
    /// Its alerts' usual severity; `None` where it depends on what changed.
    pub fn severity(&self) -> Option<Severity> {
        match self.kind {
            "app_info_changed" | "data_plan" => None,
            "first_network_activity"
            | "adapter_added"
            | "internet_access_changed"
            | "while_away"
            | "new_device"
            | "profile_switched" => Some(Severity::Info),
            "arp_spoofing" | "wifi_evil_twin" | "suspicious_host" => Some(Severity::Critical),
            "reputation" => None,
            "dns_filter" => Some(Severity::Warning),
            _ => Some(Severity::Warning),
        }
    }
}

impl Settings {
    /// Whether alerts of `kind` are raised.
    pub fn monitor_enabled(&self, kind: &str) -> bool {
        match self.monitors.get(kind) {
            Some(m) => m.enabled,
            None => MONITORS
                .iter()
                .find(|m| m.kind == kind)
                .is_none_or(|m| m.enabled_by_default),
        }
    }

    /// The severity alerts of `kind` get instead of their own, if the user chose one.
    pub fn severity_for(&self, kind: &str) -> Option<Severity> {
        self.monitors.get(kind).and_then(|m| m.severity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChange {
    Created,
    Modified,
    Deleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScope {
    /// WinHTTP's, used by services and Windows itself.
    Machine,
    /// The signed-in user's, used by browsers and most apps.
    User,
}

/// The monitors as the app lists them: what each does and its setting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorState {
    pub kind: String,
    pub label: String,
    pub description: String,
    pub enabled: bool,
    pub default_severity: Option<Severity>,
    pub severity: Option<Severity>,
}

/// The threat lists "Suspicious hosts" checks connections against.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreatStatus {
    /// Addresses on abuse.ch Feodo Tracker's botnet C2 list.
    pub feodo: usize,
    pub feodo_updated_ms: Option<i64>,
    /// Why the last download failed.
    pub feodo_error: Option<String>,
    /// Entries in the user's own list.
    pub local: usize,
    /// The user's own list: one address or name per line, `#` comments.
    pub local_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MonitorsResult {
    pub monitors: Vec<MonitorState>,
    pub threats: ThreatStatus,
}

impl MonitorInfo {
    /// The alert kind's event id in the Windows Event Log: 100 and up, in
    /// [`MONITORS`] order (which only ever grows at the end).
    pub fn event_id(kind: &str) -> u32 {
        MONITORS
            .iter()
            .position(|m| m.kind == kind)
            .map_or(99, |i| 100 + i as u32)
    }
}

/// A device on the local network (SPEC §10.2 Network).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// "aa-bb-cc-dd-ee-ff".
    pub mac: String,
    pub ip: IpAddr,
    pub name: Option<String>,
    /// The manufacturer, from the IEEE registry; `None` if unknown.
    pub vendor: Option<String>,
    /// A random (private) hardware address, as phones and laptops use.
    pub randomized: bool,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// The user said they know it.
    pub known: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DevicesResult {
    pub devices: Vec<Device>,
    pub scanning: bool,
    pub last_scan_ms: Option<i64>,
    /// The networks the scanner looks at, e.g. "192.168.1.0/24".
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetKnownParams {
    pub mac: String,
    pub known: bool,
}

/// From the app: the signed-in user's proxy settings, as one line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProxyParams {
    pub proxy: String,
}

/// A named snapshot of the firewall mode, the rules that are on (in full) and
/// DNS filtering's settings (SPEC §7.6). It's exact: while it's active, every
/// other rule is off.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub mode: Mode,
    /// The rules on in it.
    pub rules: u32,
    /// The same as `rules`, for an older app (which showed "enabled of rules").
    pub enabled: u32,
    pub saved_ms: i64,
    /// Networks it's switched to on, by itself.
    #[serde(default)]
    pub networks: Vec<NetworkMatch>,
    /// Whether DNS filtering is on in it; `None` for a profile saved before
    /// profiles held DNS filtering, which switching leaves as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_filtering: Option<bool>,
}

/// A network a profile is switched to on (SPEC §7.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkMatch {
    /// One network, by Windows' id; `name` is what it was called when chosen.
    Network { id: String, name: String },
    /// Any network Windows treats this way.
    Category { category: NetworkCategory },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfilesResult {
    pub profiles: Vec<Profile>,
    /// The profile last switched to or saved.
    pub active: Option<String>,
    /// The mode, a rule's state or DNS filtering differs from the active profile now.
    pub changed: bool,
    /// The last switch made because the network changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_auto: Option<AutoSwitch>,
}

/// A profile switched to by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoSwitch {
    pub profile: String,
    /// The network that matched, by name.
    pub network: String,
    pub at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetNetworksParams {
    pub name: String,
    pub networks: Vec<NetworkMatch>,
}

/// A network Windows knows (Network List Manager).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Windows' id, "{…}".
    pub id: String,
    pub name: String,
    pub category: NetworkCategory,
    pub connected: bool,
    pub internet: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworksResult {
    /// Connected first, then the others Windows remembers, by name.
    pub networks: Vec<NetworkInfo>,
    /// The profile the networks connected now call for, if any.
    pub wanted: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleEnableParams {
    pub id: RuleId,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileParams {
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupReason {
    /// The program has been gone for 7 days.
    Uninstalled,
    /// No traffic or blocked attempts for the configured days.
    Inactive,
}

/// An app whose rules automatic cleanup removes (or would).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupItem {
    pub app: AppRef,
    pub reason: CleanupReason,
    /// Since when the program is gone, or the app was last active.
    pub since_ms: i64,
    pub rules: u32,
    /// Removed now, or already due.
    pub due: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CleanupResult {
    /// Apps with rules that are gone or inactive, due or not yet.
    pub items: Vec<CleanupItem>,
    pub last_run_ms: Option<i64>,
    /// Rules removed by the run this answers, when it was one.
    pub removed: u32,
}

/// What a source says about a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepVerdict {
    /// The source doesn't know the file.
    Unknown,
    /// In a known-good set (CIRCL hashlookup: NSRL and vendor catalogues).
    KnownGood,
    /// Scanned or looked up, nothing found.
    Clean,
    /// Some engines flag it, fewer than the alert threshold.
    Suspicious,
    Malicious,
}

/// One source's answer for a file, as kept in history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reputation {
    pub sha256: String,
    /// "CIRCL hashlookup", "VirusTotal", "MalwareBazaar", or the antivirus' name.
    pub source: String,
    pub verdict: RepVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engines: Option<u32>,
    /// A product, threat or family name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Where to see more, e.g. the file's VirusTotal page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    pub checked_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyService {
    VirusTotal,
    /// abuse.ch: MalwareBazaar (and URLhaus and ThreatFox).
    AbuseCh,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetKeyParams {
    pub service: KeyService,
    /// `None` removes the key.
    pub key: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReputationStatus {
    pub enabled: bool,
    pub virustotal_key: bool,
    pub abuse_ch_key: bool,
    /// Apps waiting for a lookup.
    pub queued: u32,
    /// Files with an answer from at least one source.
    pub checked: u32,
    /// VirusTotal lookups today, against its free limit of 500.
    pub virustotal_today: u32,
    pub last_error: Option<String>,
    pub last_check_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppParams {
    pub app: AppId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadParams {
    pub app: AppId,
    /// The user agreed the file becomes visible to VirusTotal's community.
    pub confirm: bool,
}

/// After an upload: where the file's analysis appears.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadResult {
    pub link: String,
}

/// An app's reputation answers, best first: a bad verdict, then VirusTotal's,
/// then the others.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppReputation {
    pub app: AppId,
    pub sha256: Option<String>,
    pub results: Vec<Reputation>,
}

/// The data plan's current period.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanStatus {
    pub plan: DataPlan,
    /// Local midnight on the reset day, and the next one.
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub used: Bytes,
    /// Of the limit, 0–100 or more.
    pub percent: f64,
    /// The connection in use is metered; `None` if unknown.
    pub metered: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectionsParams {
    #[serde(default)]
    pub app: Option<AppId>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectionsResult {
    pub connections: Vec<Connection>,
}

/// Ends TCP connections: these, or every one the app has open.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CloseParams {
    #[serde(default)]
    pub app: Option<AppId>,
    /// (local, remote) pairs; empty with `app` means all of its connections.
    #[serde(default)]
    pub connections: Vec<(SocketAddr, SocketAddr)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CloseResult {
    pub closed: u32,
    /// Windows can only end IPv4 TCP connections: IPv6 ones stay open.
    pub not_closable: u32,
    /// Why one couldn't be ended (the first), if any couldn't.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Open,
    Closed,
}

/// One TCP connection or UDP flow (by local and remote address and port).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub app: AppRef,
    pub pid: u32,
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub name: Option<String>,
    pub country: Country,
    /// Network owner (ASN) of an internet address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<NetworkOwner>,
    pub locality: Locality,
    pub traffic_type: TrafficType,
    pub state: ConnectionState,
    /// `Some(true)` for connections accepted from a remote peer; `None` when unknown
    /// (UDP, or TCP opened before the service started).
    pub inbound: Option<bool>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsLogParams {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub app: Option<AppId>,
    /// Case-insensitive substring of the queried name.
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsLogResult {
    /// Newest first.
    pub entries: Vec<DnsEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsEntry {
    pub ts_ms: i64,
    pub app: AppRef,
    pub name: String,
    pub query_type: u16,
    /// 0 = answered; otherwise a Windows DNS error (9003 = no such name).
    pub status: u32,
    pub addrs: Vec<IpAddr>,
    /// What blocked it, when DNS filtering did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsTopParams {
    /// Unix milliseconds.
    pub from_ms: i64,
    pub to_ms: i64,
    #[serde(default)]
    pub app: Option<AppId>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsTopResult {
    pub domains: Vec<DomainCount>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCount {
    pub name: String,
    pub queries: u64,
    pub failed: u64,
    pub apps: u64,
    pub last_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsStatsParams {
    /// Unix milliseconds.
    pub from_ms: i64,
    pub to_ms: i64,
    /// Timeline step; made coarser if the range would need more than
    /// [`MAX_DNS_STEPS`] steps.
    pub step_ms: i64,
    /// Length of each top list.
    #[serde(default)]
    pub limit: Option<u32>,
}

pub const MAX_DNS_STEPS: i64 = 1_000;
/// Apps with their own line in [`DnsStats::app_timeline`]; the rest are "other".
pub const DNS_TIMELINE_APPS: usize = 4;

/// DNS lookups over a range, from history: the DNS view's dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsStats {
    /// Start of the first step (`from_ms` rounded down to a whole step), and the step.
    pub start_ms: i64,
    pub step_ms: i64,
    pub lookups: u64,
    pub failed: u64,
    /// Distinct names looked up.
    pub domains: u64,
    /// Apps that looked something up.
    pub apps: u64,
    /// Per step, oldest first: `[answered, failed]`.
    pub timeline: Vec<[u64; 2]>,
    /// Lookups per step by the busiest apps, busiest first.
    pub app_timeline: Vec<AppTimeline>,
    /// Lookups per step by all other apps.
    pub other_timeline: Vec<u64>,
    /// Most common first.
    pub query_types: Vec<TypeCount>,
    /// Lookups by outcome (0 = answered, else a Windows DNS error), most common first.
    pub results: Vec<StatusCount>,
    pub top_domains: Vec<DomainCount>,
    /// Names with failed lookups, most failures first.
    pub top_failed: Vec<DomainCount>,
    pub top_apps: Vec<AppLookups>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppTimeline {
    pub app: AppRef,
    pub counts: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeCount {
    pub query_type: u16,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCount {
    pub status: u32,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppLookups {
    pub app: AppRef,
    pub lookups: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollectorHealth {
    pub running: bool,
    /// Times the ETW session was stopped from outside and restarted.
    #[serde(default)]
    pub restarts: u64,
    pub events: u64,
    pub data_events: u64,
    pub parse_errors: u64,
    pub events_lost: u64,
    pub buffers_lost: u64,
    pub last_event_ms: Option<i64>,
}

/// Bytes per second. `t` is the Unix second the traffic happened in (by event timestamp).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub t: i64,
    pub recv: u64,
    pub sent: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveParams {
    /// How many seconds back (at most 600).
    pub seconds: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LiveResult {
    pub samples: Vec<Sample>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRef {
    pub id: AppId,
    pub name: String,
    /// Executable path (for icons); `System` or `Unknown` for pseudo-apps.
    #[serde(default)]
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakdownParams {
    /// First and last Unix second, inclusive.
    pub from: i64,
    pub to: i64,
    #[serde(default)]
    pub filter: BreakdownFilter,
    /// Rows per column (default 30).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Restricts every column to traffic matching all set fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakdownFilter {
    #[serde(default)]
    pub app: Option<AppId>,
    #[serde(default)]
    pub host: Option<IpAddr>,
    #[serde(default)]
    pub traffic_type: Option<TrafficType>,
    /// Country code, including `LAN` and `??`.
    #[serde(default)]
    pub country: Option<String>,
    /// Apps by this publisher (company), as their version info names it.
    #[serde(default)]
    pub publisher: Option<String>,
    /// `true`: the local network only; `false`: the internet only.
    #[serde(default)]
    pub local: Option<bool>,
}

/// Usage over a time range, by app, host, traffic type and country.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Breakdown {
    pub total: Bytes,
    pub internet: Bytes,
    pub local: Bytes,
    pub apps: Vec<AppUsage>,
    /// Rows left out by the limit.
    pub apps_more: usize,
    pub hosts: Vec<HostTotal>,
    pub hosts_more: usize,
    pub traffic_types: Vec<TypeUsage>,
    pub countries: Vec<CountryUsage>,
    /// By publisher (company); apps without one are left out.
    #[serde(default)]
    pub publishers: Vec<PublisherUsage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublisherUsage {
    pub name: String,
    pub bytes: Bytes,
    pub apps: usize,
}

/// One remote host across all apps that talked to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostTotal {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub country: Country,
    pub bytes: Bytes,
    /// The app that moved the most bytes with this host.
    pub top_app: AppRef,
    pub app_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeUsage {
    pub traffic_type: TrafficType,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountryUsage {
    pub country: Country,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppUsage {
    pub app: AppRef,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppsResult {
    pub apps: Vec<AppSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSummary {
    pub id: AppId,
    /// The Windows service's display name for svchost instances; otherwise
    /// FileDescription from the version resource, else the file name.
    pub name: String,
    pub path: String,
    /// Short service name(s) when this is a svchost instance, e.g. `TermService`.
    #[serde(default)]
    pub service: Option<String>,
    pub company: Option<String>,
    /// File version, e.g. `10.0.26100.8737`.
    #[serde(default)]
    pub version: Option<String>,
    /// Running processes of this app that the service has seen.
    #[serde(default)]
    pub pids: Vec<u32>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub total: Bytes,
    pub local: Bytes,
    /// Last 60 seconds.
    pub recent: Bytes,
    /// Bytes per second over the last few seconds.
    #[serde(default)]
    pub rate: Bytes,
    pub host_count: usize,
    /// Hosts with traffic in the last 60 seconds.
    #[serde(default)]
    pub recent_hosts: usize,
    /// The busiest of those.
    #[serde(default)]
    pub top_host: Option<HostRef>,
    /// Open TCP connections and live UDP flows.
    #[serde(default)]
    pub connections: usize,
    /// The last 60 seconds in [`ACTIVITY_STEP`]-second steps, oldest first, as
    /// `[recv, sent]` bytes. Empty when there was no traffic.
    #[serde(default)]
    pub activity: Vec<[u64; 2]>,
    /// Signature, signer, hash and download origin, once read.
    #[serde(default)]
    pub trust: Trust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_class: Option<PathClass>,
    /// When the app was first seen doing its own DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_dns_ms: Option<i64>,
    /// A known VPN client (data/vpn-clients.txt).
    #[serde(default)]
    pub vpn: bool,
}

/// Seconds per step of [`AppSummary::activity`].
pub const ACTIVITY_STEP: i64 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRef {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub country: Country,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostsParams {
    pub app: AppId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostsResult {
    pub app: AppRef,
    pub hosts: Vec<HostSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostSummary {
    pub ip: IpAddr,
    /// From the app's own DNS lookups where possible.
    pub name: Option<String>,
    pub locality: Locality,
    pub country: Country,
    /// Network owner (ASN) of an internet address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<NetworkOwner>,
    pub traffic_type: TrafficType,
    pub ports: Vec<u16>,
    pub total: Bytes,
    pub connects: u32,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubscribeParams {
    pub topics: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SamplesNotification {
    pub samples: Vec<Sample>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppField {
    Version,
    /// The version resource's company name.
    Publisher,
    /// The signing certificate's subject.
    Signer,
    /// Was signed, now isn't (or doesn't verify): a likely replacement.
    Signature,
    /// The file's hash changed but its version didn't.
    File,
}

/// What an alert is about. Serialized flat, with a `kind` tag (SPEC §11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertBody {
    /// A known app's version or publisher changed (an update, or a replaced file).
    AppInfoChanged {
        field: AppField,
        from: String,
        to: String,
    },
    /// An app used the network for the first time since win4tress was installed.
    FirstNetworkActivity { host: Option<HostRef>, port: u16 },
    /// This PC accepted a Remote Desktop connection.
    RdpConnection { remote: HostRef },
    /// Something stopped the traffic trace; the service restarted it.
    MonitoringInterrupted,
    /// An app does its own DNS (port 53 or 853, or a DNS-over-HTTPS server),
    /// bypassing Windows' DNS Client and any filtering there (SPEC §7.11).
    OwnDns { host: HostRef, port: u16 },
    /// Usage passed a share of the data plan's limit.
    DataPlan {
        used: u64,
        limit: u64,
        percent: u8,
        period_start_ms: i64,
    },
    /// A file under `drivers\etc` (hosts, networks, …) changed.
    SystemFileChanged { path: String, change: FileChange },
    /// A network adapter win4tress hadn't seen before.
    AdapterAdded {
        name: String,
        description: String,
        mac: Option<String>,
    },
    /// An adapter's DNS servers changed while on the same network.
    DnsServersChanged {
        adapter: String,
        from: Vec<IpAddr>,
        to: Vec<IpAddr>,
    },
    /// Proxy settings changed: WinHTTP's (machine-wide) or the user's.
    ProxyChanged {
        scope: ProxyScope,
        from: String,
        to: String,
    },
    /// Internet access came or went (Network List Manager).
    InternetAccessChanged { connected: bool },
    /// The gateway answered from a hardware address not seen for this network
    /// before, or its address is claimed by another device too: signs of ARP
    /// spoofing (a man in the middle).
    ArpSpoofing {
        gateway: IpAddr,
        mac: String,
        /// Addresses the gateway's network had before.
        known: Vec<String>,
        /// Other addresses answering from the same hardware address.
        also: Vec<IpAddr>,
    },
    /// A Wi-Fi network with your network's name but weaker security, or your
    /// network itself now less secure than before.
    WifiEvilTwin {
        ssid: String,
        expected: String,
        seen: String,
        /// The weaker one is the network you're connected to.
        connected: bool,
    },
    /// An app talked to a host on a threat list.
    SuspiciousHost {
        host: HostRef,
        port: u16,
        list: String,
    },
    /// What happened while nobody used the PC.
    WhileAway {
        from_ms: i64,
        to_ms: i64,
        bytes: Bytes,
        /// The busiest apps, most first.
        apps: Vec<String>,
        alerts: u32,
    },
    /// The network scanner found a device it hadn't seen.
    NewDevice {
        ip: IpAddr,
        mac: String,
        vendor: Option<String>,
        name: Option<String>,
    },
    /// A hash lookup or an antivirus scan says an app's file is bad.
    Reputation {
        sha256: String,
        verdict: RepVerdict,
        /// e.g. "VirusTotal", "MalwareBazaar", "Microsoft Defender".
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detections: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        engines: Option<u32>,
        /// A threat or malware family name, when the source gives one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// The app was blocked both ways because of it.
        #[serde(default)]
        blocked: bool,
    },
    /// The DNS filter stopped answering; Windows' own DNS was put back
    /// (SPEC §13 watchdog). It's routed through again once it answers.
    DnsFilter { reason: String },
    /// The PC joined a network a profile is chosen for, and it was switched to
    /// (SPEC §7.6).
    ProfileSwitched {
        profile: String,
        /// The network that matched, by name, or its kind ("a public network").
        network: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
    },
    /// win4tress's Windows Firewall rules were changed by something else and
    /// have been put back (SPEC §7.8). The user can keep the changes instead.
    FirewallChanged {
        /// Windows Firewall rules put back.
        repaired: u32,
        /// What was changed, per win4tress rule. Empty in alerts from before
        /// "keep" existed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        changes: Vec<OutsideChange>,
        /// When the user chose to keep the changes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kept_ms: Option<i64>,
    },
}

/// One thing something else changed in win4tress's rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutsideChange {
    /// The win4tress rule it touched; `None` for a rule added to our group.
    pub rule: Option<RuleId>,
    /// The rule's app, or an added rule's name in Windows Firewall.
    pub name: String,
    /// The win4tress rule as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    pub kind: OutsideKind,
    /// "Keep" can adopt it into win4tress's rules.
    pub keepable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutsideKind {
    Deleted,
    Disabled,
    Enabled,
    /// A block rule was switched to allow.
    Allowed,
    /// An allow rule was switched to block.
    Blocked,
    /// Its program, addresses, ports or other conditions were changed.
    Modified,
    /// A rule win4tress didn't make (or a copy of one of ours) was put in its group.
    Added,
}

impl AlertBody {
    /// The `kind` tag, for filtering.
    pub fn kind(&self) -> &'static str {
        match self {
            AlertBody::AppInfoChanged { .. } => "app_info_changed",
            AlertBody::FirstNetworkActivity { .. } => "first_network_activity",
            AlertBody::RdpConnection { .. } => "rdp_connection",
            AlertBody::MonitoringInterrupted => "monitoring_interrupted",
            AlertBody::OwnDns { .. } => "own_dns",
            AlertBody::FirewallChanged { .. } => "firewall_changed",
            AlertBody::DataPlan { .. } => "data_plan",
            AlertBody::SystemFileChanged { .. } => "system_file_changed",
            AlertBody::AdapterAdded { .. } => "adapter_added",
            AlertBody::DnsServersChanged { .. } => "dns_servers_changed",
            AlertBody::ProxyChanged { .. } => "proxy_changed",
            AlertBody::InternetAccessChanged { .. } => "internet_access_changed",
            AlertBody::ArpSpoofing { .. } => "arp_spoofing",
            AlertBody::WifiEvilTwin { .. } => "wifi_evil_twin",
            AlertBody::SuspiciousHost { .. } => "suspicious_host",
            AlertBody::WhileAway { .. } => "while_away",
            AlertBody::NewDevice { .. } => "new_device",
            AlertBody::Reputation { .. } => "reputation",
            AlertBody::DnsFilter { .. } => "dns_filter",
            AlertBody::ProfileSwitched { .. } => "profile_switched",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            AlertBody::AppInfoChanged {
                field: AppField::Version,
                ..
            }
            | AlertBody::FirstNetworkActivity { .. } => Severity::Info,
            AlertBody::AppInfoChanged {
                field: AppField::Publisher | AppField::Signer | AppField::File,
                ..
            }
            | AlertBody::RdpConnection { .. }
            | AlertBody::MonitoringInterrupted
            | AlertBody::OwnDns { .. }
            | AlertBody::FirewallChanged { .. } => Severity::Warning,
            // Info on the way, a warning at the limit.
            AlertBody::DataPlan { percent, .. } if *percent < 100 => Severity::Info,
            AlertBody::DataPlan { .. } => Severity::Warning,
            AlertBody::AdapterAdded { .. }
            | AlertBody::InternetAccessChanged { .. }
            | AlertBody::WhileAway { .. }
            | AlertBody::NewDevice { .. } => Severity::Info,
            AlertBody::SystemFileChanged { .. }
            | AlertBody::DnsServersChanged { .. }
            | AlertBody::ProxyChanged { .. } => Severity::Warning,
            AlertBody::ArpSpoofing { .. }
            | AlertBody::WifiEvilTwin { .. }
            | AlertBody::SuspiciousHost { .. } => Severity::Critical,
            AlertBody::AppInfoChanged {
                field: AppField::Signature,
                ..
            } => Severity::Critical,
            AlertBody::Reputation {
                verdict: RepVerdict::Malicious,
                ..
            } => Severity::Critical,
            AlertBody::Reputation { .. } => Severity::Warning,
            AlertBody::DnsFilter { .. } => Severity::Warning,
            AlertBody::ProfileSwitched { .. } => Severity::Info,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub ts_ms: i64,
    pub severity: Severity,
    /// The app it's about, if any.
    pub app: Option<AppRef>,
    #[serde(flatten)]
    pub body: AlertBody,
    pub read: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AlertsParams {
    /// [`AlertBody::kind`] values; empty means all.
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub unread_only: bool,
    #[serde(default)]
    pub since_ms: Option<i64>,
    /// Paging: only alerts older than this id.
    #[serde(default)]
    pub before_id: Option<i64>,
    /// Matched against the app's name and path and the alert's details.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AlertsResult {
    /// Newest first.
    pub alerts: Vec<Alert>,
    /// Older alerts match too.
    pub more: bool,
    pub unread: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MarkReadParams {
    /// `None` marks every alert.
    #[serde(default)]
    pub ids: Option<Vec<i64>>,
    pub read: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MarkReadResult {
    pub unread: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AlertsNotification {
    pub alerts: Vec<Alert>,
    pub unread: u64,
}

/// A stored rule, with its app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub app: AppRef,
    pub direction: Direction,
    pub action: Action,
    pub scope: Scope,
    pub enabled: bool,
    pub origin: Origin,
    pub note: Option<String>,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// A temporary rule's end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Expiry>,
    /// The action a temporary rule goes back to; `None` deletes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<Action>,
}

impl Rule {
    pub fn new(r: RuleRecord, app: AppRef) -> Rule {
        Rule {
            id: r.id,
            app,
            direction: r.direction,
            action: r.action,
            scope: r.scope,
            enabled: r.enabled,
            origin: r.origin,
            note: r.note,
            created_ms: r.created_ms,
            updated_ms: r.updated_ms,
            expires: r.expires,
            revert: r.revert,
        }
    }
}

/// How long a whole-app verdict lasts when it isn't for good (SPEC §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Lasts {
    /// 1 minute to 30 days.
    Minutes { minutes: u32 },
    /// Until the app's last process ends.
    AppQuits,
    /// Until Windows restarts.
    Restart,
}

/// The longest temporary rule, in minutes.
pub const MAX_RULE_MINUTES: u32 = 30 * 24 * 60;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RulesResult {
    pub rules: Vec<Rule>,
}

/// Allow or block an app in one direction. Replaces the app's opposite rule for
/// that direction and scope kind, so it works like a toggle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSetParams {
    pub app: AppId,
    pub direction: Direction,
    pub action: Action,
    /// Default: any remote address.
    #[serde(default = "any_scope")]
    pub scope: Scope,
    #[serde(default)]
    pub note: Option<String>,
    /// For a while only (whole-app rules); `None` for good.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lasts: Option<Lasts>,
}

fn any_scope() -> Scope {
    Scope::Any
}

/// One change in a [`method::RULES_APPLY`] batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuleChange {
    Set(RuleSetParams),
    Delete { id: RuleId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RulesApplyParams {
    pub changes: Vec<RuleChange>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RulesApplyResult {
    pub applied: u32,
    /// One line per change that wasn't made, with why.
    pub failed: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockAllParams {
    pub on: bool,
    /// How long; `None` until turned off.
    #[serde(default)]
    pub minutes: Option<u32>,
    /// The caller was warned that Block All drops its Remote Desktop session.
    #[serde(default)]
    pub confirm_remote: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TurnOnParams {
    /// "domain", "private" or "public"; `None` for every profile where it's off.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppRulesParams {
    pub app: AppId,
}

/// A Windows Firewall rule outside win4tress that names an app.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowsRuleInfo {
    pub name: String,
    pub direction: Direction,
    pub action: Action,
    /// Applies on a network profile in use now.
    pub active: bool,
    /// "Domain, Private, Public" or a subset.
    pub profiles: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppRulesResult {
    pub rules: Vec<WindowsRuleInfo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlocksParams {
    #[serde(default)]
    pub app: Option<AppId>,
    /// From history, back to here; otherwise since the service started.
    #[serde(default)]
    pub since_ms: Option<i64>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Repeated attempts to one address and port, blocked by the same thing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockedConnection {
    pub app: AppRef,
    pub inbound: bool,
    pub remote: SocketAddr,
    pub name: Option<String>,
    pub by: BlockedBy,
    pub count: u64,
    pub first_ms: i64,
    pub last_ms: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlocksResult {
    /// Most recent first.
    pub blocks: Vec<BlockedConnection>,
}

/// Where a prompt is (SPEC §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptState {
    /// Shown to the user now.
    Open,
    /// Over the prompt rate limit: shown when there's room.
    Waiting,
    /// Not answered within a minute, or "Decide later". The app stays blocked.
    Pending,
}

/// An app's blocked connection, waiting for the user to allow or block it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prompt {
    pub id: u64,
    pub app: AppRef,
    pub company: Option<String>,
    #[serde(default)]
    pub trust: Trust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_class: Option<PathClass>,
    /// When win4tress first saw the app.
    pub first_seen_ms: i64,
    /// The first blocked attempt's destination.
    pub remote: HostRef,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<NetworkOwner>,
    /// Blocked attempts since the prompt came.
    pub attempts: u32,
    pub first_ms: i64,
    pub last_ms: i64,
    pub state: PromptState,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PromptsResult {
    /// Open first, then waiting, then pending; oldest first within each.
    pub prompts: Vec<Prompt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block,
    /// Keep it blocked for now and ask again later (the prompt stays, pending).
    Later,
}

/// What an Allow or Block covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionScope {
    /// The app's outgoing connections.
    #[default]
    App,
    /// Only the prompt's host (its name if known, else its address).
    Host,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecideParams {
    pub id: u64,
    pub decision: Decision,
    #[serde(default)]
    pub scope: DecisionScope,
    /// For a while only (the whole app); `None` for good.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lasts: Option<Lasts>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecideResult {
    /// The rule set, for Allow and Block.
    pub rule: Option<RuleId>,
}

/// An app win4tress knows from history, whether or not it ran this time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownApp {
    pub id: AppId,
    pub name: String,
    pub path: String,
    pub service: Option<String>,
    pub company: Option<String>,
    pub version: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// `None` if it never used the network.
    pub net_first_seen_ms: Option<i64>,
    #[serde(default)]
    pub trust: Trust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_class: Option<PathClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_dns_ms: Option<i64>,
    #[serde(default)]
    pub vpn: bool,
    /// The most telling reputation answer for its file, if looked up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<Reputation>,
    /// Its traffic isn't written to history.
    #[serde(default)]
    pub incognito: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KnownAppsResult {
    pub apps: Vec<KnownApp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequireElevationParams {
    pub on: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleDeleteParams {
    pub id: RuleId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetModeParams {
    pub mode: Mode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeepChangesParams {
    /// The "firewall changed" alert.
    pub alert: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeepChangesResult {
    pub kept: u32,
    /// Changes that can't be kept, or whose rule was changed in win4tress since.
    pub skipped: u32,
}

/// For each app the service lists (`apps.list`) that a rule can name.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerdictsResult {
    pub apps: Vec<AppVerdicts>,
    /// Every network profile in use blocks connections in that direction that
    /// no rule allows. Outgoing: true in Ask to Connect, so allowing an app
    /// there takes an allow rule, not just removing a block.
    pub inbound_default_blocks: bool,
    pub outbound_default_blocks: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppVerdicts {
    pub app: AppId,
    pub inbound: Verdict,
    pub outbound: Verdict,
    /// One of win4tress's own programs: it can't be blocked from the UI (SPEC §7.4).
    #[serde(default)]
    pub protected: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerdictsParams {
    /// Every known app (the Firewall screen), not just those `apps.list` shows.
    #[serde(default)]
    pub all: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResetResult {
    /// Rules deleted from history.
    pub rules: usize,
    /// Windows Firewall matched afterwards (our group is empty).
    pub in_sync: bool,
    pub error: Option<String>,
}

/// Windows Firewall, and how win4tress's rules stand in it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FirewallStatus {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_all: Option<BlockAll>,
    /// Other firewalls and policies (SPEC §7.7).
    #[serde(default)]
    pub environment: Environment,
    /// Why win4tress can only monitor, if so: rules are kept but not applied,
    /// and changes are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_only: Option<String>,
    /// Changes need an elevated caller (SPEC §4.3 hardening option).
    #[serde(default)]
    pub require_elevation: bool,
    /// Outside changes are seen in Windows Firewall's event log as they happen,
    /// not only by the 60 s check.
    #[serde(default)]
    pub live_events: bool,
    /// `None` if Windows Firewall couldn't be read.
    pub state: Option<FirewallState>,
    /// Our Windows Firewall rule group.
    pub group: String,
    /// Stored rules, and the Windows Firewall rules they need.
    pub rules: usize,
    pub windows_rules: usize,
    /// The last check found nothing to change, or fixed everything it found.
    pub in_sync: bool,
    pub last_check_ms: Option<i64>,
    pub last_error: Option<String>,
    /// Times rules changed outside win4tress were put back.
    pub repairs: u64,
}

/// The program a rule names, as another PC can find it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedApp {
    pub name: String,
    pub path: String,
    /// Services inside svchost, comma-separated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// A Store app's package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedRule {
    pub app: ExportedApp,
    pub direction: Direction,
    pub action: Action,
    pub scope: Scope,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedProfile {
    pub name: String,
    pub mode: Mode,
    /// Which of the export's rules are on in it, by place in `rules`: all a
    /// file from before profiles were exact has, and what an older win4tress
    /// reads.
    pub rules: BTreeMap<usize, bool>,
    #[serde(default)]
    pub networks: Vec<NetworkMatch>,
    /// DNS filtering's settings in it, without a pause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsSettings>,
    /// The rules on in it, in full; every other rule is off while it's active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_on: Option<Vec<ExportedRule>>,
}

/// win4tress's rules and profiles as a file (SPEC §7.2 "Export and import").
/// Temporary rules are left out: what they go back to is exported instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesExport {
    /// Always [`RulesExport::FORMAT`].
    pub format: String,
    pub version: u32,
    pub exported_ms: i64,
    /// The computer's name.
    #[serde(default)]
    pub computer: String,
    pub mode: Mode,
    pub rules: Vec<ExportedRule>,
    #[serde(default)]
    pub profiles: Vec<ExportedProfile>,
    /// DNS filtering's settings, without a pause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsSettings>,
}

impl RulesExport {
    pub const FORMAT: &str = "win4tress-rules";
    pub const VERSION: u32 = 1;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportParams {
    pub export: RulesExport,
    /// Only say what would happen.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportResult {
    /// Rules new to this PC, and rules that replaced one for the same app,
    /// direction and kind.
    pub added: u32,
    pub replaced: u32,
    /// Rules already here as they are in the file.
    pub unchanged: u32,
    /// Programs that aren't on this PC (their rules are set anyway, for when
    /// they're installed).
    pub missing_apps: Vec<String>,
    /// Rules that couldn't be set, with why.
    pub failed: Vec<String>,
    /// Profiles added or replaced, by name.
    pub profiles: Vec<String>,
    /// This PC's DNS filtering settings replaced by the file's (they differed).
    #[serde(default)]
    pub dns: bool,
}
