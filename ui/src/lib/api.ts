// Types mirror crates/w4-ipc/src/api.rs. Times are Unix ms unless named `t` (seconds).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Bytes {
  recv: number;
  sent: number;
}

export interface Sample {
  t: number;
  recv: number;
  sent: number;
}

export interface CollectorHealth {
  running: boolean;
  restarts: number;
  events: number;
  data_events: number;
  parse_errors: number;
  events_lost: number;
  buffers_lost: number;
  last_event_ms: number | null;
}

export interface Status {
  version: string;
  started_ms: number;
  now_ms: number;
  collector: CollectorHealth;
  apps_bytes: Bytes;
  local_bytes: Bytes;
  adapter_bytes: Bytes;
  app_count: number;
  process: { working_set: number; cpu_ms: number };
  history: { enabled: boolean; path: string | null; size_bytes: number; oldest: number | null };
  unread_alerts: number;
}

export type Severity = "info" | "warning" | "critical";

/** What an alert is about; `kind` says which. */
export type AlertBody =
  | {
      kind: "app_info_changed";
      /** signer: the signing certificate; signature: was signed, now isn't;
       *  file: the hash changed but the version didn't. */
      field: "version" | "publisher" | "signer" | "signature" | "file";
      from: string;
      to: string;
    }
  | { kind: "first_network_activity"; host: HostRef | null; port: number }
  | { kind: "rdp_connection"; remote: HostRef }
  | { kind: "monitoring_interrupted" }
  | { kind: "own_dns"; host: HostRef; port: number }
  | { kind: "data_plan"; used: number; limit: number; percent: number; period_start_ms: number }
  | {
      kind: "firewall_changed";
      /** Windows Firewall rules put back. */
      repaired: number;
      /** What was changed; absent on alerts from before "keep" existed. */
      changes?: OutsideChange[];
      /** When the user chose to keep the changes. */
      kept_ms?: number | null;
    }
  | { kind: "system_file_changed"; path: string; change: "created" | "modified" | "deleted" }
  | { kind: "adapter_added"; name: string; description: string; mac: string | null }
  | { kind: "dns_servers_changed"; adapter: string; from: string[]; to: string[] }
  | { kind: "proxy_changed"; scope: "machine" | "user"; from: string; to: string }
  | { kind: "internet_access_changed"; connected: boolean }
  | {
      kind: "arp_spoofing";
      gateway: string;
      mac: string;
      /** The gateway's hardware addresses seen before on this network. */
      known: string[];
      /** Other addresses answering from the gateway's hardware address. */
      also: string[];
    }
  | {
      kind: "wifi_evil_twin";
      ssid: string;
      expected: string;
      seen: string;
      /** The weaker network is the one connected to. */
      connected: boolean;
    }
  | { kind: "suspicious_host"; host: HostRef; port: number; list: string }
  | {
      kind: "while_away";
      from_ms: number;
      to_ms: number;
      bytes: Bytes;
      /** The busiest apps, most first. */
      apps: string[];
      alerts: number;
    }
  | { kind: "new_device"; ip: string; mac: string; vendor: string | null; name: string | null }
  | { kind: "dns_filter"; reason: string }
  | {
      kind: "profile_switched";
      profile: string;
      /** The network that matched, by name, or its kind. */
      network: string;
      from?: string | null;
    }
  | {
      kind: "reputation";
      sha256: string;
      verdict: RepVerdict;
      source: string;
      detections?: number;
      engines?: number;
      detail?: string;
      /** The app was blocked both ways because of it. */
      blocked: boolean;
    };

export type Direction = "in" | "out";
export type Action = "allow" | "block";
export type Mode = "off" | "click_to_block" | "ask_to_connect";

/** Open: shown now. Waiting: over the prompt rate, shown when there's room.
 *  Pending: not answered within a minute, or "Decide later". */
export type PromptState = "open" | "waiting" | "pending";

/** An app's blocked connection in Ask to Connect, waiting for a decision. */
export interface Prompt {
  id: number;
  app: AppRef;
  company: string | null;
  trust: Trust;
  path_class?: PathClass;
  first_seen_ms: number;
  remote: HostRef;
  port: number;
  owner?: NetworkOwner;
  attempts: number;
  first_ms: number;
  last_ms: number;
  state: PromptState;
}

export type Decision = "allow" | "block" | "later";
/** "host": only the prompt's host (its name if known, else its address). */
export type DecisionScope = "app" | "host";

/** One thing something else changed in win4tress's rules. */
export interface OutsideChange {
  /** The win4tress rule; null for a rule added to win4tress's group. */
  rule: number | null;
  /** The rule's app, or an added rule's name in Windows Firewall. */
  name: string;
  direction?: Direction;
  action?: Action;
  kind: "deleted" | "disabled" | "enabled" | "allowed" | "blocked" | "modified" | "added";
  /** "Keep" can adopt it into win4tress's rules. */
  keepable: boolean;
}

/** What a rule covers. Hosts are addresses, ranges, networks or names (a name
 *  stands for the addresses this app received for it; `*.x` adds subdomains). */
export type Scope =
  | { kind: "any" }
  | { kind: "hosts"; hosts: string[] }
  /** "Allow only these hosts": a block on everything else. */
  | { kind: "except"; hosts: string[] }
  /** The app's own DNS: ports 53/853 and DNS-over-HTTPS servers. */
  | { kind: "dns" };

/** When a temporary rule ends. */
export type Expiry =
  | { kind: "at"; ms: number }
  | { kind: "app_quits" }
  | { kind: "restart"; boot_ms: number };

/** How long a whole-app verdict lasts when not for good. */
export type Lasts =
  | { kind: "minutes"; minutes: number }
  | { kind: "app_quits" }
  | { kind: "restart" };

export interface Rule {
  id: number;
  app: AppRef;
  direction: Direction;
  action: Action;
  scope: Scope;
  enabled: boolean;
  origin: string;
  note: string | null;
  created_ms: number;
  updated_ms: number;
  /** A temporary rule's end. */
  expires?: Expiry;
  /** What a temporary rule goes back to; absent: it's removed. */
  revert?: Action;
}

export interface RuleSet {
  app: number;
  direction: Direction;
  action: Action;
  scope?: Scope;
}

export type RuleChange = ({ op: "set" } & RuleSet) | { op: "delete"; id: number };

export type Signature = "signed" | "unsigned" | "invalid";
export type PathClass = "windows" | "program_files" | "user_writable" | "other";

/** Signature, signer, hash and download origin of an app's executable. */
export interface Trust {
  signature?: Signature | null;
  signer?: string | null;
  sha256?: string | null;
  origin?: { zone: number; host_url?: string; referrer_url?: string } | null;
}

/** An app win4tress knows from history. */
export interface KnownApp {
  id: number;
  name: string;
  path: string;
  service: string | null;
  company: string | null;
  version: string | null;
  first_seen_ms: number;
  last_seen_ms: number;
  net_first_seen_ms: number | null;
  trust: Trust;
  path_class?: PathClass;
  own_dns_ms?: number;
  /** A known VPN client: its traffic is other apps' traffic again. */
  vpn?: boolean;
  /** The most telling reputation answer for its file. */
  reputation?: Reputation;
  /** Its traffic isn't written to history. */
  incognito?: boolean;
}

export type RepVerdict = "unknown" | "known_good" | "clean" | "suspicious" | "malicious";

/** One source's answer about a file (SPEC §12). */
export interface Reputation {
  sha256: string;
  /** "CIRCL hashlookup", "VirusTotal", "MalwareBazaar", or the antivirus. */
  source: string;
  verdict: RepVerdict;
  detections?: number;
  engines?: number;
  detail?: string;
  link?: string;
  checked_ms: number;
}

export interface AppReputation {
  app: number;
  sha256: string | null;
  results: Reputation[];
}

export interface ReputationStatus {
  enabled: boolean;
  virustotal_key: boolean;
  abuse_ch_key: boolean;
  queued: number;
  checked: number;
  virustotal_today: number;
  last_error: string | null;
  last_check_ms: number | null;
}

export type NetworkCategory = "public" | "private" | "domain";

/** A network a profile is switched to on: one by Windows' id, or any of a kind. */
export type NetworkMatch =
  | { kind: "network"; id: string; name: string }
  | { kind: "category"; category: NetworkCategory };

/** A firewall profile: the mode, the rules on and DNS filtering. It's exact:
    while it's active, every other rule is off. */
export interface Profile {
  name: string;
  mode: Mode;
  /** The rules on in it. */
  rules: number;
  enabled: number;
  saved_ms: number;
  networks: NetworkMatch[];
  /** Whether DNS filtering is on in it; absent for a profile saved before
      profiles held DNS filtering, which switching leaves as it is. */
  dns_filtering?: boolean | null;
}

export interface ProfilesResult {
  profiles: Profile[];
  active: string | null;
  /** The mode, a rule or DNS filtering differs from the active profile now. */
  changed: boolean;
  /** The last switch made because the network changed. */
  last_auto?: { profile: string; network: string; at_ms: number } | null;
}

/** A network Windows knows. */
export interface NetworkInfo {
  id: string;
  name: string;
  category: NetworkCategory;
  connected: boolean;
  internet: boolean;
}

/** win4tress's rules, profiles and DNS filtering's settings as a file. */
export interface RulesExport {
  format: string;
  version: number;
  exported_ms: number;
  computer: string;
  mode: Mode;
  rules: unknown[];
  profiles: { name: string }[];
  /** Without a pause; absent in a file from before exports held it. */
  dns?: DnsSettings | null;
}

export interface ImportResult {
  added: number;
  replaced: number;
  unchanged: number;
  missing_apps: string[];
  failed: string[];
  profiles: string[];
  /** This PC's DNS filtering settings replaced by the file's (they differed). */
  dns: boolean;
}

export interface CloseResult {
  closed: number;
  /** IPv6 connections: Windows can only end IPv4 ones. */
  not_closable: number;
  error: string | null;
}

export interface CleanupItem {
  app: AppRef;
  reason: "uninstalled" | "inactive";
  since_ms: number;
  rules: number;
  due: boolean;
}

export interface CleanupResult {
  items: CleanupItem[];
  last_run_ms: number | null;
  removed: number;
}

/** Where the mini viewer was, and how solid its background is (20–100). */
export interface MiniPrefs {
  x: number | null;
  y: number | null;
  opacity: number;
}

/** Settings → About: the app's version (the service's is in its status) and Windows'. */
export interface AboutInfo {
  version: string;
  /** "Windows 11 Pro 24H2 (build 26100.4652)". */
  windows: string;
}

export type BlockedByKind = "win4tress" | "windows_rule" | "windows_default" | "other";

export interface BlockedConnection {
  app: AppRef;
  inbound: boolean;
  remote: string;
  name: string | null;
  by: { kind: BlockedByKind; name: string };
  count: number;
  first_ms: number;
  last_ms: number;
}

export interface WindowsRuleInfo {
  name: string;
  direction: Direction;
  action: Action;
  /** Applies on a network profile in use now. */
  active: boolean;
  profiles: string;
}

export interface BlockAll {
  since_ms: number;
  until_ms: number | null;
}

export interface Environment {
  other_firewalls: string[];
  local_rules_ignored_by: string[];
  outbound_default_forced_by: string[];
}

/** What decides whether an app's connections in one direction are allowed. */
export type VerdictSource = "win4tress" | "windows_rule" | "default" | "firewall_off";

/** Allowed or blocked, and why. Approximate: ports and addresses aren't weighed. */
export interface Verdict {
  allowed: boolean;
  by: VerdictSource;
  /** The Windows Firewall rules that decide it, for "windows_rule". */
  rules?: string[];
}

export interface VerdictsResult {
  /** `protected`: one of win4tress's own programs, which can't be blocked. */
  apps: { app: number; inbound: Verdict; outbound: Verdict; protected?: boolean }[];
  /** No rule means blocked, per direction. Outgoing: true in Ask to Connect. */
  inbound_default_blocks: boolean;
  outbound_default_blocks: boolean;
}

export interface FirewallStatus {
  mode: Mode;
  block_all?: BlockAll | null;
  environment: Environment;
  /** Why win4tress can only monitor, if so: changes are refused. */
  monitoring_only?: string | null;
  /** Changes need an elevated caller ("Require elevation"). */
  require_elevation: boolean;
  /** Outside changes are seen in Windows Firewall's log as they happen. */
  live_events: boolean;
  state: {
    profiles: {
      name: string;
      active: boolean;
      firewall_on: boolean;
      inbound_default_block: boolean;
      outbound_default_block: boolean;
    }[];
    policy_override: boolean;
    rule_count: number;
  } | null;
  group: string;
  rules: number;
  windows_rules: number;
  in_sync: boolean;
  last_check_ms: number | null;
  last_error: string | null;
  repairs: number;
}

export type AlertKind = AlertBody["kind"];

export type Alert = AlertBody & {
  id: number;
  ts_ms: number;
  severity: Severity;
  app: AppRef | null;
  read: boolean;
};

export interface AlertsQuery {
  kinds?: AlertKind[];
  unread_only?: boolean;
  since_ms?: number | null;
  before_id?: number | null;
  query?: string | null;
  limit?: number;
}

export interface AlertsResult {
  /** Newest first. */
  alerts: Alert[];
  /** Older alerts match too. */
  more: boolean;
  unread: number;
}

export interface HistoryResult {
  /** Seconds per sample. */
  step: number;
  /** Bytes per step (not per second). */
  samples: Sample[];
  /** When nobody used the PC. */
  idle: { start_ms: number; end_ms: number }[];
}

/** A monthly data plan. */
export interface DataPlan {
  limit_bytes: number;
  /** 1–28. */
  reset_day: number;
  warn_at: number[];
  metered_only: boolean;
}

export interface MonitorSetting {
  enabled: boolean;
  /** Instead of the alert's own. */
  severity: Severity | null;
}

/** All of the service's settings: changes send them all back. */
export interface Settings {
  data_plan: DataPlan | null;
  /** Leave known VPN clients out of traffic totals. */
  exclude_vpn: boolean;
  /** Per alert kind; kinds not listed use their defaults. */
  monitors: Record<string, MonitorSetting>;
  /** Copy alerts to the Windows Event Log. */
  event_log: boolean;
  /** Scan the local network now and then, and alert on new devices. */
  scanner: boolean;
  /** Download abuse.ch's threat list daily. */
  threat_feeds: boolean;
  /** Write no traffic to history at all. */
  incognito: boolean;
  /** App ids whose traffic isn't written to history. */
  incognito_apps: number[];
  cleanup: { uninstalled: boolean; inactive_days: number | null };
  reputation: {
    enabled: boolean;
    malwarebazaar: boolean;
    alert_at: number;
    auto_block: boolean;
    block_at: number;
  };
  dns: DnsSettings;
}

/** A security monitor, by the alert kind it raises. */
export interface MonitorState {
  kind: AlertKind;
  label: string;
  description: string;
  enabled: boolean;
  /** Null where it depends on what changed. */
  default_severity: Severity | null;
  /** Chosen instead of the default. */
  severity: Severity | null;
}

export interface ThreatStatus {
  feodo: number;
  feodo_updated_ms: number | null;
  feodo_error: string | null;
  local: number;
  /** One address or name per line. */
  local_path: string;
}

/** A device on the local network. */
export interface Device {
  mac: string;
  ip: string;
  name: string | null;
  vendor: string | null;
  /** A random (private) hardware address, as phones and laptops use. */
  randomized: boolean;
  first_seen_ms: number;
  last_seen_ms: number;
  known: boolean;
}

export interface DevicesResult {
  /** Most recently seen first. */
  devices: Device[];
  scanning: boolean;
  last_scan_ms: number | null;
  /** e.g. "192.168.1.0/24". */
  networks: string[];
}

export type PopupLevel = "off" | "warnings" | "all";
/** Which of a monitor's alerts pop up: none, its warnings and critical ones, or all. */
export type PopupDesktop = "off" | "important" | "all";

/** Desktop pop-ups, kept by the app for this user. */
export interface PopupPrefs {
  /** For monitors without a choice of their own. */
  level: PopupLevel;
  /** Per monitor (alert kind). */
  desktop: Partial<Record<string, PopupDesktop>>;
  /** "app:<id>" or "kind:<kind>" → snoozed until (ms). */
  snoozed: Record<string, number>;
  /** In Click to Block, a new app's first connection shows the card, with Block. */
  new_app_cards: boolean;
}

export interface PlanStatus {
  plan: DataPlan;
  period_start_ms: number;
  period_end_ms: number;
  used: Bytes;
  percent: number;
  metered: boolean | null;
}

export type FlowState = "open" | "closed";

/** A TCP connection or UDP flow. */
export interface NetConnection {
  app: AppRef;
  pid: number;
  protocol: "tcp" | "udp";
  local: string;
  remote: string;
  name: string | null;
  country: Country;
  owner?: NetworkOwner;
  locality: Locality;
  traffic_type: string;
  state: FlowState;
  /** true = accepted from a remote peer; null = unknown (UDP, or opened before the service). */
  inbound: boolean | null;
  first_seen_ms: number;
  last_seen_ms: number;
  bytes: Bytes;
}

export interface DnsEntry {
  ts_ms: number;
  app: AppRef;
  name: string;
  query_type: number;
  /** 0 = answered; otherwise a Windows DNS error (9003 = no such name). */
  status: number;
  addrs: string[];
  /** What blocked it, when DNS filtering did. */
  blocked_by?: string;
}

export type DnsUpstream = { kind: "system" } | { kind: "doh"; url: string };

export interface DnsSettings {
  enabled: boolean;
  /** Catalogue ids. */
  lists: string[];
  custom_lists: { name: string; url: string; regex: boolean }[];
  upstream: DnsUpstream;
  nxdomain: boolean;
  observe: "auto" | "on" | "off";
  allow: string[];
  deny: string[];
  regex: string[];
  local_records: { name: string; addrs: string[] }[];
  paused_until_ms: number | null;
}

export type DnsFilterState = "off" | "starting" | "on" | "passing" | "failed";

export interface DnsListState {
  id: string;
  name: string;
  description: string;
  url: string;
  homepage: string;
  licence: string;
  licence_url: string;
  enabled: boolean;
  custom: boolean;
  entries: number | null;
  updated_ms: number | null;
  error: string | null;
}

export interface DnsFilterStatus {
  state: DnsFilterState | null;
  message: string | null;
  routed: boolean;
  lists: DnsListState[];
  blocked_domains: number;
  upstream: string;
  system_servers: string[];
  upstream_blocks: boolean | null;
  queries: number;
  blocked: number;
  cached: number;
  top_blocked: [string, number][];
  problems: string[];
  restores: number;
  /** "LocalService" installed, "the service's account" in console runs. */
  resolver_account?: string | null;
  last_update_ms: number | null;
  paused_until_ms: number | null;
}

export interface DnsFilterLogEntry {
  id: number;
  ts_ms: number;
  name: string;
  qtype: number;
  outcome: string;
  reason: string | null;
  upstream_ms: number | null;
}

export interface DomainCount {
  name: string;
  queries: number;
  failed: number;
  apps: number;
  last_ms: number;
}

/** The DNS dashboard for a range, from history. */
export interface DnsStats {
  /** Start of the first step and the step, in ms. */
  start_ms: number;
  step_ms: number;
  lookups: number;
  failed: number;
  /** Distinct names looked up. */
  domains: number;
  /** Apps that looked something up. */
  apps: number;
  /** Per step, oldest first: [answered, failed]. */
  timeline: [number, number][];
  /** Lookups per step by the busiest apps, busiest first. */
  app_timeline: { app: AppRef; counts: number[] }[];
  /** Lookups per step by every other app. */
  other_timeline: number[];
  query_types: { query_type: number; count: number }[];
  /** By outcome: 0 = answered, else a Windows DNS error. */
  results: { status: number; count: number }[];
  top_domains: DomainCount[];
  /** Names with failed lookups, most failures first. */
  top_failed: DomainCount[];
  top_apps: { app: AppRef; lookups: number; failed: number }[];
}

export interface AppRef {
  id: number;
  name: string;
  path: string;
}

export interface Country {
  /** ISO 3166-1 alpha-2, or "LAN" (local network) / "??" (unknown). */
  code: string;
  name: string;
}

/** Who runs the network an address is in (its autonomous system). */
export interface NetworkOwner {
  asn: number;
  name: string;
}

export interface BreakdownFilter {
  app?: number;
  host?: string;
  traffic_type?: string;
  country?: string;
  /** Apps by this publisher (company). */
  publisher?: string;
  /** true: the local network only; false: the internet only. */
  local?: boolean;
}

export interface HostTotal {
  ip: string;
  name: string | null;
  country: Country;
  bytes: Bytes;
  top_app: AppRef;
  app_count: number;
}

export interface Breakdown {
  total: Bytes;
  internet: Bytes;
  local: Bytes;
  apps: AppUsage[];
  apps_more: number;
  hosts: HostTotal[];
  hosts_more: number;
  traffic_types: { traffic_type: string; bytes: Bytes }[];
  countries: { country: Country; bytes: Bytes }[];
  publishers: { name: string; bytes: Bytes; apps: number }[];
}

export interface AppUsage {
  app: AppRef;
  bytes: Bytes;
}

export interface AppSummary {
  id: number;
  name: string;
  path: string;
  /** Short service name(s) when this is a svchost instance. */
  service: string | null;
  company: string | null;
  /** File version, e.g. "10.0.26100.8737". */
  version: string | null;
  /** Running processes the service has seen. */
  pids: number[];
  first_seen_ms: number;
  last_seen_ms: number;
  total: Bytes;
  local: Bytes;
  /** Last 60 seconds. */
  recent: Bytes;
  /** Bytes per second over the last few seconds. */
  rate: Bytes;
  host_count: number;
  /** Hosts with traffic in the last 60 seconds, and the busiest of them. */
  recent_hosts: number;
  top_host: HostRef | null;
  /** Open TCP connections and live UDP flows. */
  connections: number;
  /** Last 60 s in 2 s steps, oldest first: [recv, sent] bytes. Empty when idle. */
  activity: [number, number][];
  trust: Trust;
  path_class?: PathClass;
  /** When the app was first seen doing its own DNS. */
  own_dns_ms?: number;
  /** A known VPN client: its traffic is other apps' traffic again. */
  vpn?: boolean;
}

export interface HostRef {
  ip: string;
  name: string | null;
  country: Country;
}

export type Locality = "loopback" | "local" | "internet";

export interface HostSummary {
  ip: string;
  name: string | null;
  locality: Locality;
  country: Country;
  owner?: NetworkOwner;
  traffic_type: string;
  ports: number[];
  total: Bytes;
  connects: number;
  first_seen_ms: number;
  last_seen_ms: number;
}

export interface HostsResult {
  app: AppRef;
  hosts: HostSummary[];
}

export interface ConnectionState {
  connected: boolean;
  reason: string | null;
}

function rpc<T>(method: string, params: unknown = null): Promise<T> {
  return invoke<T>("rpc", { method, params });
}

/** The service's error code in a transport error, e.g. "… (code -32006)". */
export function errorCode(e: unknown): number | null {
  const m = /\(code (-?\d+)\)\s*$/.exec(String(e));
  return m ? Number(m[1]) : null;
}

export const ELEVATION_REQUIRED = -32006;
export const REMOTE_SESSION = -32007;

/** A change. With "Require elevation" on, the service refuses it from this
 *  (unelevated) app; it then runs through the elevated helper, behind a UAC
 *  prompt (SPEC §4.3). */
async function change<T>(method: string, params: unknown = null): Promise<T> {
  try {
    return await rpc<T>(method, params);
  } catch (e) {
    if (errorCode(e) !== ELEVATION_REQUIRED) throw e;
    return invoke<T>("rpc_elevated", { method, params });
  }
}

export const api = {
  connection: () => invoke<ConnectionState>("connection_state"),
  status: () => rpc<Status>("status"),
  live: (seconds: number) => rpc<{ samples: Sample[] }>("traffic.live", { seconds }),
  breakdown: (from: number, to: number, filter: BreakdownFilter = {}, limit = 30) =>
    rpc<Breakdown>("traffic.breakdown", { from, to, filter, limit }),
  /** `step` in seconds: at least a minute within 35 days, an hour beyond. */
  history: (from: number, to: number, step = 60, filter: BreakdownFilter = {}) =>
    rpc<HistoryResult>("traffic.history", { from, to, step, filter }),
  settings: () => rpc<Settings>("settings.get"),
  setSettings: (settings: Settings) => change<Settings>("settings.set", settings),
  planStatus: () => rpc<PlanStatus | null>("usage.plan"),
  apps: () => rpc<{ apps: AppSummary[] }>("apps.list"),
  hosts: (app: number) => rpc<HostsResult>("apps.hosts", { app }),
  connections: () => rpc<{ connections: NetConnection[] }>("connections.list", {}),
  dnsLog: (limit = 1000, query?: string) =>
    rpc<{ entries: DnsEntry[] }>("dns.log", { limit, query: query || null }),
  dnsTop: (fromMs: number, toMs: number, limit = 50) =>
    rpc<{ domains: DomainCount[] }>("dns.top", { from_ms: fromMs, to_ms: toMs, limit }),
  dnsStats: (fromMs: number, toMs: number, stepMs: number, limit = 10) =>
    rpc<DnsStats>("dns.stats", { from_ms: fromMs, to_ms: toMs, step_ms: stepMs, limit }),
  alerts: (query: AlertsQuery) => rpc<AlertsResult>("alerts.list", query),
  /** `ids` null marks every alert. Returns the unread count. */
  markRead: (ids: number[] | null, read = true) =>
    rpc<{ unread: number }>("alerts.mark_read", { ids, read }),
  firewall: () => rpc<FirewallStatus>("firewall.status"),
  /** `all`: every known app (the Firewall screen), not just this run's. */
  verdicts: (all = false) => rpc<VerdictsResult>("firewall.verdicts", { all }),
  rules: () => rpc<{ rules: Rule[] }>("rules.list"),
  knownApps: () => rpc<{ apps: KnownApp[] }>("apps.all"),
  appRules: (app: number) => rpc<{ rules: WindowsRuleInfo[] }>("firewall.app_rules", { app }),
  /** Blocked attempts: since the service started, or from history since `sinceMs`. */
  blocks: (app: number | null = null, sinceMs: number | null = null, limit = 200) =>
    rpc<{ blocks: BlockedConnection[] }>("firewall.blocks", { app, since_ms: sinceMs, limit }),
  /** Sets an app's verdict for a direction and scope, replacing its opposite
   *  rule; `lasts` makes a whole-app one temporary. Administrators only. */
  setRule: (
    app: number,
    direction: Direction,
    action: Action,
    scope: Scope = { kind: "any" },
    lasts: Lasts | null = null,
  ) => change<Rule>("rules.set", { app, direction, action, scope, lasts }),
  deleteRule: (id: number) => change<{ deleted: number }>("rules.delete", { id }),
  /** Keeps the rule but switches it off (or on): what profiles hold. */
  enableRule: (id: number, enabled: boolean) => change<Rule>("rules.enable", { id, enabled }),
  applyRules: (changes: RuleChange[]) =>
    change<{ applied: number; failed: string[] }>("rules.apply", { changes }),
  setMode: (mode: Mode) => change<FirewallStatus>("firewall.set_mode", { mode }),
  /** Adopts the outside changes a firewall_changed alert reported. */
  keepChanges: (alert: number) =>
    change<{ kept: number; skipped: number }>("firewall.keep_changes", { alert }),
  /** `minutes` null: until turned off. Fails with REMOTE_SESSION over Remote
   *  Desktop unless `confirmRemote`. */
  blockAll: (on: boolean, minutes: number | null = null, confirmRemote = false) =>
    change<FirewallStatus>("firewall.block_all", { on, minutes, confirm_remote: confirmRemote }),
  turnOn: (profile: string | null = null) =>
    change<{ turned_on: string[] }>("firewall.turn_on", { profile }),
  /** Open first, then waiting, then pending. */
  prompts: () => rpc<{ prompts: Prompt[] }>("prompts.list"),
  decide: (id: number, decision: Decision, scope: DecisionScope = "app", lasts: Lasts | null = null) =>
    change<{ rule: number | null }>("prompts.decide", { id, decision, scope, lasts }),
  monitors: () => rpc<{ monitors: MonitorState[]; threats: ThreatStatus }>("monitors.list"),
  devices: () => rpc<DevicesResult>("devices.list"),
  /** Starts a scan; poll `devices` while `scanning`. */
  scan: () => change<DevicesResult>("devices.scan"),
  setDeviceKnown: (mac: string, known: boolean) =>
    change<DevicesResult>("devices.set_known", { mac, known }),
  popupPrefs: () => invoke<PopupPrefs>("popup_prefs"),
  /** Every monitor at once: clears their own choices. */
  setPopupLevel: (level: PopupLevel) => invoke<PopupPrefs>("set_popup_level", { level }),
  /** One monitor's pop-ups; null goes back to the default. */
  setPopupKind: (kind: string, desktop: PopupDesktop | null) =>
    invoke<PopupPrefs>("set_popup_kind", { kind, desktop }),
  /** Silences pop-ups for `key` (see `snoozeKey`) for 24 hours, or ends that. */
  snooze: (key: string, on = true) => invoke<PopupPrefs>("snooze", { key, on }),
  setNewAppCards: (on: boolean) => invoke<PopupPrefs>("set_new_app_cards", { on }),
  /** The card: new apps' first connections it shows, besides the prompts. */
  cardNotices: () => invoke<Alert[]>("card_notices"),
  /** A new app answered (Block or OK), or timed out. */
  cardDismiss: (id: number) => invoke<void>("card_dismiss", { id }),
  /** The card's page is `height` CSS pixels tall: the window follows. */
  cardFit: (height: number) => invoke<void>("card_fit", { height }),
  /** Shows the card, e.g. for the decisions still waiting. */
  showCard: () => invoke<void>("show_prompts"),
  profiles: () => rpc<ProfilesResult>("profiles.list"),
  saveProfile: (name: string) => change<ProfilesResult>("profiles.save", { name }),
  switchProfile: (name: string) => change<ProfilesResult>("profiles.switch", { name }),
  deleteProfile: (name: string) => change<ProfilesResult>("profiles.delete", { name }),
  /** The networks a profile is switched to on; empty: by hand only. */
  setProfileNetworks: (name: string, networks: NetworkMatch[]) =>
    change<ProfilesResult>("profiles.set_networks", { name, networks }),
  /** Connected first. `wanted`: the profile the connected ones call for. */
  networks: () => rpc<{ networks: NetworkInfo[]; wanted: string | null }>("networks.list"),
  exportRules: () => rpc<RulesExport>("rules.export"),
  importRules: (exported: RulesExport, dryRun: boolean) =>
    (dryRun ? rpc<ImportResult> : change<ImportResult>)("rules.import", {
      export: exported,
      dry_run: dryRun,
    }),
  /** Ends an app's TCP connections, or the ones given as [local, remote]. */
  closeConnections: (app: number | null, connections: [string, string][] = []) =>
    change<CloseResult>("connections.close", { app, connections }),
  /** Asks where to save, and saves; the path, or null if cancelled. */
  saveFile: (name: string, contents: string) =>
    invoke<string | null>("save_file", { name, contents }),
  /** Asks for a file and reads it; null if cancelled. */
  openFile: () => invoke<string | null>("open_file"),
  cleanup: () => rpc<CleanupResult>("cleanup.status"),
  runCleanup: () => change<CleanupResult>("cleanup.run"),
  reputationStatus: () => rpc<ReputationStatus>("reputation.status"),
  appReputation: (app: number) => rpc<AppReputation>("reputation.app", { app }),
  /** `key` null removes it. */
  setKey: (service: "virus_total" | "abuse_ch", key: string | null) =>
    change<ReputationStatus>("reputation.set_key", { service, key }),
  checkNow: (app: number) => change<AppReputation>("reputation.check", { app }),
  avScan: (app: number) => change<AppReputation>("reputation.scan", { app }),
  /** Only after the user agreed the file becomes visible to VirusTotal's community. */
  vtUpload: (app: number) => change<{ link: string }>("reputation.upload", { app, confirm: true }),
  dnsFilter: () => rpc<DnsFilterStatus>("dnsfilter.status"),
  dnsUpdate: () => change<DnsFilterStatus>("dnsfilter.update"),
  /** `minutes` null resumes. */
  dnsPause: (minutes: number | null) => change<DnsFilterStatus>("dnsfilter.pause", { minutes }),
  dnsFilterLog: (after = 0, limit = 500) =>
    rpc<{ entries: DnsFilterLogEntry[] }>("dnsfilter.log", { after, limit }),
  /** Whether the app starts at sign-in (in the tray). */
  autostart: () => invoke<boolean>("autostart_get"),
  setAutostart: (enabled: boolean) => invoke<boolean>("autostart_set", { enabled }),
  miniToggle: () => invoke<boolean>("mini_toggle"),
  miniPrefs: () => invoke<MiniPrefs>("mini_prefs"),
  miniSetOpacity: (percent: number) => invoke<MiniPrefs>("mini_set_opacity", { percent }),
  about: () => invoke<AboutInfo>("about_info"),
  /** VirusTotal, MalwareBazaar, abuse.ch and blocklist pages, and About's credits, only. */
  openLink: (url: string) => invoke<void>("open_link", { url }),
  /** Always through the elevated helper: the setting needs elevation, on or off. */
  setRequireElevation: (on: boolean) =>
    invoke<FirewallStatus>("rpc_elevated", { method: "settings.require_elevation", params: { on } }),
};

/** What snoozing an alert silences: its app, or its kind. */
export function snoozeKey(a: Alert): string {
  return a.app ? `app:${a.app.id}` : `kind:${a.kind}`;
}

/** A service error as a sentence, without the transport's prefix. */
export function errorText(e: unknown): string {
  return String(e)
    .replace(/^service error:\s*/i, "")
    .replace(/\s*\(code -?\d+\)$/, "");
}

const iconCache = new Map<string, Promise<string | null>>();

/** The executable's icon as a data URL, or null. Each path is fetched once. */
export function appIcon(path: string): Promise<string | null> {
  let hit = iconCache.get(path);
  if (!hit) {
    hit = invoke<string | null>("app_icon", { path }).catch(() => null);
    iconCache.set(path, hit);
  }
  return hit;
}

const productCache = new Map<string, Promise<string | null>>();

/** The product an executable is part of, from its file (its ProductName);
 *  null if it doesn't say. Each path is read once. */
export function appProduct(path: string): Promise<string | null> {
  let hit = productCache.get(path);
  if (!hit) {
    hit = invoke<string | null>("app_product", { path }).catch(() => null);
    productCache.set(path, hit);
  }
  return hit;
}

export const events = {
  onSamples: (cb: (samples: Sample[]) => void): Promise<UnlistenFn> =>
    listen<{ samples: Sample[] }>("w4://samples", (e) => cb(e.payload.samples)),
  onConnection: (cb: (state: ConnectionState) => void): Promise<UnlistenFn> =>
    listen<ConnectionState>("w4://connection", (e) => cb(e.payload)),
  /** New alerts, and the unread count after them. */
  onPrompts: (cb: (prompts: Prompt[]) => void): Promise<UnlistenFn> =>
    listen<{ prompts: Prompt[] }>("w4://prompts", (e) => cb(e.payload.prompts)),
  onAlerts: (cb: (alerts: Alert[], unread: number) => void): Promise<UnlistenFn> =>
    listen<{ alerts: Alert[]; unread: number }>("w4://alerts", (e) =>
      cb(e.payload.alerts, e.payload.unread),
    ),
  /** The card's new apps changed. */
  onNotices: (cb: (notices: Alert[]) => void): Promise<UnlistenFn> =>
    listen<Alert[]>("w4://notices", (e) => cb(e.payload)),
};
