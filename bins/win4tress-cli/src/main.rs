//! `win4tress` command-line client. Talks to the service over the pipe; no admin needed.

mod format;

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;
use w4_core::firewall::{Action, Direction, Expiry, Mode, NetworkCategory, RuleId, Scope};
use w4_core::time::now_unix_ms;
use w4_ipc::api::{
    AlertsParams, AlertsResult, AppsResult, BlockAllParams, BlocksParams, BlocksResult,
    ConnectionState, ConnectionsParams, ConnectionsResult, DnsLogParams, DnsLogResult,
    DnsTopParams, DnsTopResult, FirewallStatus, HostsParams, HostsResult, KeepChangesParams,
    KeepChangesResult, MarkReadParams, MarkReadResult, RequireElevationParams, ResetResult, Rule,
    RuleDeleteParams, RuleSetParams, RulesResult, SamplesNotification, SetModeParams, Status,
    TurnOnParams, VerdictsResult, method, notification,
};
use w4_ipc::api::{
    AppParams, AppReputation, CleanupReason, CleanupResult, KeyService, ProfileParams,
    ProfilesResult, RepVerdict, Reputation, ReputationStatus, SetKeyParams, UploadParams,
    UploadResult,
};
use w4_ipc::api::{
    CloseParams, CloseResult, ImportParams, ImportResult, Lasts, NetworkMatch, NetworksResult,
    RulesExport, SetNetworksParams,
};
use w4_ipc::api::{
    DataPlan, DecideParams, DecideResult, Decision, DecisionScope, KnownApp, KnownAppsResult,
    PlanStatus, PromptState, PromptsResult, RuleChange, RulesApplyParams, RulesApplyResult,
    Settings,
};
use w4_ipc::api::{DevicesResult, MonitorSetting, MonitorsResult, SetKnownParams, Severity};
use w4_ipc::api::{
    DnsFilterLogParams, DnsFilterLogResult, DnsFilterState, DnsFilterStatus, DnsPauseParams,
    DnsUpstream,
};
use w4_ipc::{Client, ClientError, RpcError};

use format::{
    ago, alert_text, clock, date_time, dns_status, dns_type, duration, human, rate, truncate,
    verdict_text,
};

#[derive(Parser)]
#[command(name = "win4tress", version, about = "win4tress command-line client")]
struct Cli {
    /// Service pipe (for talking to a `win4tress-svc console --pipe ...` instance)
    #[arg(long, global = true, default_value = w4_ipc::PIPE_NAME)]
    pipe: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Service and collector health, totals since the service started
    Status {
        /// Machine-readable output (used by tools/dev/soak.ps1)
        #[arg(long)]
        json: bool,
    },
    /// Apps that used the network, busiest first
    Apps {
        /// Show at most this many
        #[arg(long, default_value_t = 25)]
        top: usize,
    },
    /// Hosts an app talked to
    Hosts {
        /// App ID (from `apps`) or part of its name
        app: String,
    },
    /// Live traffic, one line per second (Ctrl+C to stop)
    Watch,
    /// Open and recently closed connections, most recent first
    Connections {
        /// Only this app: ID or part of its name
        #[arg(long)]
        app: Option<String>,
        #[arg(long, default_value_t = 40)]
        top: usize,
    },
    /// Recent DNS lookups by app, newest first
    Dns {
        /// Only this app: ID or part of its name
        #[arg(long)]
        app: Option<String>,
        /// Only names containing this text
        #[arg(long)]
        search: Option<String>,
        #[arg(long, default_value_t = 40)]
        limit: u32,
        /// Most-queried names over the last 24 hours instead
        #[arg(long)]
        top: bool,
    },
    /// Alerts, newest first
    Alerts {
        /// Only unread ones
        #[arg(long)]
        unread: bool,
        #[arg(long, default_value_t = 40)]
        limit: u32,
        /// Mark every alert read afterwards
        #[arg(long)]
        mark_read: bool,
    },
    /// Windows Firewall state and win4tress's rules
    Firewall,
    /// Block an app from the network (needs a member of Administrators)
    Block {
        /// App ID (from `apps`) or part of its name
        app: String,
        /// Block incoming connections instead of outgoing
        #[arg(long)]
        inbound: bool,
        #[command(flatten)]
        scope: ScopeArgs,
        /// Only for a while: 30m, 2h, 1d, quit (until the app quits) or
        /// restart (until Windows restarts); then it goes back to what it was
        #[arg(long = "for", value_name = "HOW_LONG", value_parser = parse_lasts)]
        lasts: Option<Lasts>,
    },
    /// Allow an app, replacing a block rule (needs a member of Administrators)
    Allow {
        /// App ID (from `apps`) or part of its name
        app: String,
        /// Allow incoming connections instead of outgoing
        #[arg(long)]
        inbound: bool,
        /// Only these hosts (comma-separated addresses, ranges, networks or names)
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Only for a while: 30m, 2h, 1d, quit (until the app quits) or
        /// restart (until Windows restarts); then it goes back to what it was
        #[arg(long = "for", value_name = "HOW_LONG", value_parser = parse_lasts, conflicts_with = "hosts")]
        lasts: Option<Lasts>,
    },
    /// End an app's open TCP connections now, e.g. after blocking it (needs a
    /// member of Administrators). Windows can only end IPv4 ones
    Disconnect {
        /// App ID (from `apps`) or part of its name
        app: String,
    },
    /// Save every rule and profile, and DNS filtering's settings, to a file, to
    /// set up another PC the same way
    Export {
        /// The file to write; "-" for the terminal
        file: std::path::PathBuf,
    },
    /// Add the rules and profiles from an exported file (needs a member of
    /// Administrators). Rules for the same app and kind are replaced; the mode
    /// stays as it is
    Import {
        file: std::path::PathBuf,
        /// Only show what would change
        #[arg(long)]
        dry_run: bool,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// The networks Windows knows, and the profile each switches to
    Networks,
    /// Block every connection, both ways, except this PC's own (needs a member
    /// of Administrators). Remote Desktop sessions are cut off too
    BlockAll {
        /// For this many minutes; without it, until `block-all --off`
        #[arg(long)]
        minutes: Option<u32>,
        /// Turn Block All off
        #[arg(long, conflicts_with = "minutes")]
        off: bool,
        /// Don't ask for confirmation over Remote Desktop
        #[arg(long)]
        yes: bool,
    },
    /// Turn Windows Firewall on where it's off (needs a member of Administrators)
    FirewallOn {
        /// domain, private or public; without it, every profile where it's off
        profile: Option<String>,
    },
    /// Connections that were blocked, and what blocked them
    Blocked {
        /// Only this app: ID or part of its name
        #[arg(long)]
        app: Option<String>,
        /// From history, this many days back (otherwise since the service started)
        #[arg(long)]
        days: Option<u32>,
        #[arg(long, default_value_t = 40)]
        limit: u32,
    },
    /// Require an elevated caller for every change (run from an elevated prompt)
    RequireElevation { setting: OnOff },
    /// Calls one service method and writes the JSON result to a file: the app's
    /// elevated helper for "Require elevation"
    #[command(hide = true)]
    Rpc {
        method: String,
        /// The parameters as base64 of JSON (on the command line, so the request
        /// that's elevated can't be swapped)
        #[arg(long)]
        params: String,
        #[arg(long)]
        result: Option<std::path::PathBuf>,
    },
    /// Delete a rule by its ID, from `firewall` (needs a member of Administrators)
    DeleteRule { id: RuleId },
    /// Switch a rule off or back on without deleting it, by its ID from
    /// `firewall`; profiles remember which rules are on (needs a member of
    /// Administrators)
    Rule { id: RuleId, setting: OnOff },
    /// Why an app's incoming and outgoing connections are allowed or blocked
    Why {
        /// App ID (from `apps`) or part of its name
        app: String,
    },
    /// Show or set the firewall mode. "off" keeps win4tress's rules but switches
    /// them off; "ask-to-connect" blocks outgoing connections without a rule and
    /// asks (setting it needs a member of Administrators)
    Mode {
        mode: Option<ModeArg>,
        /// With ask-to-connect: first allow the apps that used the network in
        /// the last 7 days and have no rule, so they keep working
        #[arg(long)]
        allow_recent: bool,
    },
    /// Connections waiting for a decision in Ask to Connect
    Prompts,
    /// Show the data plan, or set it (setting needs a member of Administrators)
    Plan {
        /// Limit a month, in GB (decimal: 1 GB = 1,000,000,000 bytes)
        #[arg(long)]
        limit_gb: Option<f64>,
        /// Day of the month a period starts, 1 to 28 (default 1)
        #[arg(long)]
        reset_day: Option<u8>,
        /// Count only traffic while on a metered connection
        #[arg(long)]
        metered_only: bool,
        /// Remove the data plan
        #[arg(long, conflicts_with = "limit_gb")]
        off: bool,
    },
    /// Leave known VPN clients out of traffic totals (needs a member of Administrators)
    ExcludeVpn { setting: OnOff },
    /// Answer a prompt from `prompts` (needs a member of Administrators)
    Decide {
        /// The prompt's ID
        id: u64,
        decision: DecisionArg,
        /// Only the prompt's host, not every connection of the app
        #[arg(long)]
        host: bool,
        /// Only for a while: 30m, 2h, 1d, quit or restart
        #[arg(long = "for", value_name = "HOW_LONG", value_parser = parse_lasts, conflicts_with = "host")]
        lasts: Option<Lasts>,
    },
    /// The security monitors and the threat lists; with options, change what
    /// applies to all of them (needs a member of Administrators)
    Monitors {
        /// Copy alerts to the Windows Event Log (Application, source "win4tress")
        #[arg(long)]
        event_log: Option<OnOff>,
        /// Download abuse.ch's threat list daily (not on metered connections)
        #[arg(long)]
        threat_feeds: Option<OnOff>,
    },
    /// Turn a security monitor on or off, or change its alerts' severity
    /// (needs a member of Administrators)
    Monitor {
        /// The monitor's alert kind, from `monitors`, e.g. arp_spoofing
        kind: String,
        setting: Option<OnOff>,
        /// Its alerts get this severity instead of their own
        #[arg(long)]
        severity: Option<SeverityArg>,
    },
    /// Devices on the local network, as the scanner saw them
    Devices {
        /// Mark the device with this hardware address known (needs a member
        /// of Administrators)
        #[arg(long, value_name = "MAC", conflicts_with = "unknown")]
        known: Option<String>,
        /// Mark it unknown again
        #[arg(long, value_name = "MAC")]
        unknown: Option<String>,
    },
    /// Scan the local network now and list what answered (needs a member of
    /// Administrators). Only private networks with a gateway are scanned
    Scan,
    /// Scan the local network every half hour and alert on new devices (needs
    /// a member of Administrators)
    Scanner { setting: OnOff },
    /// Firewall profiles: list them, save the mode, which rules are on and DNS
    /// filtering as one, switch to one or delete one (changes need a member of
    /// Administrators)
    Profile {
        #[command(subcommand)]
        action: Option<ProfileAction>,
    },
    /// Keep traffic out of history, for every app or one (needs a member of
    /// Administrators). Blocking and alerts carry on
    Incognito {
        setting: OnOff,
        /// Only this app: ID or part of its name
        #[arg(long)]
        app: Option<String>,
    },
    /// Rules of uninstalled (and, if set, inactive) apps: what's due, and
    /// settings (changes need a member of Administrators)
    Cleanup {
        /// Remove what's due now
        #[arg(long)]
        run: bool,
        /// Remove rules of apps whose program has been gone 7 days
        #[arg(long)]
        uninstalled: Option<OnOff>,
        /// Remove rules of apps inactive this many days (0 turns it off)
        #[arg(long)]
        inactive_days: Option<u32>,
    },
    /// Hash reputation lookups (CIRCL, VirusTotal, MalwareBazaar): state and
    /// settings (changes need a member of Administrators). Off by default: it
    /// sends apps' file hashes out
    Reputation {
        #[arg(long)]
        lookups: Option<OnOff>,
        /// Your VirusTotal API key (free account); "-" removes it
        #[arg(long)]
        virustotal_key: Option<String>,
        /// Your abuse.ch Auth-Key, for MalwareBazaar; "-" removes it
        #[arg(long)]
        abuse_ch_key: Option<String>,
        #[arg(long)]
        malwarebazaar: Option<OnOff>,
        /// Alert when this many engines flag a file
        #[arg(long)]
        alert_at: Option<u32>,
        /// Block apps whose file this many engines flag (with --auto-block on)
        #[arg(long)]
        block_at: Option<u32>,
        #[arg(long)]
        auto_block: Option<OnOff>,
    },
    /// What's known about an app's file; --now looks it up ahead of the queue
    Lookup {
        /// App ID or part of its name
        app: String,
        #[arg(long)]
        now: bool,
    },
    /// Scan an app's file with the installed antivirus (needs a member of Administrators)
    AvScan {
        /// App ID or part of its name
        app: String,
    },
    /// Upload an app's file to VirusTotal (needs your key). The file becomes
    /// visible to VirusTotal's community
    VtUpload {
        /// App ID or part of its name
        app: String,
        /// Upload without asking
        #[arg(long)]
        yes: bool,
    },
    /// DNS filtering: its state, or turn it on or off (needs a member of
    /// Administrators). On, Windows' lookups go through win4tress's resolver
    DnsFilter { setting: Option<OnOff> },
    /// The blocklists you can choose; add or remove one by its id, or
    /// download the chosen ones now (changes need a member of Administrators)
    DnsLists {
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        remove: Option<String>,
        #[arg(long)]
        update: bool,
    },
    /// Always allow (or with --remove, stop allowing) a domain and its subdomains
    DnsAllow {
        name: String,
        #[arg(long)]
        remove: bool,
    },
    /// Always block (or with --remove, stop blocking) a domain and its subdomains
    DnsDeny {
        name: String,
        #[arg(long)]
        remove: bool,
    },
    /// Pause blocking for some minutes; --resume ends a pause
    DnsPause {
        minutes: Option<u32>,
        #[arg(long, conflicts_with = "minutes")]
        resume: bool,
    },
    /// Where lookups go: system (your network's DNS), cloudflare, quad9,
    /// google, or an https:// DNS-over-HTTPS address
    DnsUpstream { upstream: String },
    /// The resolver's recent lookups and what blocked them
    DnsLog {
        /// Only blocked ones
        #[arg(long)]
        blocked: bool,
        #[arg(long, default_value_t = 40)]
        limit: u32,
    },
    /// Keep the changes a "firewall changed" alert reported, instead of the rules
    /// win4tress put back (needs a member of Administrators)
    KeepChanges {
        /// The alert's ID, shown by `alerts`
        alert: i64,
    },
    /// Delete every win4tress rule, remove them from Windows Firewall and switch
    /// back to Click to Block. Needs an elevated prompt; works with the service
    /// stopped, too
    Reset {
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ModeArg {
    Off,
    ClickToBlock,
    AskToConnect,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum DecisionArg {
    Allow,
    Block,
    /// Keep it blocked and decide later
    Later,
}

#[derive(Subcommand)]
enum ProfileAction {
    /// The profiles, and which is active
    List,
    /// Save the mode, which rules are on and DNS filtering's settings now as NAME
    Save {
        name: String,
    },
    /// Switch to NAME
    Switch {
        name: String,
    },
    Delete {
        name: String,
    },
    /// Show or set the networks NAME is switched to on, by itself: "current"
    /// (the networks connected now), public, private, domain, or a network's
    /// name or id from `networks`
    Networks {
        name: String,
        networks: Vec<String>,
        /// Switch it by hand only
        #[arg(long, conflicts_with = "networks")]
        clear: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SeverityArg {
    Info,
    Warning,
    Critical,
    /// The alert's own
    Default,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OnOff {
    On,
    Off,
}

/// What a block rule covers; without any of these, every connection.
#[derive(clap::Args)]
#[group(multiple = false)]
struct ScopeArgs {
    /// Only these hosts (comma-separated addresses, ranges, networks or names;
    /// `*.example.com` includes subdomains)
    #[arg(long, value_delimiter = ',')]
    hosts: Vec<String>,
    /// Everything except these hosts ("allow only these hosts")
    #[arg(long, value_delimiter = ',')]
    allow_only: Vec<String>,
    /// The app's own DNS: ports 53 and 853, and DNS-over-HTTPS servers
    #[arg(long)]
    own_dns: bool,
}

impl ScopeArgs {
    fn scope(self) -> Scope {
        if !self.hosts.is_empty() {
            Scope::Hosts { hosts: self.hosts }
        } else if !self.allow_only.is_empty() {
            Scope::Except {
                hosts: self.allow_only,
            }
        } else if self.own_dns {
            Scope::Dns
        } else {
            Scope::Any
        }
    }
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Mode {
        match m {
            ModeArg::Off => Mode::Off,
            ModeArg::ClickToBlock => Mode::ClickToBlock,
            ModeArg::AskToConnect => Mode::AskToConnect,
        }
    }
}

/// "30m", "2h", "1d", "quit", "restart" (or a number of minutes).
fn parse_lasts(s: &str) -> std::result::Result<Lasts, String> {
    let s = s.trim().to_ascii_lowercase();
    match s.as_str() {
        "quit" | "app-quits" | "until-quit" => return Ok(Lasts::AppQuits),
        "restart" | "reboot" => return Ok(Lasts::Restart),
        _ => {}
    }
    let (number, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u32 = number
        .parse()
        .map_err(|_| "30m, 2h, 1d, quit or restart".to_string())?;
    let minutes = match unit {
        "" | "m" | "min" => n,
        "h" => n.saturating_mul(60),
        "d" => n.saturating_mul(24 * 60),
        _ => return Err("30m, 2h, 1d, quit or restart".into()),
    };
    if minutes == 0 || minutes > w4_ipc::api::MAX_RULE_MINUTES {
        return Err("from 1 minute to 30 days".into());
    }
    Ok(Lasts::Minutes { minutes })
}

/// "until 15:30 on 29 Oct", "until it quits", "until Windows restarts".
fn until_text(e: &Expiry) -> String {
    match e {
        Expiry::At { ms } => format!("until {}", date_time(*ms)),
        Expiry::AppQuits => "until it quits".into(),
        Expiry::Restart { .. } => "until Windows restarts".into(),
    }
}

fn category_name(c: NetworkCategory) -> &'static str {
    match c {
        NetworkCategory::Public => "public",
        NetworkCategory::Private => "private",
        NetworkCategory::Domain => "domain",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "Off",
        Mode::ClickToBlock => "Click to Block",
        Mode::AskToConnect => "Ask to Connect",
    }
}

/// A change refused for lack of rights, with what to do about it.
fn refused<T>(result: Result<T, ClientError>, hint: &str) -> Result<T> {
    match result {
        Err(ClientError::Rpc(e)) if e.code == RpcError::FORBIDDEN => {
            bail!("{} ({hint})", e.message)
        }
        Err(ClientError::Rpc(e)) if e.code == RpcError::ELEVATION_REQUIRED => {
            bail!("{} (open the prompt with Run as administrator)", e.message)
        }
        other => Ok(other?),
    }
}

const NOT_ADMIN: &str = "you're not a member of Administrators";
const NOT_ELEVATED: &str = "open the prompt with Run as administrator";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Reset also works without the service.
    if let Command::Reset { yes } = cli.command {
        return reset(&cli.pipe, yes).await;
    }
    if let Command::Rpc {
        method,
        params,
        result,
    } = &cli.command
    {
        return rpc(&cli.pipe, method, params, result.as_deref()).await;
    }
    let client = Client::connect(&cli.pipe).await?;
    client.hello("win4tress-cli").await?;

    match cli.command {
        Command::Status { json } => status(&client, json).await,
        Command::Apps { top } => apps(&client, top).await,
        Command::Hosts { app } => hosts(&client, &app).await,
        Command::Watch => watch(&client).await,
        Command::Connections { app, top } => connections(&client, app.as_deref(), top).await,
        Command::Dns {
            app,
            search,
            limit,
            top,
        } => dns(&client, app.as_deref(), search, limit, top).await,
        Command::Alerts {
            unread,
            limit,
            mark_read,
        } => alerts(&client, unread, limit, mark_read).await,
        Command::Firewall => firewall(&client).await,
        Command::Block {
            app,
            inbound,
            scope,
            lasts,
        } => set_rule(&client, &app, inbound, Action::Block, scope.scope(), lasts).await,
        Command::Allow {
            app,
            inbound,
            hosts,
            lasts,
        } => {
            let scope = if hosts.is_empty() {
                Scope::Any
            } else {
                Scope::Hosts { hosts }
            };
            set_rule(&client, &app, inbound, Action::Allow, scope, lasts).await
        }
        Command::Disconnect { app } => {
            let id = find_app(&client, &app).await?;
            let r: CloseResult = refused(
                client
                    .call(
                        method::CONNECTIONS_CLOSE,
                        CloseParams {
                            app: Some(id),
                            connections: Vec::new(),
                        },
                    )
                    .await,
                NOT_ADMIN,
            )?;
            println!(
                "Ended {} connection(s).{}",
                r.closed,
                if r.not_closable > 0 {
                    format!(
                        " {} IPv6 connection(s) stay open: Windows can only end IPv4 ones.",
                        r.not_closable
                    )
                } else {
                    String::new()
                }
            );
            if let Some(e) = r.error {
                println!("Some couldn't be ended: {e}");
            }
            Ok(())
        }
        Command::Export { file } => export(&client, &file).await,
        Command::Import { file, dry_run, yes } => import(&client, &file, dry_run, yes).await,
        Command::Networks => networks(&client).await,
        Command::BlockAll { minutes, off, yes } => block_all(&client, minutes, off, yes).await,
        Command::FirewallOn { profile } => {
            let r: Value = refused(
                client
                    .call(method::FIREWALL_TURN_ON, TurnOnParams { profile })
                    .await,
                NOT_ADMIN,
            )?;
            let on: Vec<String> = r["turned_on"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if on.is_empty() {
                println!("Windows Firewall was already on.");
            } else {
                println!("Turned Windows Firewall on for: {}.", on.join(", "));
            }
            Ok(())
        }
        Command::Blocked { app, days, limit } => {
            blocked(&client, app.as_deref(), days, limit).await
        }
        Command::RequireElevation { setting } => {
            let s: FirewallStatus = refused(
                client
                    .call(
                        method::SETTINGS_REQUIRE_ELEVATION,
                        RequireElevationParams {
                            on: setting == OnOff::On,
                        },
                    )
                    .await,
                NOT_ELEVATED,
            )?;
            println!(
                "Changes {} an elevated caller.",
                if s.require_elevation {
                    "now need"
                } else {
                    "no longer need"
                }
            );
            Ok(())
        }
        Command::Rpc { .. } => unreachable!("handled above"),
        Command::DeleteRule { id } => {
            let _: Value = refused(
                client
                    .call(method::RULES_DELETE, RuleDeleteParams { id })
                    .await,
                NOT_ADMIN,
            )?;
            println!("Deleted rule {id}. It's removed from Windows Firewall right away.");
            Ok(())
        }
        Command::Rule { id, setting } => {
            let r: Rule = refused(
                client
                    .call(
                        method::RULES_ENABLE,
                        w4_ipc::api::RuleEnableParams {
                            id,
                            enabled: setting == OnOff::On,
                        },
                    )
                    .await,
                NOT_ADMIN,
            )?;
            println!(
                "Rule {} ({}) is {}.",
                r.id,
                r.app.name,
                if r.enabled { "on" } else { "off" }
            );
            Ok(())
        }
        Command::Mode { mode, allow_recent } => set_mode(&client, mode, allow_recent).await,
        Command::Prompts => prompts(&client).await,
        Command::Monitors {
            event_log,
            threat_feeds,
        } => monitors(&client, event_log, threat_feeds).await,
        Command::Monitor {
            kind,
            setting,
            severity,
        } => monitor(&client, &kind, setting, severity).await,
        Command::Devices { known, unknown } => {
            if let Some((mac, known)) = known.map(|m| (m, true)).or(unknown.map(|m| (m, false))) {
                let mac = mac.to_ascii_lowercase().replace(':', "-");
                let _: DevicesResult = refused(
                    client
                        .call(method::DEVICES_SET_KNOWN, SetKnownParams { mac, known })
                        .await,
                    NOT_ADMIN,
                )?;
            }
            let r: DevicesResult = client.call(method::DEVICES, Value::Null).await?;
            print_devices(&r);
            Ok(())
        }
        Command::Scan => scan(&client).await,
        Command::Profile { action } => profile(&client, action).await,
        Command::DnsFilter { setting } => {
            if let Some(on) = setting {
                change_dns(&client, |d| d.enabled = on == OnOff::On).await?;
            }
            dns_filter_status(&client).await
        }
        Command::DnsLists {
            add,
            remove,
            update,
        } => {
            if add.is_some() || remove.is_some() {
                change_dns(&client, |d| {
                    if let Some(id) = &add
                        && !d.lists.contains(id)
                    {
                        d.lists.push(id.clone());
                    }
                    if let Some(id) = &remove {
                        d.lists.retain(|l| l != id);
                    }
                })
                .await?;
            }
            if update {
                let _: DnsFilterStatus = refused(
                    client.call(method::DNS_FILTER_UPDATE, Value::Null).await,
                    NOT_ADMIN,
                )?;
                println!("Downloading the chosen lists now.");
            }
            dns_lists(&client).await
        }
        Command::DnsAllow { name, remove } => {
            change_dns(&client, |d| {
                d.allow.retain(|n| !n.eq_ignore_ascii_case(&name));
                if !remove {
                    d.allow.push(name.to_ascii_lowercase());
                }
            })
            .await?;
            println!(
                "{name} is {}.",
                if remove {
                    "no longer always allowed"
                } else {
                    "always allowed, with its subdomains"
                }
            );
            Ok(())
        }
        Command::DnsDeny { name, remove } => {
            change_dns(&client, |d| {
                d.deny.retain(|n| !n.eq_ignore_ascii_case(&name));
                if !remove {
                    d.deny.push(name.to_ascii_lowercase());
                }
            })
            .await?;
            println!(
                "{name} is {}.",
                if remove {
                    "no longer always blocked"
                } else {
                    "always blocked, with its subdomains"
                }
            );
            Ok(())
        }
        Command::DnsPause { minutes, resume } => {
            let minutes = if resume {
                None
            } else {
                Some(minutes.unwrap_or(15))
            };
            let s: DnsFilterStatus = refused(
                client
                    .call(method::DNS_FILTER_PAUSE, DnsPauseParams { minutes })
                    .await,
                NOT_ADMIN,
            )?;
            match s.paused_until_ms {
                Some(t) => println!("Blocking paused until {}.", date_time(t)),
                None => println!("Blocking resumed."),
            }
            Ok(())
        }
        Command::DnsUpstream { upstream } => {
            let chosen = match upstream.to_ascii_lowercase().as_str() {
                "system" => DnsUpstream::System,
                "cloudflare" => DnsUpstream::Doh {
                    url: "https://cloudflare-dns.com/dns-query".into(),
                },
                "quad9" => DnsUpstream::Doh {
                    url: "https://dns.quad9.net/dns-query".into(),
                },
                "google" => DnsUpstream::Doh {
                    url: "https://dns.google/dns-query".into(),
                },
                url if url.starts_with("https://") => DnsUpstream::Doh {
                    url: upstream.clone(),
                },
                _ => bail!("system, cloudflare, quad9, google, or an https:// address"),
            };
            change_dns(&client, |d| d.upstream = chosen.clone()).await?;
            dns_filter_status(&client).await
        }
        Command::DnsLog { blocked, limit } => {
            let r: DnsFilterLogResult = client
                .call(
                    method::DNS_FILTER_LOG,
                    DnsFilterLogParams {
                        after: 0,
                        limit: Some(5_000),
                    },
                )
                .await?;
            let mut shown: Vec<_> = r
                .entries
                .iter()
                .filter(|e| !blocked || e.outcome == "blocked")
                .collect();
            let skip = shown.len().saturating_sub(limit as usize);
            shown.drain(..skip);
            if shown.is_empty() {
                println!("No lookups yet{}.", if blocked { " blocked" } else { "" });
            }
            for e in shown {
                println!(
                    "{}  {:<10} {:<44} {}",
                    clock(e.ts_ms / 1000),
                    e.outcome,
                    truncate(&e.name, 44),
                    e.reason.as_deref().unwrap_or("")
                );
            }
            Ok(())
        }
        Command::Incognito { setting, app } => incognito(&client, setting, app).await,
        Command::Cleanup {
            run,
            uninstalled,
            inactive_days,
        } => cleanup(&client, run, uninstalled, inactive_days).await,
        Command::Reputation {
            lookups,
            virustotal_key,
            abuse_ch_key,
            malwarebazaar,
            alert_at,
            block_at,
            auto_block,
        } => {
            reputation(
                &client,
                lookups,
                virustotal_key,
                abuse_ch_key,
                malwarebazaar,
                (alert_at, block_at, auto_block),
            )
            .await
        }
        Command::Lookup { app, now } => lookup(&client, &app, now).await,
        Command::AvScan { app } => {
            let id = find_known_app(&client, &app).await?;
            println!("Scanning…");
            let r: AppReputation = refused(
                client
                    .call(method::REPUTATION_SCAN, AppParams { app: id })
                    .await,
                NOT_ADMIN,
            )?;
            print_reputation(&r);
            Ok(())
        }
        Command::VtUpload { app, yes } => {
            let id = find_known_app(&client, &app).await?;
            if !yes {
                bail!(
                    "uploading makes the file visible to VirusTotal's community, including companies \
                     that pay for access. Add --yes to upload"
                );
            }
            let r: UploadResult = refused(
                client
                    .call(
                        method::REPUTATION_UPLOAD,
                        UploadParams {
                            app: id,
                            confirm: true,
                        },
                    )
                    .await,
                NOT_ADMIN,
            )?;
            println!("Uploaded. The analysis takes a few minutes: {}", r.link);
            println!("win4tress fetches the result; see it with: win4tress lookup {id}");
            Ok(())
        }
        Command::Scanner { setting } => {
            let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
            settings.scanner = setting == OnOff::On;
            let _: Settings =
                refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
            println!(
                "{}",
                if setting == OnOff::On {
                    "The local network is scanned every half hour; new devices raise an alert after the first scan."
                } else {
                    "No automatic scans. Scan when you like with: win4tress scan"
                }
            );
            Ok(())
        }
        Command::Plan {
            limit_gb,
            reset_day,
            metered_only,
            off,
        } => plan(&client, limit_gb, reset_day, metered_only, off).await,
        Command::ExcludeVpn { setting } => {
            let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
            settings.exclude_vpn = setting == OnOff::On;
            let _: Settings =
                refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
            println!(
                "VPN clients are {} traffic totals.",
                if setting == OnOff::On {
                    "left out of"
                } else {
                    "counted in"
                }
            );
            Ok(())
        }
        Command::Decide {
            id,
            decision,
            host,
            lasts,
        } => decide(&client, id, decision, host, lasts).await,
        Command::Why { app } => why(&client, &app).await,
        Command::KeepChanges { alert } => {
            let r: KeepChangesResult = refused(
                client
                    .call(method::FIREWALL_KEEP_CHANGES, KeepChangesParams { alert })
                    .await,
                NOT_ADMIN,
            )?;
            println!(
                "Kept {} change(s){}. Windows Firewall is updated right away.",
                r.kept,
                if r.skipped > 0 {
                    format!(
                        "; {} couldn't be kept (not keepable, or changed in win4tress since)",
                        r.skipped
                    )
                } else {
                    String::new()
                }
            );
            Ok(())
        }
        Command::Reset { .. } => unreachable!("handled above"),
    }
}

async fn why(client: &Client, query: &str) -> Result<()> {
    let id = match query.parse::<u32>() {
        Ok(id) => id,
        Err(_) => find_app(client, query).await?,
    };
    // Every known app's: one blocked since the service started isn't active.
    let r: VerdictsResult = client
        .call(
            method::FIREWALL_VERDICTS,
            serde_json::json!({ "all": true }),
        )
        .await?;
    let Some(v) = r.apps.iter().find(|a| a.app == id) else {
        bail!("no answer for app {id}: it has no program a rule can name")
    };
    println!("Incoming: {}", verdict_text(&v.inbound, true));
    println!("Outgoing: {}", verdict_text(&v.outbound, false));
    Ok(())
}

/// Days of history "allow recent apps" looks at (SPEC §7.4 "Learning mode").
const RECENT_DAYS: i64 = 7;

/// Apps that used the network lately and have no outgoing rule for the whole
/// app: they'd be asked about once Ask to Connect is on.
async fn recent_without_rule(client: &Client) -> Result<Vec<KnownApp>> {
    let apps: KnownAppsResult = client.call(method::APPS_ALL, Value::Null).await?;
    let rules: RulesResult = client.call(method::RULES, Value::Null).await?;
    let verdicts: VerdictsResult = client
        .call(
            method::FIREWALL_VERDICTS,
            serde_json::json!({ "all": true }),
        )
        .await?;
    let since = now_unix_ms() - RECENT_DAYS * 24 * 3600 * 1000;
    Ok(apps
        .apps
        .into_iter()
        .filter(|a| a.net_first_seen_ms.is_some() && a.last_seen_ms >= since)
        .filter(|a| a.path == "System" || a.path.contains('\\'))
        .filter(|a| {
            !rules
                .rules
                .iter()
                .any(|r| r.app.id == a.id && r.direction == Direction::Out && r.scope == Scope::Any)
        })
        .filter(|a| !verdicts.apps.iter().any(|v| v.app == a.id && v.protected))
        .collect())
}

async fn set_mode(client: &Client, mode: Option<ModeArg>, allow_recent: bool) -> Result<()> {
    if mode == Some(ModeArg::AskToConnect) {
        let recent = recent_without_rule(client).await?;
        if allow_recent && !recent.is_empty() {
            let changes = recent
                .iter()
                .map(|a| {
                    RuleChange::Set(RuleSetParams {
                        app: a.id,
                        direction: Direction::Out,
                        action: Action::Allow,
                        scope: Scope::Any,
                        note: Some("Allowed when Ask to Connect was turned on".into()),
                        lasts: None,
                    })
                })
                .collect();
            let r: RulesApplyResult = refused(
                client
                    .call(method::RULES_APPLY, RulesApplyParams { changes })
                    .await,
                NOT_ADMIN,
            )?;
            println!(
                "Allowed {} app(s) that used the network in the last {RECENT_DAYS} days.",
                r.applied
            );
            for f in &r.failed {
                println!("  not allowed: {f}");
            }
        } else if !recent.is_empty() {
            println!(
                "{} app(s) used the network in the last {RECENT_DAYS} days and have no rule; they'll be asked about when they next connect (--allow-recent allows them first).",
                recent.len()
            );
        }
    }
    let status: FirewallStatus = match mode {
        None => client.call(method::FIREWALL, Value::Null).await?,
        Some(m) => refused(
            client
                .call(method::FIREWALL_SET_MODE, SetModeParams { mode: m.into() })
                .await,
            NOT_ADMIN,
        )?,
    };
    println!("Firewall mode: {}", mode_name(status.mode));
    match status.mode {
        Mode::Off => println!(
            "win4tress's rules are kept but switched off; Windows Firewall behaves as it did before."
        ),
        Mode::ClickToBlock => println!("Everything is allowed except the apps you block."),
        Mode::AskToConnect => println!(
            "Outgoing connections without a rule are blocked, and you're asked (win4tress prompts). Windows' own services and Microsoft-signed system programs are allowed."
        ),
    }
    Ok(())
}

async fn plan(
    client: &Client,
    limit_gb: Option<f64>,
    reset_day: Option<u8>,
    metered_only: bool,
    off: bool,
) -> Result<()> {
    if off || limit_gb.is_some() {
        let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
        settings.data_plan = match limit_gb {
            Some(gb) if !off => Some(DataPlan {
                limit_bytes: (gb * 1e9).round() as u64,
                reset_day: reset_day.unwrap_or(1),
                warn_at: vec![75, 90, 100],
                metered_only,
            }),
            _ => None,
        };
        let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    }
    let status: Option<PlanStatus> = client.call(method::PLAN_STATUS, Value::Null).await?;
    match status {
        None => {
            println!("No data plan. Set one with: win4tress plan --limit-gb 50 [--reset-day 15]")
        }
        Some(s) => {
            println!(
                "Data plan: {} of {} used ({:.0}%), {} to {}{}",
                human(s.used.total()),
                human(s.plan.limit_bytes),
                s.percent,
                date_time(s.period_start_ms),
                date_time(s.period_end_ms),
                if s.plan.metered_only {
                    "; metered connections only"
                } else {
                    ""
                }
            );
            if let Some(m) = s.metered {
                println!("This connection is {}metered.", if m { "" } else { "not " });
            }
        }
    }
    Ok(())
}

async fn monitors(
    client: &Client,
    event_log: Option<OnOff>,
    threat_feeds: Option<OnOff>,
) -> Result<()> {
    if event_log.is_some() || threat_feeds.is_some() {
        let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
        if let Some(v) = event_log {
            settings.event_log = v == OnOff::On;
        }
        if let Some(v) = threat_feeds {
            settings.threat_feeds = v == OnOff::On;
        }
        let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    }
    let r: MonitorsResult = client.call(method::MONITORS, Value::Null).await?;
    let settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    let severity = |s: Option<Severity>| match s {
        Some(Severity::Info) => "info",
        Some(Severity::Warning) => "warning",
        Some(Severity::Critical) => "critical",
        None => "varies",
    };
    println!("{:<24} {:<4} {:<9} What", "Kind", "On", "Severity");
    for m in &r.monitors {
        let shown = match m.severity {
            Some(s) => format!("{}*", severity(Some(s))),
            None => severity(m.default_severity).to_string(),
        };
        println!(
            "{:<24} {:<4} {:<9} {}",
            m.kind,
            if m.enabled { "on" } else { "off" },
            shown,
            m.description
        );
    }
    println!("(* chosen instead of the default)");
    println!();
    println!(
        "Event Log copies: {}",
        if settings.event_log { "on" } else { "off" }
    );
    let t = &r.threats;
    match (settings.threat_feeds, t.feodo_updated_ms, &t.feodo_error) {
        (false, ..) => println!("Threat list downloads: off"),
        (true, Some(at), _) => println!(
            "Feodo Tracker (abuse.ch): {} addresses, updated {}",
            t.feodo,
            date_time(at)
        ),
        (true, None, Some(e)) => println!("Feodo Tracker (abuse.ch): not downloaded: {e}"),
        (true, None, None) => println!("Feodo Tracker (abuse.ch): not downloaded yet"),
    }
    if let (Some(at), Some(e)) = (t.feodo_updated_ms, &t.feodo_error) {
        println!(
            "  last update failed ({e}); the list from {} is used",
            date_time(at)
        );
    }
    println!("Your own list: {} entries in {}", t.local, t.local_path);
    Ok(())
}

async fn monitor(
    client: &Client,
    kind: &str,
    setting: Option<OnOff>,
    severity: Option<SeverityArg>,
) -> Result<()> {
    let r: MonitorsResult = client.call(method::MONITORS, Value::Null).await?;
    let Some(m) = r.monitors.iter().find(|m| m.kind == kind) else {
        let kinds: Vec<_> = r.monitors.iter().map(|m| m.kind.as_str()).collect();
        bail!("no monitor {kind}; the monitors are: {}", kinds.join(", "));
    };
    let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    let entry = settings
        .monitors
        .entry(kind.to_string())
        .or_insert(MonitorSetting {
            enabled: m.enabled,
            severity: m.severity,
        });
    if let Some(s) = setting {
        entry.enabled = s == OnOff::On;
    }
    if let Some(s) = severity {
        entry.severity = match s {
            SeverityArg::Info => Some(Severity::Info),
            SeverityArg::Warning => Some(Severity::Warning),
            SeverityArg::Critical => Some(Severity::Critical),
            SeverityArg::Default => None,
        };
    }
    let enabled = entry.enabled;
    let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    println!("{} is {}.", m.label, if enabled { "on" } else { "off" });
    Ok(())
}

fn print_devices(r: &DevicesResult) {
    let networks = if r.networks.is_empty() {
        "none (no private network with a gateway)".to_string()
    } else {
        r.networks.join(", ")
    };
    let last = r
        .last_scan_ms
        .map_or("never".to_string(), |t| ago(now_unix_ms() - t));
    println!("Networks scanned: {networks}; last scan {last}");
    if r.devices.is_empty() {
        println!("No devices seen yet. Scan with: win4tress scan");
        return;
    }
    println!(
        "{:<15} {:<17} {:<26} {:<26} {:<7} Last seen",
        "Address", "Hardware", "Maker", "Name", "Known"
    );
    for d in &r.devices {
        let maker = match (&d.vendor, d.randomized) {
            (Some(v), _) => v.clone(),
            (None, true) => "(private address)".into(),
            (None, false) => "unknown".into(),
        };
        println!(
            "{:<15} {:<17} {:<26} {:<26} {:<7} {}",
            d.ip.to_string(),
            d.mac,
            truncate(&maker, 26),
            truncate(d.name.as_deref().unwrap_or(""), 26),
            if d.known { "yes" } else { "no" },
            ago(now_unix_ms() - d.last_seen_ms)
        );
    }
}

async fn scan(client: &Client) -> Result<()> {
    let mut r: DevicesResult = refused(
        client.call(method::DEVICES_SCAN, Value::Null).await,
        NOT_ADMIN,
    )?;
    if r.networks.is_empty() {
        bail!("there's no private network with a gateway to scan");
    }
    println!("Scanning {}…", r.networks.join(", "));
    let started = std::time::Instant::now();
    while r.scanning && started.elapsed() < std::time::Duration::from_secs(180) {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        r = client.call(method::DEVICES, Value::Null).await?;
    }
    print_devices(&r);
    Ok(())
}

/// Changes DNS filtering's settings (and nothing else).
async fn change_dns(client: &Client, f: impl FnOnce(&mut w4_ipc::api::DnsSettings)) -> Result<()> {
    let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    f(&mut settings.dns);
    let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    Ok(())
}

async fn dns_filter_status(client: &Client) -> Result<()> {
    let s: DnsFilterStatus = client.call(method::DNS_FILTER, Value::Null).await?;
    let state = match s.state {
        Some(DnsFilterState::Off) | None => "off",
        Some(DnsFilterState::Starting) => "starting",
        Some(DnsFilterState::On) => "on",
        Some(DnsFilterState::Passing) => "on, not blocking",
        Some(DnsFilterState::Failed) => "stopped (Windows' DNS put back)",
    };
    println!(
        "DNS filtering: {state}{}",
        s.message
            .as_deref()
            .map(|m| format!(": {m}"))
            .unwrap_or_default()
    );
    if s.state == Some(DnsFilterState::Off) || s.state.is_none() {
        println!("Turn it on with: win4tress dns-filter on   (lists: win4tress dns-lists)");
        return Ok(());
    }
    println!(
        "Routed through the resolver: {}. Upstream: {}{}.",
        if s.routed { "yes" } else { "no" },
        s.upstream,
        if s.system_servers.is_empty() {
            String::new()
        } else {
            format!(" ({})", s.system_servers.join(", "))
        }
    );
    println!(
        "{} domains on the chosen lists. Since the resolver started: {} lookups, {} blocked, {} from the cache.",
        s.blocked_domains, s.queries, s.blocked, s.cached
    );
    if let Some(t) = s.paused_until_ms {
        println!("Paused until {}.", date_time(t));
    }
    if let Some(account) = &s.resolver_account {
        println!("The resolver runs as {account}.");
    }
    if s.restores > 0 {
        println!(
            "The watchdog put Windows' DNS back {} times since the service started.",
            s.restores
        );
    }
    for p in &s.problems {
        println!("Problem: {p}");
    }
    if !s.top_blocked.is_empty() {
        println!("Most blocked:");
        for (name, n) in s.top_blocked.iter().take(10) {
            println!("  {n:>6}  {name}");
        }
    }
    Ok(())
}

async fn dns_lists(client: &Client) -> Result<()> {
    let s: DnsFilterStatus = client.call(method::DNS_FILTER, Value::Null).await?;
    println!(
        "{:<3} {:<20} {:<10} {:>9}  {:<17} About",
        "On", "Id", "Licence", "Entries", "Downloaded"
    );
    for l in &s.lists {
        println!(
            "{:<3} {:<20} {:<10} {:>9}  {:<17} {}{}",
            if l.enabled { "*" } else { "" },
            l.id,
            if l.custom {
                "(yours)"
            } else {
                l.licence.as_str()
            },
            l.entries.map(|n| n.to_string()).unwrap_or_default(),
            l.updated_ms
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
            l.description,
            l.error
                .as_deref()
                .map(|e| format!(" (last download failed: {e})"))
                .unwrap_or_default()
        );
    }
    println!(
        "Add or remove with: win4tress dns-lists --add <id> / --remove <id>. Lists are downloaded from their makers, never bundled."
    );
    Ok(())
}

async fn profile(client: &Client, action: Option<ProfileAction>) -> Result<()> {
    let r: ProfilesResult = match action {
        None | Some(ProfileAction::List) => client.call(method::PROFILES, Value::Null).await?,
        Some(ProfileAction::Save { name }) => refused(
            client
                .call(method::PROFILES_SAVE, ProfileParams { name })
                .await,
            NOT_ADMIN,
        )?,
        Some(ProfileAction::Switch { name }) => refused(
            client
                .call(method::PROFILES_SWITCH, ProfileParams { name })
                .await,
            NOT_ADMIN,
        )?,
        Some(ProfileAction::Delete { name }) => refused(
            client
                .call(method::PROFILES_DELETE, ProfileParams { name })
                .await,
            NOT_ADMIN,
        )?,
        Some(ProfileAction::Networks {
            name,
            networks,
            clear,
        }) if clear || !networks.is_empty() => {
            let chosen = if clear {
                Vec::new()
            } else {
                choose_networks(client, &networks).await?
            };
            refused(
                client
                    .call(
                        method::PROFILES_SET_NETWORKS,
                        SetNetworksParams {
                            name,
                            networks: chosen,
                        },
                    )
                    .await,
                NOT_ADMIN,
            )?
        }
        Some(ProfileAction::Networks { .. }) => client.call(method::PROFILES, Value::Null).await?,
    };
    if r.profiles.is_empty() {
        println!(
            "No profiles. Save the current mode, rules and DNS filtering as one: win4tress profile save Home"
        );
        return Ok(());
    }
    for p in &r.profiles {
        let active = r
            .active
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&p.name));
        println!(
            "{} {:<20} {:<15} {} rules on{}, saved {}",
            if active { "*" } else { " " },
            p.name,
            p.mode.as_str(),
            p.rules,
            match p.dns_filtering {
                Some(true) => ", DNS filtering on",
                Some(false) => ", DNS filtering off",
                None => "",
            },
            date_time(p.saved_ms)
        );
        if !p.networks.is_empty() {
            let on: Vec<String> = p
                .networks
                .iter()
                .map(|m| match m {
                    NetworkMatch::Network { name, .. } => format!("\"{name}\""),
                    NetworkMatch::Category { category } => {
                        format!("any {} network", category_name(*category))
                    }
                })
                .collect();
            println!("  {:<20} switched to on {}", "", on.join(", "));
        }
    }
    if let Some(a) = &r.last_auto {
        println!(
            "Last switched by itself: to {} on {}, {}.",
            a.profile,
            a.network,
            date_time(a.at_ms)
        );
    }
    if r.changed {
        println!("(* active; changed since: save it again to keep the changes)");
    } else if r.active.is_some() {
        println!("(* active)");
    }
    Ok(())
}

async fn find_known_app(client: &Client, query: &str) -> Result<u32> {
    if let Ok(id) = query.parse::<u32>() {
        return Ok(id);
    }
    let r: KnownAppsResult = client.call(method::APPS_ALL, Value::Null).await?;
    let needle = query.to_lowercase();
    let matches: Vec<_> = r
        .apps
        .iter()
        .filter(|a| {
            a.name.to_lowercase().contains(&needle) || a.path.to_lowercase().contains(&needle)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no app matches '{query}'"),
        many => {
            let names: Vec<String> = many
                .iter()
                .take(8)
                .map(|a| format!("{} ({})", a.name, a.id))
                .collect();
            bail!("'{query}' matches several apps: {}", names.join(", "))
        }
    }
}

async fn incognito(client: &Client, setting: OnOff, app: Option<String>) -> Result<()> {
    let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    let on = setting == OnOff::On;
    let what = match app {
        Some(query) => {
            let id = find_known_app(client, &query).await?;
            if on {
                settings.incognito_apps.insert(id);
            } else {
                settings.incognito_apps.remove(&id);
            }
            format!("App {id}'s traffic")
        }
        None => {
            settings.incognito = on;
            "Traffic".to_string()
        }
    };
    let s: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    println!(
        "{what} {} written to history. Blocking and alerts carry on either way.",
        if on { "isn't" } else { "is" }
    );
    if !s.incognito_apps.is_empty() {
        let ids: Vec<String> = s.incognito_apps.iter().map(u32::to_string).collect();
        println!("Incognito apps: {}", ids.join(", "));
    }
    Ok(())
}

async fn cleanup(
    client: &Client,
    run: bool,
    uninstalled: Option<OnOff>,
    inactive_days: Option<u32>,
) -> Result<()> {
    if uninstalled.is_some() || inactive_days.is_some() {
        let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
        if let Some(u) = uninstalled {
            settings.cleanup.uninstalled = u == OnOff::On;
        }
        if let Some(d) = inactive_days {
            settings.cleanup.inactive_days = (d > 0).then_some(d);
        }
        let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    }
    let settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    let r: CleanupResult = if run {
        refused(
            client.call(method::CLEANUP_RUN, Value::Null).await,
            NOT_ADMIN,
        )?
    } else {
        client.call(method::CLEANUP, Value::Null).await?
    };
    println!(
        "Uninstalled apps' rules: {}. Inactive apps' rules: {}.",
        if settings.cleanup.uninstalled {
            "removed after 7 days"
        } else {
            "kept"
        },
        match settings.cleanup.inactive_days {
            Some(d) => format!("removed after {d} days"),
            None => "kept".into(),
        }
    );
    if r.items.is_empty() {
        println!("Nothing to clean up.");
    }
    for i in &r.items {
        let why = match i.reason {
            CleanupReason::Uninstalled => format!("program gone since {}", date_time(i.since_ms)),
            CleanupReason::Inactive => format!("last active {}", date_time(i.since_ms)),
        };
        let state = match (run, i.due) {
            (true, true) => "removed",
            (false, true) => "due",
            _ => "not yet",
        };
        println!("  {:<8} {} ({} rules): {why}", state, i.app.name, i.rules);
    }
    if run {
        println!("{} rules removed.", r.removed);
    }
    Ok(())
}

fn verdict_word(v: RepVerdict) -> &'static str {
    match v {
        RepVerdict::Unknown => "unknown",
        RepVerdict::KnownGood => "known good",
        RepVerdict::Clean => "clean",
        RepVerdict::Suspicious => "suspicious",
        RepVerdict::Malicious => "MALICIOUS",
    }
}

fn reputation_line(r: &Reputation) -> String {
    let mut line = format!("{}: {}", r.source, verdict_word(r.verdict));
    if let (Some(d), Some(e)) = (r.detections, r.engines) {
        line.push_str(&format!(", {d} of {e} engines"));
    }
    if let Some(detail) = &r.detail {
        line.push_str(&format!(" ({detail})"));
    }
    line.push_str(&format!(", {}", date_time(r.checked_ms)));
    if let Some(link) = &r.link {
        line.push_str(&format!("\n      {link}"));
    }
    line
}

fn print_reputation(r: &AppReputation) {
    match &r.sha256 {
        Some(h) => println!("SHA-256 {h}"),
        None => println!("No hash for this app's file yet."),
    }
    if r.results.is_empty() {
        println!("  Not looked up or scanned yet.");
    }
    for answer in &r.results {
        println!("  {}", reputation_line(answer));
    }
}

async fn lookup(client: &Client, query: &str, now: bool) -> Result<()> {
    let id = find_known_app(client, query).await?;
    let r: AppReputation = if now {
        refused(
            client
                .call(method::REPUTATION_CHECK, AppParams { app: id })
                .await,
            NOT_ADMIN,
        )?
    } else {
        client
            .call(method::REPUTATION_APP, AppParams { app: id })
            .await?
    };
    print_reputation(&r);
    if now {
        println!("Queued first; see the answers in a few seconds with: win4tress lookup {id}");
    }
    Ok(())
}

async fn reputation(
    client: &Client,
    lookups: Option<OnOff>,
    virustotal_key: Option<String>,
    abuse_ch_key: Option<String>,
    malwarebazaar: Option<OnOff>,
    (alert_at, block_at, auto_block): (Option<u32>, Option<u32>, Option<OnOff>),
) -> Result<()> {
    for (service, key) in [
        (KeyService::VirusTotal, virustotal_key),
        (KeyService::AbuseCh, abuse_ch_key),
    ] {
        if let Some(key) = key {
            let key = (key != "-").then_some(key);
            let _: ReputationStatus = refused(
                client
                    .call(method::REPUTATION_SET_KEY, SetKeyParams { service, key })
                    .await,
                NOT_ADMIN,
            )?;
        }
    }
    if lookups.is_some()
        || malwarebazaar.is_some()
        || alert_at.is_some()
        || block_at.is_some()
        || auto_block.is_some()
    {
        let mut settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
        let r = &mut settings.reputation;
        if let Some(v) = lookups {
            r.enabled = v == OnOff::On;
        }
        if let Some(v) = malwarebazaar {
            r.malwarebazaar = v == OnOff::On;
        }
        if let Some(v) = alert_at {
            r.alert_at = v;
        }
        if let Some(v) = block_at {
            r.block_at = v;
        }
        if let Some(v) = auto_block {
            r.auto_block = v == OnOff::On;
        }
        let _: Settings = refused(client.call(method::SETTINGS_SET, settings).await, NOT_ADMIN)?;
    }
    let settings: Settings = client.call(method::SETTINGS, Value::Null).await?;
    let s: ReputationStatus = client.call(method::REPUTATION, Value::Null).await?;
    let r = &settings.reputation;
    println!(
        "Lookups: {}. VirusTotal key: {}. abuse.ch key: {}. MalwareBazaar: {}.",
        if r.enabled {
            "on (file hashes go to CIRCL, and VirusTotal with your key)"
        } else {
            "off"
        },
        if s.virustotal_key { "set" } else { "none" },
        if s.abuse_ch_key { "set" } else { "none" },
        if r.malwarebazaar { "on" } else { "off" }
    );
    println!(
        "Alert at {} engines; auto-block {}.",
        r.alert_at,
        if r.auto_block {
            format!("at {} engines", r.block_at)
        } else {
            "off".into()
        }
    );
    println!(
        "{} files answered, {} waiting; VirusTotal today: {} of 500.",
        s.checked, s.queued, s.virustotal_today
    );
    if let Some(e) = &s.last_error {
        println!("Last problem: {e}");
    }
    Ok(())
}

async fn prompts(client: &Client) -> Result<()> {
    let r: PromptsResult = client.call(method::PROMPTS, Value::Null).await?;
    if r.prompts.is_empty() {
        println!("Nothing is waiting for a decision.");
        return Ok(());
    }
    println!(
        "{:>4}  {:<8} {:<28} {:<36} {:>8}  Since",
        "ID", "State", "App", "Destination", "Attempts"
    );
    for p in &r.prompts {
        let state = match p.state {
            PromptState::Open => "open",
            PromptState::Waiting => "waiting",
            PromptState::Pending => "pending",
        };
        let host = p
            .remote
            .name
            .clone()
            .unwrap_or_else(|| p.remote.ip.to_string());
        println!(
            "{:>4}  {:<8} {:<28} {:<36} {:>8}  {}",
            p.id,
            state,
            truncate(&p.app.name, 28),
            truncate(&format!("{host}:{}", p.port), 36),
            p.attempts,
            ago(now_unix_ms() - p.first_ms)
        );
    }
    println!("Answer with: win4tress decide <ID> allow|block|later [--host]");
    Ok(())
}

async fn decide(
    client: &Client,
    id: u64,
    decision: DecisionArg,
    host: bool,
    lasts: Option<Lasts>,
) -> Result<()> {
    let decision = match decision {
        DecisionArg::Allow => Decision::Allow,
        DecisionArg::Block => Decision::Block,
        DecisionArg::Later => Decision::Later,
    };
    let r: DecideResult = refused(
        client
            .call(
                method::PROMPTS_DECIDE,
                DecideParams {
                    id,
                    decision,
                    scope: if host {
                        DecisionScope::Host
                    } else {
                        DecisionScope::App
                    },
                    lasts,
                },
            )
            .await,
        NOT_ADMIN,
    )?;
    match r.rule {
        Some(rule) => println!("Done (rule {rule}). Applied to Windows Firewall right away."),
        None => println!("Left blocked for now; it stays in `win4tress prompts` as pending."),
    }
    Ok(())
}

/// Asks on the terminal unless `yes`; anything but y/yes cancels.
fn confirm(question: &str, yes: bool) -> Result<()> {
    use std::io::Write;
    if yes {
        return Ok(());
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => bail!("cancelled; nothing was changed"),
    }
}

async fn reset(pipe: &str, yes: bool) -> Result<()> {
    let client = match Client::connect(pipe).await {
        Ok(c) => c,
        Err(ClientError::NotRunning) if pipe == w4_ipc::PIPE_NAME => return reset_offline(yes),
        Err(ClientError::NotRunning) => {
            bail!(
                "nothing is listening on {pipe}; with the service stopped, reset covers only the installed service"
            )
        }
        Err(e) => return Err(e.into()),
    };
    client.hello("win4tress-cli").await?;
    let rules: RulesResult = client.call(method::RULES, Value::Null).await?;
    confirm(
        &format!(
            "Delete all {} win4tress rules, remove them from Windows Firewall and switch back to Click to Block?",
            rules.rules.len()
        ),
        yes,
    )?;
    let r: ResetResult = refused(
        client.call(method::FIREWALL_RESET, Value::Null).await,
        NOT_ELEVATED,
    )?;
    if r.in_sync {
        println!(
            "Deleted {} rules. Windows Firewall has no win4tress rules left, and the mode is Click to Block.",
            r.rules
        );
    } else {
        println!(
            "Deleted {} rules, but Windows Firewall couldn't be fully updated yet ({}). The service keeps trying.",
            r.rules,
            r.error.unwrap_or_default()
        );
    }
    Ok(())
}

/// With the service stopped: removes our group's rules from Windows Firewall and
/// the stored rules from history, so a later start doesn't put them back.
fn reset_offline(yes: bool) -> Result<()> {
    use w4_enforce::EnforcementBackend;
    println!("The win4tress service isn't running, so its rules are reset directly.");
    // The history database is admin-only: opening it first means nothing is
    // changed when the prompt isn't elevated.
    let db = w4_store::default_dir().join(w4_store::DB_NAME);
    let mut store = if db.exists() {
        Some(
            w4_store::Store::open(&db)
                .with_context(|| format!("opening {} ({NOT_ELEVATED})", db.display()))?,
        )
    } else {
        None
    };
    let firewall = w4_enforce::ComFirewall::start(w4_enforce::GROUP)?;
    let present = firewall.list()?.len();
    let stored = match &store {
        Some(s) => s.rules()?.len(),
        None => 0,
    };
    confirm(
        &format!(
            "Remove {present} win4tress rules from Windows Firewall and delete {stored} stored rules?"
        ),
        yes,
    )?;
    let removed = w4_enforce::remove_all(&firewall)
        .with_context(|| format!("removing rules from Windows Firewall ({NOT_ELEVATED})"))?;
    let who = format!(
        "{} (win4tress reset with the service stopped)",
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown user".into())
    );
    let deleted = match &mut store {
        Some(s) => s.reset_rules(now_unix_ms(), &who)?,
        None => 0,
    };
    println!(
        "Removed {removed} rules from Windows Firewall and deleted {deleted} stored rules. The mode is Click to Block."
    );
    // DNS filtering's routing rule, if a stopped service left one: Windows'
    // own DNS again (SPEC §13).
    if w4_sys::nrpt::remove().map_err(|e| {
        anyhow::anyhow!("removing DNS filtering's routing rule: {e} ({NOT_ELEVATED})")
    })? {
        println!("Removed DNS filtering's routing rule: Windows' DNS is as before.");
    }
    Ok(())
}

async fn firewall(client: &Client) -> Result<()> {
    let f: FirewallStatus = client.call(method::FIREWALL, Value::Null).await?;
    println!(
        "Mode: {}. Outside changes are {}.",
        mode_name(f.mode),
        if f.live_events {
            "seen as Windows Firewall logs them"
        } else {
            "found by a check every 60 s"
        }
    );
    if let Some(b) = f.block_all {
        match b.until_ms {
            Some(until) => println!("BLOCK ALL is on until {}.", date_time(until)),
            None => println!("BLOCK ALL is on until turned off."),
        }
    }
    if let Some(why) = &f.monitoring_only {
        println!("Monitoring only: {why}. Rules are kept but not applied.");
    }
    if !f.environment.outbound_default_forced_by.is_empty() {
        println!(
            "{} sets the outbound default, so Ask to Connect isn't available.",
            f.environment.outbound_default_forced_by.join(" and ")
        );
    }
    if f.require_elevation {
        println!("Changes need an elevated caller (\"Require elevation\" is on).");
    }
    match &f.state {
        Some(state) => {
            for p in &state.profiles {
                println!(
                    "{:<8} {:<7} firewall {:<3}  inbound default {:<5}  outbound default {}",
                    p.name,
                    if p.active { "active" } else { "" },
                    if p.firewall_on { "on" } else { "OFF" },
                    if p.inbound_default_block {
                        "block"
                    } else {
                        "allow"
                    },
                    if p.outbound_default_block {
                        "block"
                    } else {
                        "allow"
                    },
                );
            }
            if !state.enforcing() {
                println!(
                    "Warning: the firewall is off for an active profile, so block rules don't apply there."
                );
            }
            if state.policy_override {
                println!(
                    "Warning: Group Policy or MDM controls Windows Firewall; local rules may be ignored."
                );
            }
        }
        None => println!("Windows Firewall state unavailable"),
    }
    println!(
        "Rule group '{}': {} rules → {} Windows Firewall rules, {}; last checked {}{}",
        f.group,
        f.rules,
        f.windows_rules,
        if f.in_sync { "in sync" } else { "NOT in sync" },
        f.last_check_ms
            .map(|t| ago(now_unix_ms() - t))
            .unwrap_or_else(|| "never".into()),
        if f.repairs > 0 {
            format!("; repaired outside changes {} time(s)", f.repairs)
        } else {
            String::new()
        },
    );
    if let Some(e) = &f.last_error {
        println!("Last error: {e}");
    }
    let r: RulesResult = client.call(method::RULES, Value::Null).await?;
    if r.rules.is_empty() {
        println!(
            "No rules. Everything is allowed unless Windows Firewall's own rules say otherwise."
        );
        return Ok(());
    }
    println!(
        "\n{:>4}  {:<30} {:<4} {:<6} {:<7} {:<17} Covers",
        "ID", "App", "Dir", "Action", "Enabled", "Changed"
    );
    for rule in r.rules {
        let covers = match &rule.scope {
            Scope::Any => "everything".to_string(),
            Scope::Hosts { hosts } => hosts.join(", "),
            Scope::Except { hosts } => format!("all but {}", hosts.join(", ")),
            Scope::Dns => "its own DNS".into(),
        };
        println!(
            "{:>4}  {:<30} {:<4} {:<6} {:<7} {:<17} {}",
            rule.id,
            format::truncate(&rule.app.name, 30),
            match rule.direction {
                Direction::In => "in",
                Direction::Out => "out",
            },
            match rule.action {
                Action::Allow => "allow",
                Action::Block => "block",
            },
            if rule.enabled { "yes" } else { "no" },
            date_time(rule.updated_ms),
            format::truncate(&covers, 60),
        );
        if let Some(e) = &rule.expires {
            println!(
                "{:>4}  {}{}",
                "",
                until_text(e),
                match rule.revert {
                    Some(Action::Allow) => ", then allowed again",
                    Some(Action::Block) => ", then blocked again",
                    None => ", then removed",
                }
            );
        }
    }
    Ok(())
}

async fn set_rule(
    client: &Client,
    query: &str,
    inbound: bool,
    action: Action,
    scope: Scope,
    lasts: Option<Lasts>,
) -> Result<()> {
    let app = find_app(client, query).await?;
    let params = RuleSetParams {
        app,
        direction: if inbound {
            Direction::In
        } else {
            Direction::Out
        },
        action,
        scope,
        note: None,
        lasts,
    };
    let rule: Rule = refused(client.call(method::RULES_SET, params).await, NOT_ADMIN)?;
    let what = match &rule.scope {
        Scope::Any => String::new(),
        Scope::Hosts { hosts } => format!(" to {}", hosts.join(", ")),
        Scope::Except { hosts } => format!(" to everything but {}", hosts.join(", ")),
        Scope::Dns => " to its own DNS".into(),
    };
    let how_long = match (&rule.expires, rule.action == action) {
        (Some(e), _) => format!(" {}", until_text(e)),
        // Asked for a while, but it already was for good.
        (None, true) if lasts.is_some() => " (it already was, for good)".into(),
        _ => String::new(),
    };
    println!(
        "{} {} {}{what}{how_long} (rule {}). Applied to Windows Firewall right away.",
        match action {
            Action::Allow => "Allowed",
            Action::Block => "Blocked",
        },
        rule.app.name,
        if inbound { "incoming" } else { "outgoing" },
        rule.id,
    );
    if !rule
        .scope
        .hosts()
        .iter()
        .all(|h| h.parse::<std::net::IpAddr>().is_ok())
    {
        println!(
            "Names stand for the addresses this app received for them; new answers are added as they come."
        );
    }
    Ok(())
}

/// Profile networks from the command line: "current", a kind, or one Windows
/// knows by name or id.
async fn choose_networks(client: &Client, wanted: &[String]) -> Result<Vec<NetworkMatch>> {
    let known: NetworksResult = client.call(method::NETWORKS, Value::Null).await?;
    let mut out = Vec::new();
    for w in wanted {
        let category = match w.to_ascii_lowercase().as_str() {
            "public" => Some(NetworkCategory::Public),
            "private" => Some(NetworkCategory::Private),
            "domain" => Some(NetworkCategory::Domain),
            _ => None,
        };
        if let Some(category) = category {
            out.push(NetworkMatch::Category { category });
            continue;
        }
        let matches: Vec<_> = if w.eq_ignore_ascii_case("current") {
            known.networks.iter().filter(|n| n.connected).collect()
        } else {
            known
                .networks
                .iter()
                .filter(|n| n.id.eq_ignore_ascii_case(w) || n.name.eq_ignore_ascii_case(w))
                .collect()
        };
        if matches.is_empty() {
            bail!("no network '{w}': see `win4tress networks`");
        }
        out.extend(matches.into_iter().map(|n| NetworkMatch::Network {
            id: n.id.clone(),
            name: n.name.clone(),
        }));
    }
    Ok(out)
}

async fn networks(client: &Client) -> Result<()> {
    let r: NetworksResult = client.call(method::NETWORKS, Value::Null).await?;
    let profiles: ProfilesResult = client.call(method::PROFILES, Value::Null).await?;
    if r.networks.is_empty() {
        println!("Windows doesn't know any networks yet.");
        return Ok(());
    }
    println!(
        "{:<11} {:<30} {:<8} {:<16} Id",
        "", "Network", "Kind", "Switches to"
    );
    for n in &r.networks {
        let profile = profiles
            .profiles
            .iter()
            .find(|p| {
                p.networks.iter().any(|m| {
                    matches!(m, NetworkMatch::Network { id, .. } if id.eq_ignore_ascii_case(&n.id))
                })
            })
            .map(|p| p.name.as_str())
            .unwrap_or("");
        println!(
            "{:<11} {:<30} {:<8} {:<16} {}",
            match (n.connected, n.internet) {
                (true, true) => "connected",
                (true, false) => "no internet",
                _ => "",
            },
            truncate(&n.name, 30),
            category_name(n.category),
            truncate(profile, 16),
            n.id
        );
    }
    match &r.wanted {
        Some(p) => println!("The networks connected now call for the profile {p}."),
        None => println!(
            "No profile is chosen for the networks connected now. Choose: win4tress profile networks <NAME> current"
        ),
    }
    Ok(())
}

async fn export(client: &Client, file: &Path) -> Result<()> {
    let e: RulesExport = client.call(method::RULES_EXPORT, Value::Null).await?;
    let json = serde_json::to_string_pretty(&e)?;
    if file.as_os_str() == "-" {
        println!("{json}");
        return Ok(());
    }
    std::fs::write(file, json + "\n").with_context(|| format!("writing {}", file.display()))?;
    println!(
        "Saved {} rule(s) and {} profile(s) to {}.",
        e.rules.len(),
        e.profiles.len(),
        file.display()
    );
    Ok(())
}

fn print_import(r: &ImportResult, done: bool) {
    let (add, replace) = if done {
        ("Added", "replaced")
    } else {
        ("Would add", "replace")
    };
    println!(
        "{add} {} rule(s), {replace} {}; {} already as in the file.",
        r.added, r.replaced, r.unchanged
    );
    if !r.profiles.is_empty() {
        println!("Profiles: {}.", r.profiles.join(", "));
    }
    if r.dns {
        println!(
            "{} this PC's DNS filtering settings with the file's.",
            if done { "Replaced" } else { "Would replace" }
        );
    }
    if !r.missing_apps.is_empty() {
        println!(
            "Not on this PC (their rules apply once installed): {}.",
            r.missing_apps.join(", ")
        );
    }
    for f in &r.failed {
        println!("Not imported: {f}");
    }
}

async fn import(client: &Client, file: &Path, dry_run: bool, yes: bool) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let export: RulesExport =
        serde_json::from_str(&text).context("that isn't a win4tress rules file")?;
    println!(
        "{} rule(s), {} profile(s){} from {}, saved {}.",
        export.rules.len(),
        export.profiles.len(),
        if export.dns.is_some() {
            " and DNS filtering settings"
        } else {
            ""
        },
        if export.computer.is_empty() {
            "another PC"
        } else {
            &export.computer
        },
        date_time(export.exported_ms)
    );
    let preview: ImportResult = client
        .call(
            method::RULES_IMPORT,
            ImportParams {
                export: export.clone(),
                dry_run: true,
            },
        )
        .await?;
    print_import(&preview, false);
    if dry_run {
        return Ok(());
    }
    confirm("Import them?", yes)?;
    let r: ImportResult = refused(
        client
            .call(
                method::RULES_IMPORT,
                ImportParams {
                    export,
                    dry_run: false,
                },
            )
            .await,
        NOT_ADMIN,
    )?;
    print_import(&r, true);
    println!("Applied to Windows Firewall right away.");
    Ok(())
}

async fn block_all(client: &Client, minutes: Option<u32>, off: bool, yes: bool) -> Result<()> {
    let call = |confirm_remote| {
        client.call::<_, FirewallStatus>(
            method::FIREWALL_BLOCK_ALL,
            BlockAllParams {
                on: !off,
                minutes,
                confirm_remote,
            },
        )
    };
    let status = match call(yes).await {
        Err(ClientError::Rpc(e)) if e.code == RpcError::REMOTE_SESSION => {
            confirm(
                &format!("{}. Block All anyway?", capitalize(&e.message)),
                false,
            )?;
            refused(call(true).await, NOT_ADMIN)?
        }
        other => refused(other, NOT_ADMIN)?,
    };
    match status.block_all {
        Some(b) => match b.until_ms {
            Some(until) => println!(
                "Block All is on until {}. Only this PC's own connections work.",
                date_time(until)
            ),
            None => println!("Block All is on until you turn it off (win4tress block-all --off)."),
        },
        None => println!("Block All is off."),
    }
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

async fn blocked(client: &Client, app: Option<&str>, days: Option<u32>, limit: u32) -> Result<()> {
    let app = app_filter(client, app).await?;
    let r: BlocksResult = client
        .call(
            method::FIREWALL_BLOCKS,
            BlocksParams {
                app,
                since_ms: days.map(|d| now_unix_ms() - i64::from(d) * 24 * 3600 * 1000),
                limit: Some(limit),
            },
        )
        .await?;
    if r.blocks.is_empty() {
        println!("Nothing was blocked.");
        return Ok(());
    }
    println!(
        "{:<17} {:<4} {:<26} {:<36} {:>5}  Blocked by",
        "Last", "Dir", "App", "Remote", "Times"
    );
    for b in &r.blocks {
        let remote = match &b.name {
            Some(name) => format!("{name}:{}", b.remote.port()),
            None => b.remote.to_string(),
        };
        println!(
            "{:<17} {:<4} {:<26} {:<36} {:>5}  {}",
            date_time(b.last_ms),
            if b.inbound { "in" } else { "out" },
            format::truncate(&b.app.name, 26),
            format::truncate(&remote, 36),
            b.count,
            format::blocked_by(&b.by),
        );
    }
    Ok(())
}

/// The UI's elevated helper: one method call, the result written to a file.
async fn rpc(pipe: &str, method: &str, params: &str, result: Option<&Path>) -> Result<()> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(params.trim())
        .context("params aren't base64")?;
    let params: Value = serde_json::from_slice(&bytes).context("params aren't JSON")?;
    let outcome = async {
        let client = Client::connect(pipe).await?;
        client.hello("win4tress-cli (elevated helper)").await?;
        client.call::<_, Value>(method, params).await
    }
    .await;
    let (json, ok) = match &outcome {
        Ok(v) => (serde_json::json!({ "result": v }), true),
        Err(e) => (serde_json::json!({ "error": e.to_string() }), false),
    };
    if let Some(path) = result {
        std::fs::write(path, serde_json::to_vec(&json)?)?;
    } else {
        println!("{json}");
    }
    if ok {
        Ok(())
    } else {
        bail!(
            "{}",
            outcome.err().map(|e| e.to_string()).unwrap_or_default()
        )
    }
}

async fn status(client: &Client, json: bool) -> Result<()> {
    let s: Status = client.call(method::STATUS, Value::Null).await?;
    if json {
        println!("{}", serde_json::to_string(&s)?);
        return Ok(());
    }
    let c = &s.collector;
    let overhead = s.adapter_bytes.saturating_sub(s.apps_bytes);
    println!(
        "win4tress service {}, running for {}",
        s.version,
        duration(s.now_ms - s.started_ms)
    );
    println!(
        "Collector: {} events ({} traffic), {} lost, {} lost buffers, {} parse errors, last event {}",
        c.events,
        c.data_events,
        c.events_lost,
        c.buffers_lost,
        c.parse_errors,
        c.last_event_ms
            .map_or("never".into(), |t| ago(s.now_ms - t)),
    );
    println!("Apps seen: {}", s.app_count);
    println!(
        "Service process: {} memory, {:.1} s CPU",
        human(s.process.working_set),
        s.process.cpu_ms as f64 / 1000.0
    );
    match (&s.history.path, s.history.enabled) {
        (Some(path), true) => println!(
            "History: {} ({}){}",
            path,
            human(s.history.size_bytes),
            s.history.oldest.map_or(String::new(), |t| format!(
                ", since {}",
                ago(s.now_ms - t * 1000)
            ))
        ),
        _ => println!("History: off (only the last 10 minutes are kept)"),
    }
    println!();
    println!("{:<28} {:>12} {:>12}", "Since start", "In", "Out");
    println!(
        "{:<28} {:>12} {:>12}",
        "Apps (payload)",
        human(s.apps_bytes.recv),
        human(s.apps_bytes.sent)
    );
    println!(
        "{:<28} {:>12} {:>12}",
        "  of which local network",
        human(s.local_bytes.recv),
        human(s.local_bytes.sent)
    );
    println!(
        "{:<28} {:>12} {:>12}",
        "Adapters (whole frames)",
        human(s.adapter_bytes.recv),
        human(s.adapter_bytes.sent)
    );
    println!(
        "{:<28} {:>12} {:>12}",
        "Protocol overhead & other",
        human(overhead.recv),
        human(overhead.sent)
    );
    Ok(())
}

async fn apps(client: &Client, top: usize) -> Result<()> {
    let r: AppsResult = client.call(method::APPS, Value::Null).await?;
    if r.apps.is_empty() {
        println!("No network activity seen yet.");
        return Ok(());
    }
    println!(
        "{:>4}  {:<34} {:>10} {:>10} {:>10} {:>6}  Publisher",
        "ID", "App", "In", "Out", "Last 60s", "Hosts"
    );
    for a in r.apps.iter().take(top) {
        println!(
            "{:>4}  {:<34} {:>10} {:>10} {:>10} {:>6}  {}",
            a.id,
            format::truncate(&a.name, 34),
            human(a.total.recv),
            human(a.total.sent),
            human(a.recent.total()),
            a.host_count,
            a.company.as_deref().unwrap_or(""),
        );
    }
    if r.apps.len() > top {
        println!("... and {} more (use --top)", r.apps.len() - top);
    }
    Ok(())
}

async fn hosts(client: &Client, query: &str) -> Result<()> {
    let id = match query.parse::<u32>() {
        Ok(id) => id,
        Err(_) => find_app(client, query).await?,
    };
    let r: HostsResult = client
        .call(method::HOSTS, HostsParams { app: id })
        .await
        .with_context(|| format!("app {query}"))?;
    println!("{} (ID {}): {} hosts", r.app.name, r.app.id, r.hosts.len());
    println!(
        "{:<44} {:<9} {:<20} {:>10} {:>10}  Ports",
        "Host", "Type", "Network", "In", "Out"
    );
    let now = now_unix_ms();
    for h in &r.hosts {
        let label = match &h.name {
            Some(name) => format!("{name} ({})", h.ip),
            None => h.ip.to_string(),
        };
        // Who runs the network, or just local/internet when unknown.
        let network = match &h.owner {
            Some(owner) => owner.name.clone(),
            None => format!("{:?}", h.locality).to_lowercase(),
        };
        let ports: Vec<String> = h.ports.iter().map(u16::to_string).collect();
        println!(
            "{:<44} {:<9} {:<20} {:>10} {:>10}  {}  (last {})",
            format::truncate(&label, 44),
            h.traffic_type.label(),
            format::truncate(&network, 20),
            human(h.total.recv),
            human(h.total.sent),
            ports.join(","),
            ago(now - h.last_seen_ms),
        );
    }
    Ok(())
}

/// An app by its ID, or by part of its name or path: among the apps seen since
/// the service started, else among every app win4tress knows (one blocked
/// since then has had no traffic).
async fn find_app(client: &Client, query: &str) -> Result<u32> {
    if let Ok(id) = query.parse::<u32>() {
        return Ok(id);
    }
    let r: AppsResult = client.call(method::APPS, Value::Null).await?;
    let needle = query.to_lowercase();
    let matches: Vec<_> = r
        .apps
        .iter()
        .filter(|a| {
            a.name.to_lowercase().contains(&needle) || a.path.to_lowercase().contains(&needle)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id),
        [] => find_known_app(client, query).await,
        many => {
            let names: Vec<String> = many
                .iter()
                .map(|a| format!("{} ({})", a.name, a.id))
                .collect();
            bail!("'{query}' matches several apps: {}", names.join(", "))
        }
    }
}

async fn watch(client: &Client) -> Result<()> {
    let mut notes = client.subscribe(&[notification::SAMPLES]).await?;
    println!("{:<10} {:>12} {:>12}", "Time", "In", "Out");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            note = notes.recv() => {
                let Some(note) = note else { bail!("the service closed the connection") };
                if note.method != notification::SAMPLES {
                    continue;
                }
                let batch: SamplesNotification = serde_json::from_value(note.params)?;
                for s in batch.samples {
                    println!("{:<10} {:>12} {:>12}", clock(s.t), rate(s.recv), rate(s.sent));
                }
            }
        }
    }
}

async fn app_filter(client: &Client, app: Option<&str>) -> Result<Option<u32>> {
    match app {
        None => Ok(None),
        Some(a) => match a.parse::<u32>() {
            Ok(id) => Ok(Some(id)),
            Err(_) => find_app(client, a).await.map(Some),
        },
    }
}

async fn connections(client: &Client, app: Option<&str>, top: usize) -> Result<()> {
    let app = app_filter(client, app).await?;
    let r: ConnectionsResult = client
        .call(method::CONNECTIONS, ConnectionsParams { app })
        .await?;
    if r.connections.is_empty() {
        println!("No connections.");
        return Ok(());
    }
    println!(
        "{:<7} {:<5} {:<28} {:<40} {:<8} {:>9} {:>9}  Last",
        "State", "Proto", "App", "Remote", "Type", "In", "Out"
    );
    let now = now_unix_ms();
    for c in r.connections.iter().take(top) {
        let remote = match &c.name {
            Some(name) => format!("{name}:{}", c.remote.port()),
            None => c.remote.to_string(),
        };
        let state = match (c.state, c.inbound) {
            (ConnectionState::Closed, _) => "closed",
            (ConnectionState::Open, Some(true)) => "in",
            (ConnectionState::Open, _) => "open",
        };
        println!(
            "{:<7} {:<5} {:<28} {:<40} {:<8} {:>9} {:>9}  {}",
            state,
            format!("{:?}", c.protocol).to_uppercase(),
            format::truncate(&c.app.name, 28),
            format::truncate(&remote, 40),
            c.traffic_type.label(),
            human(c.bytes.recv),
            human(c.bytes.sent),
            ago(now - c.last_seen_ms),
        );
    }
    if r.connections.len() > top {
        println!("... and {} more (use --top)", r.connections.len() - top);
    }
    Ok(())
}

async fn dns(
    client: &Client,
    app: Option<&str>,
    search: Option<String>,
    limit: u32,
    top: bool,
) -> Result<()> {
    let app = app_filter(client, app).await?;
    if top {
        let now = now_unix_ms();
        let r: DnsTopResult = client
            .call(
                method::DNS_TOP,
                DnsTopParams {
                    from_ms: now - 24 * 3600 * 1000,
                    to_ms: now,
                    app,
                    limit: Some(limit),
                },
            )
            .await?;
        println!(
            "{:>8} {:>7} {:>5}  Name (last 24 hours)",
            "Queries", "Failed", "Apps"
        );
        for d in r.domains {
            println!("{:>8} {:>7} {:>5}  {}", d.queries, d.failed, d.apps, d.name);
        }
        return Ok(());
    }
    let r: DnsLogResult = client
        .call(
            method::DNS_LOG,
            DnsLogParams {
                limit: Some(limit),
                app,
                query: search,
            },
        )
        .await?;
    println!(
        "{:<10} {:<26} {:<6} {:<44} Result",
        "Time", "App", "Type", "Name"
    );
    for e in r.entries {
        let result = if e.status == 0 {
            let addrs: Vec<String> = e.addrs.iter().map(ToString::to_string).collect();
            if addrs.is_empty() {
                "(no addresses)".into()
            } else {
                addrs.join(", ")
            }
        } else {
            dns_status(e.status)
        };
        println!(
            "{:<10} {:<26} {:<6} {:<44} {}",
            clock(e.ts_ms / 1000),
            format::truncate(&e.app.name, 26),
            dns_type(e.query_type),
            format::truncate(&e.name, 44),
            result
        );
    }
    Ok(())
}

async fn alerts(client: &Client, unread_only: bool, limit: u32, mark_read: bool) -> Result<()> {
    let r: AlertsResult = client
        .call(
            method::ALERTS,
            AlertsParams {
                unread_only,
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await?;
    if r.alerts.is_empty() {
        println!("No alerts.");
    }
    for a in &r.alerts {
        println!(
            "{} {} {:<8} {}",
            if a.read { ' ' } else { '*' },
            date_time(a.ts_ms),
            format!("{:?}", a.severity).to_lowercase(),
            alert_text(a)
        );
    }
    if r.more {
        println!("... older alerts not shown (use --limit)");
    }
    let mut unread = r.unread;
    if mark_read && unread > 0 {
        let m: MarkReadResult = client
            .call(
                method::ALERTS_MARK_READ,
                MarkReadParams {
                    ids: None,
                    read: true,
                },
            )
            .await?;
        unread = m.unread;
    }
    println!("{unread} unread (* = unread)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn how_long_reads_as_minutes_or_an_event() {
        assert_eq!(parse_lasts("30m"), Ok(Lasts::Minutes { minutes: 30 }));
        assert_eq!(parse_lasts("2h"), Ok(Lasts::Minutes { minutes: 120 }));
        assert_eq!(parse_lasts("1D"), Ok(Lasts::Minutes { minutes: 1440 }));
        assert_eq!(parse_lasts("45"), Ok(Lasts::Minutes { minutes: 45 }));
        assert_eq!(parse_lasts("quit"), Ok(Lasts::AppQuits));
        assert_eq!(parse_lasts("restart"), Ok(Lasts::Restart));
        assert!(parse_lasts("0m").is_err());
        assert!(parse_lasts("31d").is_err());
        assert!(parse_lasts("soon").is_err());
        assert!(parse_lasts("2w").is_err());
    }
}
