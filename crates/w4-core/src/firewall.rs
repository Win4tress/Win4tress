//! Firewall rules as win4tress stores them (SPEC §7.2), and Windows Firewall's
//! state. The enforcement backend turns these into Windows Firewall rules.

use serde::{Deserialize, Serialize};

pub type RuleId = i64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}

/// How win4tress enforces (SPEC §7.1). Block All is separate: a timed action
/// on top of any mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// win4tress's rules are kept but switched off; Windows Firewall behaves as before.
    Off,
    /// Everything is allowed unless blocked.
    #[default]
    ClickToBlock,
    /// Outgoing connections without a rule are blocked, and the user is asked.
    AskToConnect,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::ClickToBlock => "click_to_block",
            Mode::AskToConnect => "ask_to_connect",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "off" => Some(Mode::Off),
            "click_to_block" => Some(Mode::ClickToBlock),
            "ask_to_connect" => Some(Mode::AskToConnect),
            _ => None,
        }
    }
}

/// Who or what created a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    User,
    Prompt,
    Baseline,
    Import,
    Cleanup,
    /// Blocked automatically for its file's reputation (SPEC §12).
    Reputation,
}

/// Which remote addresses a rule covers (SPEC §7.3). Hosts are IP addresses,
/// ranges (`a-b`), networks (`10.0.0.0/8`) or names; a name stands for the
/// addresses this app received for it from DNS (`*.example.com` includes its
/// subdomains).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    Any,
    /// Only these hosts.
    Hosts {
        hosts: Vec<String>,
    },
    /// Everything but these hosts (and this PC itself): "allow only these
    /// hosts" is a block rule on the rest, since block rules beat allow rules.
    Except {
        hosts: Vec<String>,
    },
    /// The app's own DNS: remote ports 53 and 853, and known DNS-over-HTTPS
    /// servers (SPEC §7.11).
    Dns,
}

impl Scope {
    /// One rule per (app, direction, action, scope kind) (SPEC §7.2).
    pub fn kind(&self) -> &'static str {
        match self {
            Scope::Any => "any",
            Scope::Hosts { .. } => "hosts",
            Scope::Except { .. } => "except",
            Scope::Dns => "dns",
        }
    }

    pub fn hosts(&self) -> &[String] {
        match self {
            Scope::Hosts { hosts } | Scope::Except { hosts } => hosts,
            Scope::Any | Scope::Dns => &[],
        }
    }
}

/// Block All (SPEC §7.5): everything but this PC itself is blocked, both ways,
/// on top of the mode and the app rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockAll {
    pub since_ms: i64,
    /// When it turns itself off; `None` lasts until turned off.
    pub until_ms: Option<i64>,
}

impl BlockAll {
    pub fn active(&self, now_ms: i64) -> bool {
        self.until_ms.is_none_or(|until| now_ms < until)
    }
}

/// What else decides how much win4tress can enforce (SPEC §7.7).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Firewalls other than Windows Firewall that Security Center reports as on.
    pub other_firewalls: Vec<String>,
    /// Who makes Windows Firewall ignore local rules, ours included ("Group
    /// Policy", "MDM"); empty if nobody does.
    pub local_rules_ignored_by: Vec<String>,
    /// Who sets the outbound default (so Ask to Connect can't).
    pub outbound_default_forced_by: Vec<String>,
}

impl Environment {
    /// Why win4tress can only monitor here, if it can't enforce at all.
    pub fn monitoring_only(&self) -> Option<String> {
        if let Some(first) = self.other_firewalls.first() {
            return Some(format!(
                "{first} is in charge of this PC's firewall, so win4tress can monitor but not block"
            ));
        }
        let (by, verb) = match self.local_rules_ignored_by.as_slice() {
            [] => return None,
            [one] => (one.clone(), "tells"),
            many => (many.join(" and "), "tell"),
        };
        Some(format!(
            "{by} {verb} Windows Firewall to ignore local rules, win4tress's included"
        ))
    }
}

/// When a temporary rule ends (SPEC §7.2). Only whole-app rules are temporary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expiry {
    /// At this time.
    At { ms: i64 },
    /// When none of the app's processes is running any more.
    AppQuits,
    /// When Windows restarts: the rule belongs to the boot that started then.
    Restart { boot_ms: i64 },
}

/// A rule as stored: the desired state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRecord {
    pub id: RuleId,
    /// The app's id in the app table.
    pub app: u32,
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
    /// What the rule goes back to when it ends: the action it replaced. `None`
    /// deletes it then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<Action>,
}

/// What decides whether an app's connections in one direction are allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    /// A win4tress rule.
    Win4tress,
    /// One of Windows Firewall's own rules (Windows', or another program's).
    WindowsRule,
    /// No rule: the profile's default action.
    Default,
    /// Windows Firewall is off on a network in use, so nothing is blocked there.
    FirewallOff,
}

/// Whether an app's connections in one direction are allowed, and why (SPEC
/// §7.9). Approximate: it doesn't weigh ports, addresses or which network a
/// connection uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub allowed: bool,
    pub by: VerdictSource,
    /// The Windows Firewall rules that decide it, for [`VerdictSource::WindowsRule`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
}

/// What dropped a connection attempt (SPEC §7.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedByKind {
    /// One of win4tress's rules (Block All included).
    Win4tress,
    /// One of Windows Firewall's own rules.
    WindowsRule,
    /// Windows Firewall's default for the profile: no rule allowed it.
    WindowsDefault,
    /// Another WFP filter: Windows hardening, or another security product.
    Other,
}

impl BlockedByKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockedByKind::Win4tress => "win4tress",
            BlockedByKind::WindowsRule => "windows_rule",
            BlockedByKind::WindowsDefault => "windows_default",
            BlockedByKind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<BlockedByKind> {
        match s {
            "win4tress" => Some(BlockedByKind::Win4tress),
            "windows_rule" => Some(BlockedByKind::WindowsRule),
            "windows_default" => Some(BlockedByKind::WindowsDefault),
            "other" => Some(BlockedByKind::Other),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockedBy {
    pub kind: BlockedByKind,
    /// The rule's name, or the filter's for other kinds.
    pub name: String,
}

/// How Windows treats a network, which picks its Windows Firewall profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkCategory {
    Public,
    Private,
    /// Signed in to the organisation's domain.
    Domain,
}

/// One Windows Firewall profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileState {
    /// "domain", "private" or "public".
    pub name: String,
    /// A network on this profile is connected.
    pub active: bool,
    pub firewall_on: bool,
    pub inbound_default_block: bool,
    pub outbound_default_block: bool,
}

/// Windows Firewall as a whole.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    pub profiles: Vec<ProfileState>,
    /// Group Policy or MDM overrides local rules (NET_FW_MODIFY_STATE ≠ OK).
    pub policy_override: bool,
    /// All Windows Firewall rules, ours included.
    pub rule_count: u32,
}

impl FirewallState {
    /// Block rules take effect only if the firewall is on for every active profile.
    pub fn enforcing(&self) -> bool {
        self.profiles
            .iter()
            .filter(|p| p.active)
            .all(|p| p.firewall_on)
    }
}

/// Boots more than this far apart are different boots (Windows adjusts the
/// boot time when the clock is set, but not to the millisecond).
pub const SAME_BOOT_MS: i64 = 30_000;

impl Expiry {
    /// Whether a rule with this end is over: time up, or another boot. Whether
    /// an app quit is the caller's to tell.
    pub fn over(&self, now_ms: i64, boot_ms: Option<i64>) -> bool {
        match *self {
            Expiry::At { ms } => now_ms >= ms,
            Expiry::AppQuits => false,
            Expiry::Restart { boot_ms: then } => {
                boot_ms.is_some_and(|now| (now - then).abs() > SAME_BOOT_MS)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiries_end_with_time_and_reboots() {
        let at = Expiry::At { ms: 1_000 };
        assert!(!at.over(999, None));
        assert!(at.over(1_000, None));
        let restart = Expiry::Restart { boot_ms: 50_000 };
        // The same boot, with the clock nudged; unknown; a later boot.
        assert!(!restart.over(0, Some(52_000)));
        assert!(!restart.over(0, None));
        assert!(restart.over(0, Some(50_000 + 3_600_000)));
        assert!(!Expiry::AppQuits.over(i64::MAX, Some(0)));
        assert_eq!(
            serde_json::to_string(&Expiry::At { ms: 5 }).unwrap(),
            r#"{"kind":"at","ms":5}"#
        );
    }

    #[test]
    fn mode_names_round_trip() {
        for mode in [Mode::Off, Mode::ClickToBlock, Mode::AskToConnect] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                format!("\"{}\"", mode.as_str())
            );
        }
        assert_eq!(Mode::parse("ask"), None);
    }
}
