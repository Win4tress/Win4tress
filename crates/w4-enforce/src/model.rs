//! Windows Firewall rules: the ones we want, the ones that exist, and how a
//! stored win4tress rule becomes Windows Firewall rules (SPEC §7.2).

use w4_core::ask::{BaselineEntry, BaselineTarget};
use w4_core::firewall::{Action, Direction, RuleId, RuleRecord, Scope};

use crate::address::{AddressSet, complement};

/// Windows' "any protocol".
pub const PROTOCOL_ANY: i32 = 256;
pub const PROTOCOL_TCP: i32 = 6;
pub const PROTOCOL_UDP: i32 = 17;
/// NET_FW_PROFILE2_ALL.
pub const PROFILES_ALL: i32 = 0x7FFF_FFFF;
const DESCRIPTION_PREFIX: &str = "win4tress rule ";
/// Every rule we write is named `win4tress: <app> (<In|Out>, <Allow|Block>) #<id>`.
pub const NAME_PREFIX: &str = "win4tress: ";
/// DNS and DNS over TLS.
const DNS_PORTS: &str = "53,853";

/// Rules win4tress always wants that aren't stored rules have negative ids.
pub const BLOCK_ALL_IN: RuleId = -1;
pub const BLOCK_ALL_OUT: RuleId = -2;
/// Protected components: one part per program.
pub const PROTECTED: RuleId = -10;
/// Ask to Connect's baseline of Windows services: one part per entry.
pub const BASELINE: RuleId = -20;

/// What a Windows Firewall rule matches for one app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppTarget {
    /// A Win32 executable, by full path.
    Program(String),
    /// Services inside a shared svchost: one Windows Firewall rule per service.
    Services {
        program: String,
        services: Vec<String>,
    },
    /// A Store/MSIX app, by package family name (its AppContainer SID is derived).
    Package { family: String },
    /// The kernel (process ID 4).
    System,
}

/// Which stored rule a Windows Firewall rule implements, and which part of it
/// (an svchost group with several services needs one rule per service).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleKey {
    pub rule: RuleId,
    pub part: u16,
}

impl RuleKey {
    /// Written as the rule's description, which nothing else in the UI shows.
    pub fn description(&self) -> String {
        format!("{DESCRIPTION_PREFIX}{}/{}", self.rule, self.part)
    }

    pub fn parse(description: &str) -> Option<RuleKey> {
        let (rule, part) = description
            .strip_prefix(DESCRIPTION_PREFIX)?
            .split_once('/')?;
        Some(RuleKey {
            rule: rule.parse().ok()?,
            part: part.parse().ok()?,
        })
    }
}

/// A Windows Firewall rule as we want it. Local ports and addresses are
/// unrestricted and it applies to all profiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsRule {
    pub key: RuleKey,
    pub name: String,
    pub inbound: bool,
    pub block: bool,
    pub program: Option<String>,
    pub service: Option<String>,
    pub package_sid: Option<String>,
    pub remote: AddressSet,
    pub enabled: bool,
    /// [`PROTOCOL_ANY`] unless ports are set.
    pub protocol: i32,
    /// Remote ports, e.g. `53,853`; empty for any (needs TCP or UDP when set).
    pub remote_ports: String,
}

/// A rule in our Windows Firewall group, as read back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActualRule {
    pub name: String,
    pub description: String,
    pub inbound: bool,
    pub block: bool,
    pub program: Option<String>,
    pub service: Option<String>,
    pub package_sid: Option<String>,
    pub remote: AddressSet,
    pub local: AddressSet,
    pub protocol: i32,
    /// "*" or empty when unrestricted.
    pub local_ports: String,
    pub remote_ports: String,
    pub enabled: bool,
    pub profiles: i32,
}

impl ActualRule {
    pub fn key(&self) -> Option<RuleKey> {
        RuleKey::parse(&self.description)
    }
}

/// One Windows rule's traffic condition, from a stored rule's scope.
struct Condition {
    /// Added to the part number: 0, or 100/200/300 for the DNS rules.
    part_base: u16,
    protocol: i32,
    remote_ports: &'static str,
    remote: AddressSet,
}

fn conditions(scope: &Scope, addresses: &dyn Fn(&str) -> Vec<String>) -> Vec<Condition> {
    let any = |part_base, remote| Condition {
        part_base,
        protocol: PROTOCOL_ANY,
        remote_ports: "",
        remote,
    };
    let entries = |hosts: &[String]| -> Vec<String> {
        let mut all: Vec<String> = hosts.iter().flat_map(|h| addresses(h)).collect();
        all.sort();
        all.dedup();
        all
    };
    match scope {
        Scope::Any => vec![any(0, AddressSet::Any)],
        // No addresses known yet: no rule. (An empty list would mean "any".)
        Scope::Hosts { hosts } => {
            let list = entries(hosts);
            if list.is_empty() {
                Vec::new()
            } else {
                vec![any(0, AddressSet::List(list.into_iter().collect()))]
            }
        }
        Scope::Except { hosts } => {
            let rest = complement(&entries(hosts));
            vec![any(0, AddressSet::List(rest.into_iter().collect()))]
        }
        Scope::Dns => {
            let doh = w4_core::net::doh_servers()
                .into_iter()
                .map(|ip| ip.to_string())
                .collect();
            vec![
                Condition {
                    part_base: 100,
                    protocol: PROTOCOL_TCP,
                    remote_ports: DNS_PORTS,
                    remote: AddressSet::Any,
                },
                Condition {
                    part_base: 200,
                    protocol: PROTOCOL_UDP,
                    remote_ports: DNS_PORTS,
                    remote: AddressSet::Any,
                },
                any(300, AddressSet::List(doh)),
            ]
        }
    }
}

/// The Windows Firewall rules for one stored rule; `None` when the app can't
/// be targeted (a package whose SID can't be derived). `addresses` turns one
/// host entry into Windows address entries: itself if it's an address, else
/// the addresses the app received for that name.
pub fn project(
    rule: &RuleRecord,
    app_name: &str,
    target: &AppTarget,
    package_sid: impl Fn(&str) -> Option<String>,
    addresses: &dyn Fn(&str) -> Vec<String>,
) -> Option<Vec<WindowsRule>> {
    let dir = match rule.direction {
        Direction::In => "In",
        Direction::Out => "Out",
    };
    let act = match rule.action {
        Action::Allow => "Allow",
        Action::Block => "Block",
    };
    // Named so the rule reads right in Windows Firewall's own console too.
    let what = match rule.scope {
        Scope::Any => "",
        Scope::Hosts { .. } => " hosts",
        Scope::Except { .. } => " all but hosts",
        Scope::Dns => " own DNS",
    };
    let parts: Vec<(Option<String>, Option<String>, Option<String>)> = match target {
        AppTarget::Program(path) => vec![(Some(path.clone()), None, None)],
        AppTarget::System => vec![(Some("System".into()), None, None)],
        AppTarget::Services { program, services } => services
            .iter()
            .map(|s| (Some(program.clone()), Some(s.clone()), None))
            .collect(),
        AppTarget::Package { family } => vec![(None, None, Some(package_sid(family)?))],
    };
    let conditions = conditions(&rule.scope, addresses);
    let mut out = Vec::new();
    for (i, (program, service, package)) in parts.into_iter().enumerate() {
        for c in &conditions {
            let part = c.part_base + i as u16;
            let suffix = if part == 0 {
                String::new()
            } else {
                format!(".{part}")
            };
            out.push(WindowsRule {
                key: RuleKey {
                    rule: rule.id,
                    part,
                },
                name: format!(
                    "{NAME_PREFIX}{app_name} ({dir}, {act}{what}) #{}{suffix}",
                    rule.id
                ),
                inbound: rule.direction == Direction::In,
                block: rule.action == Action::Block,
                program: program.clone(),
                service: service.clone(),
                package_sid: package.clone(),
                remote: c.remote.clone(),
                enabled: rule.enabled,
                protocol: c.protocol,
                remote_ports: c.remote_ports.into(),
            });
        }
    }
    Some(out)
}

/// Block All (SPEC §7.5): every program, both ways, everything but this PC.
pub fn block_all() -> Vec<WindowsRule> {
    let rest = AddressSet::List(complement(&[]).into_iter().collect());
    [(BLOCK_ALL_IN, true, "In"), (BLOCK_ALL_OUT, false, "Out")]
        .into_iter()
        .map(|(rule, inbound, dir)| WindowsRule {
            key: RuleKey { rule, part: 0 },
            name: format!("{NAME_PREFIX}Block All ({dir})"),
            inbound,
            block: true,
            program: None,
            service: None,
            package_sid: None,
            remote: rest.clone(),
            enabled: true,
            protocol: PROTOCOL_ANY,
            remote_ports: String::new(),
        })
        .collect()
}

/// win4tress's own programs may always connect out (SPEC §7.4 "Protected
/// components"). Block rules still win, so Block All stops them too.
pub fn protected(programs: &[(String, String)]) -> Vec<WindowsRule> {
    programs
        .iter()
        .enumerate()
        .map(|(i, (label, path))| WindowsRule {
            key: RuleKey {
                rule: PROTECTED,
                part: i as u16,
            },
            name: format!("{NAME_PREFIX}{label} (Out, Allow, protected)"),
            inbound: false,
            block: false,
            program: Some(path.clone()),
            service: None,
            package_sid: None,
            remote: AddressSet::Any,
            enabled: true,
            protocol: PROTOCOL_ANY,
            remote_ports: String::new(),
        })
        .collect()
}

/// Ask to Connect's baseline (SPEC §7.4): Windows services that may always
/// connect out, so Windows keeps working. `expand` expands environment
/// variables in program paths.
pub fn baseline(entries: &[BaselineEntry], expand: &dyn Fn(&str) -> String) -> Vec<WindowsRule> {
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let (program, service) = match &e.target {
                BaselineTarget::Service(name) => (None, Some(name.clone())),
                BaselineTarget::Program(path) => (Some(expand(path)), None),
            };
            WindowsRule {
                key: RuleKey {
                    rule: BASELINE,
                    part: i as u16,
                },
                name: format!("{NAME_PREFIX}{} (Out, Allow, baseline)", e.label),
                inbound: false,
                block: false,
                program,
                service,
                package_sid: None,
                remote: AddressSet::Any,
                enabled: true,
                protocol: PROTOCOL_ANY,
                remote_ports: String::new(),
            }
        })
        .collect()
}

/// `Name_Version_Arch_ResourceId_PublisherId` → `Name_PublisherId`.
pub fn package_family(full_name: &str) -> Option<String> {
    let parts: Vec<&str> = full_name.split('_').collect();
    match (parts.first(), parts.last()) {
        (Some(name), Some(publisher))
            if parts.len() >= 5 && !name.is_empty() && !publisher.is_empty() =>
        {
            Some(format!("{name}_{publisher}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::Origin;

    use super::*;

    fn rule(id: RuleId, direction: Direction, action: Action) -> RuleRecord {
        RuleRecord {
            id,
            app: 7,
            direction,
            action,
            scope: Scope::Any,
            enabled: true,
            origin: Origin::User,
            note: None,
            created_ms: 0,
            updated_ms: 0,
            expires: None,
            revert: None,
        }
    }

    /// Names resolve to nothing; addresses to themselves.
    fn literal_only(host: &str) -> Vec<String> {
        crate::address::literal(host).into_iter().collect()
    }

    const CURL: &str = r"C:\Tools\curl.exe";

    fn program(r: &RuleRecord, addresses: &dyn Fn(&str) -> Vec<String>) -> Vec<WindowsRule> {
        project(
            r,
            "curl",
            &AppTarget::Program(CURL.into()),
            |_| None,
            addresses,
        )
        .unwrap()
    }

    #[test]
    fn program_rule() {
        let r = program(&rule(12, Direction::Out, Action::Block), &literal_only);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "win4tress: curl (Out, Block) #12");
        assert_eq!(r[0].key, RuleKey { rule: 12, part: 0 });
        assert!(r[0].block && !r[0].inbound && r[0].enabled);
        assert_eq!(r[0].program.as_deref(), Some(CURL));
        assert_eq!(r[0].remote, AddressSet::Any);
        assert_eq!(
            (r[0].protocol, r[0].remote_ports.as_str()),
            (PROTOCOL_ANY, "")
        );
    }

    #[test]
    fn svchost_group_gets_one_rule_per_service() {
        let target = AppTarget::Services {
            program: r"C:\Windows\System32\svchost.exe".into(),
            services: vec!["Dnscache".into(), "NlaSvc".into()],
        };
        let r = project(
            &rule(3, Direction::In, Action::Allow),
            "Network services",
            &target,
            |_| None,
            &literal_only,
        )
        .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].name, "win4tress: Network services (In, Allow) #3.1");
        assert_eq!(r[1].service.as_deref(), Some("NlaSvc"));
        assert_eq!(r[1].key, RuleKey { rule: 3, part: 1 });
    }

    #[test]
    fn package_rule_uses_the_sid() {
        let target = AppTarget::Package {
            family: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into(),
        };
        let block = rule(5, Direction::Out, Action::Block);
        let r = project(
            &block,
            "Calculator",
            &target,
            |f| Some(format!("S-1-15-2-{}", f.len())),
            &literal_only,
        )
        .unwrap();
        assert_eq!(r[0].program, None);
        assert_eq!(r[0].package_sid.as_deref(), Some("S-1-15-2-41"));
        // No SID: the app can't be targeted (as opposed to "nothing to write").
        assert_eq!(
            project(&block, "Calculator", &target, |_| None, &literal_only),
            None
        );
    }

    #[test]
    fn host_scopes() {
        let mut r = rule(7, Direction::Out, Action::Block);
        let names = |host: &str| -> Vec<String> {
            match host {
                "ads.example.com" => vec!["203.0.113.5".into(), "203.0.113.6".into()],
                other => literal_only(other),
            }
        };
        r.scope = Scope::Hosts {
            hosts: vec!["ads.example.com".into(), "8.8.8.8".into()],
        };
        let hosts = program(&r, &names);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "win4tress: curl (Out, Block hosts) #7");
        assert_eq!(
            hosts[0].remote,
            AddressSet::parse("203.0.113.5,203.0.113.6,8.8.8.8")
        );
        // A name with no addresses yet gives no rule, never "any".
        r.scope = Scope::Hosts {
            hosts: vec!["unseen.example.com".into()],
        };
        assert!(program(&r, &names).is_empty());

        // Allow only: a block on everything else (this PC excepted).
        r.scope = Scope::Except {
            hosts: vec!["8.8.8.8".into()],
        };
        let except = program(&r, &names);
        assert_eq!(
            except[0].name,
            "win4tress: curl (Out, Block all but hosts) #7"
        );
        let AddressSet::List(rest) = &except[0].remote else {
            panic!("a list");
        };
        assert!(rest.contains("0.0.0.0-8.8.8.7") && rest.contains("8.8.8.9-126.255.255.255"));
    }

    #[test]
    fn own_dns_scope_is_three_rules() {
        let mut r = rule(9, Direction::Out, Action::Block);
        r.scope = Scope::Dns;
        let dns = program(&r, &literal_only);
        let shapes: Vec<(u16, i32, &str)> = dns
            .iter()
            .map(|w| (w.key.part, w.protocol, w.remote_ports.as_str()))
            .collect();
        assert_eq!(
            shapes,
            [
                (100, PROTOCOL_TCP, "53,853"),
                (200, PROTOCOL_UDP, "53,853"),
                (300, PROTOCOL_ANY, "")
            ]
        );
        assert_eq!(dns[0].name, "win4tress: curl (Out, Block own DNS) #9.100");
        let AddressSet::List(doh) = &dns[2].remote else {
            panic!("a list");
        };
        assert!(doh.contains("1.1.1.1") && doh.contains("8.8.8.8"));
    }

    #[test]
    fn built_in_rules() {
        let all = block_all();
        assert_eq!(all.len(), 2);
        assert!(
            all.iter()
                .all(|r| r.block && r.program.is_none() && r.key.rule < 0)
        );
        assert_eq!(all[0].name, "win4tress: Block All (In)");
        let AddressSet::List(rest) = &all[1].remote else {
            panic!("a list");
        };
        assert!(!rest.iter().any(|e| e.starts_with("127.")));

        let own = protected(&[(
            "win4tress service".into(),
            r"C:\win4tress\win4tress-svc.exe".into(),
        )]);
        assert_eq!(
            own[0].name,
            "win4tress: win4tress service (Out, Allow, protected)"
        );
        assert_eq!(
            own[0].key,
            RuleKey {
                rule: PROTECTED,
                part: 0
            }
        );
        assert!(!own[0].block && !own[0].inbound);
        // Negative ids survive the description round trip.
        assert_eq!(RuleKey::parse(&own[0].key.description()), Some(own[0].key));
    }

    #[test]
    fn key_round_trips_through_the_description() {
        let k = RuleKey {
            rule: 1234,
            part: 2,
        };
        assert_eq!(RuleKey::parse(&k.description()), Some(k));
        assert_eq!(RuleKey::parse("something else"), None);
        assert_eq!(RuleKey::parse("win4tress rule x/0"), None);
    }

    #[test]
    fn baseline_rules_by_service_or_program() {
        let rules = baseline(&w4_core::ask::baseline(), &|p: &str| {
            p.replace("%ProgramFiles%", r"C:\Program Files")
        });
        let dns = rules
            .iter()
            .find(|r| r.service.as_deref() == Some("Dnscache"))
            .expect("DNS Client is in the baseline");
        assert_eq!(
            dns.program, None,
            "a service rule matches whatever hosts it"
        );
        assert!(!dns.inbound && !dns.block && dns.enabled);
        assert_eq!(dns.name, "win4tress: DNS Client (Out, Allow, baseline)");
        let mpcmd = rules
            .iter()
            .find(|r| r.program.is_some())
            .expect("a program entry");
        assert_eq!(
            mpcmd.program.as_deref(),
            Some(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
        );
        // Each a part of the one built-in rule, with unique keys.
        let keys: std::collections::BTreeSet<_> = rules.iter().map(|r| r.key).collect();
        assert_eq!(keys.len(), rules.len());
        assert!(rules.iter().all(|r| r.key.rule == BASELINE));
    }

    #[test]
    fn package_family_from_full_name() {
        assert_eq!(
            package_family("Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe").as_deref(),
            Some("Microsoft.WindowsCalculator_8wekyb3d8bbwe")
        );
        assert_eq!(package_family("NotAPackage"), None);
    }
}
