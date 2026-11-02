//! Whether an app's connections are allowed or blocked, and why (SPEC §7.9):
//! the firewall being off, then block rules (ours or Windows'), then allow
//! rules, then the profile default. Block beats allow, as in Windows Firewall.
//! Approximate by design: ports, addresses and which network a connection uses
//! aren't weighed.

use std::collections::{BTreeSet, HashMap};

use w4_core::firewall::{
    Action, Direction, FirewallState, Mode, RuleRecord, Verdict, VerdictSource,
};

use crate::model::{ActualRule, AppTarget};

/// One of Windows Firewall's own rules that names an app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtherRule {
    pub name: String,
    pub inbound: bool,
    pub block: bool,
    /// NET_FW_PROFILE2 bits.
    pub profiles: i32,
}

struct Indexed {
    rule: OtherRule,
    /// Expanded and lowercased, like the keys below.
    program: Option<String>,
}

/// Windows Firewall's enabled rules outside our group, by the program, service
/// or package they name. Rules naming none of these apply to every app (port
/// rules, Core Networking) and aren't any app's own.
#[derive(Default)]
pub struct OtherRules {
    rules: Vec<Indexed>,
    by_program: HashMap<String, Vec<usize>>,
    /// Service name, or `*` for "all services".
    by_service: HashMap<String, Vec<usize>>,
    by_package: HashMap<String, Vec<usize>>,
}

impl OtherRules {
    /// `expand` turns `%SystemRoot%`-style variables in program paths into paths.
    pub fn new(rules: Vec<ActualRule>, expand: impl Fn(&str) -> String) -> OtherRules {
        let mut out = OtherRules::default();
        for a in rules.into_iter().filter(|a| a.enabled) {
            let program = a.program.as_deref().map(|p| expand(p).to_lowercase());
            let service = a.service.as_deref().map(str::to_lowercase);
            let package = a.package_sid.as_deref().map(str::to_lowercase);
            if program.is_none() && service.is_none() && package.is_none() {
                continue;
            }
            let i = out.rules.len();
            for (key, map) in [
                (&program, &mut out.by_program),
                (&service, &mut out.by_service),
                (&package, &mut out.by_package),
            ] {
                if let Some(k) = key {
                    map.entry(k.clone()).or_default().push(i);
                }
            }
            out.rules.push(Indexed {
                rule: OtherRule {
                    name: a.name,
                    inbound: a.inbound,
                    block: a.block,
                    profiles: a.profiles,
                },
                program,
            });
        }
        out
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules naming this app. `path` is its executable; `package_sid` its
    /// AppContainer SID if it's a Store app.
    pub fn for_app(
        &self,
        target: &AppTarget,
        path: &str,
        package_sid: Option<&str>,
    ) -> Vec<&OtherRule> {
        let get = |map: &HashMap<String, Vec<usize>>, key: &str| -> Vec<usize> {
            map.get(&key.to_lowercase()).cloned().unwrap_or_default()
        };
        let mut hits: BTreeSet<usize> = BTreeSet::new();
        match target {
            AppTarget::Program(p) => hits.extend(get(&self.by_program, p)),
            AppTarget::System => hits.extend(get(&self.by_program, "system")),
            AppTarget::Services { program, services } => {
                let program = program.to_lowercase();
                for s in services.iter().map(String::as_str).chain(["*"]) {
                    hits.extend(
                        get(&self.by_service, s).into_iter().filter(|&i| {
                            self.rules[i].program.as_ref().is_none_or(|p| *p == program)
                        }),
                    );
                }
            }
            AppTarget::Package { .. } => {
                if let Some(sid) = package_sid {
                    hits.extend(get(&self.by_package, sid));
                }
                hits.extend(get(&self.by_program, path));
            }
        }
        hits.into_iter().map(|i| &self.rules[i].rule).collect()
    }
}

fn profile_bit(name: &str) -> i32 {
    match name {
        "domain" => 1,
        "private" => 2,
        "public" => 4,
        _ => 0,
    }
}

/// The profiles that count now: those with a network, or all if none has one.
fn active(state: &FirewallState) -> impl Iterator<Item = &w4_core::firewall::ProfileState> {
    let any = state.profiles.iter().any(|p| p.active);
    state.profiles.iter().filter(move |p| p.active || !any)
}

/// Every profile in use blocks connections in this direction that no rule allows.
pub fn default_blocks(state: &FirewallState, inbound: bool) -> bool {
    let mut profiles = active(state).peekable();
    profiles.peek().is_some()
        && profiles.all(|p| {
            if inbound {
                p.inbound_default_block
            } else {
                p.outbound_default_block
            }
        })
}

/// `ours`: the app's win4tress rule for this direction (any scope). `others`:
/// the app's Windows Firewall rules, both directions. In mode Off our rules
/// are switched off, so they don't count; Block All blocks everything anyway.
pub fn verdict(
    direction: Direction,
    ours: Option<&RuleRecord>,
    others: &[&OtherRule],
    state: &FirewallState,
    mode: Mode,
    block_all: bool,
) -> Verdict {
    let inbound = direction == Direction::In;
    let mask: i32 = active(state)
        .map(|p| profile_bit(&p.name))
        .fold(0, |m, b| m | b);
    let decided = |allowed, by, rules| Verdict { allowed, by, rules };
    if active(state).any(|p| !p.firewall_on) {
        return decided(true, VerdictSource::FirewallOff, Vec::new());
    }
    if block_all {
        return decided(
            false,
            VerdictSource::Win4tress,
            vec!["Block All".to_string()],
        );
    }
    let ours = ours.filter(|r| r.enabled && mode != Mode::Off);
    let applying = |block: bool| -> Vec<String> {
        others
            .iter()
            .filter(|r| r.inbound == inbound && r.block == block && r.profiles & mask != 0)
            .map(|r| r.name.clone())
            .collect()
    };
    if ours.is_some_and(|r| r.action == Action::Block) {
        return decided(false, VerdictSource::Win4tress, Vec::new());
    }
    let blocks = applying(true);
    if !blocks.is_empty() {
        return decided(false, VerdictSource::WindowsRule, blocks);
    }
    if ours.is_some_and(|r| r.action == Action::Allow) {
        return decided(true, VerdictSource::Win4tress, Vec::new());
    }
    let allows = applying(false);
    if !allows.is_empty() {
        return decided(true, VerdictSource::WindowsRule, allows);
    }
    decided(
        !default_blocks(state, inbound),
        VerdictSource::Default,
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::{Origin, ProfileState, Scope};

    use super::*;
    use crate::model::PROFILES_ALL;

    fn other(name: &str, inbound: bool, block: bool) -> ActualRule {
        ActualRule {
            name: name.into(),
            inbound,
            block,
            enabled: true,
            profiles: PROFILES_ALL,
            ..Default::default()
        }
    }

    fn program(mut r: ActualRule, path: &str) -> ActualRule {
        r.program = Some(path.into());
        r
    }

    fn state(firewall_on: bool, inbound_block: bool, outbound_block: bool) -> FirewallState {
        let profile = |name: &str, active| ProfileState {
            name: name.into(),
            active,
            firewall_on,
            inbound_default_block: inbound_block,
            outbound_default_block: outbound_block,
        };
        FirewallState {
            profiles: vec![
                profile("domain", false),
                profile("private", true),
                profile("public", false),
            ],
            policy_override: false,
            rule_count: 0,
        }
    }

    fn ours(direction: Direction, action: Action, enabled: bool) -> RuleRecord {
        RuleRecord {
            id: 1,
            app: 1,
            direction,
            action,
            scope: Scope::Any,
            enabled,
            origin: Origin::User,
            note: None,
            created_ms: 0,
            updated_ms: 0,
            expires: None,
            revert: None,
        }
    }

    const EXE: &str = r"C:\Games\server.exe";

    fn expand(p: &str) -> String {
        p.replace("%ProgramFiles%", r"C:\Program Files")
    }

    #[test]
    fn rules_are_matched_to_apps() {
        let rules = OtherRules::new(
            vec![
                program(other("Game server", true, false), r"c:\games\SERVER.exe"),
                program(other("Tool", true, false), r"%ProgramFiles%\Tool\tool.exe"),
                // Every program on a port: nobody's own rule.
                other("Core Networking", true, false),
                {
                    let mut r = program(
                        other("DNS", false, false),
                        r"C:\Windows\System32\svchost.exe",
                    );
                    r.service = Some("Dnscache".into());
                    r
                },
                {
                    let mut r = other("All services", true, true);
                    r.service = Some("*".into());
                    r
                },
                {
                    let mut r = other("Calculator", false, false);
                    r.package_sid = Some("S-1-15-2-1".into());
                    r
                },
                {
                    let mut r = program(other("Off", true, false), EXE);
                    r.enabled = false;
                    r
                },
            ],
            expand,
        );
        assert_eq!(rules.len(), 5);
        let names = |target: &AppTarget, path: &str, sid: Option<&str>| -> Vec<String> {
            rules
                .for_app(target, path, sid)
                .into_iter()
                .map(|r| r.name.clone())
                .collect()
        };
        assert_eq!(
            names(&AppTarget::Program(EXE.into()), EXE, None),
            ["Game server"]
        );
        let tool = r"C:\Program Files\Tool\tool.exe";
        assert_eq!(
            names(&AppTarget::Program(tool.into()), tool, None),
            ["Tool"]
        );
        let svchost = r"C:\Windows\System32\svchost.exe";
        let dns = AppTarget::Services {
            program: svchost.into(),
            services: vec!["Dnscache".into()],
        };
        assert_eq!(names(&dns, svchost, None), ["DNS", "All services"]);
        let calc = AppTarget::Package {
            family: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into(),
        };
        assert_eq!(
            names(
                &calc,
                r"C:\Program Files\WindowsApps\calc.exe",
                Some("s-1-15-2-1")
            ),
            ["Calculator"]
        );
    }

    #[test]
    fn verdict_order() {
        let fw = state(true, true, false);
        let allow = OtherRule {
            name: "Allow in".into(),
            inbound: true,
            block: false,
            profiles: PROFILES_ALL,
        };
        let block = OtherRule {
            name: "Block in".into(),
            block: true,
            ..allow.clone()
        };
        let v = |d, o: Option<&RuleRecord>, others: &[&OtherRule], fw: &FirewallState, m| {
            let v = verdict(d, o, others, fw, m, false);
            (v.allowed, v.by, v.rules)
        };
        // Block All beats every allow.
        let all = verdict(Direction::In, None, &[&allow], &fw, Mode::Off, true);
        assert_eq!(
            (all.allowed, all.by, all.rules),
            (
                false,
                VerdictSource::Win4tress,
                vec!["Block All".to_string()]
            )
        );
        let (out, inn) = (Direction::Out, Direction::In);
        use VerdictSource::*;

        // Defaults: outgoing allowed, incoming blocked.
        assert_eq!(
            v(out, None, &[], &fw, Mode::ClickToBlock),
            (true, Default, vec![])
        );
        assert_eq!(
            v(inn, None, &[], &fw, Mode::ClickToBlock),
            (false, Default, vec![])
        );
        // A Windows allow rule opens incoming; a Windows block rule beats it.
        assert_eq!(
            v(inn, None, &[&allow], &fw, Mode::ClickToBlock),
            (true, WindowsRule, vec!["Allow in".to_string()])
        );
        assert_eq!(
            v(inn, None, &[&allow, &block], &fw, Mode::ClickToBlock),
            (false, WindowsRule, vec!["Block in".to_string()])
        );
        // Our block beats a Windows allow; our allow loses to a Windows block.
        let our_block = ours(inn, Action::Block, true);
        let our_allow = ours(inn, Action::Allow, true);
        assert_eq!(
            v(inn, Some(&our_block), &[&allow], &fw, Mode::ClickToBlock),
            (false, Win4tress, vec![])
        );
        assert_eq!(
            v(inn, Some(&our_allow), &[&block], &fw, Mode::ClickToBlock),
            (false, WindowsRule, vec!["Block in".to_string()])
        );
        // Mode Off and disabled rules: ours don't count.
        assert_eq!(
            v(inn, Some(&our_block), &[&allow], &fw, Mode::Off),
            (true, WindowsRule, vec!["Allow in".to_string()])
        );
        assert_eq!(
            v(
                out,
                Some(&ours(out, Action::Block, false)),
                &[],
                &fw,
                Mode::ClickToBlock
            ),
            (true, Default, vec![])
        );
        // A rule for a profile not in use doesn't apply.
        let public_only = OtherRule {
            profiles: 4,
            ..allow.clone()
        };
        assert_eq!(
            v(inn, None, &[&public_only], &fw, Mode::ClickToBlock),
            (false, Default, vec![])
        );
        // Outgoing blocked by default (Ask to Connect): only an allow opens it.
        let strict = state(true, true, true);
        assert_eq!(
            v(out, None, &[], &strict, Mode::ClickToBlock),
            (false, Default, vec![])
        );
        assert_eq!(
            v(
                out,
                Some(&ours(out, Action::Allow, true)),
                &[],
                &strict,
                Mode::ClickToBlock
            ),
            (true, Win4tress, vec![])
        );
        // Firewall off on the network in use: nothing is blocked, ours included.
        assert_eq!(
            v(
                inn,
                Some(&our_block),
                &[],
                &state(false, true, false),
                Mode::ClickToBlock
            ),
            (true, FirewallOff, vec![])
        );
    }

    #[test]
    fn defaults_follow_the_profiles_in_use() {
        let fw = state(true, true, false);
        assert!(default_blocks(&fw, true));
        assert!(!default_blocks(&fw, false));
        // No network at all: every profile counts.
        let mut offline = fw.clone();
        for p in &mut offline.profiles {
            p.active = false;
        }
        assert!(default_blocks(&offline, true));
        assert!(!default_blocks(&FirewallState::default(), true));
    }
}
