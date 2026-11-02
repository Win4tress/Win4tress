//! Reconciliation (SPEC §7.8): the changes that turn the rules in our Windows
//! Firewall group into the rules we want. Pure, so it's tested without Windows.

use std::collections::BTreeMap;

use crate::address::AddressSet;
use crate::model::{ActualRule, PROFILES_ALL, RuleKey, WindowsRule};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Create(WindowsRule),
    /// Set name, action, enabled and remote addresses in place. Used when only
    /// those differ, so a block rule never lapses.
    Update {
        name: String,
        rule: WindowsRule,
    },
    /// Delete and create again: anything else differs (program, direction,
    /// protocol, ports…), which setters can't always undo.
    Recreate {
        name: String,
        rule: WindowsRule,
    },
    Delete {
        name: String,
    },
}

/// Creates and updates come before deletes, so a block doesn't lapse while a set
/// of changes is applied. The exception is duplicates of one of our rules (only
/// tampering makes those): Windows removes the first rule with a given name, so
/// all copies are deleted first and the rule is created afresh.
pub fn plan(desired: &[WindowsRule], actual: &[ActualRule]) -> Vec<Change> {
    let mut by_key: BTreeMap<RuleKey, Vec<&ActualRule>> = BTreeMap::new();
    let mut deletes = Vec::new();
    for a in actual {
        match a.key() {
            Some(k) => by_key.entry(k).or_default().push(a),
            // In our group but not one of ours (or its description was edited).
            None => deletes.push(Change::Delete {
                name: a.name.clone(),
            }),
        }
    }

    let mut duplicates = Vec::new();
    let mut changes = Vec::new();
    for d in desired {
        match by_key.remove(&d.key).as_deref() {
            None => changes.push(Change::Create(d.clone())),
            Some([one]) => {
                if !shape_matches(one, d) {
                    changes.push(Change::Recreate {
                        name: one.name.clone(),
                        rule: d.clone(),
                    });
                } else if !details_match(one, d) {
                    changes.push(Change::Update {
                        name: one.name.clone(),
                        rule: d.clone(),
                    });
                }
            }
            Some(copies) => {
                duplicates.extend(copies.iter().map(|a| Change::Delete {
                    name: a.name.clone(),
                }));
                changes.push(Change::Create(d.clone()));
            }
        }
    }
    // Rules we no longer want.
    for rules in by_key.into_values() {
        deletes.extend(rules.iter().map(|a| Change::Delete {
            name: a.name.clone(),
        }));
    }
    duplicates.extend(changes);
    duplicates.extend(deletes);
    duplicates
}

/// An update that only renames one of our rules (its app's display name
/// changed). That's our own doing, not a sign that something else touched the
/// firewall.
pub fn is_rename_only(change: &Change, actual: &[ActualRule]) -> bool {
    match change {
        Change::Update { name, rule } => actual.iter().find(|a| &a.name == name).is_some_and(|a| {
            a.block == rule.block && a.enabled == rule.enabled && a.remote == rule.remote
        }),
        _ => false,
    }
}

fn same(a: &Option<String>, b: &Option<String>) -> bool {
    let norm = |s: &Option<String>| {
        s.as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
    };
    norm(a) == norm(b)
}

fn unrestricted(ports: &str) -> bool {
    ports.is_empty() || ports == "*"
}

/// Port lists by meaning: order, spaces and "any" spellings don't matter.
fn same_ports(a: &str, b: &str) -> bool {
    let norm = |p: &str| -> Vec<String> {
        if unrestricted(p) {
            return Vec::new();
        }
        let mut v: Vec<String> = p.split(',').map(|s| s.trim().to_string()).collect();
        v.sort();
        v
    };
    norm(a) == norm(b)
}

/// What setters can't reliably change: who the rule applies to and what traffic.
fn shape_matches(a: &ActualRule, d: &WindowsRule) -> bool {
    a.inbound == d.inbound
        && same(&a.program, &d.program)
        && same(&a.service, &d.service)
        && same(&a.package_sid, &d.package_sid)
        && a.protocol == d.protocol
        && same_ports(&a.remote_ports, &d.remote_ports)
        && unrestricted(&a.local_ports)
        && a.local == AddressSet::Any
        && a.profiles == PROFILES_ALL
}

fn details_match(a: &ActualRule, d: &WindowsRule) -> bool {
    a.name == d.name && a.block == d.block && a.enabled == d.enabled && a.remote == d.remote
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::model::{PROTOCOL_ANY, PROTOCOL_TCP};

    fn want(rule: i64, part: u16) -> WindowsRule {
        WindowsRule {
            key: RuleKey { rule, part },
            name: format!("win4tress: app (Out, Block) #{rule}.{part}"),
            inbound: false,
            block: true,
            program: Some(format!(r"C:\Apps\app{rule}.exe")),
            service: None,
            package_sid: None,
            remote: AddressSet::Any,
            enabled: true,
            protocol: PROTOCOL_ANY,
            remote_ports: String::new(),
        }
    }

    /// What Windows would hold after creating `w`.
    fn written(w: &WindowsRule) -> ActualRule {
        ActualRule {
            name: w.name.clone(),
            description: w.key.description(),
            inbound: w.inbound,
            block: w.block,
            program: w.program.clone(),
            service: w.service.clone(),
            package_sid: w.package_sid.clone(),
            remote: w.remote.clone(),
            local: AddressSet::Any,
            protocol: w.protocol,
            local_ports: "*".into(),
            remote_ports: if w.remote_ports.is_empty() {
                "*".into()
            } else {
                w.remote_ports.clone()
            },
            enabled: w.enabled,
            profiles: PROFILES_ALL,
        }
    }

    #[test]
    fn ports_and_protocol_are_compared_by_meaning() {
        let mut dns = want(1, 100);
        dns.protocol = PROTOCOL_TCP;
        dns.remote_ports = "53,853".into();
        let mut a = written(&dns);
        a.remote_ports = "853, 53".into();
        assert!(plan(std::slice::from_ref(&dns), std::slice::from_ref(&a)).is_empty());
        // Another port or protocol needs the rule made again.
        a.remote_ports = "53".into();
        assert!(matches!(
            plan(std::slice::from_ref(&dns), std::slice::from_ref(&a))[..],
            [Change::Recreate { .. }]
        ));
        let mut udp = written(&dns);
        udp.protocol = 17;
        assert!(matches!(
            plan(std::slice::from_ref(&dns), &[udp])[..],
            [Change::Recreate { .. }]
        ));
    }

    /// A stand-in for Windows Firewall: rules in order, removal by first name match.
    fn apply(actual: &mut Vec<ActualRule>, changes: &[Change]) {
        for c in changes {
            match c {
                Change::Create(w) => actual.push(written(w)),
                Change::Update { name, rule } => {
                    if let Some(a) = actual.iter_mut().find(|a| &a.name == name) {
                        a.name = rule.name.clone();
                        a.block = rule.block;
                        a.enabled = rule.enabled;
                        a.remote = rule.remote.clone();
                    }
                }
                Change::Recreate { name, rule } => {
                    if let Some(i) = actual.iter().position(|a| &a.name == name) {
                        actual.remove(i);
                    }
                    actual.push(written(rule));
                }
                Change::Delete { name } => {
                    if let Some(i) = actual.iter().position(|a| &a.name == name) {
                        actual.remove(i);
                    }
                }
            }
        }
    }

    #[test]
    fn in_sync_means_no_changes() {
        let desired = vec![want(1, 0), want(2, 0)];
        let actual: Vec<_> = desired.iter().map(written).collect();
        assert!(plan(&desired, &actual).is_empty());
    }

    #[test]
    fn read_back_differences_alone_are_not_changes() {
        let mut d = want(1, 0);
        d.remote = AddressSet::parse("8.8.8.8");
        let mut a = written(&d);
        a.remote = AddressSet::parse("8.8.8.8/255.255.255.255");
        a.program = a.program.map(|p| p.to_uppercase());
        a.local_ports = String::new();
        assert!(plan(&[d], &[a]).is_empty());
    }

    #[test]
    fn creates_updates_recreates_and_deletes() {
        let keep = want(1, 0);
        let mut disabled = want(2, 0);
        disabled.enabled = false;
        let moved = want(3, 0);
        let new = want(4, 0);
        let mut moved_actual = written(&moved);
        moved_actual.program = Some(r"C:\Elsewhere\other.exe".into());
        let actual = vec![
            written(&keep),
            written(&want(2, 0)),
            moved_actual,
            written(&want(9, 0)),
            ActualRule {
                name: "stray".into(),
                description: "added by hand".into(),
                ..Default::default()
            },
        ];
        let changes = plan(
            &[keep, disabled.clone(), moved.clone(), new.clone()],
            &actual,
        );
        assert!(changes.contains(&Change::Create(new)));
        assert!(changes.contains(&Change::Update {
            name: disabled.name.clone(),
            rule: disabled
        }));
        assert!(changes.contains(&Change::Recreate {
            name: moved.name.clone(),
            rule: moved
        }));
        assert!(changes.contains(&Change::Delete {
            name: "stray".into()
        }));
        assert!(changes.contains(&Change::Delete {
            name: want(9, 0).name
        }));
        // Deletes come last.
        let first_delete = changes
            .iter()
            .position(|c| matches!(c, Change::Delete { .. }))
            .unwrap();
        assert!(
            changes[first_delete..]
                .iter()
                .all(|c| matches!(c, Change::Delete { .. }))
        );
    }

    #[test]
    fn renames_are_told_apart_from_tampering() {
        let d = want(1, 0);
        let mut renamed = written(&d);
        renamed.name = "win4tress: old name (Out, Block) #1.0".into();
        let changes = plan(std::slice::from_ref(&d), std::slice::from_ref(&renamed));
        assert_eq!(changes.len(), 1);
        assert!(is_rename_only(&changes[0], &[renamed.clone()]));

        let mut disabled = renamed;
        disabled.enabled = false;
        let changes = plan(std::slice::from_ref(&d), std::slice::from_ref(&disabled));
        assert!(!is_rename_only(&changes[0], &[disabled]));
    }

    #[test]
    fn duplicates_are_all_removed_then_created_once() {
        let d = want(1, 0);
        let actual = vec![written(&d), written(&d)];
        let changes = plan(std::slice::from_ref(&d), &actual);
        assert_eq!(
            changes,
            vec![
                Change::Delete {
                    name: d.name.clone()
                },
                Change::Delete {
                    name: d.name.clone()
                },
                Change::Create(d),
            ]
        );
    }

    fn arb_actual() -> impl Strategy<Value = ActualRule> {
        (
            0i64..6,
            0u16..2,
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            0usize..3,
        )
            .prop_map(|(rule, part, block, enabled, tampered, ports)| {
                let mut a = written(&want(rule, part));
                a.block = block;
                a.enabled = enabled;
                if tampered {
                    a.protocol = 6;
                }
                a.remote_ports = ["*", "443", ""][ports].into();
                a
            })
    }

    proptest! {
        /// Whatever is in the group (duplicates, strays, tampering), applying the
        /// plan leaves exactly the desired rules, and planning again finds nothing.
        #[test]
        fn plans_converge(
            wanted in proptest::collection::btree_set((0i64..6, 0u16..2), 0..8),
            mut actual in proptest::collection::vec(arb_actual(), 0..10),
            strays in 0usize..3,
        ) {
            let desired: Vec<_> = wanted.iter().map(|&(r, p)| want(r, p)).collect();
            for i in 0..strays {
                actual.push(ActualRule { name: format!("stray {i}"), ..Default::default() });
            }
            let changes = plan(&desired, &actual);
            apply(&mut actual, &changes);
            prop_assert!(plan(&desired, &actual).is_empty(), "not converged: {:?}", plan(&desired, &actual));
            prop_assert_eq!(actual.len(), desired.len());
        }
    }
}
