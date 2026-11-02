//! Firewall profiles (SPEC §7.6): switching to one, by hand or by itself when
//! the PC joins a network a profile is chosen for. A profile puts back the
//! mode, which rules are on and DNS filtering's settings. A switch by itself happens
//! only when the connected networks change, so one made by hand stands until
//! then.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use w4_core::firewall::{Mode, NetworkCategory};
use w4_core::time::now_unix_ms;
use w4_ipc::api::{AlertBody, AutoSwitch, NetworkMatch, Profile};
use w4_monitor::Monitor;
use w4_store::{SavedProfile, Store};
use w4_sys::netlist::KnownNetwork;

use crate::enforcer::Enforcer;
use crate::prompts::Prompter;
use crate::usage::Usage;

/// How often the connected networks are read.
const CHECK_EVERY: Duration = Duration::from_secs(5);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug)]
pub enum SwitchError {
    NotFound(String),
    /// The profile's mode can't be used here.
    Unavailable(String),
    Storage(String),
}

/// Puts a profile's rule states, mode and DNS filtering in place, with the same
/// checks as changing them (DNS filtering only with `usage`, and only for a
/// profile that holds it; a pause stays as it is). Returns the profile and how
/// many rules changed.
pub fn switch(
    store: &Mutex<Store>,
    enforcer: &Enforcer,
    prompter: Option<&Prompter>,
    usage: Option<&Usage>,
    name: &str,
    who: &str,
) -> Result<(Profile, usize), SwitchError> {
    let storage = |e: w4_store::Error| SwitchError::Storage(e.to_string());
    let SavedProfile { profile, dns, .. } = lock(store)
        .profile(name)
        .map_err(storage)?
        .ok_or_else(|| SwitchError::NotFound(format!("no profile {name}")))?;
    let forced = enforcer.status().environment.outbound_default_forced_by;
    if profile.mode == Mode::AskToConnect && !forced.is_empty() {
        return Err(SwitchError::Unavailable(format!(
            "this profile uses Ask to Connect, which is unavailable: {} sets what happens to outgoing connections",
            forced.join(" and ")
        )));
    }
    if let Some(dns) = &dns {
        crate::dnsfilter::check(dns).map_err(|e| {
            SwitchError::Unavailable(format!(
                "this profile's DNS filtering settings can't be used: {e}"
            ))
        })?;
    }
    let now = now_unix_ms();
    let (mode, rules_changed, mode_changed) = {
        let mut store = lock(store);
        let (mode, changed) = store
            .apply_profile(&profile.name, now, who)
            .map_err(storage)?
            .ok_or_else(|| SwitchError::NotFound(format!("no profile {name}")))?;
        let mode_changed = store
            .set_firewall_mode(mode, now, &format!("{who} (profile {})", profile.name))
            .map_err(storage)?;
        (mode, changed, mode_changed)
    };
    if mode_changed
        && mode != Mode::AskToConnect
        && let Some(prompter) = prompter
    {
        prompter.clear();
    }
    // Through the settings, as Settings changes them: the resolver follows.
    let dns_changed = match (dns, usage) {
        (Some(dns), Some(usage)) => usage
            .set_dns(dns, &format!("{who} (profile {})", profile.name))
            .map_err(SwitchError::Storage)?,
        _ => false,
    };
    tracing::info!(profile = %profile.name, rules = rules_changed, mode = mode.as_str(), dns = dns_changed, by = %who, "profile switched");
    enforcer.changed();
    Ok((profile, rules_changed))
}

fn category_words(c: NetworkCategory) -> &'static str {
    match c {
        NetworkCategory::Public => "a public network",
        NetworkCategory::Private => "a private network",
        NetworkCategory::Domain => "a domain network",
    }
}

/// The profile the connected networks call for, and the network that matched
/// (for the alert). Pure.
///
/// Only the networks that reach the internet count, when any do (a VPN's or a
/// virtual adapter's network shouldn't pick the profile). A profile chosen for
/// one of them by name wins over one chosen for its kind; otherwise profiles
/// are taken by name.
pub fn choose<'a>(
    profiles: &'a [Profile],
    connected: &[KnownNetwork],
) -> Option<(&'a Profile, String)> {
    let online: Vec<&KnownNetwork> = connected.iter().filter(|n| n.internet).collect();
    let candidates: Vec<&KnownNetwork> = if online.is_empty() {
        connected.iter().collect()
    } else {
        online
    };
    let mut sorted: Vec<&Profile> = profiles.iter().collect();
    sorted.sort_by_key(|p| p.name.to_lowercase());
    for p in &sorted {
        for m in &p.networks {
            if let NetworkMatch::Network { id, .. } = m
                && let Some(n) = candidates.iter().find(|n| n.id.eq_ignore_ascii_case(id))
            {
                return Some((p, format!("“{}”", n.name)));
            }
        }
    }
    for p in &sorted {
        for m in &p.networks {
            if let NetworkMatch::Category { category } = m
                && let Some(n) = candidates.iter().find(|n| n.category == *category)
            {
                return Some((p, format!("“{}”, {}", n.name, category_words(*category))));
            }
        }
    }
    None
}

#[derive(Default)]
struct State {
    /// The connected networks when last looked at; a switch happens only when
    /// they change.
    seen: Option<Vec<(String, NetworkCategory, bool)>>,
    last: Option<AutoSwitch>,
}

pub struct AutoProfile {
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    enforcer: Arc<Enforcer>,
    prompter: Option<Arc<Prompter>>,
    usage: Option<Arc<Usage>>,
    state: Mutex<State>,
}

impl AutoProfile {
    pub fn new(
        store: Arc<Mutex<Store>>,
        monitor: Arc<Mutex<Monitor>>,
        enforcer: Arc<Enforcer>,
        prompter: Option<Arc<Prompter>>,
        usage: Option<Arc<Usage>>,
    ) -> Arc<Self> {
        Arc::new(AutoProfile {
            store,
            monitor,
            enforcer,
            prompter,
            usage,
            state: Mutex::new(State::default()),
        })
    }

    /// The last switch made by itself.
    pub fn last(&self) -> Option<AutoSwitch> {
        lock(&self.state).last.clone()
    }

    /// A profile's networks changed: look again at the next check, as if the
    /// PC had just joined the networks it's on.
    pub fn reconsider(&self) {
        lock(&self.state).seen = None;
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            if let Err(e) = tokio::task::spawn_blocking(move || this.check()).await {
                tracing::warn!("switching profiles by network failed: {e}");
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(CHECK_EVERY) => {}
            }
        }
    }

    /// One look at the networks. Blocking (COM).
    pub(crate) fn check(&self) {
        let connected = w4_sys::netlist::networks(false);
        let mut seen: Vec<(String, NetworkCategory, bool)> = connected
            .iter()
            .map(|n| (n.id.to_lowercase(), n.category, n.internet))
            .collect();
        seen.sort();
        {
            let mut s = lock(&self.state);
            if s.seen.as_ref() == Some(&seen) {
                return;
            }
            s.seen = Some(seen);
        }
        let (profiles, active) = {
            let store = lock(&self.store);
            (
                store.profiles().unwrap_or_default(),
                store.active_profile().ok().flatten(),
            )
        };
        let Some((profile, network)) = choose(&profiles, &connected) else {
            return;
        };
        if active
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&profile.name))
        {
            return;
        }
        if let Some(why) = self.enforcer.monitoring_only() {
            tracing::info!(profile = %profile.name, "not switching profiles by network: {why}");
            return;
        }
        let who = format!("win4tress (network {network})");
        match switch(
            &self.store,
            &self.enforcer,
            self.prompter.as_deref(),
            self.usage.as_deref(),
            &profile.name,
            &who,
        ) {
            Ok((p, _)) => {
                let now = now_unix_ms();
                lock(&self.monitor).raise(
                    now,
                    None,
                    AlertBody::ProfileSwitched {
                        profile: p.name.clone(),
                        network: network.clone(),
                        from: active,
                    },
                );
                lock(&self.state).last = Some(AutoSwitch {
                    profile: p.name,
                    network,
                    at_ms: now,
                });
            }
            Err(e) => {
                tracing::warn!(profile = %profile.name, "switching profiles by network: {e:?}")
            }
        }
    }

    /// The profile the networks connected now call for. Blocking (COM).
    pub fn wanted(&self, connected: &[KnownNetwork]) -> Option<String> {
        let profiles = lock(&self.store).profiles().unwrap_or_default();
        choose(&profiles, connected).map(|(p, _)| p.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, networks: Vec<NetworkMatch>) -> Profile {
        Profile {
            name: name.into(),
            mode: Mode::ClickToBlock,
            rules: 0,
            enabled: 0,
            saved_ms: 0,
            networks,
            dns_filtering: None,
        }
    }

    fn net(id: &str, name: &str, category: NetworkCategory, internet: bool) -> KnownNetwork {
        KnownNetwork {
            id: id.into(),
            name: name.into(),
            category,
            connected: true,
            internet,
        }
    }

    #[test]
    fn a_named_network_wins_over_a_kind_and_only_online_ones_count() {
        let home_id = "{AAAA}";
        let profiles = vec![
            profile(
                "Travel",
                vec![NetworkMatch::Category {
                    category: NetworkCategory::Public,
                }],
            ),
            profile(
                "Home",
                vec![NetworkMatch::Network {
                    id: home_id.to_lowercase(),
                    name: "HomeNet".into(),
                }],
            ),
        ];
        // At home, the VPN's network is public but carries no internet.
        let home = [
            net(home_id, "HomeNet", NetworkCategory::Private, true),
            net(
                "{BBBB}",
                "Unidentified network",
                NetworkCategory::Public,
                false,
            ),
        ];
        let (p, why) = choose(&profiles, &home).unwrap();
        assert_eq!((p.name.as_str(), why.as_str()), ("Home", "“HomeNet”"));

        // The airport: no named match, the kind does.
        let airport = [net("{CCCC}", "Airport Free", NetworkCategory::Public, true)];
        let (p, why) = choose(&profiles, &airport).unwrap();
        assert_eq!(p.name, "Travel");
        assert_eq!(why, "“Airport Free”, a public network");

        // A friend's private network: nothing chosen, nothing switched.
        let friend = [net("{DDDD}", "Friend", NetworkCategory::Private, true)];
        assert!(choose(&profiles, &friend).is_none());
        // Offline: the networks without internet count then.
        let offline = [net(
            "{CCCC}",
            "Airport Free",
            NetworkCategory::Public,
            false,
        )];
        assert_eq!(choose(&profiles, &offline).unwrap().0.name, "Travel");
        assert!(choose(&profiles, &[]).is_none());
    }
}
