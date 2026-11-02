//! "Wi-Fi evil twin" (SPEC §11): a network with your network's name but weaker
//! security (an open hotspot named like your WPA2 network), or your network
//! itself now weaker than before (the password removed). Not just another
//! access point: mesh and enterprise networks share names and security, and a
//! WPA2/WPA3 transition network shows as both; those aren't reported.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use w4_ipc::api::AlertBody;
use w4_sys::wifi::WifiState;

/// How hard a network is to impersonate: open and WEP are easy, personal
/// (WPA2 or WPA3, the same to a user) needs the password, enterprise needs
/// the server's certificate.
pub fn strength(security: &str) -> u8 {
    match security {
        "Open" | "Open (WEP)" | "Shared key (WEP)" | "OWE" => 0,
        s if s.contains("Enterprise") => 2,
        s if s.contains("Personal") => 1,
        _ => 1,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    /// Network name → the security it had when connected.
    pub security: BTreeMap<String, String>,
    /// "<name>|<security>" twins already reported.
    pub reported: BTreeSet<String>,
}

pub fn check(memory: &mut Memory, state: &WifiState) -> Vec<AlertBody> {
    let mut out = Vec::new();
    for c in &state.connected {
        if c.ssid.is_empty() {
            continue;
        }
        let expected = memory
            .security
            .entry(c.ssid.clone())
            .or_insert_with(|| c.security.clone())
            .clone();
        // Connected to a weaker network under a name you used with more.
        if strength(&c.security) < strength(&expected)
            && memory.reported.insert(format!("{}|{}", c.ssid, c.security))
        {
            out.push(AlertBody::WifiEvilTwin {
                ssid: c.ssid.clone(),
                expected: expected.clone(),
                seen: c.security.clone(),
                connected: true,
            });
        }
        if strength(&c.security) > strength(&expected) {
            memory.security.insert(c.ssid.clone(), c.security.clone());
        }
        let ours = memory.security.get(&c.ssid).cloned().unwrap_or_default();
        for v in state.visible.iter().filter(|v| v.ssid == c.ssid) {
            if strength(&v.security) < strength(&ours)
                && memory.reported.insert(format!("{}|{}", v.ssid, v.security))
            {
                out.push(AlertBody::WifiEvilTwin {
                    ssid: v.ssid.clone(),
                    expected: ours.clone(),
                    seen: v.security.clone(),
                    connected: false,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use w4_sys::wifi::WifiNetwork;

    fn net(ssid: &str, security: &str) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.into(),
            bssid: None,
            interface: None,
            security: security.into(),
        }
    }

    fn state(connected: WifiNetwork, visible: &[WifiNetwork]) -> WifiState {
        WifiState {
            connected: vec![connected],
            visible: visible.to_vec(),
        }
    }

    #[test]
    fn an_open_twin_of_a_secured_network_is_reported_once() {
        let mut m = Memory::default();
        let home = net("Home", "WPA2-Personal");
        let s = state(home.clone(), &[home.clone(), net("Home", "Open")]);
        let alerts = check(&mut m, &s);
        assert!(
            matches!(&alerts[..], [AlertBody::WifiEvilTwin { seen, connected: false, .. }] if seen == "Open")
        );
        assert!(check(&mut m, &s).is_empty());
    }

    #[test]
    fn mesh_transition_mode_and_enterprise_are_normal() {
        let mut m = Memory::default();
        let home = net("Home", "WPA3-Personal");
        // Several access points, WPA2 and WPA3 (transition mode): nothing.
        let s = state(
            home.clone(),
            &[home.clone(), home.clone(), net("Home", "WPA2-Personal")],
        );
        assert!(check(&mut m, &s).is_empty());
        let work = net("Corp", "WPA2-Enterprise");
        assert!(
            check(
                &mut m,
                &state(
                    work.clone(),
                    &[work.clone(), net("Corp", "WPA3-Enterprise")]
                )
            )
            .is_empty()
        );
    }

    #[test]
    fn your_network_with_its_password_removed() {
        let mut m = Memory::default();
        check(&mut m, &state(net("Home", "WPA2-Personal"), &[]));
        let alerts = check(&mut m, &state(net("Home", "Open"), &[]));
        assert!(
            matches!(&alerts[..], [AlertBody::WifiEvilTwin { connected: true, expected, .. }] if expected == "WPA2-Personal")
        );
    }
}
