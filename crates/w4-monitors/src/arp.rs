//! "ARP spoofing": a man in the middle answers for the gateway with its own
//! hardware address. Two signs (SPEC §11):
//!
//! - the gateway answers from a hardware address never seen for it on this
//!   network (a new router is reported once, then known);
//! - the gateway's hardware address also answers for another address on the
//!   network (the attacker claims the gateway and keeps its own address).
//!
//! Unresolved and unreachable entries (as during a DHCP renewal) don't count.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use w4_ipc::api::AlertBody;
use w4_sys::netinfo::{AdapterInfo, Neighbor};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    /// "<adapter id>|<gateway>|<Wi-Fi network name>" → hardware addresses seen.
    pub gateways: BTreeMap<String, BTreeSet<String>>,
    /// "<gateway mac>|<other address>" pairs already reported.
    pub shared: BTreeSet<String>,
}

/// `ssid_of` names the Wi-Fi network an adapter is on, if it's Wi-Fi: the same
/// gateway address on another Wi-Fi network is another router.
pub fn check(
    memory: &mut Memory,
    adapters: &[AdapterInfo],
    neighbors: &[Neighbor],
    ssid_of: &dyn Fn(&str) -> Option<String>,
) -> Vec<AlertBody> {
    let mut out = Vec::new();
    for a in adapters.iter().filter(|a| a.up) {
        for gateway in a.gateways.iter().filter_map(|g| match g {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        }) {
            let Some(entry) = neighbors.iter().find(|n| n.ip == gateway) else {
                continue;
            };
            let key = format!("{}|{gateway}|{}", a.id, ssid_of(&a.id).unwrap_or_default());
            let seen = memory.gateways.entry(key).or_default();
            let new = seen.insert(entry.mac.clone());
            let also: Vec<Ipv4Addr> = neighbors
                .iter()
                .filter(|n| {
                    n.mac == entry.mac
                        && n.ip != gateway
                        && !n.ip.is_broadcast()
                        && !n.ip.is_multicast()
                })
                .map(|n| n.ip)
                .collect();
            let fresh_shares: Vec<Ipv4Addr> = also
                .iter()
                .copied()
                .filter(|ip| memory.shared.insert(format!("{}|{ip}", entry.mac)))
                .collect();
            let known: Vec<String> = seen.iter().filter(|m| **m != entry.mac).cloned().collect();
            // A first sighting of a gateway is learning, not a change.
            let changed = new && !known.is_empty();
            if changed || !fresh_shares.is_empty() {
                out.push(AlertBody::ArpSpoofing {
                    gateway: IpAddr::V4(gateway),
                    mac: entry.mac.clone(),
                    known,
                    also: also.into_iter().map(IpAddr::V4).collect(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> AdapterInfo {
        AdapterInfo {
            id: "eth".into(),
            name: "Ethernet".into(),
            description: String::new(),
            mac: None,
            up: true,
            ipv4: vec![],
            gateways: vec!["192.168.1.1".parse().unwrap()],
            dns: vec![],
            dns_suffix: None,
        }
    }

    fn n(ip: &str, mac: &str) -> Neighbor {
        Neighbor {
            ip: ip.parse().unwrap(),
            mac: mac.into(),
            interface: 1,
        }
    }

    const ROUTER: &str = "aa-aa-aa-aa-aa-01";
    const ATTACKER: &str = "bb-bb-bb-bb-bb-66";

    #[test]
    fn a_new_gateway_address_is_reported_once() {
        let mut m = Memory::default();
        let wired = |_: &str| None;
        let table = [
            n("192.168.1.1", ROUTER),
            n("192.168.1.20", "cc-cc-cc-cc-cc-20"),
        ];
        assert!(
            check(&mut m, &[adapter()], &table, &wired).is_empty(),
            "learned"
        );
        let spoofed = [n("192.168.1.1", ATTACKER)];
        let alerts = check(&mut m, &[adapter()], &spoofed, &wired);
        assert!(
            matches!(&alerts[..], [AlertBody::ArpSpoofing { mac, known, .. }] if mac == ATTACKER && known == &[ROUTER.to_string()])
        );
        // Seen now: not again; and back to the router: known.
        assert!(check(&mut m, &[adapter()], &spoofed, &wired).is_empty());
        assert!(check(&mut m, &[adapter()], &table, &wired).is_empty());
    }

    #[test]
    fn the_gateway_claimed_by_a_device_with_its_own_address() {
        let mut m = Memory::default();
        let wired = |_: &str| None;
        // First look, already poisoned: the gateway's address answers for another device too.
        let table = [n("192.168.1.1", ATTACKER), n("192.168.1.66", ATTACKER)];
        let alerts = check(&mut m, &[adapter()], &table, &wired);
        assert!(
            matches!(&alerts[..], [AlertBody::ArpSpoofing { also, .. }] if also == &["192.168.1.66".parse::<IpAddr>().unwrap()])
        );
        assert!(
            check(&mut m, &[adapter()], &table, &wired).is_empty(),
            "once"
        );
    }

    #[test]
    fn another_wifi_network_with_the_same_gateway_address_is_another_router() {
        let mut m = Memory::default();
        let mut ssid = "Home";
        let table_home = [n("192.168.1.1", ROUTER)];
        let table_cafe = [n("192.168.1.1", "dd-dd-dd-dd-dd-01")];
        check(&mut m, &[adapter()], &table_home, &|_| {
            Some(ssid.to_string())
        });
        ssid = "Cafe";
        assert!(
            check(&mut m, &[adapter()], &table_cafe, &|_| Some(
                ssid.to_string()
            ))
            .is_empty()
        );
    }
}
