//! "Network adapters changed" and "DNS servers changed".
//!
//! Adapters: only one never seen before is reported. VPNs add and remove their
//! adapters on every connect, and each was new only once.
//!
//! DNS servers: remembered per adapter *and network* (the gateway's hardware
//! address, or its address), so moving between networks isn't a change; the
//! same network handing out different servers is (the classic hijack).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use w4_ipc::api::AlertBody;
use w4_sys::netinfo::AdapterInfo;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    /// Adapter ids seen.
    pub adapters: BTreeSet<String>,
    /// "<adapter id>|<network>" → DNS servers.
    pub dns: BTreeMap<String, Vec<IpAddr>>,
    /// Filled once: the first look learns what's there without alerts.
    pub learned: bool,
}

/// The network an adapter is on: its gateway's hardware address when known,
/// else the gateway's address. `None` without a gateway.
pub fn network_of(
    adapter: &AdapterInfo,
    gateway_mac: &dyn Fn(IpAddr) -> Option<String>,
) -> Option<String> {
    let gateway = *adapter.gateways.first()?;
    Some(gateway_mac(gateway).unwrap_or_else(|| gateway.to_string()))
}

/// What's new since `memory`, as alerts; `memory` then holds what's seen now.
pub fn check(
    memory: &mut Memory,
    adapters: &[AdapterInfo],
    gateway_mac: &dyn Fn(IpAddr) -> Option<String>,
) -> Vec<AlertBody> {
    let mut out = Vec::new();
    let learning = !memory.learned;
    for a in adapters {
        if memory.adapters.insert(a.id.clone()) && !learning {
            out.push(AlertBody::AdapterAdded {
                name: a.name.clone(),
                description: a.description.clone(),
                mac: a.mac.clone(),
            });
        }
        // An adapter that's down or between addresses has no servers to compare.
        if !a.up || a.dns.is_empty() {
            continue;
        }
        let Some(network) = network_of(a, gateway_mac) else {
            continue;
        };
        let key = format!("{}|{network}", a.id);
        let mut now = a.dns.clone();
        now.sort();
        now.dedup();
        match memory.dns.insert(key, now.clone()) {
            Some(before) if before != now && !learning => out.push(AlertBody::DnsServersChanged {
                adapter: a.name.clone(),
                from: before,
                to: now,
            }),
            _ => {}
        }
    }
    memory.learned = true;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(id: &str, gateway: &str, dns: &[&str]) -> AdapterInfo {
        AdapterInfo {
            id: id.into(),
            name: format!("Adapter {id}"),
            description: "Test".into(),
            mac: Some("00-15-5d-00-00-01".into()),
            up: true,
            ipv4: vec![],
            gateways: vec![gateway.parse().unwrap()],
            dns: dns.iter().map(|d| d.parse().unwrap()).collect(),
            dns_suffix: None,
        }
    }

    fn kinds(alerts: &[AlertBody]) -> Vec<&'static str> {
        alerts.iter().map(AlertBody::kind).collect()
    }

    #[test]
    fn learns_first_then_reports_new_adapters_once() {
        let mut m = Memory::default();
        let none = |_: IpAddr| None;
        assert!(
            check(
                &mut m,
                &[adapter("eth", "192.168.1.1", &["192.168.1.1"])],
                &none
            )
            .is_empty()
        );
        let vpn = adapter("vpn", "10.0.0.1", &["10.0.0.53"]);
        assert_eq!(
            kinds(&check(&mut m, std::slice::from_ref(&vpn), &none)),
            ["adapter_added"]
        );
        // Gone and back (a VPN reconnecting): nothing.
        assert!(check(&mut m, &[], &none).is_empty());
        assert!(check(&mut m, &[vpn], &none).is_empty());
    }

    #[test]
    fn dns_changes_count_only_on_the_same_network() {
        let mut m = Memory::default();
        let home = |_: IpAddr| Some("aa-aa-aa-aa-aa-aa".to_string());
        let cafe = |_: IpAddr| Some("bb-bb-bb-bb-bb-bb".to_string());
        check(
            &mut m,
            &[adapter("wifi", "192.168.1.1", &["192.168.1.1"])],
            &home,
        );
        // Another network, other servers: normal.
        assert!(
            check(
                &mut m,
                &[adapter("wifi", "192.168.1.1", &["10.9.9.9"])],
                &cafe
            )
            .is_empty()
        );
        // Home again with the same servers, in another order: nothing.
        assert!(
            check(
                &mut m,
                &[adapter("wifi", "192.168.1.1", &["192.168.1.1"])],
                &home
            )
            .is_empty()
        );
        // Home with different servers: a change.
        let alerts = check(
            &mut m,
            &[adapter("wifi", "192.168.1.1", &["203.0.113.66"])],
            &home,
        );
        assert_eq!(kinds(&alerts), ["dns_servers_changed"]);
        // Disconnected (no servers for now): nothing.
        let mut off = adapter("wifi", "192.168.1.1", &[]);
        off.up = false;
        assert!(check(&mut m, &[off], &home).is_empty());
    }
}
