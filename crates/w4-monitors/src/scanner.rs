//! The LAN scanner (SPEC §10.2 Network): which addresses to ask, and asking
//! them with ARP requests, a few dozen at a time. Private networks only, and
//! at most 1,022 addresses a network: bigger ones are scanned around this PC.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use w4_sys::netinfo::AdapterInfo;

/// Networks bigger than this (in prefix length) are scanned as the /24 around
/// this PC's address.
const SMALLEST_PREFIX: u8 = 22;
/// ARP requests in flight at once.
pub const WORKERS: usize = 64;

/// One network to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// e.g. "192.168.1.0/24".
    pub network: String,
    pub hosts: Vec<Ipv4Addr>,
}

/// RFC 1918 private addresses.
pub fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

/// The private IPv4 networks of adapters that are up and have a gateway (a
/// real network, not a host-only one), without this PC's own addresses.
pub fn targets(adapters: &[AdapterInfo]) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for a in adapters.iter().filter(|a| a.up && !a.gateways.is_empty()) {
        for &(own, prefix) in &a.ipv4 {
            if !is_private(own) || prefix > 30 {
                continue;
            }
            let prefix = if prefix < SMALLEST_PREFIX { 24 } else { prefix };
            let mask = u32::MAX << (32 - u32::from(prefix));
            let network = u32::from(own) & mask;
            let broadcast = network | !mask;
            let name = format!("{}/{prefix}", Ipv4Addr::from(network));
            if out.iter().any(|t| t.network == name) {
                continue;
            }
            let own_ips: Vec<Ipv4Addr> = adapters
                .iter()
                .flat_map(|a| a.ipv4.iter().map(|(ip, _)| *ip))
                .collect();
            let hosts = (network + 1..broadcast)
                .map(Ipv4Addr::from)
                .filter(|ip| !own_ips.contains(ip))
                .collect();
            out.push(Target {
                network: name,
                hosts,
            });
        }
    }
    out
}

/// `f` for each address on up to `workers` threads; the answers, by address.
fn each<T: Send>(
    hosts: &[Ipv4Addr],
    workers: usize,
    f: impl Fn(Ipv4Addr) -> Option<T> + Sync,
) -> Vec<(Ipv4Addr, T)> {
    let queue = Mutex::new(hosts.iter().copied());
    let found = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..workers.max(1).min(hosts.len().max(1)) {
            s.spawn(|| {
                loop {
                    let next = queue.lock().unwrap_or_else(|p| p.into_inner()).next();
                    let Some(ip) = next else { break };
                    if let Some(answer) = f(ip) {
                        found
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push((ip, answer));
                    }
                }
            });
        }
    });
    let mut out = found.into_inner().unwrap_or_else(|p| p.into_inner());
    out.sort_by_key(|(ip, _)| *ip);
    out
}

/// Asks every address for its hardware address; returns those that answered.
/// Blocking: about a second per round of `WORKERS` silent addresses.
pub fn probe(hosts: &[Ipv4Addr], workers: usize) -> Vec<(Ipv4Addr, String)> {
    each(hosts, workers, w4_sys::netinfo::arp_probe)
}

/// A device's name, from reverse DNS (the router's DHCP names, mDNS-aware
/// resolvers); `None` if it has none.
pub fn name_of(ip: Ipv4Addr) -> Option<String> {
    w4_sys::net::reverse_lookup(IpAddr::V4(ip))
}

/// Names for several devices at once: a lookup for a device without one can
/// take seconds (NetBIOS and LLMNR time out).
pub fn names_of(hosts: &[Ipv4Addr], workers: usize) -> Vec<(Ipv4Addr, String)> {
    each(hosts, workers, name_of)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(ipv4: &[(&str, u8)], gateway: bool) -> AdapterInfo {
        AdapterInfo {
            id: "eth".into(),
            name: "Ethernet".into(),
            description: String::new(),
            mac: None,
            up: true,
            ipv4: ipv4
                .iter()
                .map(|(ip, p)| (ip.parse().unwrap(), *p))
                .collect(),
            gateways: if gateway {
                vec!["192.168.1.1".parse().unwrap()]
            } else {
                vec![]
            },
            dns: vec![],
            dns_suffix: None,
        }
    }

    #[test]
    fn private_networks_around_this_pc() {
        let t = targets(&[adapter(&[("192.168.1.50", 24)], true)]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].network, "192.168.1.0/24");
        assert_eq!(
            t[0].hosts.len(),
            253,
            "not the network, broadcast or this PC"
        );
        assert!(!t[0].hosts.contains(&"192.168.1.50".parse().unwrap()));
        // A /16 is too big: the /24 around this PC.
        let big = targets(&[adapter(&[("10.1.2.3", 16)], true)]);
        assert_eq!(big[0].network, "10.1.2.0/24");
        // Public addresses and host-only adapters (no gateway) aren't scanned.
        assert!(targets(&[adapter(&[("203.0.113.5", 24)], true)]).is_empty());
        assert!(targets(&[adapter(&[("192.168.56.1", 24)], false)]).is_empty());
    }
}
