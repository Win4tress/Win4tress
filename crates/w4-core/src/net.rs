//! Address locality and traffic-type classification (SPEC §8.3).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::Protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locality {
    Loopback,
    /// Stays on the local network: private, link-local, CGNAT, multicast.
    Local,
    Internet,
}

const DOH_SERVERS: &str = include_str!("../../../data/doh-servers.txt");
const VPN_CLIENTS: &str = include_str!("../../../data/vpn-clients.txt");

/// A known VPN client (data/vpn-clients.txt), by the program's file name: its
/// traffic is other apps' traffic again, so it can be left out of totals.
pub fn is_vpn_client(path: &str) -> bool {
    let file = path.rsplit(['\\', '/']).next().unwrap_or(path);
    VPN_CLIENTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| l.eq_ignore_ascii_case(file))
}

/// Public DNS-over-HTTPS resolvers (data/doh-servers.txt).
pub fn doh_servers() -> Vec<IpAddr> {
    DOH_SERVERS
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| l.parse().ok())
        .collect()
}

/// DNS (53) and DNS over TLS (853): an app using these itself skips Windows'
/// DNS Client.
pub fn is_dns_port(port: u16) -> bool {
    port == 53 || port == 853
}

/// Whether a host-rule pattern covers a DNS name: `example.com` only itself,
/// `*.example.com` itself and every subdomain. Case and a trailing dot don't
/// matter.
pub fn name_matches(pattern: &str, name: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = norm(name);
    match pattern.trim().strip_prefix("*.") {
        Some(base) => {
            let base = norm(base);
            name == base || name.ends_with(&format!(".{base}"))
        }
        None => name == norm(pattern),
    }
}

pub fn locality(ip: IpAddr) -> Locality {
    match ip {
        IpAddr::V4(v4) => locality_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => locality_v4(v4),
            None => locality_v6(v6),
        },
    }
}

fn locality_v4(ip: Ipv4Addr) -> Locality {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback() {
        Locality::Loopback
    } else if ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || (a == 100 && (64..=127).contains(&b))
    {
        Locality::Local
    } else {
        Locality::Internet
    }
}

fn locality_v6(ip: Ipv6Addr) -> Locality {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Locality::Loopback
    } else if ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (first & 0xffc0) == 0xfe80
    // link-local fe80::/10
    {
        Locality::Local
    } else {
        Locality::Internet
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficType {
    Https,
    Http,
    Quic,
    Dns,
    Dot,
    Ntp,
    Mdns,
    Llmnr,
    Ssdp,
    Netbios,
    Smb,
    Rdp,
    Ssh,
    Dhcp,
    Other,
}

impl TrafficType {
    /// Classifies by protocol and remote port.
    pub fn classify(proto: Protocol, remote_port: u16) -> TrafficType {
        use Protocol::{Tcp, Udp};
        match (proto, remote_port) {
            (Tcp, 443) => TrafficType::Https,
            (Tcp, 80 | 8080) => TrafficType::Http,
            (Udp, 443) => TrafficType::Quic,
            (_, 53) => TrafficType::Dns,
            (Tcp, 853) => TrafficType::Dot,
            (Udp, 123) => TrafficType::Ntp,
            (Udp, 5353) => TrafficType::Mdns,
            (_, 5355) => TrafficType::Llmnr,
            (Udp, 1900) => TrafficType::Ssdp,
            (_, 137..=139) => TrafficType::Netbios,
            (Tcp, 445) => TrafficType::Smb,
            (_, 3389) => TrafficType::Rdp,
            (Tcp, 22) => TrafficType::Ssh,
            (Udp, 67 | 68 | 546 | 547) => TrafficType::Dhcp,
            _ => TrafficType::Other,
        }
    }

    /// Stable lower-case name (the same as the JSON form), for storage.
    pub fn id(self) -> &'static str {
        match self {
            TrafficType::Https => "https",
            TrafficType::Http => "http",
            TrafficType::Quic => "quic",
            TrafficType::Dns => "dns",
            TrafficType::Dot => "dot",
            TrafficType::Ntp => "ntp",
            TrafficType::Mdns => "mdns",
            TrafficType::Llmnr => "llmnr",
            TrafficType::Ssdp => "ssdp",
            TrafficType::Netbios => "netbios",
            TrafficType::Smb => "smb",
            TrafficType::Rdp => "rdp",
            TrafficType::Ssh => "ssh",
            TrafficType::Dhcp => "dhcp",
            TrafficType::Other => "other",
        }
    }

    /// Inverse of [`TrafficType::id`]; unknown names become `Other`.
    pub fn from_id(id: &str) -> TrafficType {
        const ALL: [TrafficType; 15] = [
            TrafficType::Https,
            TrafficType::Http,
            TrafficType::Quic,
            TrafficType::Dns,
            TrafficType::Dot,
            TrafficType::Ntp,
            TrafficType::Mdns,
            TrafficType::Llmnr,
            TrafficType::Ssdp,
            TrafficType::Netbios,
            TrafficType::Smb,
            TrafficType::Rdp,
            TrafficType::Ssh,
            TrafficType::Dhcp,
            TrafficType::Other,
        ];
        ALL.into_iter()
            .find(|t| t.id() == id)
            .unwrap_or(TrafficType::Other)
    }

    pub fn label(self) -> &'static str {
        match self {
            TrafficType::Https => "HTTPS",
            TrafficType::Http => "HTTP",
            TrafficType::Quic => "QUIC",
            TrafficType::Dns => "DNS",
            TrafficType::Dot => "DNS over TLS",
            TrafficType::Ntp => "NTP",
            TrafficType::Mdns => "mDNS",
            TrafficType::Llmnr => "LLMNR",
            TrafficType::Ssdp => "SSDP",
            TrafficType::Netbios => "NetBIOS",
            TrafficType::Smb => "SMB",
            TrafficType::Rdp => "RDP",
            TrafficType::Ssh => "SSH",
            TrafficType::Dhcp => "DHCP",
            TrafficType::Other => "Other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_list_parses() {
        let servers = doh_servers();
        assert!(servers.len() > 40, "{}", servers.len());
        assert!(servers.contains(&"1.1.1.1".parse().unwrap()));
        assert!(servers.contains(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(is_dns_port(53) && is_dns_port(853) && !is_dns_port(443));
    }

    #[test]
    fn host_patterns() {
        assert!(name_matches("example.com", "Example.COM."));
        assert!(!name_matches("example.com", "ads.example.com"));
        assert!(name_matches("*.example.com", "example.com"));
        assert!(name_matches("*.example.com", "a.b.example.com"));
        assert!(!name_matches("*.example.com", "badexample.com"));
    }

    fn loc(s: &str) -> Locality {
        locality(s.parse().unwrap())
    }

    #[test]
    fn v4_localities() {
        assert_eq!(loc("127.0.0.1"), Locality::Loopback);
        assert_eq!(loc("192.168.1.10"), Locality::Local);
        assert_eq!(loc("10.0.0.1"), Locality::Local);
        assert_eq!(loc("172.20.0.1"), Locality::Local);
        assert_eq!(loc("169.254.1.1"), Locality::Local);
        assert_eq!(loc("100.64.0.1"), Locality::Local);
        assert_eq!(loc("100.128.0.1"), Locality::Internet);
        assert_eq!(loc("239.255.255.250"), Locality::Local);
        assert_eq!(loc("172.66.0.218"), Locality::Internet);
    }

    #[test]
    fn v6_localities() {
        assert_eq!(loc("::1"), Locality::Loopback);
        assert_eq!(loc("fe80::1"), Locality::Local);
        assert_eq!(loc("fd12:3456::1"), Locality::Local);
        assert_eq!(loc("ff02::fb"), Locality::Local);
        assert_eq!(loc("2606:4700::1111"), Locality::Internet);
        assert_eq!(loc("::ffff:192.168.1.1"), Locality::Local);
    }

    #[test]
    fn traffic_type_ids_round_trip_and_match_json() {
        for t in [
            TrafficType::Https,
            TrafficType::Rdp,
            TrafficType::Netbios,
            TrafficType::Other,
        ] {
            assert_eq!(TrafficType::from_id(t.id()), t);
        }
        assert_eq!(TrafficType::from_id("nonsense"), TrafficType::Other);
    }

    #[test]
    fn traffic_types() {
        assert_eq!(
            TrafficType::classify(Protocol::Tcp, 443),
            TrafficType::Https
        );
        assert_eq!(TrafficType::classify(Protocol::Udp, 443), TrafficType::Quic);
        assert_eq!(TrafficType::classify(Protocol::Udp, 53), TrafficType::Dns);
        assert_eq!(
            TrafficType::classify(Protocol::Tcp, 50000),
            TrafficType::Other
        );
    }
}
