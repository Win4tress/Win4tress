//! ETW record → NetEvent. Field names and IDs are from the provider manifests,
//! confirmed with `etw-probe --dump` (docs/spikes/0.1-etw-collector.md).

use std::net::{IpAddr, SocketAddr};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::schema::Schema;
use w4_core::time::filetime_to_unix_ms;
use w4_core::{Direction, NetEvent, Protocol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Network,
    Process,
    Dns,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

const PROCESS_START: u16 = 1;
const PROCESS_STOP: u16 = 2;
const DNS_QUERY_COMPLETED: u16 = 3008;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetKind {
    Data(Protocol, Direction),
    Connect { inbound: bool },
    Disconnect,
}

/// Kernel-Network event IDs: TCP over IPv4, IPv6 at +16, UDP at +32.
/// Event 18 ("TCP copy") repeats received data and is deliberately ignored.
fn net_kind(id: u16) -> Option<NetKind> {
    use Direction::{In, Out};
    use Protocol::{Tcp, Udp};
    Some(match id {
        10 | 26 => NetKind::Data(Tcp, Out),
        11 | 27 => NetKind::Data(Tcp, In),
        42 | 58 => NetKind::Data(Udp, Out),
        43 | 59 => NetKind::Data(Udp, In),
        12 | 28 => NetKind::Connect { inbound: false },
        15 | 31 => NetKind::Connect { inbound: true },
        13 | 29 => NetKind::Disconnect,
        _ => return None,
    })
}

macro_rules! field {
    ($parser:expr, $ty:ty, $name:literal) => {
        $parser.try_parse::<$ty>($name).map_err(|_| DecodeError)?
    };
}

/// `Ok(None)` for events we don't use.
pub fn decode(
    source: Source,
    record: &EventRecord,
    schema: &Schema,
) -> Result<Option<NetEvent>, DecodeError> {
    let id = record.event_id();
    let ts_ms = filetime_to_unix_ms(record.raw_timestamp());
    let parser = Parser::create(record, schema);

    match source {
        Source::Network => {
            let Some(kind) = net_kind(id) else {
                return Ok(None);
            };
            // Always the PID in the event data: the header PID is often wrong (spike 0.1).
            let pid = field!(parser, u32, "PID");
            let daddr = SocketAddr::new(
                field!(parser, IpAddr, "daddr"),
                port(field!(parser, u16, "dport")),
            );
            let saddr = SocketAddr::new(
                field!(parser, IpAddr, "saddr"),
                port(field!(parser, u16, "sport")),
            );
            let (local, remote) = endpoints(kind, daddr, saddr);
            Ok(Some(match kind {
                NetKind::Data(proto, dir) => NetEvent::Traffic {
                    ts_ms,
                    pid,
                    proto,
                    dir,
                    bytes: field!(parser, u32, "size"),
                    local,
                    remote,
                },
                NetKind::Connect { inbound } => NetEvent::Connect {
                    ts_ms,
                    pid,
                    local,
                    remote,
                    inbound,
                },
                NetKind::Disconnect => NetEvent::Disconnect {
                    ts_ms,
                    pid,
                    local,
                    remote,
                },
            }))
        }
        Source::Process => match id {
            PROCESS_START => {
                let package = field!(parser, String, "PackageFullName");
                Ok(Some(NetEvent::ProcessStart {
                    ts_ms,
                    pid: field!(parser, u32, "ProcessID"),
                    sequence: field!(parser, u64, "ProcessSequenceNumber"),
                    image: field!(parser, String, "ImageName"),
                    package: (!package.is_empty()).then_some(package),
                }))
            }
            PROCESS_STOP => Ok(Some(NetEvent::ProcessStop {
                ts_ms,
                pid: field!(parser, u32, "ProcessID"),
            })),
            _ => Ok(None),
        },
        Source::Dns => {
            if id != DNS_QUERY_COMPLETED {
                return Ok(None);
            }
            let status = field!(parser, u32, "QueryStatus");
            let addrs = if status == 0 {
                parse_query_results(&field!(parser, String, "QueryResults"))
            } else {
                Vec::new()
            };
            Ok(Some(NetEvent::DnsQuery {
                ts_ms,
                // DNS-Client events are logged in the querying process, so the header PID is right.
                pid: record.process_id(),
                // PTR queries carry the root dot ("4.3.2.1.in-addr.arpa.").
                name: field!(parser, String, "QueryName")
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                query_type: u16::try_from(field!(parser, u32, "QueryType")).unwrap_or(0),
                status,
                addrs,
            }))
        }
    }
}

/// Ports arrive in network byte order.
fn port(raw: u16) -> u16 {
    u16::from_be(raw)
}

/// Returns (local, remote). TCP events describe the connection, so `daddr` is
/// always the remote end. UDP events describe the datagram, so on receive `daddr`
/// is our own (destination) address and the remote end is `saddr`. Seen with
/// RDP over UDP, where received data was credited to the PC's own IP.
fn endpoints(kind: NetKind, daddr: SocketAddr, saddr: SocketAddr) -> (SocketAddr, SocketAddr) {
    match kind {
        NetKind::Data(Protocol::Udp, Direction::In) => (daddr, saddr),
        _ => (saddr, daddr),
    }
}

/// `QueryResults` looks like `type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;`.
/// CNAME entries don't parse as addresses and are skipped.
pub fn parse_query_results(results: &str) -> Vec<IpAddr> {
    results
        .split(';')
        .filter_map(|token| {
            let token = token.trim();
            token.strip_prefix("::ffff:").unwrap_or(token).parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_byte_swapped() {
        // Observed in spike 0.1: dport 47873 (0xBB01) is port 443.
        assert_eq!(port(u16::from_ne_bytes([0x01, 0xBB])), 443);
    }

    #[test]
    fn endpoint_orientation() {
        let me: SocketAddr = "192.168.1.135:3389".parse().unwrap();
        let peer: SocketAddr = "192.168.1.229:59561".parse().unwrap();
        // UDP receive: the datagram's destination is us.
        let udp_in = NetKind::Data(Protocol::Udp, Direction::In);
        assert_eq!(endpoints(udp_in, me, peer), (me, peer));
        // UDP send and all TCP events: daddr is the remote end.
        let udp_out = NetKind::Data(Protocol::Udp, Direction::Out);
        assert_eq!(endpoints(udp_out, peer, me), (me, peer));
        let tcp_in = NetKind::Data(Protocol::Tcp, Direction::In);
        assert_eq!(endpoints(tcp_in, peer, me), (me, peer));
        assert_eq!(
            endpoints(NetKind::Connect { inbound: true }, peer, me),
            (me, peer)
        );
    }

    mod properties {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use proptest::prelude::*;

        use super::super::*;

        proptest! {
            /// QueryResults is untrusted text; parsing must never panic.
            #[test]
            fn query_results_never_panic(s in "\\PC{0,300}") {
                let _ = parse_query_results(&s);
            }

            #[test]
            fn query_results_recover_embedded_addresses(
                v4 in any::<[u8; 4]>(),
                v6 in any::<[u8; 16]>(),
                cname in "[a-z]{1,12}\\.example",
            ) {
                let (a, b) = (Ipv4Addr::from(v4), Ipv6Addr::from(v6));
                let ips = parse_query_results(&format!("type:  5 {cname};::ffff:{a};{b};"));
                prop_assert!(ips.contains(&IpAddr::V4(a)));
                // A v4-mapped v6 address is reported as the v4 address it maps.
                let b_found = ips.contains(&IpAddr::V6(b))
                    || b.to_ipv4_mapped().is_some_and(|m| ips.contains(&IpAddr::V4(m)));
                prop_assert!(b_found);
            }
        }
    }

    #[test]
    fn tcp_copy_is_ignored() {
        assert_eq!(net_kind(18), None);
        assert_eq!(net_kind(34), None);
    }

    #[test]
    fn data_event_ids() {
        assert_eq!(
            net_kind(11),
            Some(NetKind::Data(Protocol::Tcp, Direction::In))
        );
        assert_eq!(
            net_kind(58),
            Some(NetKind::Data(Protocol::Udp, Direction::Out))
        );
        assert_eq!(net_kind(31), Some(NetKind::Connect { inbound: true }));
    }

    #[test]
    fn query_results() {
        let ips =
            parse_query_results("type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;");
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800::1".parse().unwrap()
            ]
        );
        assert!(parse_query_results("").is_empty());
    }
}
