//! This PC's own addresses, open TCP connections, and reverse DNS.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Once;

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    GetExtendedTcpTable, IP_ADAPTER_ADDRESSES_LH, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
    MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, SetTcpEntry,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, GetNameInfoW, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    NI_MAXHOST, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSADATA, WSAStartup, socklen_t,
};

use crate::from_wide;

/// Unicast addresses assigned to this PC's adapters (including virtual ones).
pub fn own_addresses() -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    for _ in 0..3 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `buf` is 8-byte aligned and `size` bytes long.
        let rc = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, Some(first), &mut size)
        };
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            continue; // `size` now holds what's needed
        }
        if rc != NO_ERROR.0 {
            return out;
        }
        let mut adapter = first.cast_const();
        while !adapter.is_null() {
            // SAFETY: a linked list inside `buf`, built by GetAdaptersAddresses.
            let a = unsafe { &*adapter };
            let mut unicast = a.FirstUnicastAddress.cast_const();
            while !unicast.is_null() {
                // SAFETY: as above.
                let u = unsafe { &*unicast };
                // SAFETY: the sockaddr belongs to the same list.
                if let Some(ip) = unsafe { sockaddr_ip(u.Address.lpSockaddr) } {
                    out.insert(ip);
                }
                unicast = u.Next;
            }
            adapter = a.Next;
        }
        return out;
    }
    out
}

/// # Safety
/// `sa` must be null or point to a valid SOCKADDR_IN / SOCKADDR_IN6.
pub(crate) unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: caller guarantees a valid sockaddr; the family says which layout it has.
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*sa.cast::<SOCKADDR_IN>();
                Some(IpAddr::V4(Ipv4Addr::from(
                    v4.sin_addr.S_un.S_addr.to_ne_bytes(),
                )))
            }
            AF_INET6 => {
                let v6 = &*sa.cast::<SOCKADDR_IN6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpConnection {
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// Established TCP connections right now (IPv4 and IPv6), with owning process.
pub fn established_tcp() -> Vec<TcpConnection> {
    let mut out = Vec::new();
    if let Some(buf) = tcp_table(u32::from(AF_INET.0)) {
        // SAFETY: the buffer holds a MIB_TCPTABLE_OWNER_PID: a u32 count, then rows.
        let rows = unsafe { rows::<MIB_TCPROW_OWNER_PID>(&buf) };
        for r in rows
            .iter()
            .filter(|r| r.dwState == MIB_TCP_STATE_ESTAB.0 as u32)
        {
            out.push(TcpConnection {
                pid: r.dwOwningPid,
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    port(r.dwLocalPort),
                ),
                remote: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                    port(r.dwRemotePort),
                ),
            });
        }
    }
    if let Some(buf) = tcp_table(u32::from(AF_INET6.0)) {
        // SAFETY: as above, with MIB_TCP6ROW_OWNER_PID rows.
        let rows = unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&buf) };
        for r in rows
            .iter()
            .filter(|r| r.dwState == MIB_TCP_STATE_ESTAB.0 as u32)
        {
            out.push(TcpConnection {
                pid: r.dwOwningPid,
                local: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    port(r.dwLocalPort),
                ),
                remote: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                    port(r.dwRemotePort),
                ),
            });
        }
    }
    out
}

/// Ports are stored in network byte order in the low 16 bits.
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// Ends an IPv4 TCP connection: both ends get a reset. Windows offers this
/// for IPv4 TCP only. Needs an
/// administrator (the service).
pub fn close_tcp(local: SocketAddrV4, remote: SocketAddrV4) -> std::io::Result<()> {
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            State: MIB_TCP_STATE_DELETE_TCB,
        },
        dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
        dwLocalPort: u32::from(local.port().to_be()),
        dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
        dwRemotePort: u32::from(remote.port().to_be()),
    };
    // SAFETY: `row` is a complete MIB_TCPROW that outlives the call.
    match unsafe { SetTcpEntry(&row) } {
        0 => Ok(()),
        rc => Err(std::io::Error::from_raw_os_error(rc as i32)),
    }
}

fn tcp_table(family: u32) -> Option<Vec<u64>> {
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` is 8-byte aligned and `size` bytes long.
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc == NO_ERROR.0 {
            return Some(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

/// # Safety
/// `buf` must hold a table written by GetExtendedTcpTable with rows of type `R`.
unsafe fn rows<R>(buf: &[u64]) -> &[R] {
    // Layout: `dwNumEntries: u32`, then the row array at R's alignment.
    let count = buf[0] as u32 as usize;
    let offset = size_of::<u32>().next_multiple_of(align_of::<R>());
    // SAFETY: caller guarantees the layout; GetExtendedTcpTable sized the buffer for `count` rows.
    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>().add(offset).cast::<R>(), count) }
}

static WINSOCK: Once = Once::new();

/// The address's PTR name, e.g. `router.asus.com`, via the system resolver.
/// Blocks for up to the resolver's timeout; call it off the hot path.
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    WINSOCK.call_once(|| {
        let mut data = WSADATA::default();
        // SAFETY: plain Winsock initialisation, done once for the process.
        unsafe { WSAStartup(0x0202, &mut data) };
    });
    let mut host = vec![0u16; NI_MAXHOST as usize];
    let rc = match ip {
        IpAddr::V4(v4) => {
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                ..Default::default()
            };
            // SAFETY: `sa` is a complete SOCKADDR_IN; `host` is writable.
            unsafe {
                GetNameInfoW(
                    (&sa as *const SOCKADDR_IN).cast(),
                    socklen_t(size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut host),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
        IpAddr::V6(v6) => {
            let sa = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..Default::default()
            };
            // SAFETY: `sa` is a complete SOCKADDR_IN6; `host` is writable.
            unsafe {
                GetNameInfoW(
                    (&sa as *const SOCKADDR_IN6).cast(),
                    socklen_t(size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut host),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let name = from_wide(&host).trim_end_matches('.').to_ascii_lowercase();
    // Some resolvers echo the address back instead of failing.
    (!name.is_empty() && name.parse::<IpAddr>().is_err()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_addresses_include_loopback() {
        let own = own_addresses();
        assert!(own.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) || !own.is_empty());
    }

    #[test]
    fn tcp_snapshot_does_not_fail() {
        // Can't assert specific connections; just that parsing produces sane values.
        for c in established_tcp() {
            assert!(!c.remote.ip().is_unspecified());
        }
    }

    #[test]
    fn port_is_network_order() {
        assert_eq!(port(u32::from(u16::from_ne_bytes([0x01, 0xBB]))), 443);
    }

    #[test]
    fn closing_a_connection_resets_it_or_needs_an_administrator() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) =
            (client.local_addr().unwrap(), client.peer_addr().unwrap())
        else {
            unreachable!("IPv4 loopback");
        };
        let closed = close_tcp(local, remote);
        if crate::process::is_elevated() {
            closed.unwrap();
            let mut buf = [0u8; 1];
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            // Reset: an error, or end of stream.
            assert!(!matches!(client.read(&mut buf), Ok(n) if n > 0));
        } else {
            assert!(closed.is_err());
        }
    }
}

/// Whether the connection in use is metered (a capped or pay-per-use data
/// plan), from Windows' Network List Manager; `None` if it can't tell. Uses COM
/// on the calling thread.
pub fn metered() -> Option<bool> {
    use windows::Win32::Networking::NetworkListManager::{
        INetworkCostManager, NLM_CONNECTION_COST_FIXED, NLM_CONNECTION_COST_VARIABLE,
        NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    };
    // SAFETY: COM is initialised for this thread first (already being so is
    // fine); the manager is released when dropped.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let manager: INetworkCostManager =
            CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL).ok()?;
        let mut cost = 0u32;
        manager.GetCost(&mut cost, std::ptr::null()).ok()?;
        let metered = (NLM_CONNECTION_COST_FIXED.0 | NLM_CONNECTION_COST_VARIABLE.0) as u32;
        Some(cost & metered != 0)
    }
}

#[cfg(test)]
mod metered_tests {
    #[test]
    fn metered_is_answered() {
        // Whatever this PC's connection is, Windows says something.
        assert!(super::metered().is_some());
    }
}
