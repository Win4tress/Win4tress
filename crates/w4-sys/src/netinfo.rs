//! What the network looks like from here, for the security monitors and the
//! device scanner (SPEC §11): adapters with their DNS servers and gateways,
//! the ARP (neighbor) table, one-off ARP probes, and internet connectivity.

use std::net::{IpAddr, Ipv4Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIpNetTable2, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPNET_TABLE2, SendARP,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, NlnsIncomplete, NlnsUnreachable};

use crate::net::sockaddr_ip;

/// One network adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    /// The adapter's GUID, which stays the same across reboots.
    pub id: String,
    /// The name Windows shows, e.g. "Ethernet" or "Wi-Fi".
    pub name: String,
    pub description: String,
    /// "aa-bb-cc-dd-ee-ff"; `None` for adapters without one.
    pub mac: Option<String>,
    pub up: bool,
    /// IPv4 addresses with their prefix length.
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    /// The network's own DNS suffix (e.g. "home", "corp.example.com"), if any.
    pub dns_suffix: Option<String>,
}

/// A MAC address as Windows writes it.
pub fn mac_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Every adapter but loopback.
pub fn adapters() -> Vec<AdapterInfo> {
    let mut out = Vec::new();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
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
            // SAFETY: a linked list inside `buf`, built by GetAdaptersAddresses;
            // its strings and sub-lists live in the same buffer.
            let a = unsafe { &*adapter };
            adapter = a.Next;
            if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            // SAFETY: as above; the four strings are NUL-terminated.
            let (id, name, description, suffix) = unsafe {
                (
                    a.AdapterName.to_string().unwrap_or_default(),
                    a.FriendlyName.to_string().unwrap_or_default(),
                    a.Description.to_string().unwrap_or_default(),
                    a.DnsSuffix.to_string().unwrap_or_default(),
                )
            };
            let mut info = AdapterInfo {
                id,
                name,
                description,
                mac: mac_text(&a.PhysicalAddress[..(a.PhysicalAddressLength as usize).min(8)]),
                up: a.OperStatus == IfOperStatusUp,
                ipv4: Vec::new(),
                gateways: Vec::new(),
                dns: Vec::new(),
                dns_suffix: (!suffix.trim().is_empty()).then(|| suffix.trim().to_ascii_lowercase()),
            };
            let mut unicast = a.FirstUnicastAddress.cast_const();
            while !unicast.is_null() {
                // SAFETY: as above.
                let u = unsafe { &*unicast };
                // SAFETY: the sockaddr belongs to the same list.
                if let Some(IpAddr::V4(v4)) = unsafe { sockaddr_ip(u.Address.lpSockaddr) } {
                    info.ipv4.push((v4, u.OnLinkPrefixLength));
                }
                unicast = u.Next;
            }
            let mut gateway = a.FirstGatewayAddress.cast_const();
            while !gateway.is_null() {
                // SAFETY: as above.
                let g = unsafe { &*gateway };
                // SAFETY: as above.
                if let Some(ip) = unsafe { sockaddr_ip(g.Address.lpSockaddr) } {
                    info.gateways.push(ip);
                }
                gateway = g.Next;
            }
            let mut dns = a.FirstDnsServerAddress.cast_const();
            while !dns.is_null() {
                // SAFETY: as above.
                let d = unsafe { &*dns };
                // SAFETY: as above.
                if let Some(ip) = unsafe { sockaddr_ip(d.Address.lpSockaddr) } {
                    info.dns.push(ip);
                }
                dns = d.Next;
            }
            out.push(info);
        }
        return out;
    }
    out
}

/// One IPv4 neighbor the PC knows the hardware address of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// The interface's LUID.
    pub interface: u64,
}

/// The IPv4 ARP table: entries with a hardware address (resolved, stale or
/// permanent); unresolved and unreachable ones are left out.
pub fn neighbors() -> Vec<Neighbor> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIpNetTable2 allocates the table; released with FreeMibTable.
    if unsafe { GetIpNetTable2(AF_INET, &mut table) } != NO_ERROR {
        return Vec::new();
    }
    // SAFETY: on success `table` points to NumEntries contiguous rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut out = Vec::new();
    for r in rows {
        if r.State == NlnsIncomplete || r.State == NlnsUnreachable {
            continue;
        }
        // SAFETY: an AF_INET table holds IPv4 addresses.
        let ip = Ipv4Addr::from(unsafe { r.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
        let Some(mac) = mac_text(&r.PhysicalAddress[..(r.PhysicalAddressLength as usize).min(32)])
        else {
            continue;
        };
        // SAFETY: every bit pattern of the NET_LUID union is a valid u64.
        let interface = unsafe { r.InterfaceLuid.Value };
        out.push(Neighbor { ip, mac, interface });
    }
    // SAFETY: allocated by GetIpNetTable2 and not used after this.
    unsafe { FreeMibTable(table as *const _) };
    out
}

/// Asks `ip` for its hardware address with an ARP request (blocking, up to
/// about a second); `None` if nothing answers.
pub fn arp_probe(ip: Ipv4Addr) -> Option<String> {
    let mut mac = [0u8; 8];
    let mut len = mac.len() as u32;
    // SAFETY: `mac` is a writable buffer of `len` bytes.
    let rc = unsafe {
        SendARP(
            u32::from_ne_bytes(ip.octets()),
            0,
            mac.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    mac_text(&mac[..(len as usize).min(8)])
}

/// Whether Windows says this PC reaches the internet (IPv4 or IPv6); `None`
/// if it can't tell. Uses COM on the calling thread.
pub fn internet() -> Option<bool> {
    use windows::Win32::Networking::NetworkListManager::{
        INetworkListManager, NLM_CONNECTIVITY_IPV4_INTERNET, NLM_CONNECTIVITY_IPV6_INTERNET,
        NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    };
    // SAFETY: COM is initialised for this thread first; the manager is
    // released when dropped.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let manager: INetworkListManager =
            CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL).ok()?;
        let c = manager.GetConnectivity().ok()?;
        Some(c.0 & (NLM_CONNECTIVITY_IPV4_INTERNET.0 | NLM_CONNECTIVITY_IPV6_INTERNET.0) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_text_and_empty_addresses() {
        assert_eq!(
            mac_text(&[0, 0x15, 0x5d, 1, 2, 0xff]).as_deref(),
            Some("00-15-5d-01-02-ff")
        );
        assert_eq!(mac_text(&[0; 6]), None);
        assert_eq!(mac_text(&[]), None);
    }

    #[test]
    fn this_pc_has_an_adapter_with_an_address() {
        let adapters = adapters();
        assert!(
            adapters.iter().any(|a| a.up && !a.ipv4.is_empty()),
            "{adapters:?}"
        );
    }

    #[test]
    fn the_arp_table_reads() {
        // May be empty on a PC with no neighbors; it just mustn't fail.
        let _ = neighbors();
        assert!(internet().is_some());
    }
}
