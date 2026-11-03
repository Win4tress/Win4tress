//! Finding a computer on the local network by name, as Windows does when DNS
//! doesn't know it: LLMNR for one-label names, mDNS for `.local` (SPEC §13).
//! DNS filtering's routing rule sends every lookup to the resolver, and Windows
//! takes the resolver's "no such name" as final, so the resolver asks here
//! itself. "Multicast only" keeps the DNS Client service off DNS servers, and
//! so off the routing rule: the lookup can't come back to the resolver. It
//! skips Windows' cache too, which may hold the resolver's own earlier "no
//! such name".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::Dns::{
    DNS_QUERY_BYPASS_CACHE, DNS_QUERY_MULTICAST_ONLY, DNS_RECORDA, DNS_TYPE_A, DNS_TYPE_AAAA,
    DnsFree, DnsFreeRecordList, DnsQuery_W,
};
use windows::core::HSTRING;

/// Names Windows looks for on the local network: one label, or `.local`.
pub fn is_multicast_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty() && (!name.contains('.') || name.ends_with(".local"))
}

/// `name`'s IPv4 (`v6` false) or IPv6 addresses on the local network; empty
/// when nothing answers. Link-local IPv6 addresses are left out: without
/// their interface they can't be used. Blocks until LLMNR and mDNS give up
/// (about a second) when nothing has the name.
pub fn lookup(name: &str, v6: bool) -> Vec<IpAddr> {
    let wtype = if v6 { DNS_TYPE_AAAA } else { DNS_TYPE_A };
    let mut list: *mut DNS_RECORDA = std::ptr::null_mut();
    // SAFETY: the name outlives the call; `list` receives a record list that
    // Windows allocates and that is freed below.
    let rc = unsafe {
        DnsQuery_W(
            &HSTRING::from(name),
            wtype,
            DNS_QUERY_MULTICAST_ONLY | DNS_QUERY_BYPASS_CACHE,
            None,
            &mut list,
            None,
        )
    };
    if rc != ERROR_SUCCESS || list.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut r = list;
    while !r.is_null() {
        // SAFETY: a record of the list Windows returned, read before it's freed.
        let rec = unsafe { &*r };
        if rec.wType == wtype.0 {
            let ip = if v6 {
                // SAFETY: an AAAA record's data is DNS_AAAA_DATA.
                IpAddr::V6(Ipv6Addr::from(unsafe { rec.Data.AAAA.Ip6Address.IP6Byte }))
            } else {
                // SAFETY: an A record's data is DNS_A_DATA, in network byte order.
                IpAddr::V4(Ipv4Addr::from(
                    unsafe { rec.Data.A.IpAddress }.to_ne_bytes(),
                ))
            };
            let link_local = matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80);
            if !link_local && !out.contains(&ip) {
                out.push(ip);
            }
        }
        r = rec.pNext;
    }
    // SAFETY: the list DnsQuery_W returned, freed once.
    unsafe { DnsFree(Some(list as *const _), DnsFreeRecordList) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_names_are_one_label_or_local() {
        assert!(is_multicast_name("garrserver"));
        assert!(is_multicast_name("printer.local"));
        assert!(is_multicast_name("nas.local."));
        assert!(!is_multicast_name("example.com"));
        assert!(!is_multicast_name("nas.lan"));
        assert!(!is_multicast_name(""));
    }

    #[test]
    fn a_name_nothing_has_comes_back_empty() {
        assert!(lookup("w4-no-such-host-7f3a91", false).is_empty());
    }

    /// Set W4_LOCAL_NAME to a computer on this network to try it:
    /// `$env:W4_LOCAL_NAME = "garrserver"; cargo test -p w4-sys localname -- --ignored --nocapture`
    #[test]
    #[ignore = "needs a named computer on the local network"]
    fn finds_a_computer_on_this_network() {
        let name = std::env::var("W4_LOCAL_NAME").expect("W4_LOCAL_NAME");
        let t = std::time::Instant::now();
        let v4 = lookup(&name, false);
        let v6 = lookup(&name, true);
        println!("{name}: {v4:?} {v6:?} in {:?}", t.elapsed());
        assert!(!v4.is_empty() || !v6.is_empty());
    }
}
