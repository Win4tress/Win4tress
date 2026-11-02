//! Address conditions, compared by meaning rather than by text: Windows rewrites
//! `8.8.8.8` as `8.8.8.8/255.255.255.255` when it's read back (spike 0.2).

use std::collections::BTreeSet;
use std::net::IpAddr;

/// A rule's address condition. `Any` is Windows' `*`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AddressSet {
    #[default]
    Any,
    /// Canonical entries: `1.2.3.4`, `10.0.0.0/8`, `1.0.0.0-1.1.1.0`, or a
    /// lower-case keyword such as `localsubnet`.
    List(BTreeSet<String>),
}

impl AddressSet {
    /// Parses Windows' comma-separated form. Entries it doesn't understand are
    /// kept (lower-cased) so they still compare.
    pub fn parse(text: &str) -> AddressSet {
        let entries: BTreeSet<String> = text
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(canonical)
            .collect();
        if entries.is_empty() || entries.contains("*") {
            AddressSet::Any
        } else {
            AddressSet::List(entries)
        }
    }

    /// The form written to Windows Firewall.
    pub fn to_windows(&self) -> String {
        match self {
            AddressSet::Any => "*".into(),
            AddressSet::List(entries) => entries.iter().cloned().collect::<Vec<_>>().join(","),
        }
    }
}

/// A host entry that is an address, range or network, in canonical form;
/// `None` for anything else (a name).
pub fn literal(entry: &str) -> Option<String> {
    let c = canonical(entry.trim());
    span(&c).map(|_| c)
}

/// The first and last address an entry covers, per family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Span {
    V4(u128, u128),
    V6(u128, u128),
}

fn span(canonical: &str) -> Option<Span> {
    let wrap = |a: IpAddr, b: IpAddr| match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            Some(Span::V4(u128::from(u32::from(a)), u128::from(u32::from(b))))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => Some(Span::V6(u128::from(a), u128::from(b))),
        _ => None,
    };
    if let Some((a, b)) = canonical.split_once('-') {
        return wrap(a.parse().ok()?, b.parse().ok()?);
    }
    if let Some((ip, prefix)) = canonical.split_once('/') {
        let ip: IpAddr = ip.parse().ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        let full = if ip.is_ipv4() { 32 } else { 128 };
        let host_bits = full - prefix.min(full);
        let size = 1u128.checked_shl(host_bits).map_or(u128::MAX, |n| n - 1);
        let first = match network(ip, prefix) {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        return match ip {
            IpAddr::V4(_) => Some(Span::V4(first, first + size)),
            IpAddr::V6(_) => Some(Span::V6(first, first.saturating_add(size))),
        };
    }
    let ip: IpAddr = canonical.parse().ok()?;
    wrap(ip, ip)
}

/// The gaps between `taken` spans in `[0, max]`.
fn gaps(mut taken: Vec<(u128, u128)>, max: u128) -> Vec<(u128, u128)> {
    taken.sort_unstable();
    let mut out = Vec::new();
    let mut next: Option<u128> = Some(0); // first address not yet covered
    for (a, b) in taken {
        let Some(n) = next else { break };
        if a > n {
            out.push((n, a - 1));
        }
        if b >= n {
            next = b.checked_add(1).filter(|&x| x <= max);
        }
    }
    if let Some(n) = next {
        out.push((n, max));
    }
    out
}

/// Every address except `entries` and this PC itself (loopback), as Windows
/// address entries. Entries that aren't addresses are ignored.
pub fn complement(entries: &[String]) -> Vec<String> {
    let mut v4 = vec![(127u128 << 24, (127u128 << 24) | 0x00FF_FFFF)];
    let mut v6 = vec![(1u128, 1u128)];
    for e in entries {
        match span(&canonical(e)) {
            Some(Span::V4(a, b)) => v4.push((a, b)),
            Some(Span::V6(a, b)) => v6.push((a, b)),
            None => {}
        }
    }
    let show = |a: u128, b: u128, v4: bool| {
        let ip = |n: u128| -> IpAddr {
            if v4 {
                std::net::Ipv4Addr::from(n as u32).into()
            } else {
                std::net::Ipv6Addr::from(n).into()
            }
        };
        if a == b {
            ip(a).to_string()
        } else {
            format!("{}-{}", ip(a), ip(b))
        }
    };
    let mut out: Vec<String> = gaps(v4, u128::from(u32::MAX))
        .into_iter()
        .map(|(a, b)| show(a, b, true))
        .collect();
    out.extend(
        gaps(v6, u128::MAX)
            .into_iter()
            .map(|(a, b)| show(a, b, false)),
    );
    out
}

fn canonical(entry: &str) -> String {
    let entry = entry.to_ascii_lowercase();
    if let Some((a, b)) = entry.split_once('-')
        && let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>())
    {
        return if a == b {
            a.to_string()
        } else {
            format!("{a}-{b}")
        };
    }
    if let Some((ip, mask)) = entry.split_once('/')
        && let Ok(ip) = ip.parse::<IpAddr>()
        && let Some(prefix) = prefix_len(mask, ip)
    {
        let full = if ip.is_ipv4() { 32 } else { 128 };
        return if prefix == full {
            ip.to_string()
        } else {
            format!("{}/{prefix}", network(ip, prefix))
        };
    }
    match entry.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => entry,
    }
}

/// A prefix length from either `24` or a contiguous mask like `255.255.255.0`.
fn prefix_len(mask: &str, ip: IpAddr) -> Option<u32> {
    let full = if ip.is_ipv4() { 32 } else { 128 };
    if let Ok(n) = mask.parse::<u32>() {
        return (n <= full).then_some(n);
    }
    let bits: u128 = match (mask.parse::<IpAddr>().ok()?, ip) {
        (IpAddr::V4(m), IpAddr::V4(_)) => u128::from(u32::from(m)) << 96,
        (IpAddr::V6(m), IpAddr::V6(_)) => u128::from(m),
        _ => return None,
    };
    let ones = bits.leading_ones();
    // Contiguous only: ones followed by zeros.
    (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones)
}

fn network(ip: IpAddr, prefix: u32) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> AddressSet {
        AddressSet::List(entries.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn windows_read_back_forms_match_what_was_written() {
        assert_eq!(
            AddressSet::parse("8.8.8.8/255.255.255.255"),
            AddressSet::parse("8.8.8.8")
        );
        assert_eq!(
            AddressSet::parse("10.1.2.3/255.0.0.0"),
            list(&["10.0.0.0/8"])
        );
        assert_eq!(AddressSet::parse("10.0.0.0/8"), list(&["10.0.0.0/8"]));
        assert_eq!(AddressSet::parse("2001:db8::1/128"), list(&["2001:db8::1"]));
        assert_eq!(
            AddressSet::parse("2001:DB8::/ffff:ffff::"),
            list(&["2001:db8::/32"])
        );
        assert_eq!(AddressSet::parse("1.1.1.1-1.1.1.1"), list(&["1.1.1.1"]));
        assert_eq!(
            AddressSet::parse("0.0.0.0-1.1.1.0, 1.1.1.2-255.255.255.255"),
            list(&["0.0.0.0-1.1.1.0", "1.1.1.2-255.255.255.255"])
        );
    }

    #[test]
    fn any_and_keywords() {
        assert_eq!(AddressSet::parse("*"), AddressSet::Any);
        assert_eq!(AddressSet::parse(""), AddressSet::Any);
        assert_eq!(AddressSet::parse("LocalSubnet"), list(&["localsubnet"]));
        assert_eq!(AddressSet::Any.to_windows(), "*");
    }

    #[test]
    fn order_and_duplicates_dont_matter() {
        assert_eq!(
            AddressSet::parse("8.8.8.8,1.1.1.1,8.8.8.8"),
            AddressSet::parse("1.1.1.1, 8.8.8.8")
        );
    }

    #[test]
    fn written_form_parses_back_to_itself() {
        let set = AddressSet::parse("10.0.0.0/8,1.1.1.1,::1,2001:db8::/32,localsubnet");
        assert_eq!(AddressSet::parse(&set.to_windows()), set);
    }

    #[test]
    fn literals_and_names() {
        assert_eq!(literal(" 8.8.8.8 ").as_deref(), Some("8.8.8.8"));
        assert_eq!(literal("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(
            literal("1.1.1.1-1.1.1.9").as_deref(),
            Some("1.1.1.1-1.1.1.9")
        );
        assert_eq!(literal("ads.example.com"), None);
        assert_eq!(literal("*.example.com"), None);
    }

    #[test]
    fn complement_leaves_loopback_and_the_hosts_out() {
        // Nothing excluded: all of IPv4 but 127/8, all of IPv6 but ::1.
        assert_eq!(
            complement(&[]),
            [
                "0.0.0.0-126.255.255.255",
                "128.0.0.0-255.255.255.255",
                "::",
                "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            ]
        );
        let hosts = [
            "8.8.8.8".to_string(),
            "10.0.0.0/8".into(),
            "2001:db8::1".into(),
        ];
        assert_eq!(
            complement(&hosts),
            [
                "0.0.0.0-8.8.8.7",
                "8.8.8.9-9.255.255.255",
                "11.0.0.0-126.255.255.255",
                "128.0.0.0-255.255.255.255",
                "::",
                "::2-2001:db8::",
                "2001:db8::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            ]
        );
        // Overlaps, the very first and last addresses, and names are fine.
        let edges = [
            "0.0.0.0".to_string(),
            "255.255.255.255".into(),
            "1.0.0.0-1.0.0.9".into(),
            "1.0.0.5".into(),
            "example.com".into(),
        ];
        assert_eq!(
            complement(&edges)[..3],
            [
                "0.0.0.1-0.255.255.255",
                "1.0.0.10-126.255.255.255",
                "128.0.0.0-255.255.255.254"
            ]
        );
        // What Windows reads back parses to the same set.
        let written = AddressSet::List(complement(&hosts).into_iter().collect());
        assert_eq!(AddressSet::parse(&written.to_windows()), written);
    }

    #[test]
    fn non_contiguous_masks_are_kept_as_written() {
        assert_eq!(
            AddressSet::parse("10.0.0.0/255.0.255.0"),
            list(&["10.0.0.0/255.0.255.0"])
        );
    }
}
