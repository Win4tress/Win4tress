//! Threat-intelligence lists (SPEC §11 "Suspicious host contacted", §18):
//! addresses of botnet command servers (abuse.ch Feodo Tracker), hosts serving
//! malware (abuse.ch URLhaus), and the user's own list.

use std::collections::HashSet;
use std::net::IpAddr;

/// Where a match came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatSource {
    /// abuse.ch Feodo Tracker: botnet command-and-control servers.
    Feodo,
    /// abuse.ch URLhaus: hosts serving malware.
    UrlHaus,
    /// The user's own list.
    Local,
}

impl ThreatSource {
    pub fn label(self) -> &'static str {
        match self {
            ThreatSource::Feodo => "Feodo Tracker (botnet command servers)",
            ThreatSource::UrlHaus => "URLhaus (malware hosts)",
            ThreatSource::Local => "your own list",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ThreatLists {
    pub feodo: HashSet<IpAddr>,
    pub urlhaus: HashSet<String>,
    pub local_ips: HashSet<IpAddr>,
    pub local_names: HashSet<String>,
}

/// Lines without comments; a byte-order mark (Notepad's UTF-8) is skipped.
fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
}

/// Feodo Tracker's IP blocklist: one address per line, `#` comments.
pub fn parse_ip_list(text: &str) -> HashSet<IpAddr> {
    data_lines(text).filter_map(|l| l.parse().ok()).collect()
}

/// URLhaus's hosts file: "127.0.0.1 host" per line, `#` comments.
pub fn parse_hosts_file(text: &str) -> HashSet<String> {
    data_lines(text)
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(normalize)
        .filter(|h| !h.is_empty() && h != "localhost")
        .collect()
}

/// The user's list: addresses and host names, one per line. Lines that are
/// neither are left out.
pub fn parse_local_list(text: &str) -> (HashSet<IpAddr>, HashSet<String>) {
    let mut ips = HashSet::new();
    let mut names = HashSet::new();
    for l in data_lines(text) {
        match l.parse::<IpAddr>() {
            Ok(ip) => {
                ips.insert(ip);
            }
            Err(_) => {
                let name = normalize(l);
                if is_host_name(&name) {
                    names.insert(name);
                }
            }
        }
    }
    (ips, names)
}

fn is_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl ThreatLists {
    pub fn is_empty(&self) -> bool {
        self.feodo.is_empty()
            && self.urlhaus.is_empty()
            && self.local_ips.is_empty()
            && self.local_names.is_empty()
    }

    pub fn ip(&self, ip: IpAddr) -> Option<ThreatSource> {
        if self.local_ips.contains(&ip) {
            Some(ThreatSource::Local)
        } else if self.feodo.contains(&ip) {
            Some(ThreatSource::Feodo)
        } else {
            None
        }
    }

    /// A host name, or any domain above it (a listed `bad.example` covers
    /// `cdn.bad.example`).
    pub fn name(&self, name: &str) -> Option<ThreatSource> {
        let name = normalize(name);
        let mut candidate = name.as_str();
        loop {
            if self.local_names.contains(candidate) {
                return Some(ThreatSource::Local);
            }
            if self.urlhaus.contains(candidate) {
                return Some(ThreatSource::UrlHaus);
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_parse_and_match() {
        let lists = ThreatLists {
            feodo: parse_ip_list("# Feodo\n203.0.113.7\n\nnot an ip\n198.51.100.1 # c2\n"),
            urlhaus: parse_hosts_file(
                "# URLhaus\n127.0.0.1\tbad.example\n127.0.0.1 Evil.Example.\n",
            ),
            ..Default::default()
        };
        assert_eq!(lists.feodo.len(), 2);
        assert_eq!(
            lists.ip("203.0.113.7".parse().unwrap()),
            Some(ThreatSource::Feodo)
        );
        assert_eq!(lists.ip("203.0.113.8".parse().unwrap()), None);
        assert_eq!(lists.name("BAD.example."), Some(ThreatSource::UrlHaus));
        assert_eq!(lists.name("cdn.evil.example"), Some(ThreatSource::UrlHaus));
        // Not the whole top-level domain, and not a name that just ends the same.
        assert_eq!(lists.name("example"), None);
        assert_eq!(lists.name("notbad.example"), None);
    }

    #[test]
    fn the_users_list_takes_both_kinds() {
        let (ips, names) = parse_local_list("1.2.3.4\nsuspicious.test # mine\n::1\n");
        assert_eq!(ips.len(), 2);
        assert!(names.contains("suspicious.test"));
    }

    #[test]
    fn notepads_byte_order_mark_and_stray_lines_are_left_out() {
        let (ips, names) =
            parse_local_list("\u{feff}# my list\r\nexample.com\r\nnot a name\r\nhttp://x/\r\n");
        assert!(ips.is_empty());
        assert_eq!(names.into_iter().collect::<Vec<_>>(), ["example.com"]);
    }
}
