//! Blocklists the user can pick (SPEC §13, §18). Never bundled: each is
//! downloaded from its maintainer when chosen, and its licence is shown.
//! Licences checked 2026-10-26.

use crate::lists::Format;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Stable id, kept in settings.
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub url: &'static str,
    pub homepage: &'static str,
    pub licence: &'static str,
    pub licence_url: &'static str,
    pub format: Format,
}

const HAGEZI: &str = "https://github.com/hagezi/dns-blocklists";
const HAGEZI_LICENCE: &str = "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE";
const OISD: &str = "https://oisd.nl";
const OISD_LICENCE: &str = "https://github.com/sjhgvr/oisd/blob/main/LICENSE";

pub const LISTS: &[Entry] = &[
    Entry {
        id: "hagezi-light",
        name: "HaGeZi Light",
        description: "Ads, tracking, metrics and some malware; very little breaks",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        homepage: HAGEZI,
        licence: "GPL-3.0",
        licence_url: HAGEZI_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "hagezi-normal",
        name: "HaGeZi Normal",
        description: "All-round protection against ads, tracking, malware and scams (recommended)",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        homepage: HAGEZI,
        licence: "GPL-3.0",
        licence_url: HAGEZI_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "hagezi-pro",
        name: "HaGeZi Pro",
        description: "Stronger; now and then something needs allowing",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        homepage: HAGEZI,
        licence: "GPL-3.0",
        licence_url: HAGEZI_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "hagezi-ultimate",
        name: "HaGeZi Ultimate",
        description: "Strictest; expect to allow things",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
        homepage: HAGEZI,
        licence: "GPL-3.0",
        licence_url: HAGEZI_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "hagezi-tif-medium",
        name: "HaGeZi Threat Intelligence (medium)",
        description: "Malware, phishing, scam and cryptojacking domains",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
        homepage: HAGEZI,
        licence: "GPL-3.0",
        licence_url: HAGEZI_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "oisd-small",
        name: "OISD Small",
        description: "Ads and tracking, chosen not to break things",
        url: "https://small.oisd.nl/domainswild2",
        homepage: OISD,
        licence: "GPL-3.0",
        licence_url: OISD_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "oisd-big",
        name: "OISD Big",
        description: "Ads, tracking, malware and phishing; \"block, don't break\"",
        url: "https://big.oisd.nl/domainswild2",
        homepage: OISD,
        licence: "GPL-3.0",
        licence_url: OISD_LICENCE,
        format: Format::Domains,
    },
    Entry {
        id: "stevenblack",
        name: "StevenBlack Unified",
        description: "Ads and malware, as a hosts file",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        homepage: "https://github.com/StevenBlack/hosts",
        licence: "MIT",
        licence_url: "https://github.com/StevenBlack/hosts/blob/master/license.txt",
        format: Format::Domains,
    },
    Entry {
        id: "adguard-dns",
        name: "AdGuard DNS filter",
        description: "AdGuard's base, tracking and mobile ad filters, made for DNS",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter",
        licence: "GPL-3.0",
        licence_url: "https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE",
        format: Format::Domains,
    },
];

/// What's chosen when filtering is first turned on.
pub const DEFAULT: &[&str] = &["hagezi-normal"];

pub fn find(id: &str) -> Option<&'static Entry> {
    LISTS.iter().find(|e| e.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_the_default_exists() {
        let mut ids: Vec<_> = LISTS.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), LISTS.len());
        assert!(DEFAULT.iter().all(|d| find(d).is_some()));
        assert!(LISTS.iter().all(|e| e.url.starts_with("https://")));
    }
}
