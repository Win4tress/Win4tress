//! What the service tells the resolver (SPEC §13): written by `win4tress-svc`
//! as `config.json` in the resolver's folder, with the compiled blocklist
//! beside it; the resolver reloads it when it changes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "config.json";
/// The name the service's watchdog asks for; answered by the resolver itself.
pub const HEALTH_NAME: &str = "health.win4tress.invalid";
/// Firefox turns its own encrypted DNS off when this name doesn't resolve.
pub const FIREFOX_CANARY: &str = "use-application-dns.net";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observe {
    /// Observe only when the upstream already blocks (an ad-blocking DNS server).
    #[default]
    Auto,
    /// Never block, only note what would be blocked.
    On,
    Off,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockAnswer {
    /// `0.0.0.0` / `::`.
    #[default]
    NullIp,
    Nxdomain,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Upstream {
    /// The network's own DNS servers (`system_servers`).
    #[default]
    System,
    /// DNS over HTTPS (RFC 8484), e.g. `https://cloudflare-dns.com/dns-query`.
    Doh { url: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRecord {
    pub name: String,
    pub addrs: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListName {
    pub id: u16,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Off: a plain forwarder (nothing blocked).
    #[serde(default = "yes")]
    pub filtering: bool,
    #[serde(default)]
    pub observe: Observe,
    #[serde(default)]
    pub block_answer: BlockAnswer,
    #[serde(default)]
    pub upstream: Upstream,
    /// The DNS servers the adapters had before pointing at the resolver: the
    /// upstream for `System`, and for local names, the DoH server's own name
    /// and captive portals whatever the upstream.
    #[serde(default)]
    pub system_servers: Vec<IpAddr>,
    /// The networks' own suffixes (e.g. `home`, `corp.example.com`): always
    /// asked of the system servers (split DNS).
    #[serde(default)]
    pub local_suffixes: Vec<String>,
    /// A sign-in page (captive portal): forward everything, unfiltered, to the
    /// system servers until the network is online.
    #[serde(default)]
    pub passthrough: bool,
    /// Blocking paused until then (Unix ms).
    #[serde(default)]
    pub paused_until_ms: Option<i64>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// The user's regex rules and those of regex lists.
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub local_records: Vec<LocalRecord>,
    /// The compiled blocklist's file name in the resolver's folder.
    #[serde(default)]
    pub blocklist: Option<String>,
    /// The lists in it, for naming what blocked a lookup.
    #[serde(default)]
    pub lists: Vec<ListName>,
}

fn yes() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            filtering: true,
            observe: Observe::default(),
            block_answer: BlockAnswer::default(),
            upstream: Upstream::default(),
            system_servers: Vec::new(),
            local_suffixes: Vec::new(),
            passthrough: false,
            paused_until_ms: None,
            allow: Vec::new(),
            deny: Vec::new(),
            regex: Vec::new(),
            local_records: Vec::new(),
            blocklist: None,
            lists: Vec::new(),
        }
    }
}

/// Names the system servers answer whatever the upstream: one label, a
/// network's own suffix, `.local` and reverse lookups of private addresses.
pub fn is_local_name(name: &str, suffixes: &[String]) -> bool {
    if !name.contains('.') || name.ends_with(".local") || name == "local" {
        return true;
    }
    if suffixes.iter().any(|s| {
        name == s
            || name
                .strip_suffix(s.as_str())
                .is_some_and(|p| p.ends_with('.'))
    }) {
        return true;
    }
    if let Some(rev) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rev.rsplit('.').collect();
        return match octets.as_slice() {
            ["10", ..] | ["127", ..] | ["192", "168", ..] | ["169", "254", ..] => true,
            ["172", second, ..] => second.parse::<u8>().is_ok_and(|s| (16..=31).contains(&s)),
            _ => false,
        };
    }
    if let Some(rev) = name.strip_suffix(".ip6.arpa") {
        // Nibbles, last first: fd../fc.. unique local, fe8.. link-local.
        let nibbles: String = rev.rsplit('.').take(3).collect();
        return nibbles.starts_with("fd")
            || nibbles.starts_with("fc")
            || nibbles.starts_with("fe8");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_stay_with_the_network() {
        let s = vec!["home".to_string(), "corp.example.com".to_string()];
        assert!(is_local_name("nas", &s));
        assert!(is_local_name("nas.home", &s));
        assert!(is_local_name("srv.corp.example.com", &s));
        assert!(!is_local_name("example.com", &s));
        assert!(!is_local_name("notcorp.example.com", &s));
        assert!(is_local_name("printer.local", &s));
        assert!(is_local_name("20.1.168.192.in-addr.arpa", &s));
        assert!(is_local_name("5.0.20.172.in-addr.arpa", &s));
        assert!(!is_local_name("5.0.40.172.in-addr.arpa", &s));
        assert!(!is_local_name("8.8.8.8.in-addr.arpa", &s));
        assert!(is_local_name(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
            &s
        ));
    }

    #[test]
    fn missing_fields_take_defaults() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert!(c.filtering);
        assert_eq!(c.upstream, Upstream::System);
    }
}
