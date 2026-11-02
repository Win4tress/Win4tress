//! Blocklist formats (SPEC §13): hosts files (`0.0.0.0 ads.example.com`),
//! plain domain lists (one per line, `*.` allowed), Adblock-style domain rules
//! (`||ads.example.com^`; other rule types are ignored), and regex lists
//! (one pattern per line). A list is a regex list by its catalogue
//! entry; the other three can be mixed line by line.

use crate::normalize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Hosts, domains and Adblock domain rules, recognised per line.
    Domains,
    /// One regular expression per line.
    Regex,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub domains: Vec<String>,
    pub regexes: Vec<String>,
    /// Lines that weren't comments and couldn't be used.
    pub skipped: usize,
}

/// Names hosts files list for the machine itself, not to block.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

fn is_comment(line: &str) -> bool {
    line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with('[')
}

/// A domain worth blocking: a normalized host name with at least two labels,
/// not one of the machine's own.
fn domain(token: &str) -> Option<String> {
    let token = token.strip_prefix("*.").unwrap_or(token);
    let d = normalize(token)?;
    (d.contains('.') && !LOCAL_NAMES.contains(&d.as_str())).then_some(d)
}

fn is_address(token: &str) -> bool {
    token.parse::<std::net::IpAddr>().is_ok()
}

/// One line of a domain-style list.
fn line_domains(line: &str, out: &mut Vec<String>) -> bool {
    // Adblock: `||domain^`, nothing after but `$important` or `$all`.
    if let Some(rule) = line.strip_prefix("||") {
        let Some((name, rest)) = rule.split_once('^') else {
            return false;
        };
        if !(rest.is_empty() || rest == "$important" || rest == "$all") {
            return false;
        }
        return domain(name).map(|d| out.push(d)).is_some();
    }
    // Exceptions and other Adblock rules aren't blocking domains.
    if line.starts_with("@@") || line.contains(['/', '$', '^', '|']) {
        return false;
    }
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };
    if is_address(first) {
        // Hosts file: an address, then names, maybe an inline comment.
        let mut any = false;
        for t in tokens.take_while(|t| !t.starts_with('#')) {
            if let Some(d) = domain(t) {
                out.push(d);
                any = true;
            }
        }
        return any;
    }
    match tokens.next() {
        None => domain(first).map(|d| out.push(d)).is_some(),
        Some(t) if t.starts_with('#') => domain(first).map(|d| out.push(d)).is_some(),
        Some(_) => false,
    }
}

pub fn parse(text: &str, format: Format) -> Parsed {
    let mut out = Parsed::default();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if is_comment(line) {
            continue;
        }
        let used = match format {
            Format::Regex => {
                out.regexes.push(line.to_string());
                true
            }
            Format::Domains => line_domains(line, &mut out.domains),
        };
        if !used {
            out.skipped += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_files() {
        let p = parse(
            "\u{feff}# StevenBlack\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 0.0.0.0\n\
             0.0.0.0 ads.example.com\n0.0.0.0 a.example.net b.example.net # two\n",
            Format::Domains,
        );
        assert_eq!(
            p.domains,
            ["ads.example.com", "a.example.net", "b.example.net"]
        );
        assert_eq!(p.skipped, 3, "the machine's own names");
    }

    #[test]
    fn plain_and_wildcard_domains() {
        let p = parse(
            "Tracker.Example.com\n*.ads.example.org\nnot a domain\nlocalhost\n",
            Format::Domains,
        );
        assert_eq!(p.domains, ["tracker.example.com", "ads.example.org"]);
        assert_eq!(p.skipped, 2);
    }

    #[test]
    fn adblock_domain_rules_only() {
        let p = parse(
            "[Adblock Plus]\n! comment\n||ads.example.com^\n||x.example.com^$important\n\
             @@||allowed.example.com^\n||y.example.com^$third-party\n/banner/*\nexample.com##.ad\n",
            Format::Domains,
        );
        assert_eq!(p.domains, ["ads.example.com", "x.example.com"]);
        assert_eq!(p.skipped, 4);
    }

    #[test]
    fn regex_lists() {
        let p = parse(
            "# Regex list\n(^|\\.)doubleclick\\.net$\n^ad[0-9]+\\.\n",
            Format::Regex,
        );
        assert_eq!(p.regexes.len(), 2);
    }
}
