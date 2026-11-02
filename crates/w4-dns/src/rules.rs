//! What happens to a name (SPEC §13): the user's allow rules first, then
//! deny rules, regex rules (from the user and regex lists), then the
//! blocklists. Allow and deny rules cover a name and its subdomains. Regexes
//! run on a linear-time engine (no backtracking), their number capped.

use std::collections::HashSet;

use regex::{RegexSet, RegexSetBuilder};

use crate::matcher::Blocklist;
use crate::suffixes;

/// At most this many regex rules, all sources together.
pub const MAX_REGEXES: usize = 1_000;
const REGEX_SIZE_LIMIT: usize = 16 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not on any list.
    Pass,
    /// An allow rule covers it (it would otherwise have been blocked or not).
    Allowed {
        rule: String,
    },
    Blocked(Why),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// The user's deny rule (the listed name).
    Deny(String),
    /// A regex rule, by its index among all regexes.
    Regex(usize),
    /// A blocklist, by id, and the listed name.
    List(u16, String),
}

#[derive(Default)]
pub struct Rules {
    allow: HashSet<String>,
    deny: HashSet<String>,
    regex: Option<RegexSet>,
    patterns: Vec<String>,
}

impl Rules {
    /// Builds the rules; regexes that don't compile, or past the cap, are
    /// returned as problems rather than failing the rest.
    pub fn new(
        allow: impl IntoIterator<Item = String>,
        deny: impl IntoIterator<Item = String>,
        regexes: impl IntoIterator<Item = String>,
    ) -> (Rules, Vec<String>) {
        let mut problems = Vec::new();
        let mut patterns = Vec::new();
        for p in regexes {
            if patterns.len() >= MAX_REGEXES {
                problems.push(format!(
                    "more than {MAX_REGEXES} regex rules; the rest are ignored"
                ));
                break;
            }
            match regex::Regex::new(&p) {
                Ok(_) => patterns.push(p),
                Err(e) => problems.push(format!("regex {p:?}: {e}")),
            }
        }
        let regex = if patterns.is_empty() {
            None
        } else {
            match RegexSetBuilder::new(&patterns)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(set) => Some(set),
                Err(e) => {
                    problems.push(format!("regex rules too large together: {e}"));
                    patterns.clear();
                    None
                }
            }
        };
        let rules = Rules {
            allow: allow
                .into_iter()
                .filter_map(|n| crate::normalize(&n))
                .collect(),
            deny: deny
                .into_iter()
                .filter_map(|n| crate::normalize(&n))
                .collect(),
            regex,
            patterns,
        };
        (rules, problems)
    }

    pub fn regex_count(&self) -> usize {
        self.patterns.len()
    }

    pub fn pattern(&self, i: usize) -> Option<&str> {
        self.patterns.get(i).map(String::as_str)
    }

    /// `name` is normalized (lower case, no trailing dot).
    pub fn decide(&self, name: &str, lists: Option<&Blocklist>) -> Verdict {
        if let Some(rule) = suffixes(name).find(|s| self.allow.contains(*s)) {
            return Verdict::Allowed {
                rule: rule.to_string(),
            };
        }
        if let Some(rule) = suffixes(name).find(|s| self.deny.contains(*s)) {
            return Verdict::Blocked(Why::Deny(rule.to_string()));
        }
        if let Some(set) = &self.regex
            && let Some(i) = set.matches(name).iter().next()
        {
            return Verdict::Blocked(Why::Regex(i));
        }
        if let Some(hit) = lists.and_then(|l| l.lookup(name)) {
            return Verdict::Blocked(Why::List(hit.list, hit.listed.to_string()));
        }
        Verdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::compile;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn allow_beats_deny_beats_regex_beats_lists() {
        let listed = s(&["ads.example.com", "tracker.net"]);
        let bl = Blocklist::from_vec(compile(&[(4, &listed)], [3; 16])).unwrap();
        let (rules, problems) = Rules::new(
            s(&["ok.tracker.net"]),
            s(&["Bad.Example.org"]),
            s(&[r"^ad[0-9]+\.", "(unclosed"]),
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(rules.regex_count(), 1);
        let d = |n: &str| rules.decide(n, Some(&bl));
        assert_eq!(
            d("ok.tracker.net"),
            Verdict::Allowed {
                rule: "ok.tracker.net".into()
            }
        );
        assert_eq!(
            d("x.tracker.net"),
            Verdict::Blocked(Why::List(4, "tracker.net".into()))
        );
        assert_eq!(
            d("cdn.bad.example.org"),
            Verdict::Blocked(Why::Deny("bad.example.org".into()))
        );
        assert_eq!(d("ad12.example.com"), Verdict::Blocked(Why::Regex(0)));
        assert_eq!(d("example.com"), Verdict::Pass);
        assert_eq!(rules.decide("ads.example.com", None), Verdict::Pass);
    }

    #[test]
    fn regexes_are_capped() {
        let many = (0..MAX_REGEXES + 5).map(|i| format!("^r{i}\\."));
        let (rules, problems) = Rules::new(Vec::new(), Vec::new(), many);
        assert_eq!(rules.regex_count(), MAX_REGEXES);
        assert_eq!(problems.len(), 1);
    }
}
