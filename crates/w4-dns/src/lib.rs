//! DNS filtering (SPEC §13): blocklists in their common formats, compiled when
//! downloaded into a sorted array of keyed 64-bit hashes that the resolver
//! memory-maps; the user's allow, deny and regex rules; and the DNS messages
//! the resolver reads and answers.

pub mod catalogue;
pub mod compile;
pub mod config;
pub mod lists;
pub mod matcher;
pub mod rules;
pub mod status;
pub mod wire;

/// A name as lists and rules hold it: lower case, no trailing dot; `None` if
/// it isn't a host name (labels of letters, digits, `-` and `_`, 1 to 63
/// characters, 253 in all).
pub fn normalize(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| name.to_ascii_lowercase())
}

/// The name, then each parent: `a.b.example.com`, `b.example.com`,
/// `example.com`, `com`.
pub fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.split_once('.').map(|(_, rest)| rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalized() {
        assert_eq!(
            normalize("Ads.Example.COM.").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            normalize("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
        assert_eq!(normalize("bad name.com"), None);
        assert_eq!(normalize("a..b"), None);
        assert_eq!(normalize(""), None);
        assert_eq!(normalize(&"a".repeat(64)), None);
    }

    #[test]
    fn suffixes_walk_up_to_the_top_level() {
        let all: Vec<_> = suffixes("a.b.example.com").collect();
        assert_eq!(
            all,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
        assert_eq!(suffixes("localhost").collect::<Vec<_>>(), ["localhost"]);
    }
}
