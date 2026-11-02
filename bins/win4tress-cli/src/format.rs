//! Text formatting for terminal output.

use w4_core::firewall::{Action, BlockedBy, BlockedByKind, Direction, Verdict, VerdictSource};
use w4_ipc::api::{Alert, AlertBody, HostRef, OutsideChange, OutsideKind};

pub fn human(bytes: u64) -> String {
    w4_ipc::text::bytes(bytes)
}

pub fn rate(bytes_per_sec: u64) -> String {
    format!("{}/s", human(bytes_per_sec))
}

pub fn duration(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, (s / 60) % 60),
    }
}

pub fn ago(ms: i64) -> String {
    format!("{} ago", duration(ms))
}

/// Local HH:MM:SS for a Unix second.
pub fn clock(unix_s: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(unix_s, 0) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => unix_s.to_string(),
    }
}

/// Local `YYYY-MM-DD HH:MM` for Unix milliseconds.
pub fn date_time(ms: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(ms) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M").to_string(),
        _ => ms.to_string(),
    }
}

/// An alert as one sentence, with local times and the commands that act on it.
pub fn alert_text(a: &Alert) -> String {
    let app = a.app.as_ref().map_or("An app", |r| r.name.as_str());
    let host = |h: &HostRef| h.name.clone().unwrap_or_else(|| h.ip.to_string());
    match &a.body {
        AlertBody::DataPlan {
            used,
            limit,
            percent,
            period_start_ms,
        } => format!(
            "{percent}% of the data plan used: {} of {} since {}",
            human(*used),
            human(*limit),
            date_time(*period_start_ms)
        ),
        AlertBody::OwnDns { host: h, port } => format!(
            "{app} does its own DNS ({}:{port}), bypassing Windows' DNS Client; to block it: win4tress block \"{app}\" --own-dns",
            host(h)
        ),
        AlertBody::FirewallChanged {
            repaired,
            changes,
            kept_ms,
        } => {
            let mut text = format!(
                "win4tress firewall rules were changed outside win4tress; {repaired} change(s) put back"
            );
            for c in changes {
                text.push_str(&format!(
                    "
      {}",
                    outside_change(c)
                ));
            }
            match kept_ms {
                Some(t) => text.push_str(&format!(
                    "
      Kept instead on {}",
                    date_time(*t)
                )),
                None if changes.iter().any(|c| c.keepable) => text.push_str(&format!(
                    "
      To keep them instead: win4tress keep-changes {}",
                    a.id
                )),
                None => {}
            }
            text
        }
        AlertBody::WhileAway { from_ms, to_ms, .. } => format!(
            "{} → {}: {}",
            date_time(*from_ms),
            clock(to_ms / 1000),
            a.body.text(None)
        ),
        AlertBody::NewDevice { mac, .. } => format!(
            "{}; if you know it: win4tress devices --known {mac}",
            a.body.text(None)
        ),
        body => body.text(a.app.as_ref().map(|r| r.name.as_str())),
    }
}

/// What blocked a connection, e.g. `win4tress: curl (Out, Block) #3`.
pub fn blocked_by(by: &BlockedBy) -> String {
    match by.kind {
        BlockedByKind::Win4tress => by.name.clone(),
        BlockedByKind::WindowsRule => format!("Windows Firewall rule \"{}\"", by.name),
        BlockedByKind::WindowsDefault => "Windows Firewall's default (no rule allowed it)".into(),
        BlockedByKind::Other => format!("another filter: {}", by.name),
    }
}

/// e.g. `blocked by Windows Firewall's default (no rule allows them)`.
pub fn verdict_text(v: &Verdict, inbound: bool) -> String {
    let state = if v.allowed { "allowed" } else { "blocked" };
    match v.by {
        VerdictSource::Win4tress => format!("{state} by a win4tress rule"),
        VerdictSource::WindowsRule => {
            let names: Vec<String> = v.rules.iter().map(|r| format!("\"{r}\"")).collect();
            format!(
                "{state} by Windows Firewall rule{} {}",
                if names.len() == 1 { "" } else { "s" },
                names.join(", ")
            )
        }
        VerdictSource::Default if inbound && !v.allowed => {
            "blocked by Windows Firewall's default (no rule allows them)".into()
        }
        VerdictSource::Default => format!("{state} by Windows Firewall's default"),
        VerdictSource::FirewallOff => "allowed: Windows Firewall is off on a network in use".into(),
    }
}

/// e.g. "curl (outgoing block): turned off".
pub fn outside_change(c: &OutsideChange) -> String {
    let rule = match (c.direction, c.action) {
        (Some(d), Some(a)) => format!(
            "{} ({} {})",
            c.name,
            match d {
                Direction::In => "incoming",
                Direction::Out => "outgoing",
            },
            match a {
                Action::Allow => "allow",
                Action::Block => "block",
            }
        ),
        _ => format!("\"{}\"", c.name),
    };
    let what = match c.kind {
        OutsideKind::Deleted => "deleted",
        OutsideKind::Disabled => "turned off",
        OutsideKind::Enabled => "turned on",
        OutsideKind::Allowed => "switched to allow",
        OutsideKind::Blocked => "switched to block",
        OutsideKind::Modified => "its conditions were changed",
        OutsideKind::Added => "added to win4tress's rule group",
    };
    let keep = if c.keepable { "" } else { " (can't be kept)" };
    format!("{rule}: {what}{keep}")
}

/// DNS record type name, e.g. 28 -> AAAA.
pub fn dns_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        other => other.to_string(),
    }
}

/// Plain words for common Windows DNS errors.
pub fn dns_status(status: u32) -> String {
    match status {
        0 => "ok".into(),
        9003 => "no such name".into(),
        9501 => "no records of this type".into(),
        9002 => "server failure".into(),
        9005 => "refused".into(),
        1460 => "timed out".into(),
        1214 | 123 => "invalid name".into(),
        other => format!("error {other}"),
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(human(999), "999 B");
        assert_eq!(human(1_500_000), "1.5 MB");
        assert_eq!(rate(2_000), "2.0 KB/s");
    }

    #[test]
    fn verdicts() {
        let v = |allowed, by, rules: &[&str]| Verdict {
            allowed,
            by,
            rules: rules.iter().map(|r| r.to_string()).collect(),
        };
        assert_eq!(
            verdict_text(&v(true, VerdictSource::WindowsRule, &["Steam"]), true),
            "allowed by Windows Firewall rule \"Steam\""
        );
        assert_eq!(
            verdict_text(&v(false, VerdictSource::Default, &[]), true),
            "blocked by Windows Firewall's default (no rule allows them)"
        );
        assert_eq!(
            verdict_text(&v(true, VerdictSource::Default, &[]), false),
            "allowed by Windows Firewall's default"
        );
    }

    #[test]
    fn durations() {
        assert_eq!(duration(5_000), "5s");
        assert_eq!(duration(125_000), "2m 5s");
        assert_eq!(duration(7_260_000), "2h 1m");
    }
}
