//! Alerts as one sentence, for the Event Log, desktop notifications and the
//! CLI (which adds local times and hints of its own).

use crate::api::{AlertBody, AppField, FileChange, HostRef, ProxyScope, RepVerdict};

/// e.g. "1.5 MB" (decimal units, as Windows shows network traffic).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn host(h: &HostRef) -> String {
    h.name.clone().unwrap_or_else(|| h.ip.to_string())
}

fn list<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        "none".into()
    } else {
        items
            .iter()
            .map(T::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn duration(ms: i64) -> String {
    let minutes = (ms / 60_000).max(0);
    match minutes {
        0..=59 => format!("{minutes} min"),
        _ => format!("{} h {} min", minutes / 60, minutes % 60),
    }
}

impl AlertBody {
    /// One sentence; `app` is the app's name for alerts about an app.
    pub fn text(&self, app: Option<&str>) -> String {
        let app = app.unwrap_or("An app");
        match self {
            AlertBody::AppInfoChanged { field, from, to } => match field {
                AppField::Version => format!("{app} version changed from {from} to {to}"),
                AppField::Publisher => format!("{app} publisher changed from {from} to {to}"),
                AppField::Signer => format!("{app} is now signed by {to} (was {from})"),
                AppField::Signature => format!("{app} was {from}; its file is now {to}"),
                AppField::File => format!(
                    "{app}'s file changed without a version change (SHA-256 {from}… → {to}…)"
                ),
            },
            AlertBody::FirstNetworkActivity {
                host: Some(h),
                port,
            } => format!(
                "{app} used the network for the first time, connecting to {} on port {port}",
                host(h)
            ),
            AlertBody::FirstNetworkActivity { host: None, .. } => {
                format!("{app} used the network for the first time")
            }
            AlertBody::RdpConnection { remote } => {
                format!(
                    "Remote Desktop connection from {} ({})",
                    host(remote),
                    remote.ip
                )
            }
            AlertBody::MonitoringInterrupted => {
                "Another program stopped traffic monitoring; it was restarted".into()
            }
            AlertBody::OwnDns { host: h, port } => format!(
                "{app} does its own DNS ({}:{port}), bypassing Windows' DNS Client",
                host(h)
            ),
            AlertBody::DataPlan {
                used,
                limit,
                percent,
                ..
            } => format!(
                "{percent}% of the data plan used: {} of {}",
                bytes(*used),
                bytes(*limit)
            ),
            AlertBody::FirewallChanged { repaired, .. } => format!(
                "win4tress firewall rules were changed outside win4tress; {repaired} change(s) put back"
            ),
            AlertBody::SystemFileChanged { path, change } => match change {
                FileChange::Created => format!("System file created: {path}"),
                FileChange::Modified => format!("System file changed: {path}"),
                FileChange::Deleted => format!("System file deleted: {path}"),
            },
            AlertBody::AdapterAdded {
                name,
                description,
                mac,
            } => match mac {
                Some(mac) => format!("New network adapter: {name} ({description}, {mac})"),
                None => format!("New network adapter: {name} ({description})"),
            },
            AlertBody::DnsServersChanged { adapter, from, to } => format!(
                "DNS servers on {adapter} changed from {} to {} on the same network",
                list(from),
                list(to)
            ),
            AlertBody::ProxyChanged { scope, from, to } => {
                let whose = match scope {
                    ProxyScope::Machine => "The machine's (WinHTTP)",
                    ProxyScope::User => "Your",
                };
                format!("{whose} proxy settings changed from \"{from}\" to \"{to}\"")
            }
            AlertBody::InternetAccessChanged { connected: true } => {
                "Internet access is back".into()
            }
            AlertBody::InternetAccessChanged { connected: false } => {
                "Internet access was lost".into()
            }
            AlertBody::ArpSpoofing {
                gateway,
                mac,
                known,
                also,
            } => {
                if also.is_empty() {
                    format!(
                        "Possible ARP spoofing: the gateway {gateway} now answers from {mac} (before: {})",
                        list(known)
                    )
                } else {
                    format!(
                        "Possible ARP spoofing: the gateway {gateway}'s hardware address {mac} also answers for {}",
                        list(also)
                    )
                }
            }
            AlertBody::WifiEvilTwin {
                ssid,
                expected,
                seen,
                connected,
            } => {
                if *connected {
                    format!(
                        "Possible Wi-Fi evil twin: you're connected to \"{ssid}\" with {seen}, but it had {expected}"
                    )
                } else {
                    format!(
                        "Possible Wi-Fi evil twin: a network named \"{ssid}\" with {seen} is nearby; yours has {expected}"
                    )
                }
            }
            AlertBody::SuspiciousHost {
                host: h,
                port,
                list,
            } => format!(
                "{app} connected to {} on port {port}, which is on {list}",
                host(h)
            ),
            AlertBody::WhileAway {
                from_ms,
                to_ms,
                bytes: b,
                apps,
                alerts,
            } => {
                let mut text = format!(
                    "While you were away ({}): {} down, {} up",
                    duration(to_ms - from_ms),
                    bytes(b.recv),
                    bytes(b.sent)
                );
                if !apps.is_empty() {
                    text.push_str(&format!(", mostly {}", apps.join(", ")));
                }
                if *alerts > 0 {
                    text.push_str(&format!("; {alerts} alert(s)"));
                }
                text
            }
            AlertBody::NewDevice {
                ip,
                mac,
                vendor,
                name,
            } => {
                let what = match (name, vendor) {
                    (Some(n), Some(v)) => format!("{n} ({v})"),
                    (Some(n), None) => n.clone(),
                    (None, Some(v)) => format!("a {v} device"),
                    (None, None) => "an unknown device".into(),
                };
                format!("New device on the network: {what} at {ip}, {mac}")
            }
            AlertBody::Reputation {
                verdict,
                source,
                detections,
                engines,
                detail,
                blocked,
                ..
            } => {
                let found = match (detections, engines) {
                    (Some(d), Some(e)) => format!("{source}: {d} of {e} engines flag it"),
                    (Some(d), None) => format!("{source}: {d} detections"),
                    _ => format!("{source} flags it"),
                };
                let what = match verdict {
                    RepVerdict::Malicious => "is likely malicious",
                    _ => "may be malicious",
                };
                let mut text = format!("{app}'s file {what} ({found}");
                if let Some(d) = detail {
                    text.push_str(&format!(", {d}"));
                }
                text.push(')');
                if *blocked {
                    text.push_str("; it was blocked");
                }
                text
            }
            AlertBody::DnsFilter { reason } => format!(
                "DNS filtering set aside: {reason}, so Windows' own DNS was put back until it answers again"
            ),
            AlertBody::ProfileSwitched {
                profile,
                network,
                from,
            } => match from {
                Some(from) => format!(
                    "Switched to the firewall profile “{profile}” (from “{from}”) on {network}"
                ),
                None => format!("Switched to the firewall profile “{profile}” on {network}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_decimal_units() {
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_500_000), "1.5 MB");
    }

    #[test]
    fn while_away_reads_as_a_summary() {
        let body = AlertBody::WhileAway {
            from_ms: 0,
            to_ms: 95 * 60_000,
            bytes: w4_core::Bytes {
                recv: 2_000_000,
                sent: 1_000,
            },
            apps: vec!["OneDrive".into(), "svchost".into()],
            alerts: 2,
        };
        assert_eq!(
            body.text(None),
            "While you were away (1 h 35 min): 2.0 MB down, 1.0 KB up, mostly OneDrive, svchost; 2 alert(s)"
        );
    }
}
