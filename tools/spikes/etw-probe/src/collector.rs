//! ETW callbacks. Decodes three providers into shared counters:
//! - Kernel-Network: bytes sent/received per process and remote address
//! - Kernel-Process: process start events, for names of short-lived processes
//!   and to tell PID reuse apart
//! - DNS-Client: completed lookups, mapping remote IPs back to the hostname
//!   the app asked for
//!
//! Events are decoded outside the lock and applied under it in one short step.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use ferrisetw::parser::Parser;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::{EventRecord, EventSerializer, EventSerializerOptions};

use crate::procinfo;

pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
pub const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

/// Kernel-Process keyword for process start/stop events.
pub const KEYWORD_PROCESS: u64 = 0x10;

const PROCESS_START: u16 = 1;
const DNS_QUERY_COMPLETED: u16 = 3008;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    Network,
    Process,
    Dns,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Network => "Kernel-Network",
            Source::Process => "Kernel-Process",
            Source::Dns => "DNS-Client",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    Send,
    Recv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetKind {
    Data(Dir),
    Connect,
    Accept,
    Other,
}

/// Kernel-Network event IDs from the provider manifest: TCP over IPv4, with
/// IPv6 at +16 and UDP at +32. `--dump` prints each event's actual layout.
fn classify(id: u16) -> Option<NetKind> {
    Some(match id {
        10 | 26 | 42 | 58 => NetKind::Data(Dir::Send),
        11 | 27 | 43 | 59 => NetKind::Data(Dir::Recv),
        12 | 28 => NetKind::Connect,
        15 | 31 => NetKind::Accept,
        13 | 29 => NetKind::Other,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub sent: u64,
    pub recv: u64,
}

impl Counters {
    fn add(&mut self, dir: Dir, bytes: u64) {
        match dir {
            Dir::Send => self.sent += bytes,
            Dir::Recv => self.recv += bytes,
        }
    }

    pub fn total(&self) -> u64 {
        self.sent + self.recv
    }

    pub fn minus(&self, earlier: &Counters) -> Counters {
        Counters {
            sent: self.sent.saturating_sub(earlier.sent),
            recv: self.recv.saturating_sub(earlier.recv),
        }
    }
}

/// One process instance. `generation` changes when Windows reuses a PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub pid: u32,
    pub generation: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ProcStats {
    pub name: String,
    pub external: Counters,
    pub loopback: Counters,
    pub connects: u64,
    pub accepts: u64,
    pub dns_answers: u64,
    pub hosts: HashMap<IpAddr, Counters>,
}

struct LiveProc {
    generation: u32,
    name: Option<String>,
    /// ETW timestamp of the first event seen for this generation.
    first_seen: i64,
}

#[derive(Default)]
struct State {
    external: Counters,
    loopback: Counters,
    /// External bytes whose remote IP already had a DNS name when they arrived.
    external_named: Counters,
    procs: HashMap<ProcKey, ProcStats>,
    live: HashMap<u32, LiveProc>,
    event_counts: HashMap<(Source, u16), u64>,
    data_events: u64,
    /// Data events whose header PID differs from the PID in the event data.
    header_pid_mismatch: u64,
    parse_errors: u64,
    parse_error_samples: Vec<String>,
    dns_answers: u64,
    dns_names: HashMap<IpAddr, String>,
}

/// A point-in-time copy of the counters, for reporting.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub external: Counters,
    pub loopback: Counters,
    pub external_named: Counters,
    pub procs: HashMap<ProcKey, ProcStats>,
    pub event_counts: HashMap<(Source, u16), u64>,
    pub data_events: u64,
    pub header_pid_mismatch: u64,
    pub parse_errors: u64,
    pub parse_error_samples: Vec<String>,
    pub dns_answers: u64,
    pub dns_names: HashMap<IpAddr, String>,
}

impl Snapshot {
    pub fn total_events(&self) -> u64 {
        self.event_counts.values().sum()
    }

    pub fn host_label(&self, ip: &IpAddr) -> String {
        match self.dns_names.get(ip) {
            Some(name) => format!("{name} ({ip})"),
            None => ip.to_string(),
        }
    }
}

enum Decoded {
    Net {
        pid: u32,
        header_pid: u32,
        kind: NetKind,
        size: u64,
        remote: IpAddr,
        local: IpAddr,
        ts: i64,
    },
    ProcessStart {
        pid: u32,
        image: String,
        ts: i64,
    },
    DnsAnswer {
        header_pid: u32,
        name: String,
        ips: Vec<IpAddr>,
        ts: i64,
    },
    Ignored,
}

macro_rules! field {
    ($parser:expr, $ty:ty, $name:literal) => {
        $parser
            .try_parse::<$ty>($name)
            .map_err(|e| format!("field {}: {:?}", $name, e))?
    };
}

pub struct Collector {
    state: Mutex<State>,
    dump: bool,
    dumped: Mutex<HashSet<(Source, u16)>>,
    first_event: OnceLock<Instant>,
}

impl Collector {
    pub fn new(dump: bool) -> Self {
        Collector {
            state: Mutex::new(State::default()),
            dump,
            dumped: Mutex::new(HashSet::new()),
            first_event: OnceLock::new(),
        }
    }

    pub fn first_event(&self) -> Option<Instant> {
        self.first_event.get().copied()
    }

    /// ETW callback. Never panics on bad input: malformed events are counted
    /// and skipped.
    pub fn on_event(&self, source: Source, record: &EventRecord, locator: &SchemaLocator) {
        self.first_event.get_or_init(Instant::now);
        let id = record.event_id();

        let decoded = match locator.event_schema(record) {
            Ok(schema) => {
                if self.dump {
                    self.dump_once(source, id, record, &schema);
                }
                decode(source, id, record, &Parser::create(record, &schema))
            }
            Err(e) => Err(format!("no schema: {e:?}")),
        };

        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        *st.event_counts.entry((source, id)).or_default() += 1;
        match decoded {
            Ok(d) => st.apply(d),
            Err(msg) => {
                st.parse_errors += 1;
                if st.parse_error_samples.len() < 20 {
                    st.parse_error_samples
                        .push(format!("{} event {id}: {msg}", source.label()));
                }
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Snapshot {
            external: st.external,
            loopback: st.loopback,
            external_named: st.external_named,
            procs: st.procs.clone(),
            event_counts: st.event_counts.clone(),
            data_events: st.data_events,
            header_pid_mismatch: st.header_pid_mismatch,
            parse_errors: st.parse_errors,
            parse_error_samples: st.parse_error_samples.clone(),
            dns_answers: st.dns_answers,
            dns_names: st.dns_names.clone(),
        }
    }

    fn dump_once(&self, source: Source, id: u16, record: &EventRecord, schema: &Schema) {
        let first = self
            .dumped
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((source, id));
        if !first {
            return;
        }
        let ser = EventSerializer::new(record, schema, EventSerializerOptions::default());
        match serde_json::to_string_pretty(&ser) {
            Ok(json) => println!("--- {} event {id} ---\n{json}", source.label()),
            Err(e) => println!(
                "--- {} event {id}: could not serialize: {e}",
                source.label()
            ),
        }
    }
}

fn decode(
    source: Source,
    id: u16,
    record: &EventRecord,
    parser: &Parser,
) -> Result<Decoded, String> {
    let ts = record.raw_timestamp();
    match source {
        Source::Network => {
            let Some(kind) = classify(id) else {
                return Ok(Decoded::Ignored);
            };
            let size = match kind {
                NetKind::Data(_) => u64::from(field!(parser, u32, "size")),
                _ => 0,
            };
            Ok(Decoded::Net {
                pid: field!(parser, u32, "PID"),
                header_pid: record.process_id(),
                kind,
                size,
                // daddr/saddr are the remote/local ends for both directions.
                remote: field!(parser, IpAddr, "daddr"),
                local: field!(parser, IpAddr, "saddr"),
                ts,
            })
        }
        Source::Process if id == PROCESS_START => Ok(Decoded::ProcessStart {
            pid: field!(parser, u32, "ProcessID"),
            image: field!(parser, String, "ImageName"),
            ts,
        }),
        Source::Dns if id == DNS_QUERY_COMPLETED => {
            if field!(parser, u32, "QueryStatus") != 0 {
                return Ok(Decoded::Ignored);
            }
            Ok(Decoded::DnsAnswer {
                header_pid: record.process_id(),
                name: field!(parser, String, "QueryName").to_ascii_lowercase(),
                ips: parse_query_results(&field!(parser, String, "QueryResults")),
                ts,
            })
        }
        _ => Ok(Decoded::Ignored),
    }
}

/// `QueryResults` looks like `type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;`.
/// CNAME entries don't parse as addresses and are skipped.
fn parse_query_results(results: &str) -> Vec<IpAddr> {
    results
        .split(';')
        .filter_map(|token| {
            let token = token.trim();
            token.strip_prefix("::ffff:").unwrap_or(token).parse().ok()
        })
        .collect()
}

impl State {
    fn apply(&mut self, decoded: Decoded) {
        match decoded {
            Decoded::Net {
                pid,
                header_pid,
                kind,
                size,
                remote,
                local,
                ts,
            } => {
                let key = self.proc_key(pid, ts);
                match kind {
                    NetKind::Data(dir) => {
                        self.data_events += 1;
                        if header_pid != pid {
                            self.header_pid_mismatch += 1;
                        }
                        let loopback = remote.is_loopback() || local.is_loopback();
                        if loopback {
                            self.loopback.add(dir, size);
                        } else {
                            self.external.add(dir, size);
                            if self.dns_names.contains_key(&remote) {
                                self.external_named.add(dir, size);
                            }
                        }
                        let stats = self.proc_stats(key);
                        if loopback {
                            stats.loopback.add(dir, size);
                        } else {
                            stats.external.add(dir, size);
                            stats.hosts.entry(remote).or_default().add(dir, size);
                        }
                    }
                    NetKind::Connect => self.proc_stats(key).connects += 1,
                    NetKind::Accept => self.proc_stats(key).accepts += 1,
                    NetKind::Other => {}
                }
            }
            Decoded::ProcessStart { pid, image, ts } => {
                let name = Some(procinfo::basename(&image).to_string());
                match self.live.get_mut(&pid) {
                    // Events can arrive slightly out of order. Only a start that is
                    // newer than everything seen for this PID means the PID was reused.
                    Some(live) if ts > live.first_seen => {
                        live.generation += 1;
                        live.name = name;
                        live.first_seen = ts;
                    }
                    Some(live) => live.name = name,
                    None => {
                        self.live.insert(
                            pid,
                            LiveProc {
                                generation: 0,
                                name,
                                first_seen: ts,
                            },
                        );
                    }
                }
            }
            Decoded::DnsAnswer {
                header_pid,
                name,
                ips,
                ts,
            } => {
                self.dns_answers += 1;
                let key = self.proc_key(header_pid, ts);
                self.proc_stats(key).dns_answers += 1;
                for ip in ips {
                    self.dns_names.insert(ip, name.clone());
                }
            }
            Decoded::Ignored => {}
        }
    }

    fn proc_key(&mut self, pid: u32, ts: i64) -> ProcKey {
        let live = self.live.entry(pid).or_insert(LiveProc {
            generation: 0,
            name: None,
            first_seen: ts,
        });
        live.first_seen = live.first_seen.min(ts);
        ProcKey {
            pid,
            generation: live.generation,
        }
    }

    fn proc_stats(&mut self, key: ProcKey) -> &mut ProcStats {
        let live = &self.live;
        self.procs.entry(key).or_insert_with(|| {
            let name = live.get(&key.pid).and_then(|l| l.name.clone());
            ProcStats {
                name: name.unwrap_or_else(|| procinfo::image_name(key.pid)),
                ..Default::default()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_results_skip_cnames_and_unwrap_mapped_v4() {
        let ips =
            parse_query_results("type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800::1;");
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800::1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn query_results_empty() {
        assert!(parse_query_results("").is_empty());
    }
}
