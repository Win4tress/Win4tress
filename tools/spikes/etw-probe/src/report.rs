//! Console and CSV output.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::collector::{Counters, ProcKey, ProcStats, Snapshot};
use crate::ifstats::{IfDelta, IfRow};
use crate::session::SessionStats;

/// Estimated per-packet header bytes on the wire (Ethernet 14 + IPv4 20 + TCP 20).
/// ETW reports payload; adapters count whole frames.
const HEADER_BYTES: u64 = 54;

pub struct Interval<'a> {
    pub elapsed: Duration,
    pub length: Duration,
    pub cur: &'a Snapshot,
    pub prev: &'a Snapshot,
    pub adapters: IfDelta,
    pub session: SessionStats,
    pub working_set: u64,
    /// Share of the whole machine (all logical CPUs) used by the probe.
    pub cpu_pct: f64,
}

pub fn print_interfaces(rows: &[IfRow]) {
    println!("Adapters used as the reference (physical, up, not NDIS filter rows):");
    let physical: Vec<_> = rows.iter().filter(|r| r.is_physical()).collect();
    if physical.is_empty() {
        println!("  (none found: adapter comparison will read 0)");
    }
    for r in &physical {
        println!("  {} - {}", r.alias, r.description);
    }
    let virtual_up = rows
        .iter()
        .filter(|r| r.up && !r.filter && !r.loopback && !r.connector)
        .count();
    if virtual_up > 0 {
        println!("  ({virtual_up} virtual adapters up and excluded: VPN, Hyper-V, WSL...)");
    }
    println!();
}

pub fn print_interval(iv: &Interval) {
    let etw = iv.cur.external.minus(&iv.prev.external);
    let loopback = iv.cur.loopback.minus(&iv.prev.loopback);
    let named = iv.cur.external_named.minus(&iv.prev.external_named);
    let events = iv.cur.total_events() - iv.prev.total_events();
    let data_events = iv.cur.data_events - iv.prev.data_events;
    let mismatch = iv.cur.header_pid_mismatch - iv.prev.header_pid_mismatch;
    let secs = iv.length.as_secs_f64().max(0.001);

    println!("[{}]", clock(iv.elapsed));
    println!(
        "  ETW      in {:>10}  out {:>10}   (loopback in {}, out {})",
        human(etw.recv),
        human(etw.sent),
        human(loopback.recv),
        human(loopback.sent)
    );
    println!(
        "  Adapters in {:>10}  out {:>10}",
        human(iv.adapters.in_octets),
        human(iv.adapters.out_octets)
    );
    println!("  ETW/adapters {}", ratios(&etw, &iv.adapters));
    println!(
        "  events {} ({:.0}/s)  lost {}  lost buffers {}  parse errors {}  header-PID mismatch {}  named {}",
        events,
        events as f64 / secs,
        iv.session.events_lost,
        iv.session.realtime_buffers_lost,
        iv.cur.parse_errors,
        pct(mismatch, data_events),
        pct(named.total(), etw.total()),
    );
    println!(
        "  CPU {:.2}%  RAM {}  tracking {} processes, {} DNS names  ETW buffers {} ({} free)",
        iv.cpu_pct,
        human(iv.working_set),
        iv.cur.procs.len(),
        iv.cur.dns_names.len(),
        iv.session.buffers,
        iv.session.free_buffers
    );

    let mut top: Vec<(&ProcKey, &ProcStats, Counters)> = iv
        .cur
        .procs
        .iter()
        .map(|(k, s)| {
            let before = iv.prev.procs.get(k).map(|p| p.external).unwrap_or_default();
            (k, s, s.external.minus(&before))
        })
        .filter(|(_, _, d)| d.total() > 0)
        .collect();
    top.sort_by_key(|(_, _, d)| std::cmp::Reverse(d.total()));
    for (key, stats, d) in top.iter().take(5) {
        println!(
            "    {:<26} {:>6}  in {:>10}  out {:>10}  {}",
            truncate(&stats.name, 26),
            key.pid,
            human(d.recv),
            human(d.sent),
            top_host(iv.cur, stats).unwrap_or_default()
        );
    }
    println!();
}

pub struct Totals {
    pub adapters: IfDelta,
    pub session: SessionStats,
    pub peak_working_set: u64,
    pub avg_cpu_pct: f64,
    pub peak_cpu_pct: f64,
    pub elapsed: Duration,
}

pub fn print_summary(snap: &Snapshot, totals: &Totals, top: usize) {
    let Totals {
        adapters,
        session,
        peak_working_set,
        elapsed,
        ..
    } = *totals;
    println!(
        "==================== Summary ({}) ====================",
        clock(elapsed)
    );
    println!(
        "ETW external   in {:>10}  out {:>10}",
        human(snap.external.recv),
        human(snap.external.sent)
    );
    println!(
        "Adapters       in {:>10}  out {:>10}",
        human(adapters.in_octets),
        human(adapters.out_octets)
    );
    println!("ETW/adapters   {}", ratios(&snap.external, &adapters));
    println!(
        "Loopback (not on adapters)  in {}  out {}",
        human(snap.loopback.recv),
        human(snap.loopback.sent)
    );
    println!(
        "Header PID differs from event-data PID on {} of {} data events",
        pct(snap.header_pid_mismatch, snap.data_events),
        snap.data_events
    );
    println!(
        "External bytes with a known hostname: {}  ({} DNS answers, {} IPs named)",
        pct(snap.external_named.total(), snap.external.total()),
        snap.dns_answers,
        snap.dns_names.len()
    );
    println!(
        "Session: lost events {}, lost real-time buffers {}, buffers written {}",
        session.events_lost, session.realtime_buffers_lost, session.buffers_written
    );
    println!(
        "CPU average {:.2}%, peak interval {:.2}%   Peak working set: {}",
        totals.avg_cpu_pct,
        totals.peak_cpu_pct,
        human(peak_working_set)
    );

    println!("\nEvents by provider / ID:");
    let mut counts: Vec<_> = snap.event_counts.iter().collect();
    counts.sort();
    for ((source, id), n) in counts {
        println!("  {:<15} {:>5}  {:>12}", source.label(), id, n);
    }

    println!("\nParse errors: {}", snap.parse_errors);
    for sample in &snap.parse_error_samples {
        println!("  {sample}");
    }

    println!("\nTop {top} processes by external bytes:");
    let mut procs: Vec<_> = snap.procs.iter().collect();
    procs.sort_by_key(|(_, s)| std::cmp::Reverse(s.external.total()));
    for (key, stats) in procs.iter().take(top) {
        println!(
            "  {:<26} {:>6}  in {:>10}  out {:>10}  connects {:>5}  dns {:>4}",
            truncate(&stats.name, 26),
            key.pid,
            human(stats.external.recv),
            human(stats.external.sent),
            stats.connects,
            stats.dns_answers
        );
        let mut hosts: Vec<_> = stats.hosts.iter().collect();
        hosts.sort_by_key(|(_, c)| std::cmp::Reverse(c.total()));
        for (ip, c) in hosts.iter().take(3) {
            println!("      {:>10}  {}", human(c.total()), snap.host_label(ip));
        }
    }
}

fn top_host(snap: &Snapshot, stats: &ProcStats) -> Option<String> {
    stats
        .hosts
        .iter()
        .max_by_key(|(_, c)| c.total())
        .map(|(ip, _)| snap.host_label(ip))
}

/// ETW payload as a share of adapter bytes, raw and with estimated headers removed.
fn ratios(etw: &Counters, adapters: &IfDelta) -> String {
    let in_payload = adapters
        .in_octets
        .saturating_sub(adapters.in_pkts * HEADER_BYTES);
    let out_payload = adapters
        .out_octets
        .saturating_sub(adapters.out_pkts * HEADER_BYTES);
    format!(
        "in {} ({} excl. est. headers)   out {} ({} excl. est. headers)",
        pct(etw.recv, adapters.in_octets),
        pct(etw.recv, in_payload),
        pct(etw.sent, adapters.out_octets),
        pct(etw.sent, out_payload),
    )
}

pub struct CsvLog {
    out: BufWriter<File>,
}

impl CsvLog {
    pub fn create(path: &Path) -> Result<Self> {
        let is_new = !path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut log = CsvLog {
            out: BufWriter::new(file),
        };
        if is_new {
            writeln!(
                log.out,
                "unix_time,elapsed_s,etw_in,etw_out,etw_loop_in,etw_loop_out,etw_named_in,etw_named_out,\
                 adapter_in,adapter_out,adapter_in_pkts,adapter_out_pkts,events,data_events,\
                 header_pid_mismatch,parse_errors_total,events_lost_total,rt_buffers_lost_total,\
                 cpu_pct,working_set,procs_tracked,dns_names_tracked"
            )?;
        }
        Ok(log)
    }

    pub fn write(&mut self, iv: &Interval) -> Result<()> {
        let etw = iv.cur.external.minus(&iv.prev.external);
        let lo = iv.cur.loopback.minus(&iv.prev.loopback);
        let named = iv.cur.external_named.minus(&iv.prev.external_named);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        writeln!(
            self.out,
            "{now},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{},{},{}",
            iv.elapsed.as_secs(),
            etw.recv,
            etw.sent,
            lo.recv,
            lo.sent,
            named.recv,
            named.sent,
            iv.adapters.in_octets,
            iv.adapters.out_octets,
            iv.adapters.in_pkts,
            iv.adapters.out_pkts,
            iv.cur.total_events() - iv.prev.total_events(),
            iv.cur.data_events - iv.prev.data_events,
            iv.cur.header_pid_mismatch - iv.prev.header_pid_mismatch,
            iv.cur.parse_errors,
            iv.session.events_lost,
            iv.session.realtime_buffers_lost,
            iv.cpu_pct,
            iv.working_set,
            iv.cur.procs.len(),
            iv.cur.dns_names.len(),
        )?;
        // Flush every row so an abrupt kill keeps everything written so far.
        self.out.flush()?;
        Ok(())
    }
}

pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn pct(part: u64, whole: u64) -> String {
    if whole == 0 {
        "n/a".into()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn truncate(s: &str, max: usize) -> String {
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
    fn human_units() {
        assert_eq!(human(999), "999 B");
        assert_eq!(human(1_500), "1.5 KB");
        assert_eq!(human(52_100_000), "52.1 MB");
    }

    #[test]
    fn pct_handles_zero() {
        assert_eq!(pct(5, 0), "n/a");
        assert_eq!(pct(1, 4), "25.0%");
    }
}
