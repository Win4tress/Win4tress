//! Spike 0.1: can ETW give accurate per-process network byte counts?
//!
//! Traces Kernel-Network, Kernel-Process and DNS-Client events, attributes
//! bytes to processes and hosts, and compares the totals with the adapters'
//! own counters. Pass criteria are in docs/PLAN.md, Phase 0.
//!
//! Must run elevated.

mod collector;
mod ifstats;
mod procinfo;
mod report;
mod session;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use clap::Parser as _;
use ferrisetw::EventRecord;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{
    LoggingMode, TraceBuilder, TraceError, TraceProperties, UserTrace, stop_trace_by_name,
};
use windows::Win32::UI::Shell::IsUserAnAdmin;

use collector::{Collector, Source};

/// Separate from the production session name so the probe never collides with the service.
const SESSION: &str = "win4tress-etw-probe";

#[derive(clap::Parser)]
#[command(about = "win4tress spike 0.1: per-process network bytes via ETW")]
struct Args {
    /// Stop after this many seconds (default: run until Ctrl+C)
    #[arg(long)]
    duration: Option<u64>,
    /// Seconds between reports
    #[arg(long, default_value_t = 10)]
    interval: u64,
    /// Processes listed in the final summary
    #[arg(long, default_value_t = 15)]
    top: usize,
    /// Append one row per interval to this CSV file (for 24 h / 72 h runs)
    #[arg(long)]
    csv: Option<PathBuf>,
    /// Print the first event of each provider/ID as JSON (field names and types)
    #[arg(long)]
    dump: bool,
    /// ETW buffer size in KB
    #[arg(long, default_value_t = 64)]
    buffer_kb: u32,
    /// Maximum number of ETW buffers
    #[arg(long, default_value_t = 256)]
    max_buffers: u32,
    /// How often ETW flushes partly filled buffers, in milliseconds
    #[arg(long, default_value_t = 250)]
    flush_ms: u32,
}

/// Makes Windows read FlushTimer as milliseconds (evntrace.h). ferrisetw doesn't
/// define this flag and passes `flush_timer` through as whole seconds.
const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x0000_0010;

fn main() -> Result<()> {
    let args = Args::parse();

    // SAFETY: no preconditions.
    if !unsafe { IsUserAnAdmin() }.as_bool() {
        bail!(
            "run etw-probe from an elevated (Administrator) terminal: kernel network events require it"
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))?;
    }
    let mut csv = args
        .csv
        .as_deref()
        .map(report::CsvLog::create)
        .transpose()?;

    let if_start = ifstats::snapshot()?;
    report::print_interfaces(&if_start);

    let collector = Arc::new(Collector::new(args.dump));
    let started = Instant::now();
    let trace = start_trace(&collector, &args)?;
    println!("Tracing as ETW session '{SESSION}'. Ctrl+C to stop.\n");

    let interval = Duration::from_secs(args.interval.max(1));
    let deadline = args.duration.map(|s| started + Duration::from_secs(s));
    let mut next = started + interval;
    let mut prev_if = if_start.clone();
    let mut prev_snap = collector.snapshot();
    let mut prev_at = started;
    let mut session_stats = session::SessionStats::default();
    let mut peak_ws = 0;
    let mut first_event_reported = false;
    let cpus = thread::available_parallelism().map_or(1, |n| n.get()) as f64;
    let cpu_start = procinfo::own_cpu_time();
    let mut prev_cpu = cpu_start;
    let mut peak_cpu: f64 = 0.0;

    loop {
        let done = |now: Instant| stop.load(Ordering::SeqCst) || deadline.is_some_and(|d| now >= d);
        while Instant::now() < next && !done(Instant::now()) {
            thread::sleep(Duration::from_millis(200));
        }
        let now = Instant::now();
        let finished = done(now);

        if !first_event_reported && let Some(t) = collector.first_event() {
            println!(
                "First event {} ms after starting the session.\n",
                (t - started).as_millis()
            );
            first_event_reported = true;
        }

        let cur_if = ifstats::snapshot()?;
        let cur_snap = collector.snapshot();
        match session::query(SESSION) {
            Ok(s) => session_stats = s,
            Err(e) => eprintln!("warning: {e:#}"),
        }
        let working_set = procinfo::own_working_set();
        peak_ws = peak_ws.max(working_set);
        let cpu = procinfo::own_cpu_time();
        let cpu_pct = cpu_share(cpu - prev_cpu, now - prev_at, cpus);
        peak_cpu = peak_cpu.max(cpu_pct);
        prev_cpu = cpu;

        let iv = report::Interval {
            elapsed: now - started,
            length: now - prev_at,
            cur: &cur_snap,
            prev: &prev_snap,
            adapters: ifstats::physical_delta(&prev_if, &cur_if),
            session: session_stats,
            working_set,
            cpu_pct,
        };
        report::print_interval(&iv);
        if let Some(csv) = csv.as_mut() {
            csv.write(&iv)?;
        }

        prev_if = cur_if;
        prev_snap = cur_snap;
        prev_at = now;
        if finished {
            break;
        }
        next += interval;
    }

    let avg_cpu_pct = cpu_share(
        procinfo::own_cpu_time() - cpu_start,
        started.elapsed(),
        cpus,
    );
    trace.stop().map_err(|e| anyhow!("stopping trace: {e:?}"))?;
    let end_if = ifstats::snapshot()?;
    let totals = report::Totals {
        adapters: ifstats::physical_delta(&if_start, &end_if),
        session: session_stats,
        peak_working_set: peak_ws,
        avg_cpu_pct,
        peak_cpu_pct: peak_cpu,
        elapsed: started.elapsed(),
    };
    report::print_summary(&collector.snapshot(), &totals, args.top);
    Ok(())
}

/// CPU time as a percentage of the whole machine over `wall`.
fn cpu_share(cpu: Duration, wall: Duration, cpus: f64) -> f64 {
    let wall = wall.as_secs_f64();
    if wall <= 0.0 {
        0.0
    } else {
        cpu.as_secs_f64() * 100.0 / (wall * cpus)
    }
}

/// Starts the session. A session with our name left over from a crashed run
/// is stopped and replaced: ETW sessions outlive their process.
fn start_trace(collector: &Arc<Collector>, args: &Args) -> Result<UserTrace> {
    match build_trace(collector, args).start_and_process() {
        Ok(trace) => Ok(trace),
        Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
            println!("Found a leftover '{SESSION}' session from an earlier run; stopping it.");
            stop_trace_by_name(SESSION).map_err(|e| anyhow!("stopping leftover session: {e:?}"))?;
            build_trace(collector, args)
                .start_and_process()
                .map_err(|e| anyhow!("starting trace after cleanup: {e:?}"))
        }
        Err(e) => Err(anyhow!("starting trace: {e:?}")),
    }
}

fn build_trace(collector: &Arc<Collector>, args: &Args) -> TraceBuilder<UserTrace> {
    let provider = |guid: &str, keywords: u64, source: Source| {
        let c = Arc::clone(collector);
        Provider::by_guid(guid)
            .any(keywords)
            .level(5)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                c.on_event(source, record, locator)
            })
            .build()
    };

    let mode = LoggingMode::EVENT_TRACE_REAL_TIME_MODE.bits() | EVENT_TRACE_USE_MS_FLUSH_TIMER;
    // SAFETY: from_bits_unchecked only skips bitflags' known-flags check; the extra
    // bit is a documented LogFileMode flag.
    let log_file_mode = unsafe { LoggingMode::from_bits_unchecked(mode) };

    UserTrace::new()
        .named(SESSION.to_string())
        .set_trace_properties(TraceProperties {
            buffer_size: args.buffer_kb,
            min_buffer: 0,
            max_buffer: args.max_buffers,
            // Read as milliseconds because of EVENT_TRACE_USE_MS_FLUSH_TIMER.
            flush_timer: Duration::from_secs(u64::from(args.flush_ms)),
            log_file_mode,
        })
        .enable(provider(
            collector::KERNEL_NETWORK,
            u64::MAX,
            Source::Network,
        ))
        .enable(provider(
            collector::KERNEL_PROCESS,
            collector::KEYWORD_PROCESS,
            Source::Process,
        ))
        .enable(provider(collector::DNS_CLIENT, u64::MAX, Source::Dns))
}
