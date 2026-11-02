//! Spike 0.4 follow-up: WFP drops as a real-time ETW event (Microsoft-Windows-WFP
//! event 1001, "Packet Dropped"), with the service's session settings.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use ferrisetw::EventRecord;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{LoggingMode, TraceError, TraceProperties, UserTrace, stop_trace_by_name};
use serde::Serialize;

use crate::fw::{Firewall, RuleSpec};
use crate::{Cleanup, HOST_A, Report, reach, spec, test_exe, write_report};

const WFP_PROVIDER: &str = "0C478C5B-0351-41B1-8C58-4A6737DA32E3";
/// The keyword event 1001 carries (seen in the captured trace: 0x…10).
const KEYWORD_DROPS: u64 = 0x10;
const PACKET_DROPPED: u16 = 1001;
const SESSION: &str = "w4-spike-wfp-rt";
/// evntrace.h; makes FlushTimer milliseconds, as the service's collector does.
const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x10;

#[derive(Clone, Debug, Serialize)]
pub struct EtwDrop {
    /// When the drop happened (event timestamp), Unix ms.
    pub event_ms: f64,
    /// When our callback got it, Unix ms.
    pub received_ms: f64,
    pub filter_id: u64,
    pub app: String,
}

pub struct WfpTrace {
    trace: Option<UserTrace>,
    pub drops: Arc<Mutex<Vec<EtwDrop>>>,
}

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}

fn on_record(record: &EventRecord, locator: &SchemaLocator, sink: &Mutex<Vec<EtwDrop>>) {
    let received_ms = now_ms();
    if record.event_id() != PACKET_DROPPED {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(filter_id) = parser.try_parse::<u64>("FilterId") else {
        return;
    };
    let app = parser.try_parse::<String>("AppId").unwrap_or_default();
    let ft = record.raw_timestamp() as f64;
    let e = EtwDrop {
        event_ms: (ft - 116_444_736_000_000_000.0) / 10_000.0,
        received_ms,
        filter_id,
        app,
    };
    if let Ok(mut v) = sink.lock() {
        v.push(e);
    }
}

impl WfpTrace {
    /// Starts a real-time session for WFP drop events, 250 ms flush.
    pub fn start() -> Result<WfpTrace> {
        Self::start_with(250, true)
    }

    pub fn start_with(flush_ms: u64, per_cpu: bool) -> Result<WfpTrace> {
        let drops = Arc::new(Mutex::new(Vec::new()));
        let build = || {
            let sink = Arc::clone(&drops);
            let provider = Provider::by_guid(WFP_PROVIDER)
                .any(KEYWORD_DROPS)
                .level(5)
                .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_record(r, l, &sink))
                .build();
            let mut mode =
                LoggingMode::EVENT_TRACE_REAL_TIME_MODE.bits() | EVENT_TRACE_USE_MS_FLUSH_TIMER;
            if !per_cpu {
                mode |= LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING.bits();
            }
            // SAFETY: from_bits_unchecked only skips bitflags' known-flags check;
            // the extra bit is a documented LogFileMode flag.
            let log_file_mode = unsafe { LoggingMode::from_bits_unchecked(mode) };
            UserTrace::new()
                .named(SESSION.to_string())
                .set_trace_properties(TraceProperties {
                    buffer_size: 64,
                    min_buffer: 0,
                    max_buffer: 64,
                    // Read as milliseconds because of EVENT_TRACE_USE_MS_FLUSH_TIMER.
                    flush_timer: Duration::from_secs(flush_ms),
                    log_file_mode,
                })
                .enable(provider)
                .start_and_process()
        };
        let trace = match build() {
            Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
                let _ = stop_trace_by_name(SESSION);
                build()
            }
            other => other,
        }
        .map_err(|e| anyhow!("starting the WFP trace: {e:?}"))?;
        Ok(WfpTrace {
            trace: Some(trace),
            drops,
        })
    }
}

impl Drop for WfpTrace {
    fn drop(&mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

#[derive(Serialize)]
struct Run {
    session: &'static str,
    /// (start, end) of each connection attempt, Unix ms.
    attempts: Vec<(f64, f64)>,
    events: Vec<EtwDrop>,
}

fn stats(mut v: Vec<f64>) -> String {
    v.sort_by(f64::total_cmp);
    match (v.first(), v.get(v.len() / 2), v.last()) {
        (Some(min), Some(median), Some(max)) => {
            format!("median {median:.0}, min {min:.0}, max {max:.0} ms")
        }
        _ => "no samples".into(),
    }
}

/// Where the delay between a WFP drop and our callback comes from. Blocks the
/// test app with a rule (nothing system-wide) and, under a few session settings,
/// times each attempt against the event's timestamp and our callback.
pub fn latency(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let mut r = Report::default();
    let fw = Firewall::open()?;
    let _cleanup = Cleanup(&fw);
    let exe = test_exe()?;
    let rule = RuleSpec {
        program: Some(exe.display().to_string()),
        ..spec("etw-latency")
    };
    fw.add(&rule)?;
    let mut runs = Vec::new();
    for (session, flush_ms, per_cpu) in [
        (
            "250 ms flush, per-CPU buffers (the service's settings)",
            250,
            true,
        ),
        ("250 ms flush, one set of buffers", 250, false),
        ("50 ms flush, per-CPU buffers", 50, true),
        ("1 s flush, per-CPU buffers", 1000, true),
    ] {
        let trace = WfpTrace::start_with(flush_ms, per_cpu)?;
        std::thread::sleep(Duration::from_secs(1));
        // Far enough apart that each event matches one attempt even at ~1 s delay.
        let mut attempts = Vec::new();
        for _ in 0..5 {
            let start = now_ms();
            let _ = reach(&exe, HOST_A);
            attempts.push((start, now_ms()));
            std::thread::sleep(Duration::from_millis(1500));
        }
        std::thread::sleep(Duration::from_millis(500 + 2 * flush_ms));
        let events: Vec<_> = trace
            .drops
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.app.to_ascii_lowercase().ends_with("\\w4fwtest.exe"))
            .collect();
        drop(trace);

        let (mut delivery, mut stamp, mut total) = (Vec::new(), Vec::new(), Vec::new());
        for e in &events {
            delivery.push(e.received_ms - e.event_ms);
            if let Some(&(start, _)) = attempts.iter().rev().find(|(s, _)| *s <= e.received_ms) {
                stamp.push(e.event_ms - start);
                total.push(e.received_ms - start);
            }
        }
        r.check(
            session,
            events.len() >= attempts.len(),
            format!(
                "{} events for {} attempts. Attempt → event timestamp: {}. Event → callback: {}. Attempt → callback: {}",
                events.len(),
                attempts.len(),
                stats(stamp),
                stats(delivery),
                stats(total.clone()),
            ),
            total.iter().copied().reduce(f64::max),
        );
        runs.push(Run {
            session,
            attempts,
            events,
        });
    }
    fw.remove(&rule.name)?;
    std::fs::write(
        out.join("etw-latency.json"),
        serde_json::to_string_pretty(&runs)?,
    )?;
    write_report(out, &r)
}
