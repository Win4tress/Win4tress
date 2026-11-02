//! ETW collector (SPEC §8.1). Traces Kernel-Network, Kernel-Process and
//! DNS-Client and hands decoded [`NetEvent`]s to an [`EventSink`].
//! Validated by spike 0.1 (docs/spikes/0.1-etw-collector.md).
//!
//! Requires an elevated or SYSTEM caller.

mod decode;
pub mod drops;
mod session;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use ferrisetw::native::EvntraceNativeError;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{
    DumpFileParams, FileTrace, LoggingMode, TraceBuilder, TraceError, TraceProperties, TraceTrait,
    UserTrace, stop_trace_by_name,
};
use ferrisetw::{EventRecord, GUID};
use w4_core::NetEvent;

use decode::Source;

pub const DEFAULT_SESSION: &str = "win4tress-etw";

const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
/// Kernel-Process keyword for process start/stop events.
const KEYWORD_PROCESS: u64 = 0x10;
/// Makes Windows read FlushTimer as milliseconds (evntrace.h). ferrisetw doesn't
/// define this flag and passes `flush_timer` through as whole seconds.
const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x0000_0010;

/// Receives decoded events on the ETW processing thread. Must return quickly.
pub trait EventSink: Send + Sync + 'static {
    fn on_event(&self, event: NetEvent);
}

#[derive(Clone, Debug)]
pub struct Config {
    pub session_name: String,
    /// Delivery delay is roughly this; 250 ms keeps the live graph responsive.
    pub flush_ms: u32,
    pub buffer_kb: u32,
    pub max_buffers: u32,
    /// Also write the raw events to this `.etl` file, for [`replay`] in tests.
    /// It contains this PC's traffic, so keep it out of version control.
    pub record_to: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            session_name: DEFAULT_SESSION.to_string(),
            flush_ms: 250,
            buffer_kb: 64,
            max_buffers: 256,
            record_to: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("starting ETW session {name}: {detail}")]
    Start { name: String, detail: String },
    #[error("stopping ETW session {name}: {detail}")]
    Stop { name: String, detail: String },
    #[error("replaying {path}: {detail}")]
    Replay { path: String, detail: String },
}

/// Decodes a trace recorded with [`Config::record_to`] through the same code as
/// live collection. Needs no admin rights. Blocks until the file is read.
pub fn replay(path: &Path, sink: Arc<dyn EventSink>) -> Result<Health, Error> {
    let counters = Arc::new(Counters::default());
    let replay_err = |detail: String| Error::Replay {
        path: path.display().to_string(),
        detail,
    };
    let sources = [
        (GUID::from(KERNEL_NETWORK), Source::Network),
        (GUID::from(KERNEL_PROCESS), Source::Process),
        (GUID::from(DNS_CLIENT), Source::Dns),
    ];
    let c = Arc::clone(&counters);
    let (trace, handle) = FileTrace::new(
        path.to_path_buf(),
        move |record: &EventRecord, locator: &SchemaLocator| {
            let provider = record.provider_id();
            if let Some((_, source)) = sources.iter().find(|(guid, _)| *guid == provider) {
                handle_event(*source, record, locator, &*sink, &c);
            }
        },
    )
    .start()
    .map_err(|e| replay_err(format!("{e:?}")))?;
    FileTrace::process_from_handle(handle).map_err(|e| replay_err(format!("{e:?}")))?;
    drop(trace);

    Ok(Health {
        events: counters.events.load(Ordering::Relaxed),
        data_events: counters.data_events.load(Ordering::Relaxed),
        parse_errors: counters.parse_errors.load(Ordering::Relaxed),
        last_event_ms: Some(counters.last_event_ms.load(Ordering::Relaxed)).filter(|t| *t != 0),
        ..Health::default()
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    pub events: u64,
    pub data_events: u64,
    pub parse_errors: u64,
    pub events_lost: u64,
    pub buffers_lost: u64,
    pub last_event_ms: Option<i64>,
    /// Whether the ETW session exists right now.
    pub running: bool,
    /// Times the session was found stopped from outside and started again.
    pub restarts: u64,
}

#[derive(Default)]
struct Counters {
    events: AtomicU64,
    data_events: AtomicU64,
    parse_errors: AtomicU64,
    last_event_ms: AtomicI64,
    restarts: AtomicU64,
}

pub struct Collector {
    trace: Option<UserTrace>,
    config: Config,
    sink: Arc<dyn EventSink>,
    counters: Arc<Counters>,
}

impl Collector {
    /// Starts the session. A session with the same name left over from a crashed
    /// run is stopped and replaced: ETW sessions outlive their process.
    pub fn start(config: Config, sink: Arc<dyn EventSink>) -> Result<Collector, Error> {
        let mut collector = Collector {
            trace: None,
            config,
            sink,
            counters: Arc::default(),
        };
        collector.trace = Some(collector.open()?);
        tracing::info!(
            session = %collector.config.session_name,
            flush_ms = collector.config.flush_ms,
            "ETW collector started"
        );
        Ok(collector)
    }

    fn open(&self) -> Result<UserTrace, Error> {
        let name = &self.config.session_name;
        let start = || build(&self.config, &self.sink, &self.counters).start_and_process();
        match start() {
            Ok(trace) => Ok(trace),
            Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
                tracing::warn!(session = %name, "replacing leftover ETW session");
                stop_trace_by_name(name).map_err(|e| Error::Stop {
                    name: name.clone(),
                    detail: format!("{e:?}"),
                })?;
                start().map_err(|e| Error::Start {
                    name: name.clone(),
                    detail: format!("{e:?}"),
                })
            }
            Err(e) => Err(Error::Start {
                name: name.clone(),
                detail: format!("{e:?}"),
            }),
        }
    }

    /// Whether our ETW session still exists. Other software, or an admin running
    /// `logman stop`, can stop it.
    pub fn is_running(&self) -> bool {
        session::query(&self.config.session_name).is_ok()
    }

    /// Starts a new session if ours was stopped from outside. Returns true if it did.
    pub fn ensure_running(&mut self) -> Result<bool, Error> {
        if self.is_running() {
            return Ok(false);
        }
        self.forget_trace();
        // A new session would overwrite the recording made so far.
        self.config.record_to = None;
        self.trace = Some(self.open()?);
        self.counters.restarts.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// A cheap handle for reading health without owning (and so keeping alive) the session.
    pub fn health_probe(&self) -> HealthProbe {
        HealthProbe {
            name: self.config.session_name.clone(),
            counters: Arc::clone(&self.counters),
        }
    }

    pub fn health(&self) -> Health {
        self.health_probe().health()
    }

    pub fn stop(mut self) -> Result<(), Error> {
        self.stop_inner()
    }

    /// For a trace whose session was stopped from outside. Its control handle is a
    /// logger id that ETW may already have given to another session, so stopping
    /// through it could stop someone else's trace. The small handle is leaked instead.
    fn forget_trace(&mut self) {
        if let Some(stale) = self.trace.take() {
            std::mem::forget(stale);
        }
    }

    fn stop_inner(&mut self) -> Result<(), Error> {
        if self.trace.is_some() && !self.is_running() {
            self.forget_trace();
            return Ok(());
        }
        match self.trace.take() {
            Some(trace) => trace.stop().map_err(|e| Error::Stop {
                name: self.config.session_name.clone(),
                detail: format!("{e:?}"),
            }),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct HealthProbe {
    name: String,
    counters: Arc<Counters>,
}

impl HealthProbe {
    /// A probe for a session no collector feeds: reports it not running.
    /// For tests of what answers health questions.
    pub fn idle(name: &str) -> HealthProbe {
        HealthProbe {
            name: name.into(),
            counters: Arc::default(),
        }
    }

    pub fn health(&self) -> Health {
        let c = &self.counters;
        let last = c.last_event_ms.load(Ordering::Relaxed);
        let session = session::query(&self.name);
        let running = session.is_ok();
        let session = session.unwrap_or_default();
        Health {
            events: c.events.load(Ordering::Relaxed),
            data_events: c.data_events.load(Ordering::Relaxed),
            parse_errors: c.parse_errors.load(Ordering::Relaxed),
            events_lost: session.events_lost,
            buffers_lost: session.realtime_buffers_lost,
            last_event_ms: (last != 0).then_some(last),
            running,
            restarts: c.restarts.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        if let Err(e) = self.stop_inner() {
            tracing::warn!("{e}");
        }
    }
}

fn build(
    config: &Config,
    sink: &Arc<dyn EventSink>,
    counters: &Arc<Counters>,
) -> TraceBuilder<UserTrace> {
    let provider = |guid: &str, keywords: u64, source: Source| {
        let sink = Arc::clone(sink);
        let counters = Arc::clone(counters);
        Provider::by_guid(guid)
            .any(keywords)
            .level(5)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                handle_event(source, record, locator, &*sink, &counters)
            })
            .build()
    };

    let mode = LoggingMode::EVENT_TRACE_REAL_TIME_MODE.bits() | EVENT_TRACE_USE_MS_FLUSH_TIMER;
    // SAFETY: from_bits_unchecked only skips bitflags' known-flags check; the extra
    // bit is a documented LogFileMode flag.
    let log_file_mode = unsafe { LoggingMode::from_bits_unchecked(mode) };

    let mut builder = UserTrace::new()
        .named(config.session_name.clone())
        .set_trace_properties(TraceProperties {
            buffer_size: config.buffer_kb,
            min_buffer: 0,
            max_buffer: config.max_buffers,
            // Read as milliseconds because of EVENT_TRACE_USE_MS_FLUSH_TIMER.
            flush_timer: Duration::from_secs(u64::from(config.flush_ms)),
            log_file_mode,
        })
        .enable(provider(KERNEL_NETWORK, u64::MAX, Source::Network))
        .enable(provider(KERNEL_PROCESS, KEYWORD_PROCESS, Source::Process))
        .enable(provider(DNS_CLIENT, u64::MAX, Source::Dns));
    if let Some(path) = &config.record_to {
        builder = builder.set_etl_dump_file(DumpFileParams {
            file_path: path.clone(),
            max_size: Some(200), // MB
            ..Default::default()
        });
    }
    builder
}

/// ETW callback. Never panics on bad input: malformed events are counted and skipped.
fn handle_event(
    source: Source,
    record: &EventRecord,
    locator: &SchemaLocator,
    sink: &dyn EventSink,
    counters: &Counters,
) {
    counters.events.fetch_add(1, Ordering::Relaxed);
    let event = match locator.event_schema(record) {
        Ok(schema) => decode::decode(source, record, &schema),
        Err(_) => Err(decode::DecodeError),
    };
    match event {
        Ok(Some(event)) => {
            if matches!(event, NetEvent::Traffic { .. }) {
                counters.data_events.fetch_add(1, Ordering::Relaxed);
            }
            counters
                .last_event_ms
                .store(event.ts_ms(), Ordering::Relaxed);
            sink.on_event(event);
        }
        Ok(None) => {}
        Err(decode::DecodeError) => {
            counters.parse_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}
