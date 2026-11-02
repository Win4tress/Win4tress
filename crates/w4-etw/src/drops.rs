//! Connection attempts WFP dropped, as they happen (SPEC §7.9, spike 0.4):
//! `Microsoft-Windows-WFP` event 1001 in a small real-time session of its own,
//! kept apart from the traffic collector so a flood there can't lose these.
//! A 50 ms flush delivers them in about 0.12 s.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ferrisetw::EventRecord;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{LoggingMode, TraceError, TraceProperties, UserTrace, stop_trace_by_name};
use w4_core::time::filetime_to_unix_ms;

use crate::{EVENT_TRACE_USE_MS_FLUSH_TIMER, Error, session};

pub const DEFAULT_DROPS_SESSION: &str = "win4tress-wfp";

const WFP: &str = "0C478C5B-0351-41B1-8C58-4A6737DA32E3";
/// The keyword event 1001 carries.
const KEYWORD_DROPS: u64 = 0x10;
const PACKET_DROPPED: u16 = 1001;
/// FWP direction values in WFP's events (as in Security event 5157).
const DIRECTION_INBOUND: u32 = 14592;
const FLUSH_MS: u64 = 50;

/// One dropped attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WfpDrop {
    pub ts_ms: i64,
    pub filter_id: u64,
    /// NT path of the app, e.g. `\device\harddiskvolume3\…\curl.exe`; empty
    /// when no app was involved.
    pub app: String,
    /// The process the event was raised in: for an outgoing attempt, normally
    /// the app itself (so svchost's services can be told apart); for incoming
    /// drops, unrelated. Check it against `app` before relying on it.
    pub pid: u32,
    pub inbound: bool,
    pub remote: Option<SocketAddr>,
}

/// Receives drops on the ETW thread. Must return quickly.
pub trait DropSink: Send + Sync + 'static {
    fn on_drop(&self, drop: WfpDrop);
}

/// A `SOCKADDR_IN` or `SOCKADDR_IN6`, as the event carries it.
pub fn sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    let ip: IpAddr = match family {
        2 => Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?).into(),
        23 => Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?).into(),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn on_record(record: &EventRecord, locator: &SchemaLocator, sink: &dyn DropSink) {
    if record.event_id() != PACKET_DROPPED {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let p = Parser::create(record, &schema);
    let Ok(filter_id) = p.try_parse::<u64>("FilterId") else {
        return;
    };
    sink.on_drop(WfpDrop {
        ts_ms: filetime_to_unix_ms(record.raw_timestamp()),
        filter_id,
        app: p.try_parse::<String>("AppId").unwrap_or_default(),
        pid: record.process_id(),
        inbound: p.try_parse::<u32>("PacketDirection").ok() == Some(DIRECTION_INBOUND),
        remote: p
            .try_parse::<Vec<u8>>("RemoteAddress")
            .ok()
            .and_then(|b| sockaddr(&b)),
    });
}

pub struct DropWatcher {
    trace: Option<UserTrace>,
    name: String,
    sink: Arc<dyn DropSink>,
}

impl DropWatcher {
    /// Starts the session, replacing one with the same name left by a crash.
    pub fn start(name: &str, sink: Arc<dyn DropSink>) -> Result<DropWatcher, Error> {
        let mut w = DropWatcher {
            trace: None,
            name: name.to_string(),
            sink,
        };
        w.trace = Some(w.open()?);
        tracing::info!(session = %w.name, "WFP drop session started");
        Ok(w)
    }

    fn open(&self) -> Result<UserTrace, Error> {
        let start_err = |e: TraceError| Error::Start {
            name: self.name.clone(),
            detail: format!("{e:?}"),
        };
        let build = || {
            let sink = Arc::clone(&self.sink);
            let provider = Provider::by_guid(WFP)
                .any(KEYWORD_DROPS)
                .level(5)
                .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_record(r, l, &*sink))
                .build();
            let mode =
                LoggingMode::EVENT_TRACE_REAL_TIME_MODE.bits() | EVENT_TRACE_USE_MS_FLUSH_TIMER;
            // SAFETY: from_bits_unchecked only skips bitflags' known-flags check;
            // the extra bit is a documented LogFileMode flag.
            let log_file_mode = unsafe { LoggingMode::from_bits_unchecked(mode) };
            UserTrace::new()
                .named(self.name.clone())
                .set_trace_properties(TraceProperties {
                    buffer_size: 16,
                    min_buffer: 0,
                    max_buffer: 32,
                    // Read as milliseconds because of EVENT_TRACE_USE_MS_FLUSH_TIMER.
                    flush_timer: Duration::from_secs(FLUSH_MS),
                    log_file_mode,
                })
                .enable(provider)
                .start_and_process()
        };
        match build() {
            Ok(t) => Ok(t),
            Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
                stop_trace_by_name(&self.name).map_err(|e| Error::Stop {
                    name: self.name.clone(),
                    detail: format!("{e:?}"),
                })?;
                build().map_err(start_err)
            }
            Err(e) => Err(start_err(e)),
        }
    }

    /// Starts a new session if ours was stopped from outside. Returns true if it did.
    pub fn ensure_running(&mut self) -> Result<bool, Error> {
        if session::query(&self.name).is_ok() {
            return Ok(false);
        }
        // Its logger id may belong to another session by now: don't stop through it.
        if let Some(stale) = self.trace.take() {
            std::mem::forget(stale);
        }
        self.trace = Some(self.open()?);
        Ok(true)
    }
}

impl Drop for DropWatcher {
    fn drop(&mut self) {
        if let Some(t) = self.trace.take()
            && session::query(&self.name).is_ok()
        {
            let _ = t.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses() {
        // AF_INET, port 443, 1.1.1.1, then padding.
        let v4 = [2, 0, 1, 187, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(sockaddr(&v4), Some("1.1.1.1:443".parse().unwrap()));
        // AF_INET6, port 53, flow info, 2001:db8::1, scope id.
        let mut v6 = vec![23, 0, 0, 53, 0, 0, 0, 0];
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(sockaddr(&v6), Some("[2001:db8::1]:53".parse().unwrap()));
        assert_eq!(sockaddr(&[2, 0]), None);
        assert_eq!(sockaddr(&[99, 0, 0, 0, 1, 1, 1, 1]), None);
    }
}
