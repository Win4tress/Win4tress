//! Decoder regression test against a real recorded trace.
//!
//! Record one with `tools/dev/record-trace.ps1` (elevated). The file holds your
//! PC's traffic, so it is git-ignored and this test skips itself when it's
//! absent (as in CI). Point `WIN4TRESS_TRACE` at another `.etl` to use that.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use w4_core::{NetEvent, Protocol};
use w4_etw::EventSink;

#[derive(Default)]
struct Collect(Mutex<Vec<NetEvent>>);

impl EventSink for Collect {
    fn on_event(&self, event: NetEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn trace_path() -> PathBuf {
    std::env::var_os("WIN4TRESS_TRACE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/traces/local.etl")
        })
}

#[test]
fn recorded_trace_decodes_cleanly() {
    let path = trace_path();
    if !path.is_file() {
        eprintln!(
            "skipped: no trace at {} (run tools/dev/record-trace.ps1)",
            path.display()
        );
        return;
    }
    let sink = Arc::new(Collect::default());
    let health = w4_etw::replay(&path, sink.clone()).expect("trace replays");
    let events = sink.0.lock().unwrap();

    assert!(health.events > 0, "the trace has events");
    // Every event we subscribe to should decode; allow a sliver for unusual ones.
    assert!(
        health.parse_errors * 200 <= health.events,
        "{} of {} events failed to decode",
        health.parse_errors,
        health.events
    );

    let traffic: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            NetEvent::Traffic {
                proto,
                remote,
                local,
                ..
            } => Some((*proto, *local, *remote)),
            _ => None,
        })
        .collect();
    assert!(!traffic.is_empty(), "the trace has traffic");
    // The recording script downloads over HTTPS, so byte-swapped ports must show 443.
    assert!(
        traffic
            .iter()
            .any(|(proto, _, remote)| *proto == Protocol::Tcp && remote.port() == 443),
        "no TCP traffic to port 443: are ports decoded in the right byte order?"
    );
    // Local and remote are never the same socket.
    assert!(traffic.iter().all(|(_, local, remote)| local != remote));

    assert!(
        events
            .iter()
            .any(|e| matches!(e, NetEvent::DnsQuery { .. })),
        "the trace has DNS lookups"
    );
}
