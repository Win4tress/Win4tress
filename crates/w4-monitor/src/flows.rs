//! Live connections: TCP connections and UDP flows by (process, local, remote).

use std::collections::HashMap;
use std::net::SocketAddr;

use w4_core::{Bytes, Direction, Protocol};
use w4_ipc::api::AppId;

/// Closed TCP connections stay listed this long.
const CLOSED_KEEP_MS: i64 = 60_000;
/// UDP has no close; a flow ends after this much silence.
const UDP_IDLE_MS: i64 = 120_000;
/// Request/response UDP services use a new port per query, so each query would
/// otherwise linger as its own "connection" for [`UDP_IDLE_MS`].
const UDP_QUERY_IDLE_MS: i64 = 15_000;
/// DNS, NetBIOS name service, SSDP, mDNS, LLMNR.
const UDP_QUERY_PORTS: [u16; 5] = [53, 137, 1900, 5353, 5355];
/// TCP connections whose close we missed are dropped after this much silence.
const TCP_IDLE_MS: i64 = 2 * 3600 * 1000;
const MAX_FLOWS: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub proto: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct Flow {
    pub app: AppId,
    pub inbound: Option<bool>,
    pub open: bool,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub closed_ms: Option<i64>,
    pub bytes: Bytes,
}

impl Flow {
    fn new(app: AppId, inbound: Option<bool>, ts_ms: i64) -> Self {
        Flow {
            app,
            inbound,
            open: true,
            first_seen_ms: ts_ms,
            last_seen_ms: ts_ms,
            closed_ms: None,
            bytes: Bytes::default(),
        }
    }
}

#[derive(Default)]
pub struct Flows {
    map: HashMap<FlowKey, Flow>,
}

impl Flows {
    pub fn traffic(&mut self, key: FlowKey, app: AppId, dir: Direction, n: u64, ts_ms: i64) {
        let flow = self
            .map
            .entry(key)
            .or_insert_with(|| Flow::new(app, None, ts_ms));
        flow.bytes.add(dir, n);
        flow.last_seen_ms = flow.last_seen_ms.max(ts_ms);
    }

    pub fn connect(&mut self, key: FlowKey, app: AppId, inbound: bool, ts_ms: i64) {
        match self.map.get_mut(&key) {
            // The same four-tuple reused after a close is a new connection.
            Some(flow) if !flow.open => *flow = Flow::new(app, Some(inbound), ts_ms),
            Some(flow) => flow.inbound = Some(inbound),
            None => {
                self.map.insert(key, Flow::new(app, Some(inbound), ts_ms));
            }
        }
    }

    pub fn disconnect(&mut self, key: &FlowKey, ts_ms: i64) {
        if let Some(flow) = self.map.get_mut(key) {
            flow.open = false;
            flow.closed_ms = Some(ts_ms);
            flow.last_seen_ms = flow.last_seen_ms.max(ts_ms);
        }
    }

    /// A connection that was already open when the service started.
    pub fn seed(&mut self, key: FlowKey, app: AppId, ts_ms: i64) {
        self.map
            .entry(key)
            .or_insert_with(|| Flow::new(app, None, ts_ms));
    }

    pub fn evict(&mut self, now_ms: i64) {
        self.map.retain(|key, flow| match (flow.open, key.proto) {
            (false, _) => flow.closed_ms.unwrap_or(flow.last_seen_ms) > now_ms - CLOSED_KEEP_MS,
            (true, Protocol::Udp) if UDP_QUERY_PORTS.contains(&key.remote.port()) => {
                flow.last_seen_ms > now_ms - UDP_QUERY_IDLE_MS
            }
            (true, Protocol::Udp) => flow.last_seen_ms > now_ms - UDP_IDLE_MS,
            (true, Protocol::Tcp) => flow.last_seen_ms > now_ms - TCP_IDLE_MS,
        });
        if self.map.len() > MAX_FLOWS {
            let mut by_age: Vec<_> = self.map.iter().map(|(k, f)| (f.last_seen_ms, *k)).collect();
            by_age.sort_unstable_by_key(|(t, _)| *t);
            for (_, key) in by_age.into_iter().take(self.map.len() - MAX_FLOWS) {
                self.map.remove(&key);
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &Flow)> {
        self.map.iter()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}
