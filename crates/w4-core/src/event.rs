//! Decoded collector events, independent of ETW.

use std::net::{IpAddr, SocketAddr};

use crate::{Direction, Protocol};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// Payload bytes sent or received by a process.
    Traffic {
        ts_ms: i64,
        pid: u32,
        proto: Protocol,
        dir: Direction,
        bytes: u32,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// A TCP connection was opened (`inbound` = accepted from a remote peer).
    Connect {
        ts_ms: i64,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
        inbound: bool,
    },
    /// A TCP connection was closed.
    Disconnect {
        ts_ms: i64,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
    },
    ProcessStart {
        ts_ms: i64,
        pid: u32,
        /// Unique until reboot, unlike the PID.
        sequence: u64,
        /// NT device path, e.g. `\Device\HarddiskVolume3\Windows\System32\curl.exe`.
        image: String,
        /// Store/MSIX package, if any.
        package: Option<String>,
    },
    ProcessStop {
        ts_ms: i64,
        pid: u32,
    },
    /// A DNS lookup made by a process, successful or not.
    DnsQuery {
        ts_ms: i64,
        pid: u32,
        name: String,
        /// DNS record type: 1 = A, 28 = AAAA, 65 = HTTPS, ...
        query_type: u16,
        /// 0 on success, otherwise a Windows DNS error such as 9003 (no such name).
        status: u32,
        addrs: Vec<IpAddr>,
    },
}

impl NetEvent {
    pub fn ts_ms(&self) -> i64 {
        match self {
            NetEvent::Traffic { ts_ms, .. }
            | NetEvent::Connect { ts_ms, .. }
            | NetEvent::Disconnect { ts_ms, .. }
            | NetEvent::ProcessStart { ts_ms, .. }
            | NetEvent::ProcessStop { ts_ms, .. }
            | NetEvent::DnsQuery { ts_ms, .. } => *ts_ms,
        }
    }
}
