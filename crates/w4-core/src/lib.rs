//! Shared domain types for win4tress.

pub mod ask;
pub mod event;
pub mod firewall;
pub mod net;
pub mod threats;
pub mod time;
pub mod trust;

use serde::{Deserialize, Serialize};

pub use event::NetEvent;
pub use net::{Locality, TrafficType, locality};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Received and sent byte counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes {
    pub recv: u64,
    pub sent: u64,
}

impl Bytes {
    pub fn add(&mut self, dir: Direction, n: u64) {
        match dir {
            Direction::In => self.recv += n,
            Direction::Out => self.sent += n,
        }
    }

    pub fn total(&self) -> u64 {
        self.recv + self.sent
    }

    pub fn plus(self, other: Bytes) -> Bytes {
        Bytes {
            recv: self.recv + other.recv,
            sent: self.sent + other.sent,
        }
    }

    pub fn saturating_sub(self, other: Bytes) -> Bytes {
        Bytes {
            recv: self.recv.saturating_sub(other.recv),
            sent: self.sent.saturating_sub(other.sent),
        }
    }
}

impl std::ops::AddAssign for Bytes {
    fn add_assign(&mut self, other: Bytes) {
        *self = self.plus(other);
    }
}

/// Where a remote address is. `code` is ISO 3166-1 alpha-2, or [`Country::LOCAL`]
/// for the local network and [`Country::UNKNOWN`] when the lookup has no answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Country {
    pub code: String,
    pub name: String,
}

impl Country {
    pub const LOCAL: &str = "LAN";
    pub const UNKNOWN: &str = "??";

    pub fn local() -> Self {
        Country {
            code: Self::LOCAL.into(),
            name: "Local network".into(),
        }
    }

    pub fn unknown() -> Self {
        Country {
            code: Self::UNKNOWN.into(),
            name: "Unknown".into(),
        }
    }
}

/// The organisation whose network an address belongs to (its autonomous system).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkOwner {
    pub asn: u32,
    pub name: String,
}
