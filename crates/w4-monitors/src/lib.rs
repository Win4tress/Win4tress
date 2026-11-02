//! Security monitors (SPEC §11): each compares what it sees now with what it
//! remembers and says what changed, as alerts. The decisions are pure (and
//! tested) and the memory is serializable, so the service can keep it across
//! restarts. Also the LAN scanner and manufacturer lookup (SPEC §10.2 Network).

pub mod arp;
pub mod files;
pub mod network;
pub mod oui;
pub mod scanner;
pub mod wifi;
