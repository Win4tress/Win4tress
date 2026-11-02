//! What the resolver reports over its pipe (`\\.\pipe\win4tress-dns`), shared
//! with the service, which reads it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const PIPE_NAME: &str = r"\\.\pipe\win4tress-dns";
/// SYSTEM and Administrators: the service and an elevated CLI. LocalService is
/// the resolver itself, installed: opening the next instance of its pipe after
/// each client takes read and write access as well as "create instance" (in
/// write), so it has those; without them the pipe was gone after the first
/// client.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;LS)";

pub mod method {
    /// [`super::ResolverStatus`].
    pub const STATUS: &str = "dns.status";
    /// Params [`super::LogParams`]; result [`super::LogResult`].
    pub const LOG: &str = "dns.log";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded and answered.
    Answered,
    /// From the cache.
    Cached,
    Blocked,
    /// Would have been blocked, but only observing.
    WouldBlock,
    /// An allow rule let it through.
    Allowed,
    /// The upstream answered with a null address: it blocks too (an ad-blocking DNS server).
    BlockedUpstream,
    Local,
    /// Unfiltered: a sign-in page, or not a standard query.
    Passed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts_ms: i64,
    pub name: String,
    pub qtype: u16,
    pub outcome: Outcome,
    /// What blocked or allowed it: a list, a rule, a CNAME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Time spent upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_ms: Option<u32>,
    pub rcode: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub queries: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub blocked_upstream: u64,
    /// Blocked lookups per list name or rule kind.
    pub by_reason: HashMap<String, u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolverStatus {
    pub version: String,
    pub started_ms: i64,
    /// Where it answers, e.g. "127.0.0.1:53".
    pub listening: Vec<String>,
    pub filtering: bool,
    /// Observing only now (set so, or the upstream already blocks).
    pub observing: bool,
    pub paused_until_ms: Option<i64>,
    pub passthrough: bool,
    /// "system", or the DoH server's name.
    pub upstream: String,
    pub system_servers: Vec<String>,
    pub blocklist_domains: usize,
    pub regex_rules: usize,
    /// Whether the upstream blocks ads itself; `None` until asked.
    pub upstream_blocks: Option<bool>,
    pub cache_entries: usize,
    pub problems: Vec<String>,
    pub counters: Counters,
    /// Most blocked names since start.
    pub top_blocked: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogParams {
    /// Entries after this id.
    #[serde(default)]
    pub after: u64,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogResult {
    pub entries: Vec<LogEntry>,
}
