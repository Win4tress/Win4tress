//! What the resolver did: the last lookups with their outcome and reason, and
//! counters since it started. The service reads them over the pipe and joins
//! them to the app that asked (from DNS-Client ETW).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub use w4_dns::status::{Counters, LogEntry as Entry, Outcome};

const KEEP: usize = 5_000;
const TOP_BLOCKED: usize = 2_000;

#[derive(Default)]
struct Inner {
    next: u64,
    recent: VecDeque<Entry>,
    counters: Counters,
    top_blocked: HashMap<String, u64>,
}

#[derive(Default)]
pub struct Journal {
    inner: Mutex<Inner>,
}

impl Journal {
    pub fn record(&self, mut e: Entry, reason_kind: Option<&str>) {
        let mut j = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        j.next += 1;
        e.id = j.next;
        let c = &mut j.counters;
        c.queries += 1;
        match e.outcome {
            Outcome::Blocked => {
                c.blocked += 1;
                if let Some(k) = reason_kind {
                    *c.by_reason.entry(k.to_string()).or_default() += 1;
                }
            }
            Outcome::Cached => c.cached += 1,
            Outcome::Answered | Outcome::Allowed | Outcome::WouldBlock | Outcome::Passed => {
                c.forwarded += 1
            }
            Outcome::BlockedUpstream => {
                c.forwarded += 1;
                c.blocked_upstream += 1;
            }
            Outcome::Failed => c.failed += 1,
            Outcome::Local => {}
        }
        if e.outcome == Outcome::Blocked
            && (j.top_blocked.len() < TOP_BLOCKED || j.top_blocked.contains_key(&e.name))
        {
            *j.top_blocked.entry(e.name.clone()).or_default() += 1;
        }
        if j.recent.len() >= KEEP {
            j.recent.pop_front();
        }
        j.recent.push_back(e);
    }

    /// Entries after `after` (an entry id), oldest first, at most `limit`.
    pub fn since(&self, after: u64, limit: usize) -> Vec<Entry> {
        let j = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        j.recent
            .iter()
            .filter(|e| e.id > after)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn counters(&self) -> Counters {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .counters
            .clone()
    }

    pub fn top_blocked(&self, limit: usize) -> Vec<(String, u64)> {
        let j = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut top: Vec<_> = j.top_blocked.iter().map(|(n, c)| (n.clone(), *c)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(limit);
        top
    }
}
