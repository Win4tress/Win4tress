//! Recent DNS queries by app, and the ones not yet written to history.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use w4_ipc::api::{AppId, DomainCount};

/// Queries kept in memory for the live log.
const RECENT: usize = 5_000;
/// Cap on unsaved queries when history is unavailable.
const UNSAVED_MAX: usize = 20_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub ts_ms: i64,
    pub app: AppId,
    pub name: String,
    pub query_type: u16,
    pub status: u32,
    pub addrs: Vec<IpAddr>,
}

#[derive(Default)]
pub struct DnsLog {
    recent: VecDeque<DnsRecord>,
    unsaved: Vec<DnsRecord>,
}

impl DnsLog {
    pub fn push(&mut self, record: DnsRecord) {
        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(record.clone());
        self.unsaved.push(record);
        if self.unsaved.len() > UNSAVED_MAX {
            let excess = self.unsaved.len() - UNSAVED_MAX;
            self.unsaved.drain(..excess);
        }
    }

    pub fn take_unsaved(&mut self) -> Vec<DnsRecord> {
        std::mem::take(&mut self.unsaved)
    }

    /// Newest first, optionally for one app and/or names containing `needle`.
    pub fn query<'a>(
        &'a self,
        app: Option<AppId>,
        needle: Option<&'a str>,
    ) -> impl Iterator<Item = &'a DnsRecord> + 'a {
        let needle = needle.map(str::to_ascii_lowercase);
        self.recent.iter().rev().filter(move |r| {
            app.is_none_or(|a| a == r.app) && needle.as_deref().is_none_or(|n| r.name.contains(n))
        })
    }

    /// Most-queried names in [from_ms, to_ms] among the recent queries.
    pub fn top(
        &self,
        from_ms: i64,
        to_ms: i64,
        app: Option<AppId>,
        limit: usize,
    ) -> Vec<DomainCount> {
        top_domains(
            self.recent
                .iter()
                .filter(|r| r.ts_ms >= from_ms && r.ts_ms <= to_ms)
                .filter(|r| app.is_none_or(|a| a == r.app)),
            limit,
        )
    }
}

/// Groups queries by name, busiest first.
pub fn top_domains<'a>(
    records: impl Iterator<Item = &'a DnsRecord>,
    limit: usize,
) -> Vec<DomainCount> {
    #[derive(Default)]
    struct Agg {
        queries: u64,
        failed: u64,
        apps: HashSet<AppId>,
        last_ms: i64,
    }
    let mut by_name: HashMap<&str, Agg> = HashMap::new();
    for r in records {
        let agg = by_name.entry(&r.name).or_default();
        agg.queries += 1;
        if r.status != 0 {
            agg.failed += 1;
        }
        agg.apps.insert(r.app);
        agg.last_ms = agg.last_ms.max(r.ts_ms);
    }
    let mut out: Vec<DomainCount> = by_name
        .into_iter()
        .map(|(name, a)| DomainCount {
            name: name.to_string(),
            queries: a.queries,
            failed: a.failed,
            apps: a.apps.len() as u64,
            last_ms: a.last_ms,
        })
        .collect();
    out.sort_by(|a, b| b.queries.cmp(&a.queries).then_with(|| a.name.cmp(&b.name)));
    out.truncate(limit);
    out
}
