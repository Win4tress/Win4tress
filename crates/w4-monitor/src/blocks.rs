//! Connection attempts Windows Filtering Platform dropped, and what dropped
//! them (SPEC §7.9). Repeats are counted, not listed: a blocked app retries.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use w4_core::firewall::BlockedBy;
use w4_ipc::api::AppId;

/// Distinct (app, direction, address, port, cause) kept in memory.
const RECENT: usize = 2_000;
/// Cap on minute rows waiting for history.
const UNSAVED_MAX: usize = 20_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockKey {
    pub app: AppId,
    pub inbound: bool,
    pub ip: IpAddr,
    pub port: u16,
    pub by: BlockedBy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockCount {
    pub count: u64,
    pub first_ms: i64,
    pub last_ms: i64,
}

/// Blocks in one minute, for history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRow {
    /// Unix minute.
    pub minute: i64,
    pub key: BlockKey,
    pub count: u64,
}

#[derive(Default)]
pub struct Blocks {
    recent: HashMap<BlockKey, BlockCount>,
    unsaved: BTreeMap<(i64, BlockKey), u64>,
}

impl Blocks {
    pub fn record(&mut self, key: BlockKey, ts_ms: i64) {
        if !self.recent.contains_key(&key) && self.recent.len() >= RECENT {
            // Make room: forget the one seen least recently.
            if let Some(oldest) = self
                .recent
                .iter()
                .min_by_key(|(_, c)| c.last_ms)
                .map(|(k, _)| k.clone())
            {
                self.recent.remove(&oldest);
            }
        }
        let c = self.recent.entry(key.clone()).or_insert(BlockCount {
            count: 0,
            first_ms: ts_ms,
            last_ms: ts_ms,
        });
        c.count += 1;
        c.first_ms = c.first_ms.min(ts_ms);
        c.last_ms = c.last_ms.max(ts_ms);
        let row = (ts_ms.div_euclid(60_000), key);
        if self.unsaved.len() < UNSAVED_MAX || self.unsaved.contains_key(&row) {
            *self.unsaved.entry(row).or_default() += 1;
        }
    }

    /// Most recent first.
    pub fn recent(&self, app: Option<AppId>, limit: usize) -> Vec<(BlockKey, BlockCount)> {
        let mut out: Vec<(BlockKey, BlockCount)> = self
            .recent
            .iter()
            .filter(|(k, _)| app.is_none_or(|a| a == k.app))
            .map(|(k, c)| (k.clone(), *c))
            .collect();
        out.sort_by(|a, b| b.1.last_ms.cmp(&a.1.last_ms).then_with(|| a.0.cmp(&b.0)));
        out.truncate(limit);
        out
    }

    pub fn take_unsaved(&mut self) -> Vec<BlockRow> {
        std::mem::take(&mut self.unsaved)
            .into_iter()
            .map(|((minute, key), count)| BlockRow { minute, key, count })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::BlockedByKind;

    use super::*;

    fn key(app: AppId, port: u16) -> BlockKey {
        BlockKey {
            app,
            inbound: false,
            ip: "1.1.1.1".parse().unwrap(),
            port,
            by: BlockedBy {
                kind: BlockedByKind::Win4tress,
                name: "win4tress: curl (Out, Block) #1".into(),
            },
        }
    }

    #[test]
    fn repeats_are_counted_and_saved_per_minute() {
        let mut b = Blocks::default();
        b.record(key(1, 443), 60_000);
        b.record(key(1, 443), 61_000);
        b.record(key(1, 443), 125_000);
        b.record(key(2, 80), 126_000);
        let recent = b.recent(None, 10);
        assert_eq!(recent[0].0.app, 2);
        assert_eq!(
            recent[1].1,
            BlockCount {
                count: 3,
                first_ms: 60_000,
                last_ms: 125_000
            }
        );
        assert_eq!(b.recent(Some(1), 10).len(), 1);
        let rows = b.take_unsaved();
        let counts: Vec<(i64, AppId, u64)> = rows
            .iter()
            .map(|r| (r.minute, r.key.app, r.count))
            .collect();
        assert_eq!(counts, [(1, 1, 2), (2, 1, 1), (2, 2, 1)]);
        assert!(b.take_unsaved().is_empty());
    }
}
