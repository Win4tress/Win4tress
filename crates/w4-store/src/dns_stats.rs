//! The DNS dashboard: totals, timelines and top lists over `dns_queries`.

use std::collections::HashMap;

use rusqlite::params;
use w4_ipc::api::{AppId, DNS_TIMELINE_APPS, DomainCount, MAX_DNS_STEPS, StatusCount, TypeCount};

use crate::{Result, Store};

/// [`w4_ipc::api::DnsStats`] with app ids; the service fills in app names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsStatsRows {
    pub start_ms: i64,
    pub step_ms: i64,
    pub lookups: u64,
    pub failed: u64,
    pub domains: u64,
    pub apps: u64,
    pub timeline: Vec<[u64; 2]>,
    /// The busiest apps' lookups per step, busiest first.
    pub app_timeline: Vec<(AppId, Vec<u64>)>,
    pub other_timeline: Vec<u64>,
    pub query_types: Vec<TypeCount>,
    pub results: Vec<StatusCount>,
    pub top_domains: Vec<DomainCount>,
    pub top_failed: Vec<DomainCount>,
    /// (app, lookups, failed), busiest first.
    pub top_apps: Vec<(AppId, u64, u64)>,
}

impl Store {
    /// Lookups in [from_ms, to_ms]. `step_ms` is the timeline step: at least a
    /// minute, and coarser if the range would need more than [`MAX_DNS_STEPS`].
    pub fn dns_stats(
        &self,
        from_ms: i64,
        to_ms: i64,
        step_ms: i64,
        limit: usize,
    ) -> Result<DnsStatsRows> {
        let span = (to_ms - from_ms).max(1);
        // Rounded up (`div_ceil` isn't stable for i64).
        let step_ms = step_ms
            .max(60_000)
            .max((span + MAX_DNS_STEPS - 1) / MAX_DNS_STEPS);
        let start_ms = from_ms - from_ms.rem_euclid(step_ms);
        let steps = ((to_ms - start_ms) / step_ms + 1) as usize;
        let range = params![from_ms, to_ms];

        let (lookups, failed, domains, apps) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(status != 0), 0), COUNT(DISTINCT name),
                    COUNT(DISTINCT app_id)
             FROM dns_queries WHERE ts_ms BETWEEN ?1 AND ?2",
            range,
            |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                ))
            },
        )?;

        // Busiest apps first; the first few get their own timeline.
        let top_apps: Vec<(AppId, u64, u64)> = self
            .conn
            .prepare_cached(
                "SELECT app_id, COUNT(*), SUM(status != 0) FROM dns_queries
                 WHERE ts_ms BETWEEN ?1 AND ?2
                 GROUP BY app_id ORDER BY COUNT(*) DESC, app_id LIMIT ?3",
            )?
            .query_map(
                params![from_ms, to_ms, limit.max(DNS_TIMELINE_APPS) as i64],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)? as u64,
                    ))
                },
            )?
            .collect::<Result<_>>()?;
        let mut app_timeline: Vec<(AppId, Vec<u64>)> = top_apps
            .iter()
            .take(DNS_TIMELINE_APPS)
            .map(|&(app, _, _)| (app, vec![0; steps]))
            .collect();
        let line_of: HashMap<AppId, usize> = app_timeline
            .iter()
            .enumerate()
            .map(|(i, (app, _))| (*app, i))
            .collect();

        // One pass over the range fills both timelines.
        let mut timeline = vec![[0u64; 2]; steps];
        let mut other_timeline = vec![0u64; steps];
        let mut stmt = self.conn.prepare_cached(
            "SELECT (ts_ms - ?3) / ?4, app_id, SUM(status = 0), SUM(status != 0)
             FROM dns_queries WHERE ts_ms BETWEEN ?1 AND ?2
             GROUP BY 1, app_id",
        )?;
        let rows = stmt.query_map(params![from_ms, to_ms, start_ms, step_ms], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, AppId>(1)?,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        for row in rows {
            let (step, app, answered, failed) = row?;
            let i = (step.max(0) as usize).min(steps - 1);
            timeline[i][0] += answered;
            timeline[i][1] += failed;
            match line_of.get(&app) {
                Some(&line) => app_timeline[line].1[i] += answered + failed,
                None => other_timeline[i] += answered + failed,
            }
        }

        let query_types = self
            .conn
            .prepare_cached(
                "SELECT query_type, COUNT(*) FROM dns_queries WHERE ts_ms BETWEEN ?1 AND ?2
                 GROUP BY query_type ORDER BY COUNT(*) DESC, query_type",
            )?
            .query_map(range, |r| {
                Ok(TypeCount {
                    query_type: r.get::<_, i64>(0)? as u16,
                    count: r.get::<_, i64>(1)? as u64,
                })
            })?
            .collect::<Result<_>>()?;
        let results = self
            .conn
            .prepare_cached(
                "SELECT status, COUNT(*) FROM dns_queries WHERE ts_ms BETWEEN ?1 AND ?2
                 GROUP BY status ORDER BY COUNT(*) DESC, status",
            )?
            .query_map(range, |r| {
                Ok(StatusCount {
                    status: r.get::<_, i64>(0)? as u32,
                    count: r.get::<_, i64>(1)? as u64,
                })
            })?
            .collect::<Result<_>>()?;

        let mut top_apps = top_apps;
        top_apps.truncate(limit);
        Ok(DnsStatsRows {
            start_ms,
            step_ms,
            lookups,
            failed,
            domains,
            apps,
            timeline,
            app_timeline,
            other_timeline,
            query_types,
            results,
            top_domains: self.dns_top(from_ms, to_ms, None, limit)?,
            top_failed: self.dns_top_failed(from_ms, to_ms, limit)?,
            top_apps,
        })
    }

    /// Names with failed lookups, most failures first.
    fn dns_top_failed(&self, from_ms: i64, to_ms: i64, limit: usize) -> Result<Vec<DomainCount>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT name, COUNT(*), SUM(status != 0) AS failed, COUNT(DISTINCT app_id), MAX(ts_ms)
             FROM dns_queries WHERE ts_ms BETWEEN ?1 AND ?2
             GROUP BY name HAVING failed > 0 ORDER BY failed DESC, name LIMIT ?3",
        )?;
        stmt.query_map(params![from_ms, to_ms, limit as i64], |r| {
            Ok(DomainCount {
                name: r.get(0)?,
                queries: r.get::<_, i64>(1)? as u64,
                failed: r.get::<_, i64>(2)? as u64,
                apps: r.get::<_, i64>(3)? as u64,
                last_ms: r.get(4)?,
            })
        })?
        .collect()
    }
}
