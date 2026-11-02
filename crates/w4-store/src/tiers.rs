//! Traffic tiers beyond the 48 hours of per-minute detail (SPEC §9.1): per
//! minute and app for 35 days, per hour, app and host for 2 years, and per
//! local day by one dimension at a time, kept indefinitely. Every flush adds to
//! all of them, so they always agree; queries pick the finest tier that still
//! covers the range and has the detail a filter needs.

use std::collections::HashMap;

use rusqlite::{Transaction, params};
use w4_core::{Bytes, Country, TrafficType};
use w4_ipc::api::{AppId, Settings};
use w4_monitor::UsageRow;

use crate::{MINUTE_RETENTION_MS, Result, Store};

pub const APP_MINUTE_RETENTION_MS: i64 = 35 * DAY_MS;
pub const HOUR_RETENTION_MS: i64 = 730 * DAY_MS;
/// Idle spans and DNS day counts are kept as long as the hourly detail.
pub const IDLE_RETENTION_MS: i64 = HOUR_RETENTION_MS;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Country code the monitor gives local-network addresses.
const LAN: &str = "LAN";

pub(crate) const SCHEMA_V9: &str = "
-- App detail: per minute and app, by traffic type; 35 days.
CREATE TABLE traffic_app_min (
    minute INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    traffic_type TEXT NOT NULL,
    recv INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    PRIMARY KEY (minute, app_id, traffic_type)
) WITHOUT ROWID;

-- Long-term detail: per hour, app and host (the type belongs to the pair); 2 years.
CREATE TABLE traffic_hour (
    hour INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    traffic_type TEXT NOT NULL,
    recv INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    PRIMARY KEY (hour, app_id, host_id)
) WITHOUT ROWID;

-- Usage per local day, one dimension at a time; kept indefinitely.
-- dim: app | host | country | type | total | internet | metered (internet traffic
-- while on a metered connection).
CREATE TABLE usage_day (
    day INTEGER NOT NULL,
    dim TEXT NOT NULL,
    key TEXT NOT NULL,
    recv INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    PRIMARY KEY (day, dim, key)
) WITHOUT ROWID;

-- DNS lookups after their 30 days in dns_queries.
CREATE TABLE dns_daily (
    day INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    queries INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    PRIMARY KEY (day, app_id, name)
) WITHOUT ROWID;

-- When nobody used the PC (SPEC §8.4).
CREATE TABLE idle (
    start_ms INTEGER PRIMARY KEY,
    end_ms INTEGER NOT NULL
);
";

/// What a series (the graph) is limited to. App ids come from the app, or
/// from all of a publisher's apps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeriesFilter {
    pub apps: Option<Vec<AppId>>,
    pub traffic_type: Option<TrafficType>,
    pub country: Option<String>,
    /// `Some(true)`: the local network only; `Some(false)`: the internet only.
    pub local: Option<bool>,
}

impl SeriesFilter {
    /// Hosts are only in the minute and hour tiers.
    fn needs_hosts(&self) -> bool {
        self.country.is_some() || self.local.is_some()
    }
}

/// Which table a range is read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Minute,
    AppMinute,
    Hour,
}

impl Tier {
    /// Seconds per row.
    pub fn resolution(self) -> i64 {
        match self {
            Tier::Minute | Tier::AppMinute => 60,
            Tier::Hour => 3600,
        }
    }

    /// The finest tier that still holds `from_s` and has what `filter` needs.
    pub fn for_range(from_s: i64, now_ms: i64, filter: &SeriesFilter) -> Tier {
        let age_ms = now_ms - from_s * 1000;
        if age_ms <= MINUTE_RETENTION_MS {
            Tier::Minute
        } else if age_ms <= APP_MINUTE_RETENTION_MS && !filter.needs_hosts() {
            Tier::AppMinute
        } else {
            Tier::Hour
        }
    }
}

/// `app_id IN (1,2,3)` from ids, which are integers and safe to inline.
fn id_list(ids: &[AppId]) -> String {
    let list: Vec<String> = ids.iter().map(ToString::to_string).collect();
    format!("({})", list.join(","))
}

/// Context for a flush the store can't know itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct SaveContext {
    /// Minutes east of UTC, for local days (updated as daylight saving changes).
    pub utc_offset_min: i32,
    /// The connection in use is metered (for data plans).
    pub metered: bool,
}

/// One minute row's share of each tier.
pub(crate) struct TierRow<'a> {
    pub minute: i64,
    pub app: AppId,
    pub host_id: i64,
    pub traffic_type: &'a str,
    pub country: &'a str,
    pub bytes: Bytes,
}

pub(crate) fn add_to_tiers(tx: &Transaction, row: &TierRow, ctx: SaveContext) -> Result<()> {
    let (recv, sent) = (row.bytes.recv as i64, row.bytes.sent as i64);
    tx.prepare_cached(
        "INSERT INTO traffic_app_min (minute, app_id, traffic_type, recv, sent)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(minute, app_id, traffic_type) DO UPDATE SET
            recv = recv + excluded.recv, sent = sent + excluded.sent",
    )?
    .execute(params![row.minute, row.app, row.traffic_type, recv, sent])?;
    tx.prepare_cached(
        "INSERT INTO traffic_hour (hour, app_id, host_id, traffic_type, recv, sent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(hour, app_id, host_id) DO UPDATE SET
            recv = recv + excluded.recv, sent = sent + excluded.sent",
    )?
    .execute(params![
        row.minute.div_euclid(60),
        row.app,
        row.host_id,
        row.traffic_type,
        recv,
        sent
    ])?;
    let day = local_day(row.minute, ctx.utc_offset_min);
    let mut add_day = tx.prepare_cached(
        "INSERT INTO usage_day (day, dim, key, recv, sent) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(day, dim, key) DO UPDATE SET
            recv = recv + excluded.recv, sent = sent + excluded.sent",
    )?;
    let internet = row.country != LAN;
    let mut dims: Vec<(&str, String)> = vec![
        ("app", row.app.to_string()),
        ("host", row.host_id.to_string()),
        ("country", row.country.to_string()),
        ("type", row.traffic_type.to_string()),
        ("total", String::new()),
    ];
    if internet {
        dims.push(("internet", String::new()));
        if ctx.metered {
            dims.push(("metered", String::new()));
        }
    }
    for (dim, key) in dims {
        add_day.execute(params![day, dim, key, recv, sent])?;
    }
    Ok(())
}

/// The local day (days since 1970-01-01 in local time) a Unix minute falls on.
pub fn local_day(minute: i64, utc_offset_min: i32) -> i64 {
    (minute + i64::from(utc_offset_min)).div_euclid(1440)
}

const SETTINGS_KEY: &str = "settings";
/// The data plan threshold last alerted: "<period start day>:<percent>".
const PLAN_ALERTED_KEY: &str = "data_plan_alerted";

impl Store {
    pub fn set_save_context(&mut self, ctx: SaveContext) {
        self.context = ctx;
    }

    pub fn settings(&self) -> Result<Settings> {
        Ok(self
            .meta(SETTINGS_KEY)?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default())
    }

    /// Replaces the settings; audited as `who`.
    pub fn set_settings(&mut self, settings: &Settings, now_ms: i64, who: &str) -> Result<()> {
        let json = serde_json::to_string(settings)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        self.set_meta(SETTINGS_KEY, Some(&json), now_ms, who, "settings")
    }

    /// The data plan threshold last alerted, as (period start day, percent).
    pub fn plan_alerted(&self) -> Result<Option<(i64, u8)>> {
        Ok(self.meta(PLAN_ALERTED_KEY)?.and_then(|v| {
            let (day, percent) = v.split_once(':')?;
            Some((day.parse().ok()?, percent.parse().ok()?))
        }))
    }

    /// Not audited: it's the service's own bookkeeping.
    pub fn set_plan_alerted(&self, period_start_day: i64, percent: u8) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![PLAN_ALERTED_KEY, format!("{period_start_day}:{percent}")],
        )?;
        Ok(())
    }

    /// Totals per step in [from_s, to_s] (Unix seconds), quiet steps absent,
    /// read from the finest tier that covers the range. `step_s` is rounded up
    /// to the tier's resolution. Returns the step used.
    pub fn series(
        &self,
        from_s: i64,
        to_s: i64,
        step_s: i64,
        filter: &SeriesFilter,
        exclude: &[AppId],
        now_ms: i64,
    ) -> Result<(i64, Vec<(i64, Bytes)>)> {
        // Whole days come from the per-day totals, when one dimension is enough.
        if step_s >= 86_400
            && let Some(days) = self.series_days(from_s, to_s, filter, exclude)?
        {
            return Ok((86_400, days));
        }
        let tier = Tier::for_range(from_s, now_ms, filter);
        let res = tier.resolution();
        let step = (step_s.max(res) + res - 1) / res * res;
        let (table, unit) = match tier {
            Tier::Minute => ("traffic_min", "minute"),
            Tier::AppMinute => ("traffic_app_min", "minute"),
            Tier::Hour => ("traffic_hour", "hour"),
        };
        // Steps start on local time: a day step at local midnight.
        let off = i64::from(self.context.utc_offset_min) * 60;
        let mut sql = format!(
            "SELECT (({unit} * {res} + {off}) / {step}) * {step} - {off} AS t, SUM(recv), SUM(sent)
             FROM {table} WHERE {unit} BETWEEN ?1 AND ?2"
        );
        if let Some(apps) = &filter.apps {
            sql += &format!(" AND app_id IN {}", id_list(apps));
        }
        if !exclude.is_empty() {
            sql += &format!(" AND app_id NOT IN {}", id_list(exclude));
        }
        if filter.traffic_type.is_some() {
            sql += " AND traffic_type = ?3";
        }
        if let Some(country) = &filter.country {
            // Quoted for SQL; codes are two letters, LAN or ??.
            sql += &format!(
                " AND host_id IN (SELECT id FROM hosts WHERE country = '{}')",
                country.replace('\'', "''")
            );
        }
        match filter.local {
            Some(true) => {
                sql += &format!(" AND host_id IN (SELECT id FROM hosts WHERE country = '{LAN}')")
            }
            Some(false) => {
                sql +=
                    &format!(" AND host_id NOT IN (SELECT id FROM hosts WHERE country = '{LAN}')")
            }
            None => {}
        }
        sql += " GROUP BY t ORDER BY t";
        let mut stmt = self.conn.prepare(&sql)?;
        let traffic_type = filter.traffic_type.map(|t| t.id());
        let from = from_s.div_euclid(res);
        let to = to_s.div_euclid(res);
        let map = |r: &rusqlite::Row| {
            Ok((
                r.get::<_, i64>(0)?,
                Bytes {
                    recv: r.get::<_, i64>(1)? as u64,
                    sent: r.get::<_, i64>(2)? as u64,
                },
            ))
        };
        let rows: Result<Vec<(i64, Bytes)>> = match traffic_type {
            Some(t) => stmt.query_map(params![from, to, t], map)?.collect(),
            None => stmt.query_map(params![from, to], map)?.collect(),
        };
        rows.map(|r| (step, r))
    }

    /// Totals per local day from `usage_day`, each at its local midnight (Unix
    /// seconds, today's offset), or `None` when the filter needs more than one
    /// dimension at a time (the hourly tier answers that).
    fn series_days(
        &self,
        from_s: i64,
        to_s: i64,
        filter: &SeriesFilter,
        exclude: &[AppId],
    ) -> Result<Option<Vec<(i64, Bytes)>>> {
        let set = [
            filter.apps.is_some(),
            filter.traffic_type.is_some(),
            filter.country.is_some(),
            filter.local.is_some(),
        ];
        if set.iter().filter(|&&s| s).count() > 1 {
            return Ok(None);
        }
        let offset = i64::from(self.context.utc_offset_min);
        let from_day = local_day(from_s.div_euclid(60), self.context.utc_offset_min);
        let to_day = local_day(to_s.div_euclid(60), self.context.utc_offset_min);
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let keys = |ids: &[AppId]| {
            let list: Vec<String> = ids.iter().map(|id| quote(&id.to_string())).collect();
            format!("({})", list.join(","))
        };
        // (dim, key condition, subtract the excluded apps)
        let (dim, key, subtract) = match filter {
            SeriesFilter {
                apps: Some(apps), ..
            } => {
                let apps: Vec<AppId> = apps
                    .iter()
                    .copied()
                    .filter(|a| !exclude.contains(a))
                    .collect();
                ("app", format!("key IN {}", keys(&apps)), false)
            }
            SeriesFilter {
                traffic_type: Some(t),
                ..
            } => ("type", format!("key = {}", quote(t.id())), true),
            SeriesFilter {
                country: Some(c), ..
            } => ("country", format!("key = {}", quote(c)), true),
            SeriesFilter {
                local: Some(false), ..
            } => ("internet", "1".into(), true),
            // The local network is the total less the internet.
            SeriesFilter {
                local: Some(true), ..
            } => return Ok(None),
            _ => ("total", "1".into(), true),
        };
        // Excluded apps' traffic can only be taken off whole totals.
        if subtract && !exclude.is_empty() && dim != "total" {
            return Ok(None);
        }
        let mut stmt = self.conn.prepare(&format!(
            "SELECT day, SUM(recv), SUM(sent) FROM usage_day
             WHERE day BETWEEN ?1 AND ?2 AND dim = '{dim}' AND {key} GROUP BY day ORDER BY day"
        ))?;
        let mut days: Vec<(i64, Bytes)> = stmt
            .query_map([from_day, to_day], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    Bytes {
                        recv: r.get::<_, i64>(1)? as u64,
                        sent: r.get::<_, i64>(2)? as u64,
                    },
                ))
            })?
            .collect::<Result<_>>()?;
        if subtract && !exclude.is_empty() {
            let excluded = self.usage_days_by_app(from_day, to_day, exclude)?;
            for (day, bytes) in &mut days {
                if let Some(x) = excluded.get(day) {
                    bytes.recv = bytes.recv.saturating_sub(x.recv);
                    bytes.sent = bytes.sent.saturating_sub(x.sent);
                }
            }
        }
        Ok(Some(
            days.into_iter()
                .map(|(day, b)| (day * 86_400 - offset * 60, b))
                .collect(),
        ))
    }

    fn usage_days_by_app(
        &self,
        from_day: i64,
        to_day: i64,
        apps: &[AppId],
    ) -> Result<HashMap<i64, Bytes>> {
        let list: Vec<String> = apps.iter().map(|id| format!("'{id}'")).collect();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT day, SUM(recv), SUM(sent) FROM usage_day
             WHERE day BETWEEN ?1 AND ?2 AND dim = 'app' AND key IN ({}) GROUP BY day",
            list.join(",")
        ))?;
        stmt.query_map([from_day, to_day], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Bytes {
                    recv: r.get::<_, i64>(1)? as u64,
                    sent: r.get::<_, i64>(2)? as u64,
                },
            ))
        })?
        .collect()
    }

    /// Usage rows for [from_s, to_s], one per app and host, from the minute
    /// tier for the last 48 hours and the hourly one before that (whole hours
    /// at the edges), for [`w4_monitor::build_breakdown`].
    pub fn usage_rows(
        &self,
        from_s: i64,
        to_s: i64,
        exclude: &[AppId],
        now_ms: i64,
    ) -> Result<Vec<UsageRow>> {
        let hosts_needed = SeriesFilter {
            local: Some(false),
            ..Default::default()
        };
        let tier = Tier::for_range(from_s, now_ms, &hosts_needed);
        let (table, unit, res) = match tier {
            Tier::Hour => ("traffic_hour", "hour", 3600),
            _ => ("traffic_min", "minute", 60),
        };
        let not_excluded = if exclude.is_empty() {
            String::new()
        } else {
            format!(" AND t.app_id NOT IN {}", id_list(exclude))
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT t.app_id, h.ip, h.name, h.country, h.country_name, t.traffic_type,
                    SUM(t.recv), SUM(t.sent)
             FROM {table} t JOIN hosts h ON h.id = t.host_id
             WHERE t.{unit} BETWEEN ?1 AND ?2{not_excluded}
             GROUP BY t.app_id, t.host_id, t.traffic_type"
        ))?;
        let rows = stmt.query_map([from_s.div_euclid(res), to_s.div_euclid(res)], |r| {
            Ok((
                r.get::<_, AppId>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                Country {
                    code: r.get(3)?,
                    name: r.get(4)?,
                },
                r.get::<_, String>(5)?,
                Bytes {
                    recv: r.get::<_, i64>(6)? as u64,
                    sent: r.get::<_, i64>(7)? as u64,
                },
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (app, ip, name, country, traffic_type, bytes) = row?;
            let Ok(ip) = ip.parse() else { continue };
            out.push(UsageRow {
                app,
                ip,
                name,
                country,
                traffic_type: TrafficType::from_id(&traffic_type),
                bytes,
            });
        }
        Ok(out)
    }

    /// Internet traffic on local days [from_day, to_day], or only what went over
    /// metered connections (data plans).
    pub fn plan_usage(&self, from_day: i64, to_day: i64, metered_only: bool) -> Result<Bytes> {
        self.conn.query_row(
            "SELECT COALESCE(SUM(recv), 0), COALESCE(SUM(sent), 0) FROM usage_day
             WHERE day BETWEEN ?1 AND ?2 AND dim = ?3",
            params![
                from_day,
                to_day,
                if metered_only { "metered" } else { "internet" }
            ],
            |r| {
                Ok(Bytes {
                    recv: r.get::<_, i64>(0)? as u64,
                    sent: r.get::<_, i64>(1)? as u64,
                })
            },
        )
    }

    /// Totals per local day by one dimension (`app`, `host`, `country`, `type`),
    /// for ranges older than the hourly detail.
    pub fn usage_days(
        &self,
        from_day: i64,
        to_day: i64,
        dim: &str,
    ) -> Result<HashMap<String, Bytes>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, SUM(recv), SUM(sent) FROM usage_day
             WHERE day BETWEEN ?1 AND ?2 AND dim = ?3 GROUP BY key",
        )?;
        stmt.query_map(params![from_day, to_day, dim], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Bytes {
                    recv: r.get::<_, i64>(1)? as u64,
                    sent: r.get::<_, i64>(2)? as u64,
                },
            ))
        })?
        .collect()
    }

    /// Records that nobody used the PC from `start_ms` to `end_ms` (a later
    /// report of the same span extends it).
    pub fn save_idle(&self, start_ms: i64, end_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO idle (start_ms, end_ms) VALUES (?1, ?2)
             ON CONFLICT(start_ms) DO UPDATE SET end_ms = MAX(end_ms, excluded.end_ms)",
            params![start_ms, end_ms],
        )?;
        Ok(())
    }

    /// Idle spans overlapping [from_ms, to_ms].
    pub fn idle(&self, from_ms: i64, to_ms: i64) -> Result<Vec<(i64, i64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT start_ms, end_ms FROM idle
             WHERE end_ms >= ?1 AND start_ms <= ?2 ORDER BY start_ms",
        )?;
        stmt.query_map([from_ms, to_ms], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Rebuilds the tiers from the per-minute detail, once, after the upgrade
    /// that added them.
    pub(crate) fn backfill_tiers(&mut self) -> Result<()> {
        let ctx = self.context;
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "SELECT t.minute, t.app_id, t.host_id, t.traffic_type, h.country, t.recv, t.sent
                 FROM traffic_min t JOIN hosts h ON h.id = t.host_id",
            )?;
            let rows: Vec<(i64, AppId, i64, String, String, i64, i64)> = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<Result<_>>()?;
            for (minute, app, host_id, traffic_type, country, recv, sent) in rows {
                add_to_tiers(
                    &tx,
                    &TierRow {
                        minute,
                        app,
                        host_id,
                        traffic_type: &traffic_type,
                        country: &country,
                        bytes: Bytes {
                            recv: recv as u64,
                            sent: sent as u64,
                        },
                    },
                    // Metered state then isn't known.
                    SaveContext {
                        metered: false,
                        ..ctx
                    },
                )?;
            }
        }
        tx.commit()
    }

    /// Past their time: the tiers, idle spans, and DNS lookups, which become
    /// per-day counts first. Returns rows removed.
    pub(crate) fn prune_tiers(&self, now_ms: i64) -> Result<usize> {
        let minute = |ms: i64| ms.div_euclid(60_000);
        let mut removed = self.conn.execute(
            "DELETE FROM traffic_app_min WHERE minute < ?1",
            [minute(now_ms - APP_MINUTE_RETENTION_MS)],
        )?;
        removed += self.conn.execute(
            "DELETE FROM traffic_hour WHERE hour < ?1",
            [minute(now_ms - HOUR_RETENTION_MS).div_euclid(60)],
        )?;
        removed += self.conn.execute(
            "DELETE FROM idle WHERE end_ms < ?1",
            [now_ms - IDLE_RETENTION_MS],
        )?;
        removed += self.conn.execute(
            "DELETE FROM dns_daily WHERE day < ?1",
            [(now_ms - HOUR_RETENTION_MS).div_euclid(DAY_MS)],
        )?;
        Ok(removed)
    }

    /// DNS lookups about to leave their 30 days, as per-day counts by app and name.
    pub(crate) fn roll_up_dns(&self, before_ms: i64) -> Result<usize> {
        let offset = i64::from(self.context.utc_offset_min) * 60_000;
        self.conn.execute(
            "INSERT INTO dns_daily (day, app_id, name, queries, failed)
             SELECT (ts_ms + ?2) / 86400000, app_id, name, COUNT(*), SUM(status != 0)
             FROM dns_queries WHERE ts_ms < ?1
             GROUP BY (ts_ms + ?2) / 86400000, app_id, name
             ON CONFLICT(day, app_id, name) DO UPDATE SET
                queries = queries + excluded.queries, failed = failed + excluded.failed",
            params![before_ms, offset],
        )
    }
}

#[cfg(test)]
#[path = "tiers_tests.rs"]
mod tests;
