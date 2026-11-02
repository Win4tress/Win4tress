//! Firewall settings kept in `meta` (Block All, "Require elevation", the
//! original profile settings), the DNS answers host rules resolve names with,
//! and blocked connections ("Blocked by", SPEC §7.9). Setting changes are
//! audited in `rule_audit` with no rule id, like mode changes.

use std::net::IpAddr;

use rusqlite::{OptionalExtension, params};
use w4_core::firewall::{BlockAll, BlockedBy, BlockedByKind, ProfileState};
use w4_ipc::api::AppId;
use w4_monitor::blocks::{BlockCount, BlockKey, BlockRow};

use crate::{Error, Result, Store};

const BLOCK_ALL_KEY: &str = "block_all";
const REQUIRE_ELEVATION_KEY: &str = "require_elevation";
const PROFILE_ORIGINALS_KEY: &str = "profile_originals";

fn json_error(e: serde_json::Error) -> Error {
    Error::ToSqlConversionFailure(Box::new(e))
}

impl Store {
    pub(crate) fn meta(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
    }

    /// Sets (or with `None` removes) a meta value and audits it as `change`.
    pub(crate) fn set_meta(
        &mut self,
        key: &str,
        value: Option<&str>,
        now_ms: i64,
        who: &str,
        change: &str,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        match value {
            Some(v) => tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, v],
            )?,
            None => tx.execute("DELETE FROM meta WHERE key = ?1", [key])?,
        };
        tx.execute(
            "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule) VALUES (?1, NULL, ?2, ?3, ?4)",
            params![now_ms, change, who, value.unwrap_or("null")],
        )?;
        tx.commit()
    }

    /// Block All as last set; it may have run out (see [`BlockAll::active`]).
    pub fn block_all(&self) -> Result<Option<BlockAll>> {
        Ok(self
            .meta(BLOCK_ALL_KEY)?
            .and_then(|v| serde_json::from_str(&v).ok()))
    }

    pub fn set_block_all(&mut self, value: Option<BlockAll>, now_ms: i64, who: &str) -> Result<()> {
        let json = value
            .map(|v| serde_json::to_string(&v))
            .transpose()
            .map_err(json_error)?;
        self.set_meta(BLOCK_ALL_KEY, json.as_deref(), now_ms, who, "block all")
    }

    pub fn require_elevation(&self) -> Result<bool> {
        Ok(self.meta(REQUIRE_ELEVATION_KEY)?.as_deref() == Some("1"))
    }

    pub fn set_require_elevation(&mut self, on: bool, now_ms: i64, who: &str) -> Result<()> {
        let value = on.then_some("1");
        self.set_meta(
            REQUIRE_ELEVATION_KEY,
            value,
            now_ms,
            who,
            "require elevation",
        )
    }

    /// Records Windows Firewall's profile settings before win4tress first
    /// changes one, so they can be put back. Later calls keep the first record.
    /// Returns whether this call recorded them.
    pub fn save_profile_originals(
        &mut self,
        profiles: &[ProfileState],
        now_ms: i64,
    ) -> Result<bool> {
        if self.meta(PROFILE_ORIGINALS_KEY)?.is_some() {
            return Ok(false);
        }
        let json = serde_json::to_string(profiles).map_err(json_error)?;
        self.set_meta(
            PROFILE_ORIGINALS_KEY,
            Some(&json),
            now_ms,
            "win4tress",
            "saved profile settings",
        )?;
        Ok(true)
    }

    pub fn profile_originals(&self) -> Result<Option<Vec<ProfileState>>> {
        Ok(self
            .meta(PROFILE_ORIGINALS_KEY)?
            .and_then(|v| serde_json::from_str(&v).ok()))
    }

    /// After they've been put back.
    pub fn clear_profile_originals(&mut self, now_ms: i64, who: &str) -> Result<()> {
        if self.meta(PROFILE_ORIGINALS_KEY)?.is_none() {
            return Ok(());
        }
        self.set_meta(
            PROFILE_ORIGINALS_KEY,
            None,
            now_ms,
            who,
            "restored profile settings",
        )
    }

    /// Addresses `app` received from DNS, in the history kept, for names
    /// `pattern` covers (`name`, or `*.name` for it and its subdomains).
    pub fn dns_addresses(&self, app: AppId, pattern: &str) -> Result<Vec<IpAddr>> {
        let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        let (base, subdomains) = match p.strip_prefix("*.") {
            Some(base) => (base.to_string(), true),
            None => (p, false),
        };
        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT addrs FROM dns_queries
             WHERE app_id = ?1 AND status = 0 AND addrs != ''
               AND (name = ?2 OR (?3 AND name LIKE '%.' || ?2))",
        )?;
        let mut out: Vec<IpAddr> = Vec::new();
        for addrs in stmt.query_map(params![app, base, subdomains], |r| r.get::<_, String>(0))? {
            out.extend(addrs?.split(' ').filter_map(|a| a.parse::<IpAddr>().ok()));
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    pub fn save_blocks(&mut self, rows: &[BlockRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut add = tx.prepare_cached(
                "INSERT INTO blocks (minute, app_id, inbound, ip, port, by_kind, by_name, count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(minute, app_id, inbound, ip, port, by_kind, by_name)
                 DO UPDATE SET count = count + excluded.count",
            )?;
            for r in rows {
                let k = &r.key;
                add.execute(params![
                    r.minute,
                    k.app,
                    k.inbound,
                    k.ip.to_string(),
                    k.port,
                    k.by.kind.as_str(),
                    k.by.name,
                    r.count as i64
                ])?;
            }
        }
        tx.commit()
    }

    /// Blocked attempts since `since_ms`, combined per (app, direction,
    /// address, port, cause), most recent first.
    pub fn blocks(
        &self,
        app: Option<AppId>,
        since_ms: i64,
        limit: usize,
    ) -> Result<Vec<(BlockKey, BlockCount)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT app_id, inbound, ip, port, by_kind, by_name,
                    SUM(count), MIN(minute), MAX(minute)
             FROM blocks
             WHERE minute >= ?1 AND (?2 IS NULL OR app_id = ?2)
             GROUP BY app_id, inbound, ip, port, by_kind, by_name
             ORDER BY MAX(minute) DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![since_ms.div_euclid(60_000), app, limit as i64],
            |r| {
                Ok((
                    r.get::<_, AppId>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u16>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (app, inbound, ip, port, kind, name, count, first, last) = row?;
            let (Ok(ip), Some(kind)) = (ip.parse(), BlockedByKind::parse(&kind)) else {
                continue;
            };
            out.push((
                BlockKey {
                    app,
                    inbound,
                    ip,
                    port,
                    by: BlockedBy { kind, name },
                },
                BlockCount {
                    count: count as u64,
                    first_ms: first * 60_000,
                    last_ms: last * 60_000 + 59_999,
                },
            ));
        }
        Ok(out)
    }
}
