//! History in SQLite (SPEC §9): traffic per minute for 48 hours, then coarser
//! tiers (`tiers.rs`), DNS queries for 30 days and per day after, alerts for a
//! year, and the app table, so ids and names survive restarts.
//!
//! The monitor owns all live state; this crate only writes what it hands over
//! and answers range queries.

mod alerts;
mod cleanup;
mod dns_stats;
mod firewall;
mod network;
mod profiles;
mod reputation;
mod rules;
mod tiers;

pub use alerts::StoredAlert;
pub use cleanup::AppWithRules;
pub use dns_stats::DnsStatsRows;
pub use profiles::{ProfileRule, SavedProfile};
pub use rules::{AuditEntry, NewRule, RuleEdit};
pub use tiers::{
    APP_MINUTE_RETENTION_MS, HOUR_RETENTION_MS, SaveContext, SeriesFilter, Tier, local_day,
};

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use w4_core::trust::{Signature, Trust};
use w4_core::{Bytes, Country, TrafficType};
use w4_ipc::api::{AppId, DomainCount};
use w4_monitor::{AppRecord, DnsRecord, MinuteRow, UsageRow};

pub use rusqlite::Error;
pub type Result<T> = rusqlite::Result<T>;

/// Per-minute traffic by host is kept this long; coarser tiers keep more.
pub const MINUTE_RETENTION_MS: i64 = 48 * 3600 * 1000;
pub const DNS_RETENTION_MS: i64 = 30 * 24 * 3600 * 1000;
pub const ALERT_RETENTION_MS: i64 = 365 * 24 * 3600 * 1000;

/// The installed service's database, in [`default_dir`].
pub const DB_NAME: &str = "history.db";

/// Where the service keeps its data: `%ProgramData%\win4tress`, readable and
/// writable only by SYSTEM and Administrators (SPEC §9).
pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("win4tress")
}

/// Schema version N is reached by running `MIGRATIONS[..N]` in order.
const MIGRATIONS: &[&str] = &[
    SCHEMA_V1,
    SCHEMA_V2,
    SCHEMA_V3,
    SCHEMA_V4,
    SCHEMA_V5,
    SCHEMA_V6,
    SCHEMA_V7,
    SCHEMA_V8,
    tiers::SCHEMA_V9,
    network::SCHEMA_V10,
    SCHEMA_V11,
    SCHEMA_V12,
    SCHEMA_V13,
    SCHEMA_V14,
];
/// The version that added the traffic tiers, filled from the minute detail.
const TIERS_VERSION: i32 = 9;
/// The version that made profiles exact, their rules converted.
const EXACT_PROFILES_VERSION: i32 = 14;
const SCHEMA_VERSION: i32 = MIGRATIONS.len() as i32;
/// Blocked connections are kept this long.
pub const BLOCK_RETENTION_MS: i64 = 30 * 24 * 3600 * 1000;

/// Exact profiles (SPEC §7.6): `profiles.rules` holds the rules on, in full
/// (a `profiles::ProfileRule` list as JSON), rather than rule id -> on.
/// Converted in Rust, after the migrations.
const SCHEMA_V14: &str = "
UPDATE profiles SET rules = rules;
";

/// DNS filtering's settings in a profile (SPEC §7.6).
const SCHEMA_V13: &str = "
-- w4_ipc::api::DnsSettings as JSON, without a pause; NULL for a profile saved
-- before profiles held them
ALTER TABLE profiles ADD COLUMN dns TEXT;
";

/// Temporary rules: when each ends and what it goes back to (SPEC §7.2); the
/// networks a profile is switched to on (SPEC §7.6).
const SCHEMA_V12: &str = "
-- w4_core::firewall::Expiry as JSON
ALTER TABLE rules ADD COLUMN expires TEXT;
-- the action it goes back to
ALTER TABLE rules ADD COLUMN revert TEXT;
-- w4_ipc::api::NetworkMatch list as JSON
ALTER TABLE profiles ADD COLUMN networks TEXT NOT NULL DEFAULT '[]';
";

/// Firewall profiles (SPEC §7.6), reputation answers per file and source
/// (SPEC §12), and since when an app's program is missing (cleanup, §7.10).
const SCHEMA_V11: &str = "
CREATE TABLE profiles (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    mode TEXT NOT NULL,
    -- rule id -> on, as JSON
    rules TEXT NOT NULL,
    saved_ms INTEGER NOT NULL
);

CREATE TABLE reputation (
    sha256 TEXT NOT NULL,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detections INTEGER,
    engines INTEGER,
    detail TEXT,
    link TEXT,
    checked_ms INTEGER NOT NULL,
    PRIMARY KEY (sha256, source)
) WITHOUT ROWID;

ALTER TABLE apps ADD COLUMN missing_since_ms INTEGER;
";

/// Trust (tier 1) and own-DNS sightings per app; blocked connections per
/// minute ("Blocked by", SPEC §7.9); per-app DNS answers by name, for host rules.
const SCHEMA_V8: &str = "
ALTER TABLE apps ADD COLUMN signature TEXT;
ALTER TABLE apps ADD COLUMN signer TEXT;
ALTER TABLE apps ADD COLUMN sha256 TEXT;
-- w4_core::trust::DownloadOrigin as JSON
ALTER TABLE apps ADD COLUMN origin TEXT;
ALTER TABLE apps ADD COLUMN own_dns_ms INTEGER;
CREATE INDEX dns_queries_app_name ON dns_queries(app_id, name);

CREATE TABLE blocks (
    minute INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    inbound INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    -- w4_core::firewall::BlockedByKind
    by_kind TEXT NOT NULL,
    by_name TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (minute, app_id, inbound, ip, port, by_kind, by_name)
) WITHOUT ROWID;
CREATE INDEX blocks_app ON blocks(app_id, minute);
";

/// Rule ids are never reused: they name Windows Firewall rules and the audit
/// trail refers to them. SQLite reuses the highest rowid after a delete unless
/// the table is AUTOINCREMENT, which needs a rebuild.
const SCHEMA_V7: &str = "
CREATE TABLE rules_v7 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    direction TEXT NOT NULL,
    action TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    origin TEXT NOT NULL,
    note TEXT,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
INSERT INTO rules_v7 SELECT id, app_id, direction, action, scope_kind, scope, enabled, origin, note,
                            created_ms, updated_ms FROM rules;
DROP TABLE rules;
ALTER TABLE rules_v7 RENAME TO rules;
CREATE UNIQUE INDEX rules_identity ON rules(app_id, direction, action, scope_kind);
-- Continue above every id ever used, deleted ones included.
DELETE FROM sqlite_sequence WHERE name IN ('rules', 'rules_v7');
INSERT INTO sqlite_sequence (name, seq) VALUES ('rules', MAX(
    COALESCE((SELECT MAX(id) FROM rules), 0),
    COALESCE((SELECT MAX(rule_id) FROM rule_audit), 0)));
";

/// Firewall rules: the desired state (SPEC §4.4, §7.2), and who changed what.
const SCHEMA_V6: &str = "
CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    app_id INTEGER NOT NULL,
    direction TEXT NOT NULL,
    action TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    -- w4_core::firewall::Scope as JSON
    scope TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    origin TEXT NOT NULL,
    note TEXT,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
-- One rule per (app, direction, action, scope kind).
CREATE UNIQUE INDEX rules_identity ON rules(app_id, direction, action, scope_kind);

CREATE TABLE rule_audit (
    id INTEGER PRIMARY KEY,
    ts_ms INTEGER NOT NULL,
    rule_id INTEGER,
    -- created | updated | deleted | repaired
    change TEXT NOT NULL,
    who TEXT NOT NULL,
    -- the rule as JSON: after the change, or before it for deletes
    rule TEXT NOT NULL
);
CREATE INDEX rule_audit_ts ON rule_audit(ts_ms);
";

/// Drops DNS rows that builds before 2026-10-25 evening recorded by mistake:
/// the empty ERROR_INVALID_PARAMETER echo of combined A+AAAA lookups, and the
/// service's own reverse lookups. Also removes the root dot from names.
const SCHEMA_V5: &str = r"
DELETE FROM dns_queries WHERE status = 87 AND addrs = '';
DELETE FROM dns_queries WHERE query_type = 12
    AND app_id IN (SELECT id FROM apps WHERE lower(path) LIKE '%\win4tress-svc.exe');
UPDATE dns_queries SET name = rtrim(name, '.') WHERE name LIKE '%.';
";

/// The app's name when the alert was raised (an update can change it).
const SCHEMA_V4: &str = "ALTER TABLE alerts ADD COLUMN app_name TEXT;";

const SCHEMA_V3: &str = "
ALTER TABLE apps ADD COLUMN net_first_seen_ms INTEGER;
-- Apps with traffic in history have used the network: no first-activity alert for them.
UPDATE apps SET net_first_seen_ms =
    (SELECT MIN(minute) * 60000 FROM traffic_min WHERE app_id = apps.id)
WHERE id IN (SELECT app_id FROM traffic_min);

CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    ts_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    app_id INTEGER,
    -- w4_ipc::api::AlertBody as JSON
    body TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alerts_ts ON alerts(ts_ms);
CREATE INDEX alerts_unread ON alerts(read) WHERE read = 0;
";

const SCHEMA_V2: &str = "ALTER TABLE apps ADD COLUMN version TEXT;";

const SCHEMA_V1: &str = "
CREATE TABLE apps (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    path TEXT NOT NULL,
    description TEXT,
    company TEXT,
    package TEXT,
    service TEXT,
    service_display TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL
);
CREATE INDEX apps_key ON apps(key);

CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    name TEXT,
    country TEXT NOT NULL,
    country_name TEXT NOT NULL
);

-- One row per (minute, app, host). The traffic type belongs to the (app, host) pair.
CREATE TABLE traffic_min (
    minute INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    traffic_type TEXT NOT NULL,
    recv INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    PRIMARY KEY (minute, app_id, host_id)
) WITHOUT ROWID;

CREATE TABLE dns_queries (
    ts_ms INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    query_type INTEGER NOT NULL,
    status INTEGER NOT NULL,
    addrs TEXT NOT NULL
);
CREATE INDEX dns_queries_ts ON dns_queries(ts_ms);
";

struct CachedHost {
    id: i64,
    name: Option<String>,
    country: String,
}

pub struct Store {
    conn: Connection,
    hosts: HashMap<IpAddr, CachedHost>,
    context: SaveContext,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Store> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::InvalidParameterName(format!(
                "history database is schema {version}; this build understands {SCHEMA_VERSION}"
            )));
        }
        // Each step commits with its version number, so an interrupted upgrade resumes.
        for (done, migration) in MIGRATIONS.iter().enumerate().skip(version.max(0) as usize) {
            let tx = conn.transaction()?;
            tx.execute_batch(migration)?;
            tx.pragma_update(None, "user_version", done as i32 + 1)?;
            tx.commit()?;
        }
        let mut store = Store {
            conn,
            hosts: HashMap::new(),
            context: SaveContext::default(),
        };
        // Days in UTC for these 48 hours: the local offset isn't known yet.
        if (1..TIERS_VERSION).contains(&version) {
            store.backfill_tiers()?;
        }
        if (1..EXACT_PROFILES_VERSION).contains(&version) {
            store.convert_profile_rules()?;
        }
        Ok(store)
    }

    pub fn load_apps(&self) -> Result<Vec<AppRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, key, path, description, company, package, service, service_display,
                    first_seen_ms, last_seen_ms, version, net_first_seen_ms,
                    signature, signer, sha256, origin, own_dns_ms
             FROM apps ORDER BY id",
        )?;
        stmt.query_map([], |r| {
            let signature: Option<String> = r.get(12)?;
            let origin: Option<String> = r.get(15)?;
            Ok(AppRecord {
                id: r.get(0)?,
                key: r.get(1)?,
                path: r.get(2)?,
                description: r.get(3)?,
                company: r.get(4)?,
                package: r.get(5)?,
                service: r.get(6)?,
                service_display: r.get(7)?,
                first_seen_ms: r.get(8)?,
                last_seen_ms: r.get(9)?,
                version: r.get(10)?,
                net_first_seen_ms: r.get(11)?,
                trust: Trust {
                    signature: signature.as_deref().and_then(Signature::parse),
                    signer: r.get(13)?,
                    sha256: r.get(14)?,
                    origin: origin.and_then(|o| serde_json::from_str(&o).ok()),
                },
                own_dns_ms: r.get(16)?,
            })
        })?
        .collect()
    }

    /// Writes one flush from the monitor in a single transaction.
    pub fn save(
        &mut self,
        apps: &[AppRecord],
        minutes: &[MinuteRow],
        dns: &[DnsRecord],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut upsert_app = tx.prepare_cached(
                "INSERT INTO apps (id, key, path, description, company, package, service,
                                   service_display, first_seen_ms, last_seen_ms, version,
                                   net_first_seen_ms, signature, signer, sha256, origin,
                                   own_dns_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17)
                 ON CONFLICT(id) DO UPDATE SET
                    key = excluded.key, path = excluded.path,
                    description = excluded.description, company = excluded.company,
                    package = excluded.package, service = excluded.service,
                    service_display = excluded.service_display,
                    first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
                    last_seen_ms = MAX(last_seen_ms, excluded.last_seen_ms),
                    version = excluded.version,
                    -- The earliest known; SQLite's MIN() is NULL if either is.
                    net_first_seen_ms = COALESCE(
                        MIN(net_first_seen_ms, excluded.net_first_seen_ms),
                        net_first_seen_ms, excluded.net_first_seen_ms),
                    signature = excluded.signature, signer = excluded.signer,
                    sha256 = excluded.sha256, origin = excluded.origin,
                    own_dns_ms = COALESCE(
                        MIN(own_dns_ms, excluded.own_dns_ms), own_dns_ms, excluded.own_dns_ms)",
            )?;
            for a in apps {
                let origin = a
                    .trust
                    .origin
                    .as_ref()
                    .and_then(|o| serde_json::to_string(o).ok());
                upsert_app.execute(params![
                    a.id,
                    a.key,
                    a.path,
                    a.description,
                    a.company,
                    a.package,
                    a.service,
                    a.service_display,
                    a.first_seen_ms,
                    a.last_seen_ms,
                    a.version,
                    a.net_first_seen_ms,
                    a.trust.signature.map(Signature::as_str),
                    a.trust.signer,
                    a.trust.sha256,
                    origin,
                    a.own_dns_ms
                ])?;
            }

            let mut upsert_host = tx.prepare_cached(
                "INSERT INTO hosts (ip, name, country, country_name) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(ip) DO UPDATE SET
                    name = COALESCE(excluded.name, hosts.name),
                    country = excluded.country, country_name = excluded.country_name
                 RETURNING id",
            )?;
            let mut add_minute = tx.prepare_cached(
                "INSERT INTO traffic_min (minute, app_id, host_id, traffic_type, recv, sent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(minute, app_id, host_id) DO UPDATE SET
                    recv = recv + excluded.recv, sent = sent + excluded.sent",
            )?;
            for m in minutes {
                let r = &m.row;
                let cached = self.hosts.get(&r.ip);
                let stale = cached.is_none_or(|c| {
                    (r.name.is_some() && c.name != r.name) || c.country != r.country.code
                });
                let host_id = if stale {
                    let id: i64 = upsert_host.query_row(
                        params![r.ip.to_string(), r.name, r.country.code, r.country.name],
                        |row| row.get(0),
                    )?;
                    self.hosts.insert(
                        r.ip,
                        CachedHost {
                            id,
                            name: r.name.clone(),
                            country: r.country.code.clone(),
                        },
                    );
                    id
                } else {
                    cached.map(|c| c.id).expect("not stale, so cached")
                };
                add_minute.execute(params![
                    m.minute,
                    r.app,
                    host_id,
                    r.traffic_type.id(),
                    r.bytes.recv as i64,
                    r.bytes.sent as i64
                ])?;
                tiers::add_to_tiers(
                    &tx,
                    &tiers::TierRow {
                        minute: m.minute,
                        app: r.app,
                        host_id,
                        traffic_type: r.traffic_type.id(),
                        country: &r.country.code,
                        bytes: r.bytes,
                    },
                    self.context,
                )?;
            }

            let mut add_dns = tx.prepare_cached(
                "INSERT INTO dns_queries (ts_ms, app_id, name, query_type, status, addrs)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for d in dns {
                let addrs: Vec<String> = d.addrs.iter().map(IpAddr::to_string).collect();
                add_dns.execute(params![
                    d.ts_ms,
                    d.app,
                    d.name,
                    d.query_type,
                    d.status,
                    addrs.join(" ")
                ])?;
            }
        }
        tx.commit()
    }

    /// Deletes data past its retention. Returns rows removed.
    pub fn prune(&self, now_ms: i64) -> Result<usize> {
        let minute_cutoff = (now_ms - MINUTE_RETENTION_MS).div_euclid(60_000);
        let mut removed = self
            .conn
            .execute("DELETE FROM traffic_min WHERE minute < ?1", [minute_cutoff])?;
        self.roll_up_dns(now_ms - DNS_RETENTION_MS)?;
        removed += self.conn.execute(
            "DELETE FROM dns_queries WHERE ts_ms < ?1",
            [now_ms - DNS_RETENTION_MS],
        )?;
        removed += self.prune_tiers(now_ms)?;
        removed += self.conn.execute(
            "DELETE FROM alerts WHERE ts_ms < ?1",
            [now_ms - ALERT_RETENTION_MS],
        )?;
        removed += self.conn.execute(
            "DELETE FROM blocks WHERE minute < ?1",
            [(now_ms - BLOCK_RETENTION_MS).div_euclid(60_000)],
        )?;
        Ok(removed)
    }

    /// Totals per minute in [from, to] (Unix minutes); quiet minutes are absent.
    pub fn history(&self, from_minute: i64, to_minute: i64) -> Result<Vec<(i64, Bytes)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT minute, SUM(recv), SUM(sent) FROM traffic_min
             WHERE minute BETWEEN ?1 AND ?2 GROUP BY minute ORDER BY minute",
        )?;
        stmt.query_map([from_minute, to_minute], |r| {
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

    /// Usage rows for [from, to] (Unix minutes), one per app and host, for
    /// [`w4_monitor::build_breakdown`].
    pub fn usage(&self, from_minute: i64, to_minute: i64) -> Result<Vec<UsageRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT t.app_id, h.ip, h.name, h.country, h.country_name, t.traffic_type,
                    SUM(t.recv), SUM(t.sent)
             FROM traffic_min t JOIN hosts h ON h.id = t.host_id
             WHERE t.minute BETWEEN ?1 AND ?2
             GROUP BY t.app_id, t.host_id, t.traffic_type",
        )?;
        let rows = stmt.query_map([from_minute, to_minute], |r| {
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
            // Skip rows whose address no longer parses rather than failing the query.
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

    /// Most-queried names in [from_ms, to_ms], optionally for one app.
    pub fn dns_top(
        &self,
        from_ms: i64,
        to_ms: i64,
        app: Option<AppId>,
        limit: usize,
    ) -> Result<Vec<DomainCount>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT name, COUNT(*), SUM(status != 0), COUNT(DISTINCT app_id), MAX(ts_ms)
             FROM dns_queries
             WHERE ts_ms BETWEEN ?1 AND ?2 AND (?3 IS NULL OR app_id = ?3)
             GROUP BY name ORDER BY COUNT(*) DESC, name LIMIT ?4",
        )?;
        stmt.query_map(params![from_ms, to_ms, app, limit as i64], |r| {
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

    /// The oldest stored minute, if any.
    pub fn oldest_minute(&self) -> Result<Option<i64>> {
        self.conn
            .query_row("SELECT MIN(minute) FROM traffic_min", [], |r| r.get(0))
            .optional()
            .map(Option::flatten)
    }
}

#[cfg(test)]
mod tests;
