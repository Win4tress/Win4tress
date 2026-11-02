//! Alerts (SPEC §11): written as the monitor raises them, read by the Alerts view.

use rusqlite::types::Value;
use rusqlite::{OptionalExtension, Row, params, params_from_iter};
use w4_ipc::api::{AlertBody, AlertsParams, AppId, Severity};
use w4_monitor::PendingAlert;

use crate::{Error, Result, Store};

/// An alert as stored; the service fills in the app's name for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAlert {
    pub id: i64,
    pub ts_ms: i64,
    pub severity: Severity,
    pub app: Option<AppId>,
    /// What the app was called when the alert was raised.
    pub app_name: Option<String>,
    pub body: AlertBody,
    pub read: bool,
}

const FIRST_RUN_KEY: &str = "first_run_ms";
/// Read by [`stored`], in this order.
const COLUMNS: &str = "a.id, a.ts_ms, a.severity, a.app_id, a.body, a.read, a.app_name";

fn stored(r: &Row) -> rusqlite::Result<Option<StoredAlert>> {
    let body: String = r.get(4)?;
    // A kind from a newer version of win4tress: skip it rather than fail.
    let Ok(body) = serde_json::from_str::<AlertBody>(&body) else {
        return Ok(None);
    };
    Ok(Some(StoredAlert {
        id: r.get(0)?,
        ts_ms: r.get(1)?,
        severity: parse_severity(&r.get::<_, String>(2)?),
        app: r.get(3)?,
        app_name: r.get(6)?,
        body,
        read: r.get::<_, i64>(5)? != 0,
    }))
}

impl Store {
    /// When win4tress first ran with this database. The first call records `now_ms`.
    pub fn first_run_ms(&self, now_ms: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            params![FIRST_RUN_KEY, now_ms.to_string()],
        )?;
        let value: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [FIRST_RUN_KEY],
            |r| r.get(0),
        )?;
        value
            .parse()
            .map_err(|_| Error::InvalidParameterName(format!("bad {FIRST_RUN_KEY}: {value}")))
    }

    /// Stores alerts in one transaction and returns their ids, in order.
    pub fn insert_alerts(&mut self, alerts: &[PendingAlert]) -> Result<Vec<i64>> {
        let tx = self.conn.transaction()?;
        let mut ids = Vec::with_capacity(alerts.len());
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO alerts (ts_ms, kind, severity, app_id, app_name, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for a in alerts {
                let body = serde_json::to_string(&a.body)
                    .map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))?;
                insert.execute(params![
                    a.ts_ms,
                    a.body.kind(),
                    severity_name(a.severity.unwrap_or(a.body.severity())),
                    a.app,
                    a.app_name,
                    body
                ])?;
                ids.push(tx.last_insert_rowid());
            }
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Newest first, at most `limit`, and whether older ones match too.
    pub fn alerts(&self, p: &AlertsParams, limit: usize) -> Result<(Vec<StoredAlert>, bool)> {
        let mut sql =
            format!("SELECT {COLUMNS} FROM alerts a LEFT JOIN apps ON apps.id = a.app_id WHERE 1");
        let mut args: Vec<Value> = Vec::new();
        if !p.kinds.is_empty() {
            let marks = vec!["?"; p.kinds.len()].join(", ");
            sql.push_str(&format!(" AND a.kind IN ({marks})"));
            args.extend(p.kinds.iter().map(|k| Value::Text(k.clone())));
        }
        if p.unread_only {
            sql.push_str(" AND a.read = 0");
        }
        if let Some(since) = p.since_ms {
            sql.push_str(" AND a.ts_ms >= ?");
            args.push(Value::Integer(since));
        }
        if let Some(before) = p.before_id {
            sql.push_str(" AND a.id < ?");
            args.push(Value::Integer(before));
        }
        if let Some(q) = p.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
            sql.push_str(
                " AND (a.body LIKE ? ESCAPE '\\' OR a.app_name LIKE ? ESCAPE '\\'
                       OR apps.path LIKE ? ESCAPE '\\'
                       OR apps.description LIKE ? ESCAPE '\\'
                       OR apps.service_display LIKE ? ESCAPE '\\')",
            );
            let pattern = Value::Text(format!("%{}%", escape_like(q)));
            args.extend(std::iter::repeat_n(pattern, 5));
        }
        sql.push_str(&format!(" ORDER BY a.id DESC LIMIT {}", limit + 1));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), stored)?;
        let mut alerts = Vec::new();
        for row in rows {
            alerts.extend(row?);
        }
        let more = alerts.len() > limit;
        alerts.truncate(limit);
        Ok((alerts, more))
    }

    /// One alert, or `None` if there's no such alert (or it's of a kind this
    /// build doesn't know).
    pub fn alert(&self, id: i64) -> Result<Option<StoredAlert>> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM alerts a WHERE a.id = ?1"),
                [id],
                stored,
            )
            .optional()
            .map(Option::flatten)
    }

    /// Replaces an alert's details, e.g. to record what the user did about it.
    pub fn set_alert_body(&self, id: i64, body: &AlertBody) -> Result<bool> {
        let json =
            serde_json::to_string(body).map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(self.conn.execute(
            "UPDATE alerts SET body = ?2 WHERE id = ?1 AND kind = ?3",
            params![id, json, body.kind()],
        )? == 1)
    }

    /// Marks the given alerts, or all of them, read or unread.
    pub fn mark_read(&self, ids: Option<&[i64]>, read: bool) -> Result<usize> {
        let flag = i64::from(read);
        match ids {
            None => self
                .conn
                .execute("UPDATE alerts SET read = ?1 WHERE read != ?1", [flag]),
            Some(ids) => {
                let mut stmt = self
                    .conn
                    .prepare_cached("UPDATE alerts SET read = ?1 WHERE id = ?2 AND read != ?1")?;
                let mut changed = 0;
                for id in ids {
                    changed += stmt.execute([flag, *id])?;
                }
                Ok(changed)
            }
        }
    }

    pub fn unread_alerts(&self) -> Result<u64> {
        let n: Option<i64> = self
            .conn
            .query_row("SELECT COUNT(*) FROM alerts WHERE read = 0", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(n.unwrap_or(0) as u64)
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Makes `%`, `_` and `\` literal in a LIKE pattern that uses `ESCAPE '\'`.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
