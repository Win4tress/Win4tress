//! Firewall rules and the mode (the desired state), and their audit trail
//! (SPEC §4.4). Mode changes are audited too, with no rule id.

use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use w4_core::firewall::{Action, Direction, Expiry, Mode, Origin, RuleId, RuleRecord, Scope};

use crate::{Error, Result, Store};

const MODE_KEY: &str = "firewall_mode";

/// A change to a stored rule's verdict (unset fields stay as they are).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleEdit {
    pub enabled: Option<bool>,
    pub action: Option<Action>,
}

/// A rule to set. The store fills in id and timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewRule {
    pub app: u32,
    pub direction: Direction,
    pub action: Action,
    pub scope: Scope,
    pub origin: Origin,
    pub note: Option<String>,
    /// A temporary rule's end; `None` for good.
    pub expires: Option<Expiry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts_ms: i64,
    pub rule_id: Option<RuleId>,
    pub change: String,
    pub who: String,
    /// The rule as JSON.
    pub rule: String,
}

fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::In => "in",
        Direction::Out => "out",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Block => "block",
    }
}

fn origin_name(o: Origin) -> &'static str {
    match o {
        Origin::User => "user",
        Origin::Prompt => "prompt",
        Origin::Baseline => "baseline",
        Origin::Import => "import",
        Origin::Cleanup => "cleanup",
        Origin::Reputation => "reputation",
    }
}

fn bad(what: &str, value: &str) -> Error {
    Error::InvalidParameterName(format!("unknown {what} {value:?} in the rules table"))
}

const COLUMNS: &str =
    "id, app_id, direction, action, scope, enabled, origin, note, created_ms, updated_ms,
     expires, revert";

fn to_json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))
}

fn parse_action(s: &str) -> rusqlite::Result<Action> {
    match s {
        "allow" => Ok(Action::Allow),
        "block" => Ok(Action::Block),
        other => Err(bad("action", other)),
    }
}

fn record(r: &Row) -> rusqlite::Result<RuleRecord> {
    let text = |i: usize| r.get::<_, String>(i);
    let direction = match text(2)?.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        other => return Err(bad("direction", other)),
    };
    let action = parse_action(&text(3)?)?;
    let scope_json = text(4)?;
    let scope: Scope = serde_json::from_str(&scope_json).map_err(|_| bad("scope", &scope_json))?;
    let origin = match text(6)?.as_str() {
        "user" => Origin::User,
        "prompt" => Origin::Prompt,
        "baseline" => Origin::Baseline,
        "import" => Origin::Import,
        "cleanup" => Origin::Cleanup,
        "reputation" => Origin::Reputation,
        other => return Err(bad("origin", other)),
    };
    Ok(RuleRecord {
        id: r.get(0)?,
        app: r.get(1)?,
        direction,
        action,
        scope,
        enabled: r.get::<_, i64>(5)? != 0,
        origin,
        note: r.get(7)?,
        created_ms: r.get(8)?,
        updated_ms: r.get(9)?,
        // An end that doesn't read leaves the rule for good rather than failing.
        expires: r
            .get::<_, Option<String>>(10)?
            .and_then(|j| serde_json::from_str(&j).ok()),
        revert: r
            .get::<_, Option<String>>(11)?
            .map(|a| parse_action(&a))
            .transpose()?,
    })
}

fn audit(tx: &Transaction, ts_ms: i64, rule: &RuleRecord, change: &str, who: &str) -> Result<()> {
    let json =
        serde_json::to_string(rule).map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))?;
    tx.execute(
        "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ts_ms, rule.id, change, who, json],
    )?;
    Ok(())
}

fn audit_mode(tx: &Transaction, ts_ms: i64, mode: Mode, who: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule) VALUES (?1, NULL, 'mode', ?2, ?3)",
        params![ts_ms, who, format!("{{\"mode\":\"{}\"}}", mode.as_str())],
    )?;
    Ok(())
}

fn mode_in(conn: &Connection) -> Result<Mode> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [MODE_KEY], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(value.as_deref().and_then(Mode::parse).unwrap_or_default())
}

fn rule_in(conn: &Connection, id: RuleId) -> Result<Option<RuleRecord>> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM rules WHERE id = ?1"),
        [id],
        record,
    )
    .optional()
}

/// The app's rule with this action for a direction and scope kind (at most one).
fn find(
    conn: &Connection,
    app: u32,
    direction: Direction,
    action: Action,
    scope_kind: &str,
) -> Result<Option<RuleRecord>> {
    conn.query_row(
        &format!(
            "SELECT {COLUMNS} FROM rules
             WHERE app_id = ?1 AND direction = ?2 AND action = ?3 AND scope_kind = ?4"
        ),
        params![
            app,
            direction_name(direction),
            action_name(action),
            scope_kind
        ],
        record,
    )
    .optional()
}

impl Store {
    /// The enforcement mode; the default until one is set.
    pub fn firewall_mode(&self) -> Result<Mode> {
        mode_in(&self.conn)
    }

    /// Sets the mode, audited as `who`. Returns whether it changed.
    pub fn set_firewall_mode(&mut self, mode: Mode, now_ms: i64, who: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        if mode_in(&tx)? == mode {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![MODE_KEY, mode.as_str()],
        )?;
        audit_mode(&tx, now_ms, mode, who)?;
        tx.commit()?;
        Ok(true)
    }

    /// Deletes every rule and goes back to the default mode, all audited as
    /// `who` (SPEC §4.3 `reset`). Returns how many rules were deleted.
    pub fn reset_rules(&mut self, now_ms: i64, who: &str) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let rules: Vec<RuleRecord> = {
            let mut stmt = tx.prepare(&format!("SELECT {COLUMNS} FROM rules ORDER BY id"))?;
            stmt.query_map([], record)?.collect::<Result<_>>()?
        };
        for r in &rules {
            tx.execute("DELETE FROM rules WHERE id = ?1", [r.id])?;
            audit(&tx, now_ms, r, "reset", who)?;
        }
        if mode_in(&tx)? != Mode::default() {
            tx.execute("DELETE FROM meta WHERE key = ?1", [MODE_KEY])?;
            audit_mode(&tx, now_ms, Mode::default(), who)?;
        }
        tx.commit()?;
        Ok(rules.len())
    }

    pub fn rules(&self) -> Result<Vec<RuleRecord>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {COLUMNS} FROM rules ORDER BY id"))?;
        stmt.query_map([], record)?.collect()
    }

    pub fn rule(&self, id: RuleId) -> Result<Option<RuleRecord>> {
        rule_in(&self.conn, id)
    }

    /// Sets an app's verdict for one direction and scope: creates or updates the
    /// rule, and removes the app's opposite rule for the same direction and scope
    /// kind (a toggle). Audited as `who`. Returns the rule.
    ///
    /// A temporary verdict (`expires`) takes the opposite rule's place instead,
    /// and puts its action back when it ends; it never shortens a rule that
    /// already says the same for good.
    pub fn set_rule(&mut self, new: &NewRule, now_ms: i64, who: &str) -> Result<RuleRecord> {
        let scope_json = to_json(&new.scope)?;
        let expires_json = new.expires.as_ref().map(to_json).transpose()?;
        let opposite = match new.action {
            Action::Allow => Action::Block,
            Action::Block => Action::Allow,
        };
        let tx = self.conn.transaction()?;
        let kind = new.scope.kind();
        if let Some(old) = find(&tx, new.app, new.direction, opposite, kind)? {
            // What the app has for good: the rule's action, or what a temporary
            // one goes back to.
            let lasting = match old.expires {
                Some(_) => old.revert,
                None => Some(old.action),
            };
            if new.expires.is_some() && old.enabled && lasting.is_some() {
                let (expires, revert) = if lasting == Some(new.action) {
                    (None, None)
                } else {
                    (expires_json.clone(), lasting.map(action_name))
                };
                tx.execute(
                    "UPDATE rules SET action = ?2, scope = ?3, enabled = 1, origin = ?4, note = ?5,
                                      updated_ms = ?6, expires = ?7, revert = ?8
                     WHERE id = ?1",
                    params![
                        old.id,
                        action_name(new.action),
                        scope_json,
                        origin_name(new.origin),
                        new.note,
                        now_ms,
                        expires,
                        revert
                    ],
                )?;
                let rule = rule_in(&tx, old.id)?.ok_or(Error::QueryReturnedNoRows)?;
                audit(&tx, now_ms, &rule, "updated", who)?;
                tx.commit()?;
                return Ok(rule);
            }
            tx.execute("DELETE FROM rules WHERE id = ?1", [old.id])?;
            audit(&tx, now_ms, &old, "deleted", who)?;
        }
        let existing = find(&tx, new.app, new.direction, new.action, kind)?;
        let id = match &existing {
            Some(r) => {
                // For good replaces temporary; temporary only changes temporary.
                let (expires, revert) = match (new.expires, r.expires) {
                    (Some(_), None) if r.enabled => (None, None),
                    (Some(_), _) => (expires_json.clone(), r.revert.map(action_name)),
                    (None, _) => (None, None),
                };
                tx.execute(
                    "UPDATE rules SET scope = ?2, enabled = 1, origin = ?3, note = ?4, updated_ms = ?5,
                                      expires = ?6, revert = ?7
                     WHERE id = ?1",
                    params![
                        r.id,
                        scope_json,
                        origin_name(new.origin),
                        new.note,
                        now_ms,
                        expires,
                        revert
                    ],
                )?;
                r.id
            }
            None => {
                tx.execute(
                    "INSERT INTO rules (app_id, direction, action, scope_kind, scope, enabled, origin, note,
                                        created_ms, updated_ms, expires)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?8, ?9)",
                    params![
                        new.app,
                        direction_name(new.direction),
                        action_name(new.action),
                        new.scope.kind(),
                        scope_json,
                        origin_name(new.origin),
                        new.note,
                        now_ms,
                        expires_json
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };
        let rule = rule_in(&tx, id)?.ok_or(Error::QueryReturnedNoRows)?;
        audit(
            &tx,
            now_ms,
            &rule,
            if existing.is_some() {
                "updated"
            } else {
                "created"
            },
            who,
        )?;
        tx.commit()?;
        Ok(rule)
    }

    /// Changes a rule's enabled flag or action, audited as `change` by `who`.
    /// A new action replaces the app's other rule with that action for the same
    /// direction and scope kind, as [`Store::set_rule`] does. Returns the rule,
    /// or `None` if there's no such rule.
    pub fn edit_rule(
        &mut self,
        id: RuleId,
        edit: RuleEdit,
        now_ms: i64,
        who: &str,
        change: &str,
    ) -> Result<Option<RuleRecord>> {
        let tx = self.conn.transaction()?;
        let Some(rule) = rule_in(&tx, id)? else {
            return Ok(None);
        };
        if let Some(action) = edit.action.filter(|a| *a != rule.action) {
            if let Some(other) = find(&tx, rule.app, rule.direction, action, rule.scope.kind())? {
                tx.execute("DELETE FROM rules WHERE id = ?1", [other.id])?;
                audit(&tx, now_ms, &other, "deleted", who)?;
            }
            // A decision for good: a temporary rule stops being one.
            tx.execute(
                "UPDATE rules SET action = ?2, expires = NULL, revert = NULL WHERE id = ?1",
                params![id, action_name(action)],
            )?;
        }
        if let Some(enabled) = edit.enabled {
            tx.execute(
                "UPDATE rules SET enabled = ?2 WHERE id = ?1",
                params![id, i64::from(enabled)],
            )?;
        }
        tx.execute(
            "UPDATE rules SET updated_ms = ?2 WHERE id = ?1",
            params![id, now_ms],
        )?;
        let rule = rule_in(&tx, id)?.ok_or(Error::QueryReturnedNoRows)?;
        audit(&tx, now_ms, &rule, change, who)?;
        tx.commit()?;
        Ok(Some(rule))
    }

    /// Removes a rule, audited as `change` by `who`. Returns it, or `None` if
    /// there was none.
    pub fn delete_rule(
        &mut self,
        id: RuleId,
        now_ms: i64,
        who: &str,
        change: &str,
    ) -> Result<Option<RuleRecord>> {
        let tx = self.conn.transaction()?;
        let rule = rule_in(&tx, id)?;
        if let Some(r) = &rule {
            tx.execute("DELETE FROM rules WHERE id = ?1", [id])?;
            audit(&tx, now_ms, r, change, who)?;
        }
        tx.commit()?;
        Ok(rule)
    }

    /// Ends a temporary rule, audited as "expired" by `who`: it goes back to
    /// the action it replaced, or is deleted. Returns it as it was, or `None`
    /// if there's no such rule.
    pub fn expire_rule(
        &mut self,
        id: RuleId,
        now_ms: i64,
        who: &str,
    ) -> Result<Option<RuleRecord>> {
        let tx = self.conn.transaction()?;
        let Some(rule) = rule_in(&tx, id)? else {
            return Ok(None);
        };
        match rule.revert {
            Some(action) => {
                if let Some(other) = find(&tx, rule.app, rule.direction, action, rule.scope.kind())?
                    && other.id != id
                {
                    tx.execute("DELETE FROM rules WHERE id = ?1", [other.id])?;
                    audit(&tx, now_ms, &other, "deleted", who)?;
                }
                tx.execute(
                    "UPDATE rules SET action = ?2, expires = NULL, revert = NULL, updated_ms = ?3
                     WHERE id = ?1",
                    params![id, action_name(action), now_ms],
                )?;
                let after = rule_in(&tx, id)?.ok_or(Error::QueryReturnedNoRows)?;
                audit(&tx, now_ms, &after, "expired", who)?;
            }
            None => {
                tx.execute("DELETE FROM rules WHERE id = ?1", [id])?;
                audit(&tx, now_ms, &rule, "expired", who)?;
            }
        }
        tx.commit()?;
        Ok(Some(rule))
    }

    /// Records that a rule had to be put back in Windows Firewall.
    pub fn audit_repair(&mut self, rule: &RuleRecord, now_ms: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        audit(&tx, now_ms, rule, "repaired", "win4tress")?;
        tx.commit()?;
        Ok(())
    }

    /// Newest first.
    pub fn rule_audit(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts_ms, rule_id, change, who, rule FROM rule_audit ORDER BY id DESC LIMIT ?1",
        )?;
        stmt.query_map([limit as i64], |r| {
            Ok(AuditEntry {
                ts_ms: r.get(0)?,
                rule_id: r.get(1)?,
                change: r.get(2)?,
                who: r.get(3)?,
                rule: r.get(4)?,
            })
        })?
        .collect()
    }
}
