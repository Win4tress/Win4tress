//! Automatic cleanup's bookkeeping (SPEC §7.10): apps with rules, since when
//! their program is gone, when they were last active, and removing their rules.

use rusqlite::params;
use w4_core::firewall::{Origin, RuleId};
use w4_ipc::api::AppId;

use crate::{Result, Store};

/// An app that has rules win4tress may clean up (baseline rules excluded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppWithRules {
    pub app: AppId,
    pub path: String,
    /// Its last traffic or blocked attempt.
    pub last_active_ms: i64,
    pub missing_since_ms: Option<i64>,
    pub rules: Vec<RuleId>,
}

impl Store {
    pub fn apps_with_rules(&self) -> Result<Vec<AppWithRules>> {
        let baseline = "baseline";
        let mut stmt = self.conn.prepare(
            "SELECT a.id, a.path, a.last_seen_ms, a.missing_since_ms,
                    (SELECT MAX(b.minute) * 60000 FROM blocks b WHERE b.app_id = a.id),
                    group_concat(r.id)
             FROM rules r JOIN apps a ON a.id = r.app_id
             WHERE r.origin != ?1
             GROUP BY a.id ORDER BY a.id",
        )?;
        let rows = stmt.query_map([baseline], |r| {
            let ids: String = r.get(5)?;
            let last_seen: i64 = r.get(2)?;
            let last_block: Option<i64> = r.get(4)?;
            Ok(AppWithRules {
                app: r.get(0)?,
                path: r.get(1)?,
                last_active_ms: last_block.map_or(last_seen, |b| b.max(last_seen)),
                missing_since_ms: r.get(3)?,
                rules: ids.split(',').filter_map(|i| i.parse().ok()).collect(),
            })
        })?;
        rows.collect()
    }

    /// When the app's program was first found missing; `None` when it's there.
    pub fn set_missing_since(&self, app: AppId, since_ms: Option<i64>) -> Result<()> {
        self.conn.execute(
            "UPDATE apps SET missing_since_ms = ?2 WHERE id = ?1",
            params![app, since_ms],
        )?;
        Ok(())
    }

    /// Removes the app's rules (not baseline ones), each audited as `change`,
    /// and its rules in profiles; the app counts as new if it comes back.
    /// Returns how many were removed.
    pub fn clean_up_app(&mut self, app: AppId, now_ms: i64, change: &str) -> Result<usize> {
        let ids: Vec<RuleId> = self
            .rules()?
            .into_iter()
            .filter(|r| r.app == app && r.origin != Origin::Baseline)
            .map(|r| r.id)
            .collect();
        let mut removed = 0;
        for id in ids {
            if self
                .delete_rule(id, now_ms, "automatic cleanup", change)?
                .is_some()
            {
                removed += 1;
            }
        }
        self.forget_app_in_profiles(app)?;
        self.conn.execute(
            "UPDATE apps SET net_first_seen_ms = NULL, missing_since_ms = NULL WHERE id = ?1",
            [app],
        )?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::{Action, Direction, Scope};
    use w4_monitor::AppRecord;

    use super::*;
    use crate::NewRule;

    fn app(id: AppId, path: &str, last_seen_ms: i64) -> AppRecord {
        AppRecord {
            id,
            key: path.to_lowercase(),
            path: path.into(),
            description: None,
            company: None,
            version: None,
            package: None,
            service: None,
            service_display: None,
            first_seen_ms: 0,
            last_seen_ms,
            net_first_seen_ms: Some(0),
            trust: Default::default(),
            own_dns_ms: None,
        }
    }

    fn rule(app: AppId, origin: Origin, direction: Direction) -> NewRule {
        NewRule {
            app,
            direction,
            action: Action::Block,
            scope: Scope::Any,
            origin,
            note: None,
            expires: None,
        }
    }

    #[test]
    fn apps_with_rules_and_their_cleanup() {
        let mut s = Store::open_in_memory().unwrap();
        s.save(
            &[app(1, r"C:\gone.exe", 1_000), app(2, r"C:\base.exe", 5_000)],
            &[],
            &[],
        )
        .unwrap();
        s.set_rule(&rule(1, Origin::User, Direction::Out), 1, "t")
            .unwrap();
        s.set_rule(&rule(1, Origin::Prompt, Direction::In), 1, "t")
            .unwrap();
        s.set_rule(&rule(2, Origin::Baseline, Direction::Out), 1, "t")
            .unwrap();
        let apps = s.apps_with_rules().unwrap();
        assert_eq!(apps.len(), 1, "baseline rules aren't cleanup's");
        assert_eq!(
            (apps[0].app, apps[0].rules.len(), apps[0].last_active_ms),
            (1, 2, 1_000)
        );

        s.set_missing_since(1, Some(7)).unwrap();
        assert_eq!(s.apps_with_rules().unwrap()[0].missing_since_ms, Some(7));
        assert_eq!(s.clean_up_app(1, 9, "removed: uninstalled").unwrap(), 2);
        assert!(s.apps_with_rules().unwrap().is_empty());
        let loaded = s.load_apps().unwrap();
        assert_eq!(
            loaded[0].net_first_seen_ms, None,
            "new again if it comes back"
        );
        assert!(
            s.rule_audit(10)
                .unwrap()
                .iter()
                .any(|a| a.change == "removed: uninstalled")
        );
    }
}
