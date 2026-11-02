//! Firewall profiles (SPEC §7.6): named snapshots of the mode, of the rules
//! that are on (each in full) and of DNS filtering's settings, switched by hand
//! or by the network the PC is on. A profile is exact: switching to it puts
//! its rules back as they were saved and turns every other rule off.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use w4_core::firewall::{Action, Direction, Mode, Origin, RuleId, RuleRecord, Scope};
use w4_ipc::api::{DnsSettings, NetworkMatch, Profile};

use crate::{Error, NewRule, Result, RuleEdit, Store};

const ACTIVE_KEY: &str = "active_profile";

fn to_json(v: &serde_json::Value) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))
}

fn json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))
}

/// A rule a profile has on, in full, so switching can put it back after it
/// was deleted, turned off or changed between allow and block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRule {
    pub app: u32,
    pub direction: Direction,
    pub action: Action,
    pub scope: Scope,
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// An app has one rule per direction and kind of scope (SPEC §7.2).
type Key = (u32, Direction, &'static str);

fn key(r: &RuleRecord) -> Key {
    (r.app, r.direction, r.scope.kind())
}

/// win4tress's own allows for Windows' programs (Ask to Connect's baseline)
/// and blocks for a file's reputation: the same in every profile, never
/// switched, and where one is, a profile's rule isn't put back.
fn left_alone(origin: Origin) -> bool {
    matches!(origin, Origin::Baseline | Origin::Reputation)
}

impl ProfileRule {
    fn key(&self) -> Key {
        (self.app, self.direction, self.scope.kind())
    }

    /// The rule as it is for good: a temporary rule as what it goes back to,
    /// or `None` if it goes away (or is one profiles leave alone).
    fn lasting(r: &RuleRecord) -> Option<ProfileRule> {
        if left_alone(r.origin) {
            return None;
        }
        let action = match (&r.expires, r.revert) {
            (None, _) => r.action,
            (Some(_), Some(back)) => back,
            (Some(_), None) => return None,
        };
        Some(ProfileRule {
            app: r.app,
            direction: r.direction,
            action,
            scope: r.scope.clone(),
            origin: r.origin,
            note: r.note.clone(),
        })
    }

    /// The rule as a profile holds it, if it's on.
    pub fn of(r: &RuleRecord) -> Option<ProfileRule> {
        r.enabled.then(|| Self::lasting(r)).flatten()
    }

    fn rule(&self) -> NewRule {
        NewRule {
            app: self.app,
            direction: self.direction,
            action: self.action,
            scope: self.scope.clone(),
            origin: self.origin,
            note: self.note.clone(),
            expires: None,
        }
    }
}

/// What's compared, per app, direction and kind of scope: the action and the
/// scope, where no rule profiles leave alone is.
fn compared<'a>(
    rules: &'a [ProfileRule],
    skip: &BTreeSet<Key>,
) -> BTreeMap<Key, (Action, &'a Scope)> {
    rules
        .iter()
        .filter(|r| !skip.contains(&r.key()))
        .map(|r| (r.key(), (r.action, &r.scope)))
        .collect()
}

/// A profile as saved: what's shown of it, and what switching puts back.
#[derive(Clone, Debug)]
pub struct SavedProfile {
    pub profile: Profile,
    /// The rules it has on; every other rule is off while it's active.
    pub rules: Vec<ProfileRule>,
    /// DNS filtering's settings, without a pause; `None` for a profile saved
    /// before profiles held them.
    pub dns: Option<DnsSettings>,
}

fn profile(
    name: String,
    mode: &str,
    rules: &str,
    saved_ms: i64,
    networks: &str,
    dns: Option<&str>,
) -> SavedProfile {
    let rules: Vec<ProfileRule> = serde_json::from_str(rules).unwrap_or_default();
    let dns: Option<DnsSettings> = dns.and_then(|d| serde_json::from_str(d).ok());
    SavedProfile {
        profile: Profile {
            name,
            mode: Mode::parse(mode).unwrap_or_default(),
            rules: rules.len() as u32,
            enabled: rules.len() as u32,
            saved_ms,
            networks: serde_json::from_str(networks).unwrap_or_default(),
            dns_filtering: dns.as_ref().map(|d| d.enabled),
        },
        rules,
        dns,
    }
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<SavedProfile> {
    Ok(profile(
        r.get(0)?,
        &r.get::<_, String>(1)?,
        &r.get::<_, String>(2)?,
        r.get(3)?,
        &r.get::<_, String>(4)?,
        r.get::<_, Option<String>>(5)?.as_deref(),
    ))
}

const COLUMNS: &str = "name, mode, rules, saved_ms, networks, dns";

impl Store {
    /// By name.
    pub fn profiles(&self) -> Result<Vec<Profile>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM profiles ORDER BY name COLLATE NOCASE"
        ))?;
        let rows = stmt.query_map([], |r| row(r).map(|p| p.profile))?;
        rows.collect()
    }

    /// A profile and what it puts back; names match regardless of case.
    pub fn profile(&self, name: &str) -> Result<Option<SavedProfile>> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM profiles WHERE name = ?1 COLLATE NOCASE"),
                [name],
                row,
            )
            .optional()
    }

    /// The mode, the rules on now and DNS filtering's settings, under `name`
    /// (replacing a profile of that name, whose networks it keeps). It becomes
    /// the active profile.
    pub fn save_profile(&mut self, name: &str, now_ms: i64, who: &str) -> Result<Profile> {
        let mode = self.firewall_mode()?;
        let on: Vec<ProfileRule> = self.rules()?.iter().filter_map(ProfileRule::of).collect();
        let dns = self.settings()?.dns.without_pause();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO profiles (name, mode, rules, saved_ms, dns) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET name = excluded.name, mode = excluded.mode,
                 rules = excluded.rules, saved_ms = excluded.saved_ms, dns = excluded.dns",
            params![name, mode.as_str(), json(&on)?, now_ms, json(&dns)?],
        )?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![ACTIVE_KEY, name],
        )?;
        tx.execute(
            "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule)
             VALUES (?1, NULL, 'profile saved', ?2, ?3)",
            params![now_ms, who, to_json(&serde_json::json!({ "profile": name, "mode": mode.as_str(), "rules": on.len(), "dns_filtering": dns.enabled }))?],
        )?;
        tx.commit()?;
        Ok(self
            .profile(name)?
            .ok_or(Error::QueryReturnedNoRows)?
            .profile)
    }

    /// The networks a profile is switched to on; returns whether there's such
    /// a profile.
    pub fn set_profile_networks(
        &mut self,
        name: &str,
        networks: &[NetworkMatch],
        now_ms: i64,
        who: &str,
    ) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE profiles SET networks = ?2 WHERE name = ?1 COLLATE NOCASE",
            params![name, json(&networks)?],
        )? > 0;
        if changed {
            tx.execute(
                "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule)
                 VALUES (?1, NULL, 'profile networks', ?2, ?3)",
                params![
                    now_ms,
                    who,
                    to_json(&serde_json::json!({ "profile": name, "networks": networks }))?
                ],
            )?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// A profile from another PC (rules export, SPEC §7.2): replaces one of the
    /// same name, not made active.
    pub fn import_profile(
        &mut self,
        p: &Profile,
        rules: &[ProfileRule],
        dns: Option<&DnsSettings>,
        now_ms: i64,
        who: &str,
    ) -> Result<()> {
        let dns = dns.map(|d| json(&d.without_pause())).transpose()?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO profiles (name, mode, rules, saved_ms, networks, dns) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET name = excluded.name, mode = excluded.mode,
                 rules = excluded.rules, saved_ms = excluded.saved_ms, networks = excluded.networks,
                 dns = excluded.dns",
            params![p.name, p.mode.as_str(), json(&rules)?, now_ms, json(&p.networks)?, dns],
        )?;
        tx.execute(
            "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule)
             VALUES (?1, NULL, 'profile imported', ?2, ?3)",
            params![
                now_ms,
                who,
                to_json(&serde_json::json!({ "profile": p.name, "mode": p.mode.as_str(), "rules": rules.len() }))?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Returns whether there was such a profile.
    pub fn delete_profile(&mut self, name: &str, now_ms: i64, who: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM profiles WHERE name = ?1 COLLATE NOCASE",
            [name],
        )? > 0;
        if deleted {
            tx.execute(
                "DELETE FROM meta WHERE key = ?1 AND value = ?2 COLLATE NOCASE",
                params![ACTIVE_KEY, name],
            )?;
            tx.execute(
                "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule)
                 VALUES (?1, NULL, 'profile deleted', ?2, ?3)",
                params![
                    now_ms,
                    who,
                    to_json(&serde_json::json!({ "profile": name }))?
                ],
            )?;
        }
        tx.commit()?;
        Ok(deleted)
    }

    pub fn active_profile(&self) -> Result<Option<String>> {
        self.meta(ACTIVE_KEY)
    }

    /// Makes the rules match the profile and makes it the active profile: each
    /// of its rules on as saved (made again if it was deleted, set back if its
    /// action or scope changed), every other rule off. Temporary rules run out
    /// as they would, and rules profiles leave alone stay. The mode and DNS
    /// filtering are the caller's to set, with their checks. Returns the
    /// profile's mode and how many rules changed, or `None` for no such profile.
    pub fn apply_profile(
        &mut self,
        name: &str,
        now_ms: i64,
        who: &str,
    ) -> Result<Option<(Mode, usize)>> {
        let Some(SavedProfile {
            profile: p,
            rules: wanted,
            ..
        }) = self.profile(name)?
        else {
            return Ok(None);
        };
        let who = format!("{who} (profile {})", p.name);
        let switch = |on: bool| RuleEdit {
            enabled: Some(on),
            action: None,
        };
        let mut placed: BTreeSet<Key> = BTreeSet::new();
        let mut changed = 0;
        for r in self.rules()? {
            if r.expires.is_some() || left_alone(r.origin) {
                placed.insert(key(&r));
                continue;
            }
            match wanted.iter().find(|w| w.key() == key(&r)) {
                Some(w) => {
                    placed.insert(key(&r));
                    if r.action != w.action || r.scope != w.scope {
                        self.set_rule(&w.rule(), now_ms, &who)?;
                        changed += 1;
                    } else if !r.enabled {
                        self.edit_rule(r.id, switch(true), now_ms, &who, "updated")?;
                        changed += 1;
                    }
                }
                None if r.enabled => {
                    self.edit_rule(r.id, switch(false), now_ms, &who, "updated")?;
                    changed += 1;
                }
                None => {}
            }
        }
        // Deleted since it was saved: made again.
        for w in &wanted {
            if placed.insert(w.key()) {
                self.set_rule(&w.rule(), now_ms, &who)?;
                changed += 1;
            }
        }
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![ACTIVE_KEY, p.name],
        )?;
        Ok(Some((p.mode, changed)))
    }

    /// Whether the mode, the rules on (a temporary rule as what it goes back
    /// to) or DNS filtering (a pause aside) differ from the profile.
    pub fn profile_changed(&self, name: &str) -> Result<bool> {
        let Some(SavedProfile {
            profile: p,
            rules: wanted,
            dns,
        }) = self.profile(name)?
        else {
            return Ok(false);
        };
        if self.firewall_mode()? != p.mode {
            return Ok(true);
        }
        if let Some(dns) = dns
            && dns != self.settings()?.dns.without_pause()
        {
            return Ok(true);
        }
        let rules = self.rules()?;
        let skip: BTreeSet<Key> = rules
            .iter()
            .filter(|r| left_alone(r.origin))
            .map(key)
            .collect();
        let on: Vec<ProfileRule> = rules.iter().filter_map(ProfileRule::of).collect();
        Ok(compared(&on, &skip) != compared(&wanted, &skip))
    }

    /// The app's rules out of every profile: its rules were cleaned up, so no
    /// profile makes them again.
    pub(crate) fn forget_app_in_profiles(&mut self, app: u32) -> Result<()> {
        let rows: Vec<(String, String)> = {
            let mut stmt = self.conn.prepare("SELECT name, rules FROM profiles")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (name, rules) in rows {
            let mut rules: Vec<ProfileRule> = serde_json::from_str(&rules).unwrap_or_default();
            let before = rules.len();
            rules.retain(|r| r.app != app);
            if rules.len() != before {
                self.conn.execute(
                    "UPDATE profiles SET rules = ?2 WHERE name = ?1",
                    params![name, json(&rules)?],
                )?;
            }
        }
        Ok(())
    }

    /// Profiles from before they were exact held each rule's id and whether it
    /// was on: each now holds the rules it had on, as they are now (rules
    /// deleted since are gone).
    pub(crate) fn convert_profile_rules(&mut self) -> Result<()> {
        let rules: BTreeMap<RuleId, RuleRecord> =
            self.rules()?.into_iter().map(|r| (r.id, r)).collect();
        let rows: Vec<(String, String)> = {
            let mut stmt = self.conn.prepare("SELECT name, rules FROM profiles")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let tx = self.conn.transaction()?;
        for (name, old) in rows {
            let Ok(states) = serde_json::from_str::<BTreeMap<RuleId, bool>>(&old) else {
                continue;
            };
            let on: Vec<ProfileRule> = states
                .iter()
                .filter(|(_, on)| **on)
                .filter_map(|(id, _)| ProfileRule::lasting(rules.get(id)?))
                .collect();
            tx.execute(
                "UPDATE profiles SET rules = ?2 WHERE name = ?1",
                params![name, json(&on)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use w4_core::firewall::Expiry;

    use super::*;

    fn rule(app: u32, action: Action, origin: Origin) -> NewRule {
        NewRule {
            app,
            direction: Direction::Out,
            action,
            scope: Scope::Any,
            origin,
            note: None,
            expires: None,
        }
    }

    fn block(app: u32) -> NewRule {
        rule(app, Action::Block, Origin::User)
    }

    /// Each app's outgoing rule that's on: (app, action).
    fn on(s: &Store) -> Vec<(u32, Action)> {
        let mut on: Vec<_> = s
            .rules()
            .unwrap()
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| (r.app, r.action))
            .collect();
        on.sort();
        on
    }

    #[test]
    fn a_profile_puts_every_rule_back_as_saved() {
        let mut s = Store::open_in_memory().unwrap();
        s.set_rule(&block(1), 1, "t").unwrap();
        let b = s.set_rule(&block(2), 1, "t").unwrap();
        s.set_firewall_mode(Mode::AskToConnect, 2, "t").unwrap();
        let home = s.save_profile("Home", 3, "t").unwrap();
        assert_eq!(home.rules, 2);
        assert_eq!(s.active_profile().unwrap().as_deref(), Some("Home"));
        assert!(!s.profile_changed("Home").unwrap());

        // As the Apps tab does it: app 2 unblocked (its rule deleted), app 3
        // blocked, app 1 switched to allowed (a new rule in its block's
        // place). Each is a change.
        s.delete_rule(b.id, 4, "t", "deleted").unwrap();
        assert!(s.profile_changed("Home").unwrap());
        s.save_profile("Home", 4, "t").unwrap();
        s.set_rule(&block(3), 5, "t").unwrap();
        assert!(s.profile_changed("Home").unwrap());
        s.save_profile("Home", 5, "t").unwrap();
        s.set_rule(&rule(1, Action::Allow, Origin::User), 6, "t")
            .unwrap();
        assert!(s.profile_changed("Home").unwrap());
        s.set_firewall_mode(Mode::ClickToBlock, 7, "t").unwrap();
        s.save_profile("Travel", 7, "t").unwrap();
        assert_eq!(on(&s), [(1, Action::Allow), (3, Action::Block)]);

        // Home's blocks back as saved, app 1's allow gone in their place.
        s.delete_rule(
            s.rules().unwrap().iter().find(|r| r.app == 3).unwrap().id,
            8,
            "t",
            "deleted",
        )
        .unwrap();
        let (mode, changed) = s.apply_profile("home", 9, "t").unwrap().unwrap();
        assert_eq!(mode, Mode::AskToConnect);
        assert_eq!(changed, 2, "app 1 set back to block, app 3 made again");
        assert_eq!(on(&s), [(1, Action::Block), (3, Action::Block)]);
        assert_eq!(s.active_profile().unwrap().as_deref(), Some("Home"));
        // The mode isn't the store's to switch: still Click to Block, so changed.
        assert!(s.profile_changed("Home").unwrap());
        s.set_firewall_mode(Mode::AskToConnect, 9, "t").unwrap();
        assert!(!s.profile_changed("Home").unwrap());

        // A rule Travel doesn't have is turned off, not deleted.
        s.set_rule(&block(4), 10, "t").unwrap();
        s.apply_profile("Travel", 11, "t").unwrap();
        assert_eq!(on(&s), [(1, Action::Allow), (3, Action::Block)]);
        assert!(s.rules().unwrap().iter().any(|r| r.app == 4 && !r.enabled));
        s.set_firewall_mode(Mode::ClickToBlock, 11, "t").unwrap();
        assert!(!s.profile_changed("Travel").unwrap());

        // Networks stay with the profile when it's saved again.
        let public = vec![NetworkMatch::Category {
            category: w4_core::firewall::NetworkCategory::Public,
        }];
        assert!(s.set_profile_networks("travel", &public, 12, "t").unwrap());
        assert!(!s.set_profile_networks("Nowhere", &public, 12, "t").unwrap());
        let again = s.save_profile("Travel", 12, "t").unwrap();
        assert_eq!(again.networks, public);

        assert!(s.delete_profile("TRAVEL", 13, "t").unwrap());
        assert_eq!(s.active_profile().unwrap(), None);
        assert_eq!(s.profiles().unwrap().len(), 1);
        assert!(s.apply_profile("Travel", 14, "t").unwrap().is_none());
    }

    #[test]
    fn profiles_leave_baseline_reputation_and_temporary_rules_alone() {
        let mut s = Store::open_in_memory().unwrap();
        s.set_rule(&block(1), 1, "t").unwrap();
        s.save_profile("Home", 2, "t").unwrap();

        // Ask to Connect's allow for a Windows program and a reputation block:
        // not a change, and switching leaves them on.
        s.set_rule(&rule(5, Action::Allow, Origin::Baseline), 3, "t")
            .unwrap();
        s.set_rule(&rule(6, Action::Block, Origin::Reputation), 3, "t")
            .unwrap();
        assert!(!s.profile_changed("Home").unwrap());
        // App 1 allowed for an hour: what it goes back to is what counts.
        let mut hour = rule(1, Action::Allow, Origin::User);
        hour.expires = Some(Expiry::At { ms: 3_600_000 });
        s.set_rule(&hour, 4, "t").unwrap();
        assert!(!s.profile_changed("Home").unwrap());
        let (_, changed) = s.apply_profile("Home", 5, "t").unwrap().unwrap();
        assert_eq!(changed, 0);
        assert_eq!(
            on(&s),
            [(1, Action::Allow), (5, Action::Allow), (6, Action::Block)]
        );

        // Saved again, it doesn't hold them; app 1 as what it goes back to.
        s.save_profile("Home", 6, "t").unwrap();
        let held: Vec<_> = s
            .profile("Home")
            .unwrap()
            .unwrap()
            .rules
            .iter()
            .map(|r| (r.app, r.action))
            .collect();
        assert_eq!(held, [(1, Action::Block)]);

        // Cleaned up: an uninstalled app's rules leave every profile too.
        s.clean_up_app(1, 6, "cleaned up").unwrap();
        assert!(s.profile("Home").unwrap().unwrap().rules.is_empty());
    }

    #[test]
    fn profiles_from_before_hold_the_rules_they_had_on() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for m in &crate::MIGRATIONS[..13] {
            conn.execute_batch(m).unwrap();
        }
        conn.pragma_update(None, "user_version", 13).unwrap();
        let insert = |id: i64, app: u32, action: &str, enabled: bool| {
            conn.execute(
                "INSERT INTO rules (id, app_id, direction, action, scope_kind, scope, enabled, origin,
                                    created_ms, updated_ms)
                 VALUES (?1, ?2, 'out', ?3, 'any', '{\"kind\":\"any\"}', ?4, 'user', 1, 1)",
                params![id, app, action, enabled],
            )
            .unwrap();
        };
        insert(1, 1, "block", true);
        insert(2, 2, "allow", false);
        insert(3, 3, "block", true);
        // On in it: rule 1, rule 2 (off now: another profile's), and rule 9,
        // deleted since. Rule 3 was off in it.
        conn.execute(
            "INSERT INTO profiles (name, mode, rules, saved_ms, networks)
             VALUES ('Home', 'click_to_block', '{\"1\":true,\"2\":true,\"3\":false,\"9\":true}', 1, '[]')",
            [],
        )
        .unwrap();

        let s = Store::init(conn).unwrap();
        let home = s.profile("Home").unwrap().unwrap();
        let held: Vec<_> = home.rules.iter().map(|r| (r.app, r.action)).collect();
        assert_eq!(held, [(1, Action::Block), (2, Action::Allow)]);
        assert_eq!(home.profile.rules, 2);
    }

    #[test]
    fn profiles_hold_dns_filtering_but_not_a_pause() {
        let mut s = Store::open_in_memory().unwrap();
        let mut settings = s.settings().unwrap();
        settings.dns.enabled = true;
        settings.dns.allow = vec!["example.com".into()];
        s.set_settings(&settings, 1, "t").unwrap();
        let home = s.save_profile("Home", 2, "t").unwrap();
        assert_eq!(home.dns_filtering, Some(true));
        assert!(!s.profile_changed("Home").unwrap());

        // A pause isn't a change, nor saved.
        settings.dns.paused_until_ms = Some(10_000);
        s.set_settings(&settings, 3, "t").unwrap();
        assert!(!s.profile_changed("Home").unwrap());
        s.save_profile("Home", 4, "t").unwrap();
        let saved = s.profile("Home").unwrap().unwrap().dns.unwrap();
        assert_eq!(saved.paused_until_ms, None);
        assert_eq!(saved.allow, ["example.com"]);

        // Any other DNS filtering setting is a change.
        settings.dns.deny = vec!["ads.example".into()];
        s.set_settings(&settings, 5, "t").unwrap();
        assert!(s.profile_changed("Home").unwrap());
        s.save_profile("Home", 6, "t").unwrap();
        assert!(!s.profile_changed("Home").unwrap());

        // A profile without DNS filtering (saved before profiles held it, or
        // from an older export) isn't changed by it.
        let old = Profile {
            name: "Old".into(),
            mode: s.firewall_mode().unwrap(),
            rules: 0,
            enabled: 0,
            saved_ms: 0,
            networks: Vec::new(),
            dns_filtering: None,
        };
        s.import_profile(&old, &[], None, 7, "t").unwrap();
        s.apply_profile("Old", 8, "t").unwrap();
        settings.dns.enabled = false;
        s.set_settings(&settings, 9, "t").unwrap();
        assert!(!s.profile_changed("Old").unwrap());
        assert_eq!(
            s.profile("Old").unwrap().unwrap().profile.dns_filtering,
            None
        );
    }
}
