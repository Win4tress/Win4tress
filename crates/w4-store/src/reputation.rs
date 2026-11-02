//! Reputation answers per file hash and source (SPEC §12), and secrets (API
//! keys, already encrypted by the caller) kept out of the audit trail.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};
use w4_ipc::api::{RepVerdict, Reputation};

use crate::{Result, Store};

fn verdict_name(v: RepVerdict) -> &'static str {
    match v {
        RepVerdict::Unknown => "unknown",
        RepVerdict::KnownGood => "known_good",
        RepVerdict::Clean => "clean",
        RepVerdict::Suspicious => "suspicious",
        RepVerdict::Malicious => "malicious",
    }
}

fn verdict(name: &str) -> RepVerdict {
    match name {
        "known_good" => RepVerdict::KnownGood,
        "clean" => RepVerdict::Clean,
        "suspicious" => RepVerdict::Suspicious,
        "malicious" => RepVerdict::Malicious,
        _ => RepVerdict::Unknown,
    }
}

const COLUMNS: &str = "sha256, source, verdict, detections, engines, detail, link, checked_ms";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Reputation> {
    Ok(Reputation {
        sha256: r.get(0)?,
        source: r.get(1)?,
        verdict: verdict(&r.get::<_, String>(2)?),
        detections: r.get(3)?,
        engines: r.get(4)?,
        detail: r.get(5)?,
        link: r.get(6)?,
        checked_ms: r.get(7)?,
    })
}

fn secret_key(name: &str) -> String {
    format!("secret:{name}")
}

impl Store {
    /// Records a source's answer for a file, replacing its earlier one.
    pub fn save_reputation(&self, r: &Reputation) -> Result<()> {
        self.conn.execute(
            &format!(
                "INSERT INTO reputation ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(sha256, source) DO UPDATE SET
                    verdict = excluded.verdict, detections = excluded.detections,
                    engines = excluded.engines, detail = excluded.detail,
                    link = excluded.link, checked_ms = excluded.checked_ms"
            ),
            params![
                r.sha256.to_ascii_lowercase(),
                r.source,
                verdict_name(r.verdict),
                r.detections,
                r.engines,
                r.detail,
                r.link,
                r.checked_ms
            ],
        )?;
        Ok(())
    }

    /// Every source's answer for a file.
    pub fn reputation(&self, sha256: &str) -> Result<Vec<Reputation>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {COLUMNS} FROM reputation WHERE sha256 = ?1"
        ))?;
        let rows = stmt.query_map([sha256.to_ascii_lowercase()], row)?;
        rows.collect()
    }

    /// All answers, by hash.
    pub fn reputations(&self) -> Result<HashMap<String, Vec<Reputation>>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM reputation"))?;
        let mut out: HashMap<String, Vec<Reputation>> = HashMap::new();
        for r in stmt.query_map([], row)? {
            let r = r?;
            out.entry(r.sha256.clone()).or_default().push(r);
        }
        Ok(out)
    }

    /// A secret as stored (encrypted by the caller).
    pub fn secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let hex: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [secret_key(name)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(hex.and_then(|h| from_hex(&h)))
    }

    /// Stores (or with `None` removes) a secret. The audit trail notes that it
    /// changed, never its value.
    pub fn set_secret(
        &mut self,
        name: &str,
        value: Option<&[u8]>,
        now_ms: i64,
        who: &str,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        match value {
            Some(v) => tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![secret_key(name), to_hex(v)],
            )?,
            None => tx.execute("DELETE FROM meta WHERE key = ?1", [secret_key(name)])?,
        };
        let change = if value.is_some() {
            "key set"
        } else {
            "key removed"
        };
        tx.execute(
            "INSERT INTO rule_audit (ts_ms, rule_id, change, who, rule) VALUES (?1, NULL, ?2, ?3, ?4)",
            params![now_ms, change, who, format!("{{\"key\":\"{name}\"}}")],
        )?;
        tx.commit()
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(source: &str, verdict: RepVerdict, at: i64) -> Reputation {
        Reputation {
            sha256: "AB".repeat(32),
            source: source.into(),
            verdict,
            detections: Some(0),
            engines: Some(70),
            detail: None,
            link: None,
            checked_ms: at,
        }
    }

    #[test]
    fn answers_replace_per_source() {
        let s = Store::open_in_memory().unwrap();
        s.save_reputation(&answer("VirusTotal", RepVerdict::Unknown, 1))
            .unwrap();
        s.save_reputation(&answer("VirusTotal", RepVerdict::Clean, 2))
            .unwrap();
        s.save_reputation(&answer("CIRCL hashlookup", RepVerdict::KnownGood, 3))
            .unwrap();
        let all = s.reputation(&"ab".repeat(32)).unwrap();
        assert_eq!(all.len(), 2);
        let vt = all.iter().find(|r| r.source == "VirusTotal").unwrap();
        assert_eq!((vt.verdict, vt.checked_ms), (RepVerdict::Clean, 2));
        assert_eq!(s.reputations().unwrap().len(), 1);
    }

    #[test]
    fn secrets_round_trip_and_stay_out_of_the_audit() {
        let mut s = Store::open_in_memory().unwrap();
        s.set_secret("virustotal", Some(&[0, 1, 0xfe, 0xff]), 1, "t")
            .unwrap();
        assert_eq!(
            s.secret("virustotal").unwrap(),
            Some(vec![0, 1, 0xfe, 0xff])
        );
        let audit = s.rule_audit(10).unwrap();
        assert!(audit.iter().all(|a| !a.rule.contains("01feff")));
        s.set_secret("virustotal", None, 2, "t").unwrap();
        assert_eq!(s.secret("virustotal").unwrap(), None);
    }
}
