//! Devices on the local network (SPEC §10.2 Network), and the security
//! monitors' memory (what they've seen, so a restart doesn't re-learn it).

use std::net::IpAddr;

use rusqlite::{OptionalExtension, params};
use w4_ipc::api::Device;

use crate::{Result, Store};

pub(crate) const SCHEMA_V10: &str = "
CREATE TABLE devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    name TEXT,
    vendor TEXT,
    randomized INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    known INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
";

fn monitor_key(name: &str) -> String {
    format!("monitor:{name}")
}

impl Store {
    /// Every device seen, most recently seen first.
    pub fn devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT mac, ip, name, vendor, randomized, first_seen_ms, last_seen_ms, known
             FROM devices ORDER BY last_seen_ms DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, bool>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mac, ip, name, vendor, randomized, first_seen_ms, last_seen_ms, known) = row?;
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            out.push(Device {
                mac,
                ip,
                name,
                vendor,
                randomized,
                first_seen_ms,
                last_seen_ms,
                known,
            });
        }
        Ok(out)
    }

    /// Records a device seen now: new ones are added; known ones get their
    /// address, name and last-seen time updated. Returns whether it's new.
    pub fn saw_device(&self, d: &Device) -> Result<bool> {
        let existed: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM devices WHERE mac = ?1", [&d.mac], |r| {
                r.get(0)
            })
            .optional()?;
        self.conn.execute(
            "INSERT INTO devices (mac, ip, name, vendor, randomized, first_seen_ms, last_seen_ms, known)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                name = COALESCE(excluded.name, devices.name),
                vendor = COALESCE(excluded.vendor, devices.vendor),
                last_seen_ms = MAX(devices.last_seen_ms, excluded.last_seen_ms)",
            params![
                d.mac,
                d.ip.to_string(),
                d.name,
                d.vendor,
                d.randomized,
                d.first_seen_ms,
                d.last_seen_ms,
                d.known
            ],
        )?;
        Ok(existed.is_none())
    }

    /// Returns whether there was such a device.
    pub fn set_device_known(&self, mac: &str, known: bool) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE devices SET known = ?2 WHERE mac = ?1",
            params![mac, known],
        )? > 0)
    }

    /// A monitor's memory, as JSON it wrote.
    pub fn monitor_state(&self, name: &str) -> Result<Option<String>> {
        self.meta(&monitor_key(name))
    }

    /// Not audited: it's the monitors' own bookkeeping.
    pub fn set_monitor_state(&self, name: &str, json: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![monitor_key(name), json],
        )?;
        Ok(())
    }

    /// Alerts raised in [from_ms, to_ms].
    pub fn alerts_between(&self, from_ms: i64, to_ms: i64) -> Result<u32> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE ts_ms BETWEEN ?1 AND ?2",
            [from_ms, to_ms],
            |r| r.get(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(mac: &str, ip: &str, seen: i64) -> Device {
        Device {
            mac: mac.into(),
            ip: ip.parse().unwrap(),
            name: None,
            vendor: Some("Acme".into()),
            randomized: false,
            first_seen_ms: seen,
            last_seen_ms: seen,
            known: false,
        }
    }

    #[test]
    fn devices_are_added_updated_and_marked_known() {
        let s = Store::open_in_memory().unwrap();
        assert!(
            s.saw_device(&device("aa-aa-aa-aa-aa-01", "192.168.1.20", 1_000))
                .unwrap()
        );
        let mut moved = device("aa-aa-aa-aa-aa-01", "192.168.1.21", 2_000);
        moved.name = Some("printer.lan".into());
        assert!(!s.saw_device(&moved).unwrap(), "not new");
        assert!(s.set_device_known("aa-aa-aa-aa-aa-01", true).unwrap());
        assert!(!s.set_device_known("ff-ff-ff-ff-ff-ff", true).unwrap());
        let all = s.devices().unwrap();
        assert_eq!(all.len(), 1);
        let d = &all[0];
        assert_eq!(
            (d.ip.to_string().as_str(), d.first_seen_ms, d.last_seen_ms),
            ("192.168.1.21", 1_000, 2_000)
        );
        assert_eq!(d.name.as_deref(), Some("printer.lan"));
        assert!(d.known);
    }

    #[test]
    fn monitor_memory_round_trips() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.monitor_state("arp").unwrap(), None);
        s.set_monitor_state("arp", "{\"a\":1}").unwrap();
        s.set_monitor_state("arp", "{\"a\":2}").unwrap();
        assert_eq!(
            s.monitor_state("arp").unwrap().as_deref(),
            Some("{\"a\":2}")
        );
    }
}
