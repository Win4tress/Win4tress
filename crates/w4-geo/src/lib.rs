//! Country and network-owner lookup with DB-IP's IP-to-Country Lite and
//! IP-to-ASN Lite databases (SPEC §8.3). Licensed CC BY 4.0: show
//! [`ATTRIBUTION`] wherever results appear.
//! Fetch them for development with `tools/dev/fetch-geo.ps1`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub use maxminddb::MaxMindDbError;
use maxminddb::{Reader, geoip2};
use w4_core::{Country, NetworkOwner};

pub const FILE_NAME: &str = "dbip-country-lite.mmdb";
pub const ASN_FILE_NAME: &str = "dbip-asn-lite.mmdb";
pub const ATTRIBUTION: &str = "IP geolocation by DB-IP.com";

pub struct GeoDb {
    reader: Reader<Vec<u8>>,
}

impl GeoDb {
    pub fn open(path: &Path) -> Result<Self, maxminddb::MaxMindDbError> {
        Ok(GeoDb {
            reader: Reader::open_readfile(path)?,
        })
    }

    /// `None` when the database has no entry (private ranges, unallocated space).
    pub fn country(&self, ip: IpAddr) -> Option<Country> {
        let found = self.reader.lookup(ip).ok()?;
        let record = found.decode::<geoip2::Country>().ok()??;
        let code = record.country.iso_code?;
        Some(Country {
            code: code.to_string(),
            name: record.country.names.english.unwrap_or(code).to_string(),
        })
    }
}

pub struct AsnDb {
    reader: Reader<Vec<u8>>,
}

impl AsnDb {
    pub fn open(path: &Path) -> Result<Self, maxminddb::MaxMindDbError> {
        Ok(AsnDb {
            reader: Reader::open_readfile(path)?,
        })
    }

    /// `None` when the database has no entry (private ranges, unallocated space).
    pub fn owner(&self, ip: IpAddr) -> Option<NetworkOwner> {
        let found = self.reader.lookup(ip).ok()?;
        let record = found.decode::<geoip2::Asn>().ok()??;
        Some(NetworkOwner {
            asn: record.autonomous_system_number?,
            name: record.autonomous_system_organization?.to_string(),
        })
    }
}

/// Where a database file is looked for, in order:
/// 1. `WIN4TRESS_GEO_DIR` (a folder holding the files)
/// 2. next to the executable
/// 3. `%ProgramData%\win4tress`
/// 4. `data\geo` in a repository checkout above the executable (development)
pub fn find(file_name: &str) -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("WIN4TRESS_GEO_DIR") {
        return Some(PathBuf::from(dir).join(file_name));
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(5) {
            candidates.push(dir.join(file_name));
            candidates.push(dir.join("data").join("geo").join(file_name));
        }
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        candidates.insert(
            1,
            PathBuf::from(program_data)
                .join("win4tress")
                .join(file_name),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses the downloaded databases when present; skipped otherwise (e.g. in CI).
    fn path(file_name: &str) -> Option<PathBuf> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/geo")
            .join(file_name);
        path.is_file().then_some(path)
    }

    fn db() -> Option<GeoDb> {
        path(FILE_NAME).map(|p| GeoDb::open(&p).expect("database opens"))
    }

    fn asn_db() -> Option<AsnDb> {
        path(ASN_FILE_NAME).map(|p| AsnDb::open(&p).expect("database opens"))
    }

    #[test]
    fn public_address_has_a_country() {
        let Some(db) = db() else { return };
        let us = db
            .country("8.8.8.8".parse().unwrap())
            .expect("8.8.8.8 is listed");
        assert_eq!(us.code.len(), 2);
        assert!(!us.name.is_empty());
    }

    #[test]
    fn private_address_has_none() {
        let Some(db) = db() else { return };
        assert_eq!(db.country("192.168.1.1".parse().unwrap()), None);
    }

    #[test]
    fn public_address_has_an_owner() {
        let Some(db) = asn_db() else { return };
        let google = db
            .owner("8.8.8.8".parse().unwrap())
            .expect("8.8.8.8 is listed");
        assert_eq!(google.asn, 15169);
        assert!(!google.name.is_empty());
        assert_eq!(db.owner("192.168.1.1".parse().unwrap()), None);
    }
}
