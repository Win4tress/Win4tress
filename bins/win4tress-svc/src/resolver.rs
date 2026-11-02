//! Win32 implementation of the monitor's lookups: process images, services,
//! this PC's addresses, countries and network owners.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use w4_core::trust::PathClass;
use w4_core::{Country, NetworkOwner};
use w4_geo::{AsnDb, GeoDb};
use w4_monitor::ServiceInfo;
use w4_sys::paths::DevicePaths;

/// Drive mappings change when drives are added; reload at most this often on a miss.
const PATHS_RELOAD: Duration = Duration::from_secs(30);
/// Services start and stop; re-list them at most this often when a PID is missing.
const SERVICES_RELOAD: Duration = Duration::from_secs(5);
/// Addresses change with networks and VPNs.
const ADDRESSES_RELOAD: Duration = Duration::from_secs(30);

struct Timed<T> {
    value: T,
    loaded: Instant,
}

impl<T> Timed<T> {
    fn new(value: T) -> Self {
        Timed {
            value,
            loaded: Instant::now(),
        }
    }
}

pub struct Win32Resolver {
    paths: Mutex<Timed<DevicePaths>>,
    services: Mutex<Timed<HashMap<u32, Vec<w4_sys::services::Service>>>>,
    addresses: Mutex<Timed<HashSet<IpAddr>>>,
    geo: Option<GeoDb>,
    asn: Option<AsnDb>,
}

impl Win32Resolver {
    pub fn new() -> Self {
        Win32Resolver {
            paths: Mutex::new(Timed::new(DevicePaths::load())),
            services: Mutex::new(Timed::new(w4_sys::services::by_pid())),
            addresses: Mutex::new(Timed::new(w4_sys::net::own_addresses())),
            geo: open_db(w4_geo::FILE_NAME, "country", GeoDb::open),
            asn: open_db(w4_geo::ASN_FILE_NAME, "network owner", AsnDb::open),
        }
    }
}

/// Opens one of the DB-IP databases; `what` names it in the log.
fn open_db<T>(
    file_name: &str,
    what: &str,
    open: impl FnOnce(&std::path::Path) -> Result<T, w4_geo::MaxMindDbError>,
) -> Option<T> {
    let Some(path) = w4_geo::find(file_name) else {
        tracing::warn!(
            "no {file_name} found; {what} will show as unknown (run tools/dev/fetch-geo.ps1)"
        );
        return None;
    };
    match open(&path) {
        Ok(db) => {
            tracing::info!(path = %path.display(), "{what} database loaded ({})", w4_geo::ATTRIBUTION);
            Some(db)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), "{what} database unreadable: {e}");
            None
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl w4_monitor::Resolver for Win32Resolver {
    fn image_path(&self, pid: u32) -> Option<String> {
        w4_sys::process::image_path(pid)
    }

    fn to_win32(&self, nt_path: &str) -> String {
        let mut paths = lock(&self.paths);
        let converted = paths.value.to_win32(nt_path);
        if converted == nt_path && paths.loaded.elapsed() > PATHS_RELOAD {
            *paths = Timed::new(DevicePaths::load());
            return paths.value.to_win32(nt_path);
        }
        converted
    }

    fn country(&self, ip: IpAddr) -> Option<Country> {
        self.geo.as_ref()?.country(ip)
    }

    fn network_owner(&self, ip: IpAddr) -> Option<NetworkOwner> {
        self.asn.as_ref()?.owner(ip)
    }

    fn services(&self, pid: u32) -> Option<Vec<ServiceInfo>> {
        let mut services = lock(&self.services);
        if !services.value.contains_key(&pid) && services.loaded.elapsed() > SERVICES_RELOAD {
            *services = Timed::new(w4_sys::services::by_pid());
        }
        services.value.get(&pid).map(|list| {
            list.iter()
                .map(|s| ServiceInfo {
                    name: s.name.clone(),
                    display_name: s.display_name.clone(),
                })
                .collect()
        })
    }

    fn is_own_address(&self, ip: IpAddr) -> bool {
        let mut addresses = lock(&self.addresses);
        if addresses.loaded.elapsed() > ADDRESSES_RELOAD {
            *addresses = Timed::new(w4_sys::net::own_addresses());
        }
        addresses.value.contains(&ip)
    }

    fn path_class(&self, path: &str) -> Option<PathClass> {
        path.contains('\\').then(|| w4_sys::trust::path_class(path))
    }
}
