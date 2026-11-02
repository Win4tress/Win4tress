//! Usage by app, host, traffic type, country and publisher. Shared by the live
//! buckets and the history database, so both give identical results.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use w4_core::{Bytes, Country, Locality, TrafficType, locality};
use w4_ipc::api::{
    AppId, AppRef, AppUsage, Breakdown, BreakdownFilter, CountryUsage, HostTotal, PublisherUsage,
    TypeUsage,
};

/// Bytes between one app and one remote address over some range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageRow {
    pub app: AppId,
    pub ip: IpAddr,
    pub name: Option<String>,
    pub country: Country,
    pub traffic_type: TrafficType,
    pub bytes: Bytes,
}

fn keeps(
    filter: &BreakdownFilter,
    row: &UsageRow,
    publisher: &dyn Fn(AppId) -> Option<String>,
) -> bool {
    filter.app.is_none_or(|a| a == row.app)
        && filter.host.is_none_or(|h| h == row.ip)
        && filter.traffic_type.is_none_or(|t| t == row.traffic_type)
        && filter
            .country
            .as_deref()
            .is_none_or(|c| c == row.country.code)
        && filter
            .local
            .is_none_or(|local| local == (locality(row.ip) == Locality::Local))
        && filter
            .publisher
            .as_deref()
            .is_none_or(|p| publisher(row.app).as_deref() == Some(p))
}

#[derive(Default)]
struct HostAgg {
    bytes: Bytes,
    by_app: HashMap<AppId, Bytes>,
    names: HashMap<AppId, String>,
    country: Option<Country>,
}

/// Groups rows into the breakdown columns, keeping rows that match `filter`.
/// At most `limit` rows in the app and host columns. `publisher` is an app's
/// company, if known.
pub fn build_breakdown(
    rows: impl IntoIterator<Item = UsageRow>,
    filter: &BreakdownFilter,
    limit: usize,
    app_ref: impl Fn(AppId) -> AppRef,
    publisher: impl Fn(AppId) -> Option<String>,
) -> Breakdown {
    let mut out = Breakdown::default();
    let mut apps: HashMap<AppId, Bytes> = HashMap::new();
    let mut hosts: HashMap<IpAddr, HostAgg> = HashMap::new();
    let mut types: HashMap<TrafficType, Bytes> = HashMap::new();
    let mut countries: HashMap<String, (Country, Bytes)> = HashMap::new();

    for row in rows.into_iter().filter(|r| keeps(filter, r, &publisher)) {
        let bytes = row.bytes;
        out.total += bytes;
        if locality(row.ip) == Locality::Local {
            out.local += bytes;
        } else {
            out.internet += bytes;
        }
        *apps.entry(row.app).or_default() += bytes;
        *types.entry(row.traffic_type).or_default() += bytes;
        countries
            .entry(row.country.code.clone())
            .or_insert_with(|| (row.country.clone(), Bytes::default()))
            .1 += bytes;

        let host = hosts.entry(row.ip).or_default();
        host.bytes += bytes;
        *host.by_app.entry(row.app).or_default() += bytes;
        if let Some(name) = row.name {
            host.names.insert(row.app, name);
        }
        host.country.get_or_insert(row.country);
    }

    let busiest = |b: &Bytes| std::cmp::Reverse(b.total());

    let mut apps: Vec<_> = apps.into_iter().collect();
    apps.sort_by_key(|(_, b)| busiest(b));
    // Publishers from every app, before the limit cuts the list.
    let mut publishers: HashMap<String, (Bytes, HashSet<AppId>)> = HashMap::new();
    for (id, bytes) in &apps {
        if let Some(name) = publisher(*id) {
            let p = publishers.entry(name).or_default();
            p.0 += *bytes;
            p.1.insert(*id);
        }
    }
    let mut publishers: Vec<_> = publishers.into_iter().collect();
    publishers.sort_by_key(|(_, (b, _))| busiest(b));
    out.publishers = publishers
        .into_iter()
        .take(limit)
        .map(|(name, (bytes, apps))| PublisherUsage {
            name,
            bytes,
            apps: apps.len(),
        })
        .collect();

    out.apps_more = apps.len().saturating_sub(limit);
    out.apps = apps
        .into_iter()
        .take(limit)
        .map(|(id, bytes)| AppUsage {
            app: app_ref(id),
            bytes,
        })
        .collect();

    let mut hosts: Vec<_> = hosts.into_iter().collect();
    hosts.sort_by_key(|(_, h)| busiest(&h.bytes));
    out.hosts_more = hosts.len().saturating_sub(limit);
    out.hosts = hosts
        .into_iter()
        .take(limit)
        .map(|(ip, mut h)| {
            let top = h
                .by_app
                .iter()
                .max_by_key(|(_, b)| b.total())
                .map_or(0, |(id, _)| *id);
            // Prefer the name the busiest app looked up; else any app's.
            let name = h
                .names
                .remove(&top)
                .or_else(|| h.names.into_values().next());
            HostTotal {
                ip,
                name,
                country: h.country.unwrap_or_else(Country::unknown),
                bytes: h.bytes,
                top_app: app_ref(top),
                app_count: h.by_app.len(),
            }
        })
        .collect();

    let mut types: Vec<_> = types.into_iter().collect();
    types.sort_by_key(|(_, b)| busiest(b));
    out.traffic_types = types
        .into_iter()
        .map(|(traffic_type, bytes)| TypeUsage {
            traffic_type,
            bytes,
        })
        .collect();

    let mut countries: Vec<_> = countries.into_values().collect();
    countries.sort_by_key(|(_, b)| busiest(b));
    out.countries = countries
        .into_iter()
        .map(|(country, bytes)| CountryUsage { country, bytes })
        .collect();
    out
}
