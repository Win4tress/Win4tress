use w4_core::{Bytes, Country, TrafficType};
use w4_ipc::api::BreakdownFilter;
use w4_monitor::{DnsRecord, MinuteRow, UsageRow, build_breakdown};

use super::*;
use crate::{DNS_RETENTION_MS, Store};

/// 2026-10-25 00:00 UTC, in minutes.
const M0: i64 = 29_355_840;
const HOUR_MS: i64 = 3600 * 1000;

fn row(minute: i64, app: u32, ip: &str, country: &str, kind: TrafficType, recv: u64) -> MinuteRow {
    MinuteRow {
        minute,
        row: UsageRow {
            app,
            ip: ip.parse().unwrap(),
            name: None,
            country: Country {
                code: country.into(),
                name: country.into(),
            },
            traffic_type: kind,
            bytes: Bytes { recv, sent: 1 },
        },
    }
}

/// Two apps over three hours: app 1 to the internet (HTTPS), app 2 on the LAN (SMB).
fn store() -> Store {
    let mut s = Store::open_in_memory().unwrap();
    let mut rows = Vec::new();
    for m in 0..180 {
        rows.push(row(M0 + m, 1, "203.0.113.7", "US", TrafficType::Https, 100));
        rows.push(row(M0 + m, 2, "192.168.1.20", "LAN", TrafficType::Smb, 10));
    }
    s.save(&[], &rows, &[]).unwrap();
    s
}

fn total(series: &[(i64, Bytes)]) -> u64 {
    series.iter().map(|(_, b)| b.recv).sum()
}

const FROM: i64 = M0 * 60;
const TO: i64 = (M0 + 179) * 60 + 59;

#[test]
fn every_tier_holds_the_same_totals() {
    let s = store();
    let none = SeriesFilter::default();
    // Read as if now were just after, 3 days later (no hosts), and 3 days
    // later with a host filter: the minute, app-minute and hour tiers.
    let soon = (M0 + 180) * 60_000;
    let later = soon + 3 * 24 * HOUR_MS;
    assert_eq!(Tier::for_range(FROM, soon, &none), Tier::Minute);
    assert_eq!(Tier::for_range(FROM, later, &none), Tier::AppMinute);
    let internet = SeriesFilter {
        local: Some(false),
        ..Default::default()
    };
    assert_eq!(Tier::for_range(FROM, later, &internet), Tier::Hour);
    let (_, minute) = s.series(FROM, TO, 60, &none, &[], soon).unwrap();
    let (_, app_minute) = s.series(FROM, TO, 60, &none, &[], later).unwrap();
    let (step, hour) = s
        .series(FROM, TO, 60, &none, &[], later + 40 * 24 * HOUR_MS)
        .unwrap();
    assert_eq!(total(&minute), 180 * 110);
    assert_eq!(total(&app_minute), 180 * 110);
    assert_eq!(total(&hour), 180 * 110);
    assert_eq!(step, 3600, "the hour tier can't do finer steps");
    assert_eq!(hour.len(), 3);
}

#[test]
fn steps_and_filters() {
    let s = store();
    let now = (M0 + 180) * 60_000;
    let (step, hourly) = s
        .series(FROM, TO, 3600, &SeriesFilter::default(), &[], now)
        .unwrap();
    assert_eq!(step, 3600);
    assert_eq!(hourly.len(), 3);
    assert_eq!(
        hourly[0],
        (
            FROM,
            Bytes {
                recv: 60 * 110,
                sent: 120
            }
        )
    );
    let only = |f: SeriesFilter| total(&s.series(FROM, TO, 60, &f, &[], now).unwrap().1);
    assert_eq!(
        only(SeriesFilter {
            apps: Some(vec![2]),
            ..Default::default()
        }),
        180 * 10
    );
    assert_eq!(
        only(SeriesFilter {
            traffic_type: Some(TrafficType::Https),
            ..Default::default()
        }),
        180 * 100
    );
    assert_eq!(
        only(SeriesFilter {
            country: Some("US".into()),
            ..Default::default()
        }),
        180 * 100
    );
    assert_eq!(
        only(SeriesFilter {
            local: Some(true),
            ..Default::default()
        }),
        180 * 10
    );
    // VPN clients (or anything else) left out of the totals.
    assert_eq!(
        total(
            &s.series(FROM, TO, 60, &SeriesFilter::default(), &[1], now)
                .unwrap()
                .1
        ),
        180 * 10
    );
}

#[test]
fn whole_days_come_from_the_day_totals() {
    let s = store();
    let now = (M0 + 180) * 60_000;
    let day = |f: &SeriesFilter, exclude: &[u32]| {
        s.series(FROM, FROM + 86_399, 86_400, f, exclude, now)
            .unwrap()
    };
    let none = SeriesFilter::default();
    let (step, days) = day(&none, &[]);
    assert_eq!(step, 86_400);
    assert_eq!(
        days,
        [(
            FROM,
            Bytes {
                recv: 180 * 110,
                sent: 360
            }
        )]
    );
    assert_eq!(
        total(&day(&none, &[1]).1),
        180 * 10,
        "excluded apps taken off the total"
    );
    let https = SeriesFilter {
        traffic_type: Some(TrafficType::Https),
        ..Default::default()
    };
    assert_eq!(total(&day(&https, &[]).1), 180 * 100);
    // Needing two dimensions, or the local network: the hourly tier, same totals.
    let lan = SeriesFilter {
        local: Some(true),
        ..Default::default()
    };
    assert_eq!(total(&day(&lan, &[]).1), 180 * 10);
    assert_eq!(total(&day(&https, &[1]).1), 0);
}

#[test]
fn usage_totals_match_graph_totals() {
    let s = store();
    for now in [(M0 + 180) * 60_000, (M0 + 180) * 60_000 + 5 * 24 * HOUR_MS] {
        let rows = s.usage_rows(FROM, TO, &[], now).unwrap();
        let b = build_breakdown(
            rows,
            &BreakdownFilter::default(),
            10,
            |id| w4_ipc::api::AppRef {
                id,
                name: id.to_string(),
                path: String::new(),
            },
            |_| None,
        );
        let (_, series) = s
            .series(FROM, TO, 60, &SeriesFilter::default(), &[], now)
            .unwrap();
        assert_eq!(b.total.recv, total(&series));
        assert_eq!(b.local.recv, 180 * 10);
    }
    let rows = s.usage_rows(FROM, TO, &[2], (M0 + 180) * 60_000).unwrap();
    assert!(rows.iter().all(|r| r.app == 1));
}

#[test]
fn plan_usage_counts_internet_by_local_day() {
    let mut s = Store::open_in_memory().unwrap();
    // UTC+2: 23:00 UTC is already the next local day.
    s.set_save_context(SaveContext {
        utc_offset_min: 120,
        metered: false,
    });
    s.save(
        &[],
        &[row(
            M0 + 21 * 60 + 59,
            1,
            "203.0.113.7",
            "US",
            TrafficType::Https,
            5,
        )],
        &[],
    )
    .unwrap();
    s.set_save_context(SaveContext {
        utc_offset_min: 120,
        metered: true,
    });
    s.save(
        &[],
        &[
            row(M0 + 23 * 60, 1, "203.0.113.7", "US", TrafficType::Https, 7),
            // The local network isn't part of a data plan.
            row(
                M0 + 23 * 60,
                2,
                "192.168.1.20",
                "LAN",
                TrafficType::Smb,
                1000,
            ),
        ],
        &[],
    )
    .unwrap();
    let day = local_day(M0, 120);
    assert_eq!(s.plan_usage(day, day, false).unwrap().recv, 5);
    assert_eq!(s.plan_usage(day + 1, day + 1, false).unwrap().recv, 7);
    assert_eq!(s.plan_usage(day, day + 1, true).unwrap().recv, 7);
    let apps = s.usage_days(day, day + 1, "app").unwrap();
    assert_eq!(apps["2"].recv, 1000);
}

#[test]
fn idle_spans_extend_and_overlap() {
    let s = Store::open_in_memory().unwrap();
    s.save_idle(1_000, 5_000).unwrap();
    s.save_idle(1_000, 9_000).unwrap();
    s.save_idle(1_000, 7_000).unwrap();
    s.save_idle(20_000, 30_000).unwrap();
    assert_eq!(
        s.idle(8_000, 25_000).unwrap(),
        [(1_000, 9_000), (20_000, 30_000)]
    );
    assert_eq!(s.idle(10_000, 19_000).unwrap(), []);
}

#[test]
fn tiers_and_dns_are_pruned_and_rolled_up() {
    let mut s = store();
    let dns = DnsRecord {
        ts_ms: M0 * 60_000,
        app: 1,
        name: "example.com".into(),
        query_type: 1,
        status: 0,
        addrs: vec![],
    };
    s.save(&[], &[], &[dns.clone(), dns]).unwrap();
    let after = |ms: i64| (M0 + 180) * 60_000 + ms;
    let count = |table: &str| -> i64 {
        s.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    s.prune(after(DNS_RETENTION_MS)).unwrap();
    assert_eq!(count("traffic_min"), 0);
    assert_eq!(count("dns_queries"), 0);
    let (queries, failed): (i64, i64) = s
        .conn
        .query_row("SELECT queries, failed FROM dns_daily", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((queries, failed), (2, 0));
    assert!(count("traffic_app_min") > 0, "35 days");
    s.prune(after(APP_MINUTE_RETENTION_MS)).unwrap();
    assert_eq!(count("traffic_app_min"), 0);
    assert!(count("traffic_hour") > 0, "2 years");
    s.prune(after(HOUR_RETENTION_MS)).unwrap();
    assert_eq!(count("traffic_hour"), 0);
    // Day counts go a whole day at a time.
    s.prune(after(HOUR_RETENTION_MS + 24 * HOUR_MS)).unwrap();
    assert_eq!(count("dns_daily"), 0);
    assert!(count("usage_day") > 0, "kept indefinitely");
}

#[test]
fn upgrading_fills_the_tiers_from_the_minute_detail() {
    let dir = std::env::temp_dir().join(format!("w4-tiers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("history.db");
    {
        let mut s = Store::open(&path).unwrap();
        s.save(
            &[],
            &[row(M0, 1, "203.0.113.7", "US", TrafficType::Https, 42)],
            &[],
        )
        .unwrap();
        // Back to schema 8, as a build before the tiers left it.
        s.conn
            .execute_batch(
                "DROP TABLE traffic_app_min; DROP TABLE traffic_hour; DROP TABLE usage_day;
                 DROP TABLE dns_daily; DROP TABLE idle; DROP TABLE devices;
                 DROP TABLE profiles; DROP TABLE reputation;
                 ALTER TABLE apps DROP COLUMN missing_since_ms;
                 ALTER TABLE rules DROP COLUMN expires; ALTER TABLE rules DROP COLUMN revert;
                 PRAGMA user_version = 8;",
            )
            .unwrap();
    }
    let s = Store::open(&path).unwrap();
    let late = M0 * 60_000 + 10 * 24 * HOUR_MS;
    let (_, hour) = s
        .series(
            M0 * 60,
            M0 * 60 + 59,
            3600,
            &SeriesFilter::default(),
            &[],
            late,
        )
        .unwrap();
    assert_eq!(total(&hour), 42);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A year of busy use, written straight into the tiers as they'd stand after
/// retention: ~150 app × host pairs an hour, a browser's worth of hosts, and a
/// DNS log of 20,000 lookups a day. Checks the size budget (SPEC §9.1, 500 MB a
/// year) and that a month view reads in 500 ms (PLAN Phase 4 exit). Run it with
/// `cargo test -p w4-store --release synthetic_year -- --ignored --nocapture`.
#[test]
#[ignore = "builds a year of data; run on demand"]
fn synthetic_year_fits_the_budget() {
    use std::time::Instant;
    let dir = std::env::temp_dir().join(format!("w4-year-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("history.db");
    let mut s = Store::open(&path).unwrap();
    let now_min = M0;
    let hours = 365 * 24;
    let built = Instant::now();
    {
        let tx = s.conn.transaction().unwrap();
        {
            let mut host = tx
                .prepare(
                    "INSERT INTO hosts (ip, name, country, country_name) VALUES (?1, ?2, ?3, ?3)",
                )
                .unwrap();
            for h in 0..50_000i64 {
                let ip = format!("10.{}.{}.{}", h / 65536, (h / 256) % 256, h % 256);
                let country = ["US", "DE", "GB", "NL", "LAN"][(h % 5) as usize];
                host.execute(params![ip, format!("host{h}.example.com"), country])
                    .unwrap();
            }
            let mut hour = tx
                .prepare("INSERT OR IGNORE INTO traffic_hour VALUES (?1, ?2, ?3, 'https', ?4, ?5)")
                .unwrap();
            let base_hour = now_min / 60 - hours;
            for h in 0..hours {
                for p in 0..150i64 {
                    let app = p % 40;
                    let host = (h * 7 + p * 13) % 50_000;
                    hour.execute(params![base_hour + h, app, host, 50_000 + p, 5_000 + p])
                        .unwrap();
                }
            }
            let mut app_min = tx
                .prepare("INSERT OR IGNORE INTO traffic_app_min VALUES (?1, ?2, 'https', ?3, ?4)")
                .unwrap();
            for m in 0..35 * 1440 {
                for a in 0..12i64 {
                    app_min
                        .execute(params![now_min - 35 * 1440 + m, (m + a) % 40, 900 + a, 90])
                        .unwrap();
                }
            }
            let mut minute = tx
                .prepare("INSERT OR IGNORE INTO traffic_min VALUES (?1, ?2, ?3, 'https', ?4, ?5)")
                .unwrap();
            for m in 0..2 * 1440 {
                for p in 0..25i64 {
                    minute
                        .execute(params![
                            now_min - 2 * 1440 + m,
                            p % 40,
                            (m * 3 + p) % 50_000,
                            800,
                            80
                        ])
                        .unwrap();
                }
            }
            let mut day = tx
                .prepare("INSERT OR IGNORE INTO usage_day VALUES (?1, ?2, ?3, ?4, ?5)")
                .unwrap();
            let today = now_min / 1440;
            for d in 0..365 {
                for k in 0..40 {
                    day.execute(params![today - d, "app", k.to_string(), 1_000_000, 100_000])
                        .unwrap();
                }
                for k in 0..1_500 {
                    day.execute(params![
                        today - d,
                        "host",
                        ((d * 31 + k) % 50_000).to_string(),
                        10_000,
                        1_000
                    ])
                    .unwrap();
                }
                for (dim, n) in [("country", 30), ("type", 10)] {
                    for k in 0..n {
                        day.execute(params![today - d, dim, k.to_string(), 1, 1])
                            .unwrap();
                    }
                }
                for dim in ["total", "internet", "metered"] {
                    day.execute(params![today - d, dim, "", 1, 1]).unwrap();
                }
            }
            let mut dns = tx
                .prepare(
                    "INSERT INTO dns_queries VALUES (?1, ?2, ?3, 1, 0, '203.0.113.7 2001:db8::7')",
                )
                .unwrap();
            for q in 0..30 * 20_000i64 {
                dns.execute(params![
                    (now_min - 30 * 1440) * 60_000 + q * 4_320,
                    q % 40,
                    format!("n{}.example.com", q % 3_000)
                ])
                .unwrap();
            }
            let mut daily = tx
                .prepare("INSERT OR IGNORE INTO dns_daily VALUES (?1, ?2, ?3, 7, 0)")
                .unwrap();
            for d in 0..335 {
                for k in 0..3_000 {
                    daily
                        .execute(params![today - 30 - d, k % 40, format!("n{k}.example.com")])
                        .unwrap();
                }
            }
        }
        tx.commit().unwrap();
    }
    s.conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
        .unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    println!(
        "built in {:?}; {:.0} MB",
        built.elapsed(),
        size as f64 / 1e6
    );

    let now_ms = now_min * 60_000;
    let month_from = (now_min - 30 * 1440) * 60;
    let to = now_min * 60;
    let timed = |what: &str, f: &dyn Fn() -> usize| {
        let t = Instant::now();
        let n = f();
        let ms = t.elapsed().as_millis();
        println!("{what}: {n} rows in {ms} ms");
        ms
    };
    let none = SeriesFilter::default();
    let internet = SeriesFilter {
        local: Some(false),
        ..Default::default()
    };
    let month = timed("month graph (hour tier)", &|| {
        s.series(month_from, to, 3600, &internet, &[], now_ms)
            .unwrap()
            .1
            .len()
    });
    let month_usage = timed("month usage", &|| {
        s.usage_rows(month_from, to, &[], now_ms).unwrap().len()
    });
    timed("week graph (app-minute tier)", &|| {
        s.series(to - 7 * 86_400, to, 600, &none, &[], now_ms)
            .unwrap()
            .1
            .len()
    });
    timed("24 h graph (minute tier)", &|| {
        s.series(to - 86_400, to, 60, &none, &[], now_ms)
            .unwrap()
            .1
            .len()
    });
    timed("year graph", &|| {
        s.series(to - 365 * 86_400, to, 86_400, &none, &[], now_ms)
            .unwrap()
            .1
            .len()
    });
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(size <= 500_000_000, "a year is {size} bytes");
    assert!(month <= 500 && month_usage <= 500, "month view too slow");
}
