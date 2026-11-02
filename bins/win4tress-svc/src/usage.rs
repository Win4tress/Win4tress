//! History & usage (SPEC §9.1, §10.2 Usage): whether the connection is
//! metered, when nobody used the PC (idle spans the app reports, and "While you
//! were away" on return), VPN clients left out of totals, and the data plan's
//! alerts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use w4_core::Bytes;
use w4_core::time::{now_unix_ms, plan_period};
use w4_ipc::api::{AlertBody, AppId, DataPlan, DnsSettings, PlanStatus, Settings};
use w4_monitor::Monitor;
use w4_store::{SaveContext, Store, local_day};

/// No input for this long counts as away (SPEC §8.4).
pub const IDLE_AFTER_MS: i64 = 10 * 60_000;
/// Away this long gets a "While you were away" summary on return (SPEC §11).
const AWAY_SUMMARY_MS: i64 = 30 * 60_000;
/// The summary names this many of the busiest apps.
const AWAY_APPS: usize = 3;
/// How often the connection's cost, the VPN exclusions and the data plan are checked.
const CHECK_EVERY: Duration = Duration::from_secs(60);
const DAY_MS: i64 = 24 * 3600 * 1000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct Usage {
    store: Arc<Mutex<Store>>,
    monitor: Arc<Mutex<Monitor>>,
    settings: Mutex<Settings>,
    metered: Mutex<Option<bool>>,
    /// The idle span being extended by the app's reports.
    idle: Mutex<Option<(i64, i64)>>,
}

impl Usage {
    pub fn new(store: Arc<Mutex<Store>>, monitor: Arc<Mutex<Monitor>>) -> Arc<Usage> {
        let settings = lock(&store).settings().unwrap_or_default();
        let usage = Arc::new(Usage {
            store,
            monitor,
            settings: Mutex::new(settings),
            metered: Mutex::new(None),
            idle: Mutex::new(None),
        });
        usage.apply_exclusions();
        usage
    }

    /// For each flush to history: local days, and whether to count it as metered.
    pub fn save_context(&self) -> SaveContext {
        SaveContext {
            utc_offset_min: w4_sys::time::utc_offset_minutes(),
            metered: lock(&self.metered).unwrap_or(false),
        }
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    pub fn set_settings(&self, settings: Settings, who: &str) -> Result<(), String> {
        if let Some(plan) = &settings.data_plan {
            if plan.limit_bytes == 0 {
                return Err("the data plan needs a limit".into());
            }
            if !(1..=28).contains(&plan.reset_day) {
                return Err("the reset day is 1 to 28".into());
            }
        }
        if settings
            .cleanup
            .inactive_days
            .is_some_and(|d| !(1..=3650).contains(&d))
        {
            return Err("inactive apps are cleaned up after 1 to 3650 days".into());
        }
        let r = &settings.reputation;
        if r.alert_at == 0 || r.block_at == 0 || r.alert_at > 100 || r.block_at > 100 {
            return Err("reputation thresholds are 1 to 100 engines".into());
        }
        lock(&self.store)
            .set_settings(&settings, now_unix_ms(), who)
            .map_err(|e| format!("saving settings: {e}"))?;
        *lock(&self.settings) = settings;
        self.apply_exclusions();
        Ok(())
    }

    /// DNS filtering's settings from a profile or a rules export, a pause kept
    /// as it is. Returns whether they changed.
    pub fn set_dns(&self, dns: DnsSettings, who: &str) -> Result<bool, String> {
        let mut settings = self.settings();
        if settings.dns.without_pause() == dns.without_pause() {
            return Ok(false);
        }
        settings.dns = DnsSettings {
            paused_until_ms: settings.dns.paused_until_ms,
            ..dns
        };
        self.set_settings(settings, who)?;
        Ok(true)
    }

    /// Apps left out of totals: the known VPN clients, if the user says so.
    pub fn excluded(&self) -> Vec<AppId> {
        if lock(&self.settings).exclude_vpn {
            lock(&self.monitor).vpn_apps()
        } else {
            Vec::new()
        }
    }

    fn apply_exclusions(&self) {
        let excluded = self.excluded();
        lock(&self.monitor).set_excluded(excluded);
    }

    /// From the app: the user's last input. Away for 10 minutes or more extends
    /// (or starts) an idle span; anything sooner ends it.
    pub fn report_input(&self, last_input_ms: i64, now_ms: i64) -> Result<(), String> {
        let last = last_input_ms.min(now_ms);
        let mut idle = lock(&self.idle);
        if now_ms - last < IDLE_AFTER_MS {
            if let Some((start, _)) = idle.take()
                && last - start >= AWAY_SUMMARY_MS
            {
                drop(idle);
                self.while_away(start, last, now_ms);
            }
            return Ok(());
        }
        // The same absence as last time keeps its start; a new one starts anew.
        let start = match *idle {
            Some((start, _)) if (start - last).abs() < 60_000 => start,
            _ => last,
        };
        *idle = Some((start, now_ms));
        lock(&self.store)
            .save_idle(start, now_ms)
            .map_err(|e| format!("saving idle time: {e}"))
    }

    /// Back after a while: what the network did meanwhile, if anything.
    fn while_away(&self, from_ms: i64, to_ms: i64, now_ms: i64) {
        let exclude = self.excluded();
        let (rows, alerts) = {
            let store = lock(&self.store);
            (
                store.usage_rows(from_ms / 1000, to_ms / 1000, &exclude, now_ms),
                store.alerts_between(from_ms, to_ms),
            )
        };
        let mut bytes = Bytes::default();
        let mut per_app: HashMap<AppId, u64> = HashMap::new();
        for r in rows.unwrap_or_default() {
            bytes.recv += r.bytes.recv;
            bytes.sent += r.bytes.sent;
            *per_app.entry(r.app).or_default() += r.bytes.recv + r.bytes.sent;
        }
        let alerts = alerts.unwrap_or(0);
        if bytes == Bytes::default() && alerts == 0 {
            return;
        }
        let mut busiest: Vec<_> = per_app.into_iter().collect();
        busiest.sort_by_key(|&(_, bytes)| std::cmp::Reverse(bytes));
        let mut monitor = lock(&self.monitor);
        let apps = busiest
            .iter()
            .take(AWAY_APPS)
            .map(|(id, _)| monitor.app_ref(*id).name)
            .collect();
        monitor.raise(
            now_ms,
            None,
            AlertBody::WhileAway {
                from_ms,
                to_ms,
                bytes,
                apps,
                alerts,
            },
        );
    }

    /// The data plan's current period and usage, if there's a plan.
    pub fn plan_status(&self, now_ms: i64) -> Option<PlanStatus> {
        let plan = lock(&self.settings).data_plan.clone()?;
        let offset = w4_sys::time::utc_offset_minutes();
        let (start, end) =
            plan_period(local_day(now_ms.div_euclid(60_000), offset), plan.reset_day);
        let used = lock(&self.store)
            .plan_usage(start, end - 1, plan.metered_only)
            .ok()?;
        let midnight = |day: i64| day * DAY_MS - i64::from(offset) * 60_000;
        Some(PlanStatus {
            percent: used.total() as f64 * 100.0 / plan.limit_bytes as f64,
            period_start_ms: midnight(start),
            period_end_ms: midnight(end),
            used,
            plan,
            metered: *lock(&self.metered),
        })
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let this = Arc::clone(&self);
            let _ = tokio::task::spawn_blocking(move || this.check(now_unix_ms())).await;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(CHECK_EVERY) => {}
            }
        }
    }

    fn check(&self, now_ms: i64) {
        let metered = w4_sys::net::metered();
        *lock(&self.metered) = metered;
        // VPN clients seen since.
        self.apply_exclusions();
        let Some(status) = self.plan_status(now_ms) else {
            return;
        };
        let offset = w4_sys::time::utc_offset_minutes();
        let start_day = local_day(status.period_start_ms.div_euclid(60_000), offset);
        let alerted = lock(&self.store).plan_alerted().ok().flatten();
        if let Some(percent) = plan_alert(&status.plan, status.used.total(), start_day, alerted) {
            tracing::info!(
                percent,
                used = status.used.total(),
                "data plan threshold passed"
            );
            let _ = lock(&self.store).set_plan_alerted(start_day, percent);
            lock(&self.monitor).raise(
                now_ms,
                None,
                AlertBody::DataPlan {
                    used: status.used.total(),
                    limit: status.plan.limit_bytes,
                    percent,
                    period_start_ms: status.period_start_ms,
                },
            );
        }
    }
}

/// The highest threshold `used` has passed this period that wasn't alerted yet.
pub fn plan_alert(
    plan: &DataPlan,
    used: u64,
    period_start_day: i64,
    alerted: Option<(i64, u8)>,
) -> Option<u8> {
    let passed = plan
        .warn_at
        .iter()
        .copied()
        .filter(|&p| u128::from(used) * 100 >= u128::from(p) * u128::from(plan.limit_bytes))
        .max()?;
    match alerted {
        Some((day, done)) if day == period_start_day && done >= passed => None,
        _ => Some(passed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> DataPlan {
        DataPlan {
            limit_bytes: 1_000,
            reset_day: 1,
            warn_at: vec![75, 90, 100],
            metered_only: false,
        }
    }

    #[test]
    fn idle_spans_from_input_reports() {
        const T0: i64 = 1_792_886_400_000;
        const MIN: i64 = 60_000;
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let monitor = Arc::new(Mutex::new(Monitor::new(
            Box::new(crate::resolver::Win32Resolver::new()),
            T0,
        )));
        let u = Usage::new(Arc::clone(&store), monitor);
        // In use: nothing to record.
        u.report_input(T0 - MIN, T0).unwrap();
        // Away since T0, reported at 20 and 21 minutes: one span, extended.
        u.report_input(T0, T0 + 20 * MIN).unwrap();
        u.report_input(T0, T0 + 21 * MIN).unwrap();
        // Back, then away again from 25 minutes.
        u.report_input(T0 + 21 * MIN + 30_000, T0 + 22 * MIN)
            .unwrap();
        u.report_input(T0 + 25 * MIN, T0 + 40 * MIN).unwrap();
        assert_eq!(
            lock(&store).idle(T0, T0 + 60 * MIN).unwrap(),
            [(T0, T0 + 21 * MIN), (T0 + 25 * MIN, T0 + 40 * MIN)]
        );
    }

    #[test]
    fn coming_back_after_half_an_hour_sums_up_the_absence() {
        const T0: i64 = 1_792_886_400_000;
        const MIN: i64 = 60_000;
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let monitor = Arc::new(Mutex::new(Monitor::new(
            Box::new(crate::resolver::Win32Resolver::new()),
            T0,
        )));
        let u = Usage::new(Arc::clone(&store), Arc::clone(&monitor));
        let alert = w4_monitor::PendingAlert {
            ts_ms: T0 + 5 * MIN,
            app: None,
            app_name: None,
            body: AlertBody::InternetAccessChanged { connected: false },
            severity: None,
        };
        lock(&store).insert_alerts(&[alert]).unwrap();
        // Away 20 minutes: no summary.
        u.report_input(T0, T0 + 20 * MIN).unwrap();
        u.report_input(T0 + 20 * MIN, T0 + 21 * MIN).unwrap();
        assert!(lock(&monitor).take_alerts().is_empty());
        // Away 40 minutes, with an alert meanwhile.
        u.report_input(T0, T0 + 30 * MIN).unwrap();
        u.report_input(T0 + 40 * MIN, T0 + 41 * MIN).unwrap();
        let raised = lock(&monitor).take_alerts();
        assert_eq!(raised.len(), 1);
        assert!(matches!(
            raised[0].body,
            AlertBody::WhileAway { from_ms: T0, to_ms, alerts: 1, .. } if to_ms == T0 + 40 * MIN
        ));
    }

    #[test]
    fn each_threshold_alerts_once_a_period() {
        let p = plan();
        assert_eq!(plan_alert(&p, 700, 10, None), None);
        assert_eq!(plan_alert(&p, 750, 10, None), Some(75));
        assert_eq!(plan_alert(&p, 800, 10, Some((10, 75))), None);
        // Jumping past two thresholds at once: the higher one.
        assert_eq!(plan_alert(&p, 1_200, 10, Some((10, 75))), Some(100));
        assert_eq!(plan_alert(&p, 1_300, 10, Some((10, 100))), None);
        // A new period starts over.
        assert_eq!(plan_alert(&p, 800, 41, Some((10, 100))), Some(75));
    }
}
