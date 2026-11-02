//! Time conversions. Everything internal uses Unix milliseconds.

use std::time::{SystemTime, UNIX_EPOCH};

/// 1970-01-01 in FILETIME units (100 ns ticks since 1601-01-01).
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

pub fn filetime_to_unix_ms(filetime: i64) -> i64 {
    (filetime - FILETIME_UNIX_EPOCH) / 10_000
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 as (year, month 1–12, day 1–31), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The inverse of [`civil_from_days`].
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The data plan period holding local day `today`: from the last `reset_day`
/// of a month (1–28) up to, not including, the next one. In local days.
pub fn plan_period(today: i64, reset_day: u8) -> (i64, i64) {
    let reset = u32::from(reset_day.clamp(1, 28));
    let (y, m, d) = civil_from_days(today);
    let (start_y, start_m) = if d >= reset {
        (y, m)
    } else if m == 1 {
        (y - 1, 12)
    } else {
        (y, m - 1)
    };
    let (end_y, end_m) = if start_m == 12 {
        (start_y + 1, 1)
    } else {
        (start_y, start_m + 1)
    };
    (
        days_from_civil(start_y, start_m, reset),
        days_from_civil(end_y, end_m, reset),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-10-25 is day 20,751; 2024-02-29 exists.
        assert_eq!(civil_from_days(20_751), (2026, 10, 25));
        assert_eq!(days_from_civil(2026, 10, 25), 20_751);
        let leap = days_from_civil(2024, 2, 29);
        assert_eq!(civil_from_days(leap), (2024, 2, 29));
        for day in -1_000..30_000 {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
        }
    }

    #[test]
    fn plan_periods_run_from_reset_day_to_reset_day() {
        let day = |y, m, d| days_from_civil(y, m, d);
        // Reset on the 15th: on the 25th, since the 15th of this month.
        assert_eq!(
            plan_period(day(2026, 10, 25), 15),
            (day(2026, 10, 15), day(2026, 11, 15))
        );
        // On the 3rd, since the 15th of last month; across a new year too.
        assert_eq!(
            plan_period(day(2026, 1, 3), 15),
            (day(2025, 12, 15), day(2026, 1, 15))
        );
        // The reset day itself starts a new period.
        assert_eq!(
            plan_period(day(2026, 3, 1), 1),
            (day(2026, 3, 1), day(2026, 4, 1))
        );
        // Days past 28 are clamped, so every month has one.
        assert_eq!(
            plan_period(day(2026, 2, 28), 31),
            (day(2026, 2, 28), day(2026, 3, 28))
        );
    }

    #[test]
    fn filetime_epoch_is_zero() {
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH), 0);
    }

    #[test]
    fn filetime_known_date() {
        // 2026-10-25T00:00:00Z
        let unix_ms = 1_792_886_400_000;
        assert_eq!(
            filetime_to_unix_ms(FILETIME_UNIX_EPOCH + unix_ms * 10_000),
            unix_ms
        );
    }
}
