//! Local time: the offset from UTC, for local days (SPEC §9.1 usage tier);
//! and when Windows started, for rules that last until a restart (SPEC §7.2).

use windows::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemTimeOfDayInformation,
};
use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

/// SYSTEM_TIMEOFDAY_INFORMATION (winternl.h): times in 100 ns since 1601.
#[repr(C)]
#[derive(Default)]
struct TimeOfDay {
    boot_time: i64,
    current_time: i64,
    time_zone_bias: i64,
    time_zone_id: u32,
    reserved: u32,
    boot_time_bias: u64,
    sleep_time_bias: u64,
}

/// 100 ns intervals from 1601 to 1970.
const EPOCH_DIFFERENCE: i64 = 116_444_736_000_000_000;

/// When Windows started (Unix ms), as Task Manager's "Up time" counts: a
/// restart starts a new boot, and so does a shutdown without fast startup;
/// sleep and fast startup don't. Kept in step when the clock is set.
pub fn boot_ms() -> Option<i64> {
    let mut info = TimeOfDay::default();
    let mut len = 0u32;
    // SAFETY: `info` is a writable buffer of the size passed.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemTimeOfDayInformation,
            (&mut info as *mut TimeOfDay).cast(),
            size_of::<TimeOfDay>() as u32,
            &mut len,
        )
    };
    (status.is_ok() && info.boot_time > EPOCH_DIFFERENCE)
        .then(|| (info.boot_time - EPOCH_DIFFERENCE) / 10_000)
}

/// GetTimeZoneInformation's answer while daylight saving time is in effect.
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

/// Minutes east of UTC right now, daylight saving included (UTC+2 is 120).
pub fn utc_offset_minutes() -> i32 {
    let mut tz = TIME_ZONE_INFORMATION::default();
    // SAFETY: `tz` is a valid out-pointer for the call.
    let id = unsafe { GetTimeZoneInformation(&mut tz) };
    // Bias is in minutes, local + bias = UTC.
    let extra = if id == TIME_ZONE_ID_DAYLIGHT {
        tz.DaylightBias
    } else {
        tz.StandardBias
    };
    -(tz.Bias + extra)
}

#[cfg(test)]
mod tests {
    #[test]
    fn offset_is_a_real_time_zone() {
        let offset = super::utc_offset_minutes();
        assert!((-12 * 60..=14 * 60).contains(&offset), "{offset}");
    }

    #[test]
    fn windows_started_in_the_past_and_stays_put() {
        let boot = super::boot_ms().expect("boot time");
        let now = w4_core::time::now_unix_ms();
        // After 2020, before now.
        assert!(boot > 1_577_836_800_000 && boot < now, "{boot} vs {now}");
        assert_eq!(super::boot_ms(), Some(boot));
    }
}
