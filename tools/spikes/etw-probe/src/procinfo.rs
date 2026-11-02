//! Process naming and our own memory usage.

use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Best-effort executable name for a running process. Falls back to `pid N`
/// when the process has already exited or can't be opened.
pub fn image_name(pid: u32) -> String {
    match pid {
        0 => return "Idle".into(),
        4 => return "System".into(),
        _ => {}
    }
    query_image_path(pid)
        .map(|path| basename(&path).to_string())
        .unwrap_or_else(|| format!("pid {pid}"))
}

fn query_image_path(pid: u32) -> Option<String> {
    // SAFETY: plain Win32 call; the returned handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` outlives the call and `len` holds its capacity in characters.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    // SAFETY: `handle` came from OpenProcess and is closed exactly once.
    let _ = unsafe { CloseHandle(handle) };
    result.ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Last path component of either a Win32 path (`C:\...\curl.exe`) or an NT
/// device path (`\Device\HarddiskVolume3\...\curl.exe`).
pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Working set of this process, in bytes.
pub fn own_working_set() -> u64 {
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: `counters` is a correctly sized, writable PROCESS_MEMORY_COUNTERS.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.WorkingSetSize as u64
    } else {
        0
    }
}

/// Total CPU time (kernel + user) this process has used.
pub fn own_cpu_time() -> Duration {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all four out-pointers refer to live FILETIMEs.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    if ok.is_err() {
        return Duration::ZERO;
    }
    let ticks = |ft: FILETIME| (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    // FILETIME counts 100 ns ticks.
    Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
}
