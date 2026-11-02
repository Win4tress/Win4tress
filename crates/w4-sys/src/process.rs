//! Process queries, and starting a helper as LocalService.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED,
    ERROR_PRIVILEGE_NOT_HELD, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    GetTokenInformation, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcesses, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSClientProtocolType, WTSFreeMemory, WTSQuerySessionInformationW,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR, w};

/// Whether a process runs in a Remote Desktop session: Block All would cut it
/// off (SPEC §7.5).
pub fn in_remote_session(pid: u32) -> bool {
    let mut session = 0u32;
    // SAFETY: `session` is a valid out pointer.
    if unsafe { ProcessIdToSessionId(pid, &mut session) }.is_err() {
        return false;
    }
    let mut buf = PWSTR::null();
    let mut len = 0u32;
    // SAFETY: Windows allocates `buf`; it's read as the documented USHORT and freed.
    unsafe {
        if WTSQuerySessionInformationW(None, session, WTSClientProtocolType, &mut buf, &mut len)
            .is_err()
            || buf.is_null()
        {
            return false;
        }
        let protocol = if len as usize >= size_of::<u16>() {
            *buf.0.cast::<u16>()
        } else {
            0
        };
        WTSFreeMemory(buf.0.cast());
        // WTS_PROTOCOL_TYPE_RDP
        protocol == 2
    }
}

/// Win32 path of a running process's executable, e.g. `C:\Windows\System32\curl.exe`.
pub fn image_path(pid: u32) -> Option<String> {
    // SAFETY: plain Win32 call; the handle is closed below.
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
    close(handle);
    result.ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// IDs of the running processes.
pub fn all() -> Vec<u32> {
    let mut pids = vec![0u32; 4096];
    loop {
        let mut used = 0u32;
        let bytes = (pids.len() * size_of::<u32>()) as u32;
        // SAFETY: `pids` is writable for `bytes` bytes; `used` receives what was written.
        if unsafe { EnumProcesses(pids.as_mut_ptr(), bytes, &mut used) }.is_err() {
            return Vec::new();
        }
        if used < bytes {
            pids.truncate(used as usize / size_of::<u32>());
            return pids;
        }
        pids.resize(pids.len() * 2, 0);
    }
}

/// The executables running now, lower-cased; the ones this process can't
/// look into (protected processes) are missing.
pub fn running_paths() -> std::collections::HashSet<String> {
    all()
        .into_iter()
        .filter_map(image_path)
        .map(|p| p.to_lowercase())
        .collect()
}

/// Ends every process running `path` (compared without case), other than
/// this one; returns how many were ended.
pub fn kill_all(path: &std::path::Path) -> usize {
    let me = std::process::id();
    let wanted = path.to_string_lossy();
    let mut ended = 0;
    for pid in all() {
        if pid == me || !image_path(pid).is_some_and(|p| p.eq_ignore_ascii_case(&wanted)) {
            continue;
        }
        // SAFETY: plain Win32 call; the handle is closed below.
        if let Ok(handle) = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
            // SAFETY: `handle` was just opened with PROCESS_TERMINATE.
            if unsafe { TerminateProcess(handle, 1) }.is_ok() {
                ended += 1;
            }
            close(handle);
        }
    }
    ended
}

/// Whether the current process runs with an elevated (admin) token.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size passed.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    close(token);
    result.is_ok() && elevation.TokenIsElevated != 0
}

/// This process's working set (bytes) and total CPU time (ms).
pub fn own_usage() -> (u64, u64) {
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing.
    let me = unsafe { GetCurrentProcess() };
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: `counters` is a correctly sized, writable PROCESS_MEMORY_COUNTERS.
    let working_set = match unsafe { GetProcessMemoryInfo(me, &mut counters, counters.cb) } {
        Ok(()) => counters.WorkingSetSize as u64,
        Err(_) => 0,
    };
    let [mut created, mut exited, mut kernel, mut user] = [FILETIME::default(); 4];
    // SAFETY: all four out-pointers refer to live FILETIMEs.
    let cpu_ms = match unsafe {
        GetProcessTimes(me, &mut created, &mut exited, &mut kernel, &mut user)
    } {
        Ok(()) => {
            let ticks =
                |ft: FILETIME| (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
            (ticks(kernel) + ticks(user)) / 10_000 // 100 ns ticks -> ms
        }
        Err(_) => 0,
    };
    (working_set, cpu_ms)
}

/// A process started by [`spawn_as_local_service`].
pub struct Spawned {
    handle: HANDLE,
    pid: u32,
}

// SAFETY: a process handle can be waited on and terminated from any thread.
unsafe impl Send for Spawned {}
// SAFETY: as above; no method needs exclusive access to the handle.
unsafe impl Sync for Spawned {}

impl Spawned {
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Its exit code once it has ended.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        // SAFETY: `handle` is this process's, open until drop.
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: as above; `code` is a valid out pointer.
                unsafe { GetExitCodeProcess(self.handle, &mut code) }.map_err(io::Error::other)?;
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Ends it and waits until it has.
    pub fn kill(&self) {
        // SAFETY: as above. Failing because it already ended is fine.
        unsafe {
            let _ = TerminateProcess(self.handle, 1);
            WaitForSingleObject(self.handle, INFINITE);
        }
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        close(self.handle);
    }
}

/// Starts `exe` as LocalService, without a window, with output and errors
/// going to `log` (the only handle it inherits). Only SYSTEM can: it logs
/// the account on and assigns its token; see [`not_system`].
pub fn spawn_as_local_service(
    exe: &Path,
    args: &[&OsStr],
    log: &std::fs::File,
) -> io::Result<Spawned> {
    let mut token = HANDLE::default();
    // SAFETY: constant strings; `token` is closed below. Service accounts have no password.
    unsafe {
        LogonUserW(
            w!("LocalService"),
            w!("NT AUTHORITY"),
            PCWSTR::null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    }
    .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?;
    let result = spawn_with_token(token, exe, args, log);
    close(token);
    result
}

/// Whether an error from [`spawn_as_local_service`] means the caller isn't
/// SYSTEM (denied outright, or missing the privilege when elevated).
pub fn not_system(e: &io::Error) -> bool {
    [ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD]
        .iter()
        .any(|c| e.raw_os_error() == Some(c.0 as i32))
}

fn spawn_with_token(
    token: HANDLE,
    exe: &Path,
    args: &[&OsStr],
    log: &std::fs::File,
) -> io::Result<Spawned> {
    // SAFETY: the pseudo-handle needs no closing.
    let me = unsafe { GetCurrentProcess() };
    let mut out = HANDLE::default();
    // An inheritable copy of the log's handle; closed below.
    // SAFETY: `log` is open for the call.
    unsafe {
        DuplicateHandle(
            me,
            HANDLE(log.as_raw_handle()),
            me,
            &mut out,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(io::Error::other)?;

    // Only that handle is inherited, not whatever else happens to be inheritable.
    let mut size = 0usize;
    // SAFETY: a size query; it fails by design and fills `size`.
    let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
    let mut buffer = vec![0u8; size];
    let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
    let handles = [out];
    let mut command = command_line(exe, args);
    let result = (|| {
        // SAFETY: `buffer` has the size asked for and outlives the list.
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
            .map_err(io::Error::other)?;
        // SAFETY: `handles` outlives the process creation below.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                size_of_val(&handles),
                None,
                None,
            )
        };
        let created = updated.and_then(|()| {
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdOutput = out;
            startup.StartupInfo.hStdError = out;
            startup.lpAttributeList = list;
            let mut info = PROCESS_INFORMATION::default();
            // SAFETY: every pointer refers to a live local; `command` is NUL-terminated and writable.
            unsafe {
                CreateProcessAsUserW(
                    Some(token),
                    PCWSTR::null(),
                    Some(PWSTR(command.as_mut_ptr())),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    None,
                    PCWSTR::null(),
                    &startup.StartupInfo,
                    &mut info,
                )
            }
            .map(|()| info)
        });
        // SAFETY: initialized above.
        unsafe { DeleteProcThreadAttributeList(list) };
        let info = created.map_err(io::Error::other)?;
        close(info.hThread);
        Ok(Spawned {
            handle: info.hProcess,
            pid: info.dwProcessId,
        })
    })();
    close(out);
    result
}

/// A command line the C runtime splits back into `exe` and `args`.
fn command_line(exe: &Path, args: &[&OsStr]) -> Vec<u16> {
    let mut line = Vec::new();
    push_arg(&mut line, exe.as_os_str());
    for a in args {
        line.push(u16::from(b' '));
        push_arg(&mut line, a);
    }
    line.push(0);
    line
}

fn push_arg(line: &mut Vec<u16>, arg: &OsStr) {
    let wide: Vec<u16> = arg.encode_wide().collect();
    let [quote, backslash, space, tab] = b"\"\\ \t".map(u16::from);
    if !wide.is_empty() && !wide.iter().any(|c| [quote, space, tab].contains(c)) {
        line.extend(wide);
        return;
    }
    line.push(quote);
    let mut backslashes = 0;
    for c in wide {
        if c == backslash {
            backslashes += 1;
            continue;
        }
        // Backslashes count only before a quote: doubled, plus one for the quote.
        let run = if c == quote {
            2 * backslashes + 1
        } else {
            backslashes
        };
        line.extend(std::iter::repeat_n(backslash, run));
        line.push(c);
        backslashes = 0;
    }
    line.extend(std::iter::repeat_n(backslash, 2 * backslashes));
    line.push(quote);
}

fn close(handle: HANDLE) {
    // SAFETY: callers pass a handle they own, exactly once.
    let _ = unsafe { CloseHandle(handle) };
}

#[cfg(test)]
mod tests {
    #[test]
    fn remote_session_check_answers() {
        // No such process: not remote. This process: whatever the session is.
        assert!(!super::in_remote_session(u32::MAX));
        let _ = super::in_remote_session(std::process::id());
    }

    #[test]
    fn command_lines_are_quoted_as_the_c_runtime_splits_them() {
        let line = super::command_line(
            std::path::Path::new(r"C:\Program Files\win4tress\win4tress-dns.exe"),
            &[
                "console".as_ref(),
                r"C:\ProgramData\win4tress\dns".as_ref(),
                r"C:\dir with space\".as_ref(),
                r#"a"b"#.as_ref(),
                "".as_ref(),
            ],
        );
        assert_eq!(
            String::from_utf16_lossy(&line[..line.len() - 1]),
            r#""C:\Program Files\win4tress\win4tress-dns.exe" console C:\ProgramData\win4tress\dns "C:\dir with space\\" "a\"b" """#
        );
    }

    #[test]
    fn only_system_starts_local_service_processes() {
        // Tests don't run as SYSTEM: refused for want of the privilege.
        let log = std::fs::File::create(std::env::temp_dir().join("w4-spawn-test.log")).unwrap();
        let exe = std::env::current_exe().unwrap();
        match super::spawn_as_local_service(&exe, &[], &log) {
            Err(e) => assert!(super::not_system(&e), "{e}"),
            Ok(p) => p.kill(),
        }
    }

    #[test]
    fn processes_are_listed_and_not_killed_by_mistake() {
        assert!(super::all().contains(&std::process::id()));
        // This test's own executable is skipped; nothing else runs it.
        let me = std::env::current_exe().unwrap();
        assert_eq!(super::kill_all(&me), 0);
    }
}
