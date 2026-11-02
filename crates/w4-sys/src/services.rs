//! Running Windows services by process, for telling svchost instances apart.

use std::collections::HashMap;

use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows::core::PCWSTR;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// Short name, e.g. `TermService`.
    pub name: String,
    /// e.g. `Remote Desktop Services`.
    pub display_name: String,
}

/// Running Win32 services grouped by the process hosting them.
pub fn by_pid() -> HashMap<u32, Vec<Service>> {
    let mut out: HashMap<u32, Vec<Service>> = HashMap::new();
    // SAFETY: plain Win32 call; the handle is closed below.
    let Ok(scm) =
        (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) })
    else {
        return out;
    };

    // u64 backing keeps the pointer-bearing entries aligned.
    let mut buf = vec![0u64; 16 * 1024];
    let mut resume = 0u32;
    for _ in 0..16 {
        let mut needed = 0u32;
        let mut returned = 0u32;
        // SAFETY: `bytes` covers `buf`, which outlives the call.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 8) };
        // SAFETY: valid SCM handle and buffers; `resume` continues a partial listing.
        let result = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                Some(bytes),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };
        // SAFETY: the call wrote `returned` entries at the start of `buf`; their
        // string pointers point into `buf`, which is not modified while reading.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                returned as usize,
            )
        };
        for e in entries {
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid == 0 {
                continue;
            }
            // SAFETY: NUL-terminated strings inside `buf`.
            let (name, display_name) = unsafe {
                (
                    e.lpServiceName.to_string().unwrap_or_default(),
                    e.lpDisplayName.to_string().unwrap_or_default(),
                )
            };
            out.entry(pid)
                .or_default()
                .push(Service { name, display_name });
        }
        match result {
            Ok(()) => break,
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
                let wanted = (needed as usize).div_ceil(8);
                if wanted > buf.len() {
                    buf.resize(wanted, 0);
                }
            }
            Err(_) => break,
        }
    }
    // SAFETY: `scm` came from OpenSCManagerW and is closed exactly once.
    let _ = unsafe { CloseServiceHandle(scm) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_running_services() {
        let services = by_pid();
        // Every Windows machine runs dozens of services, e.g. the RPC endpoint mapper.
        assert!(services.values().map(Vec::len).sum::<usize>() > 10);
        assert!(
            services
                .values()
                .flatten()
                .any(|s| s.name.eq_ignore_ascii_case("RpcSs"))
        );
    }
}
