//! Private directories for the service's data (SPEC §9: SYSTEM and Administrators only).

use std::io;
use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::core::{BOOL, PCWSTR};

use crate::wide;

/// SYSTEM and Administrators: full control, inherited by everything inside.
pub const ADMIN_ONLY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Creates `path` (and parents) and replaces its access list with `sddl`,
/// blocking inherited entries. Existing contents pick up the new entries.
pub fn create_private_dir(path: &Path, sddl: &str) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let sddl_w = wide(sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_w` is NUL-terminated; the descriptor is freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io::Error::other)?;

    let result = (|| {
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `descriptor` is valid; `dacl` points into it.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .map_err(io::Error::other)?;
        let path_w = wide(&path.to_string_lossy());
        // SAFETY: `path_w` is NUL-terminated; `dacl` stays valid until LocalFree below.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        rc.ok().map_err(io::Error::other)
    })();

    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result
}
