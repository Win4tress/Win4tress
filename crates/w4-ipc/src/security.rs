//! Pipe security: SECURITY_ATTRIBUTES built from an SDDL string, for creating
//! the pipe, and the identity of a connected client (SPEC §4.3).

use std::ffi::c_void;
use std::io;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenGroups, TokenUser, WinBuiltinAdministratorsSid,
};
use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::{PCWSTR, PWSTR};

/// Who is on the other end of the pipe, from its token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallerToken {
    /// The user's SID, e.g. `S-1-5-21-…-1001`.
    pub user: String,
    /// A member of BUILTIN\Administrators, counting membership that UAC has
    /// filtered to deny-only (an unelevated admin).
    pub admin: bool,
    /// Running elevated.
    pub elevated: bool,
}

/// Reads the client's token by impersonating it. Windows allows that only after
/// data has been read from the pipe, so call it once a request has arrived. The
/// thread reverts to itself before returning, whatever happens.
pub fn client_token(pipe: HANDLE) -> io::Result<CallerToken> {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: undoes the impersonation below on this same thread.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }
    struct Close(HANDLE);
    impl Drop for Close {
        fn drop(&mut self) {
            // SAFETY: the token handle was opened below and is closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // SAFETY: `pipe` is a connected server end; the guard reverts.
    unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(io::Error::other)?;
    let _revert = Revert;
    let mut token = HANDLE::default();
    // SAFETY: open the impersonation token of this thread, checked against the
    // service's own access (OpenAsSelf).
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
        .map_err(io::Error::other)?;
    let token = Close(token);

    let groups = token_info(token.0, TokenGroups)?;
    // SAFETY: GetTokenInformation(TokenGroups) filled the buffer with a TOKEN_GROUPS
    // whose array has GroupCount entries; the buffer is 8-byte aligned.
    let admin = unsafe {
        let groups = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        let entries =
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
        let admins = admins_sid()?;
        let admins_psid = PSID(admins.as_ptr().cast_mut().cast());
        entries.iter().any(|g| EqualSid(g.Sid, admins_psid).is_ok())
    };

    let user = token_info(token.0, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER; the string is freed with LocalFree.
    let user = unsafe {
        let sid = (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).map_err(io::Error::other)?;
        let s = text.to_string().unwrap_or_default();
        LocalFree(Some(HLOCAL(text.0.cast())));
        s
    };

    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: TOKEN_ELEVATION is a fixed-size struct written in place.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(std::ptr::addr_of_mut!(elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    }
    .map_err(io::Error::other)?;

    Ok(CallerToken {
        user,
        admin,
        elevated: elevation.TokenIsElevated != 0,
    })
}

/// A variable-length token information block, in an 8-byte-aligned buffer.
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a size query; it fails with ERROR_INSUFFICIENT_BUFFER and sets `len`.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` has at least `len` bytes.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 8) as u32,
            &mut len,
        )
    }
    .map_err(io::Error::other)?;
    Ok(buf)
}

/// S-1-5-32-544, in an 8-byte-aligned buffer.
fn admins_sid() -> io::Result<Vec<u64>> {
    let mut buf = vec![0u64; 16];
    let mut len = (buf.len() * 8) as u32;
    // SAFETY: `buf` holds `len` bytes, more than SECURITY_MAX_SID_SIZE (68).
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(PSID(buf.as_mut_ptr().cast())),
            &mut len,
        )
    }
    .map_err(io::Error::other)?;
    Ok(buf)
}

pub struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

// SAFETY: the descriptor is an immutable, heap-allocated blob owned by this value.
unsafe impl Send for PipeSecurity {}
// SAFETY: as above; it is only read after construction.
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    /// Boxed so the pointer handed to Win32 stays stable.
    pub fn from_sddl(sddl: &str) -> io::Result<Box<Self>> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; the descriptor is freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(io::Error::other)?;

        let mut this = Box::new(PipeSecurity {
            descriptor,
            attributes: SECURITY_ATTRIBUTES::default(),
        });
        this.attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: this.descriptor.0,
            bInheritHandle: false.into(),
        };
        Ok(this)
    }

    /// For `ServerOptions::create_with_security_attributes_raw`. Valid while `self` lives.
    pub fn as_ptr(&self) -> *mut c_void {
        (&self.attributes as *const SECURITY_ATTRIBUTES)
            .cast_mut()
            .cast()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(Some(HLOCAL(self.descriptor.0))) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_production_sddl() {
        let sec = PipeSecurity::from_sddl(crate::PIPE_SDDL).unwrap();
        assert!(!sec.as_ptr().is_null());
    }

    #[test]
    fn rejects_garbage() {
        assert!(PipeSecurity::from_sddl("not sddl").is_err());
    }
}
