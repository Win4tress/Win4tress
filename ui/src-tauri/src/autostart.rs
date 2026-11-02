//! Starting the app when the user signs in (Settings → General): a value in
//! the user's own Run key, so no admin rights are needed. It starts the app
//! in the tray (`--minimized`), without building the window. The service is a
//! Windows service and starts with Windows either way.
//!
//! Windows' own switch (Task Manager → Startup apps, Settings → Apps →
//! Startup) is a value under StartupApproved: off there is off here, and
//! turning it on here clears it.

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW,
    RegSetKeyValueW,
};
use windows::core::w;

const RUN: windows::core::PCWSTR = w!(r"Software\Microsoft\Windows\CurrentVersion\Run");
const APPROVED: windows::core::PCWSTR =
    w!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
const NAME: windows::core::PCWSTR = w!("Win4tress");
/// The argument that starts the app in the tray.
pub const MINIMIZED: &str = "--minimized";

/// The command line Windows runs at sign-in: this executable, in the tray.
fn command() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(format!("\"{}\" {MINIMIZED}", exe.display()))
}

/// Whether the app starts at sign-in.
pub fn enabled() -> bool {
    let mut size = 0u32;
    // SAFETY: a size query; no buffer is passed.
    let registered = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            RUN,
            NAME,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    } == ERROR_SUCCESS;
    registered && !disabled_by_windows()
}

/// Task Manager's "Disabled": the first byte of the StartupApproved value is
/// odd (3) when off, even (2) when on; no value means on.
fn disabled_by_windows() -> bool {
    let mut data = [0u8; 12];
    let mut size = data.len() as u32;
    // SAFETY: `data` holds `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            APPROVED,
            NAME,
            RRF_RT_REG_BINARY,
            None,
            Some(data.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    rc == ERROR_SUCCESS && size > 0 && data[0] & 1 == 1
}

/// Turns starting at sign-in on or off; returns the state now.
pub fn set(on: bool) -> Result<bool, String> {
    if on {
        let command = command().ok_or("can't find this program's path")?;
        let wide: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a NUL-terminated string of the byte length given.
        let rc = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                RUN,
                NAME,
                REG_SZ.0,
                Some(wide.as_ptr().cast()),
                (wide.len() * 2) as u32,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!(
                "couldn't add Win4tress to startup: {}",
                rc.to_hresult().message()
            ));
        }
        // Undo "Disabled" in Task Manager, which would win otherwise.
        // SAFETY: deletes one value of the user's own; absent is fine.
        let _ = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, APPROVED, NAME) };
    } else {
        // SAFETY: as above.
        let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, RUN, NAME) };
        if rc != ERROR_SUCCESS && enabled() {
            return Err(format!(
                "couldn't remove Win4tress from startup: {}",
                rc.to_hresult().message()
            ));
        }
    }
    Ok(enabled())
}

/// At start: if it's on, point it at this copy of the app (after an update
/// or a move, the old path would start nothing).
pub fn refresh() {
    if !enabled() {
        return;
    }
    let Some(command) = command() else { return };
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            RUN,
            NAME,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    let current = (rc == ERROR_SUCCESS).then(|| {
        let chars = (size as usize / 2).saturating_sub(1);
        String::from_utf16_lossy(&buf[..chars])
    });
    if current.as_deref() != Some(command.as_str()) {
        let _ = set(true);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_command_starts_this_program_in_the_tray() {
        let command = super::command().unwrap();
        assert!(command.starts_with('"'));
        assert!(command.ends_with("\" --minimized"));
    }
}
