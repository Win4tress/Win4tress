//! Copying alerts to the Windows Event Log (SPEC §11, a setting), in the
//! Application log under the source "win4tress".

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR};

pub const SOURCE: &str = "win4tress";

/// How serious an event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Information,
    Warning,
    Error,
}

/// .NET's generic message file: event ids 0–65535 each show "%1", so the
/// event's text appears as written without a message file of our own.
const MESSAGE_FILE: &str =
    r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll";

fn wide_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Registers the event source, so Event Viewer can show the text. Needs
/// administrators (the service); harmless to repeat.
pub fn register() -> Result<(), String> {
    let key = HSTRING::from(format!(
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{SOURCE}"
    ));
    let mut hkey = HKEY::default();
    // SAFETY: a key created here, written and closed.
    unsafe {
        let rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &key,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if rc.is_err() {
            return Err(format!("registering the event source: {rc:?}"));
        }
        let _ = RegSetValueExW(
            hkey,
            &HSTRING::from("EventMessageFile"),
            None,
            REG_EXPAND_SZ,
            Some(&wide_bytes(MESSAGE_FILE)),
        );
        let _ = RegSetValueExW(
            hkey,
            &HSTRING::from("TypesSupported"),
            None,
            REG_DWORD,
            Some(&7u32.to_le_bytes()),
        );
        let _ = RegCloseKey(hkey);
    }
    Ok(())
}

/// Writes one event.
pub fn report(level: Level, id: u32, text: &str) -> Result<(), String> {
    let kind = match level {
        Level::Information => EVENTLOG_INFORMATION_TYPE,
        Level::Warning => EVENTLOG_WARNING_TYPE,
        Level::Error => EVENTLOG_ERROR_TYPE,
    };
    let text = HSTRING::from(text);
    // SAFETY: a source handle opened and closed here; the string outlives the call.
    unsafe {
        let source: HANDLE = RegisterEventSourceW(PCWSTR::null(), &HSTRING::from(SOURCE))
            .map_err(|e| format!("opening the event log: {e}"))?;
        let result = ReportEventW(
            source,
            kind,
            0,
            id,
            None,
            0,
            Some(&[PCWSTR(text.as_ptr())]),
            None,
        )
        .map_err(|e| format!("writing to the event log: {e}"));
        let _ = DeregisterEventSource(source);
        result
    }
}
