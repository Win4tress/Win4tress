//! What only the signed-in user's session can tell or do: when the user last
//! touched the keyboard or mouse (idle shading, SPEC §8.4), whether a
//! full-screen app is on, saving a picture of the graph to their Pictures
//! folder, and opening a web page.

use std::path::PathBuf;

use base64::Engine as _;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemInformation::{GetLocalTime, GetTickCount};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::Shell::{
    FOLDERID_Pictures, KF_FLAG_DEFAULT, QUERY_USER_NOTIFICATION_STATE, QUNS_APP, QUNS_BUSY,
    QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN, SHGetKnownFolderPath,
    SHQueryUserNotificationState, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HSTRING, w};

/// When the user last used the keyboard or mouse, in Unix ms.
pub fn last_input_ms() -> Option<i64> {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a valid, sized LASTINPUTINFO.
    unsafe { GetLastInputInfo(&mut info) }.ok().ok()?;
    // Both are tick counts that wrap every 49.7 days; the difference doesn't care.
    // SAFETY: no arguments.
    let ago = unsafe { GetTickCount() }.wrapping_sub(info.dwTime);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    Some(now - i64::from(ago))
}

/// A full-screen game, video or app, or presentation mode, is on: what
/// Windows itself holds its notifications back for.
pub fn full_screen() -> bool {
    // SAFETY: no arguments; returns a value.
    unsafe { SHQueryUserNotificationState() }.is_ok_and(holds_back)
}

fn holds_back(state: QUERY_USER_NOTIFICATION_STATE) -> bool {
    [
        QUNS_BUSY,
        QUNS_RUNNING_D3D_FULL_SCREEN,
        QUNS_PRESENTATION_MODE,
        QUNS_APP,
    ]
    .contains(&state)
}

/// The user's Pictures folder (wherever it was moved to).
fn pictures() -> Result<PathBuf, String> {
    // SAFETY: the returned string is copied, then freed with CoTaskMemFree.
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_Pictures, KF_FLAG_DEFAULT, None)
            .map_err(|e| format!("finding the Pictures folder: {e}"))?;
        let path = p.to_string().map_err(|e| e.to_string());
        CoTaskMemFree(Some(p.0 as _));
        path.map(PathBuf::from)
    }
}

/// Saves a `data:image/png;base64,…` URL as Pictures\win4tress\traffic-<time>.png.
pub fn save_png(data_url: &str) -> Result<PathBuf, String> {
    let encoded = data_url
        .strip_prefix("data:image/png;base64,")
        .ok_or("not a PNG picture")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| e.to_string())?;
    let dir = pictures()?.join("win4tress");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // SAFETY: no arguments.
    let t = unsafe { GetLocalTime() };
    let path = dir.join(format!(
        "traffic-{:04}-{:02}-{:02}-{:02}{:02}{:02}.png",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    ));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Opens `url` in the default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    // SAFETY: plain strings that outlive the call; no window handle.
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            &HSTRING::from(url),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute returns a value above 32 on success.
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!("couldn't open {url}"))
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::UI::Shell::{
        QUNS_ACCEPTS_NOTIFICATIONS, QUNS_NOT_PRESENT, QUNS_QUIET_TIME,
    };

    use super::*;

    #[test]
    fn holds_back_for_full_screen_only() {
        assert!(holds_back(QUNS_RUNNING_D3D_FULL_SCREEN));
        assert!(holds_back(QUNS_PRESENTATION_MODE));
        assert!(!holds_back(QUNS_ACCEPTS_NOTIFICATIONS));
        // Locked or a screen saver: it waits on the desktop for the user.
        assert!(!holds_back(QUNS_NOT_PRESENT));
        assert!(!holds_back(QUNS_QUIET_TIME));
        // Whatever this desktop is doing now, asking doesn't fail.
        let _ = full_screen();
    }
}
