//! The title bar in Windows' accent colour while "Show accent color on title
//! bars and window borders" is on, like the taskbar. Windows colours standard
//! title bars from the accent its window manager keeps, which can lag the one
//! chosen in Settings (blue there while Start and the taskbar are purple);
//! this uses the accent Settings shows. An inactive window gets the plain
//! title bar back, as Windows does. Before Windows 11 nothing changes.

use std::ffi::c_void;

use windows::UI::ViewManagement::{UIColorType, UISettings};
use windows::Win32::Foundation::{ERROR_SUCCESS, HWND};
use windows::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_COLOR_DEFAULT, DWMWA_TEXT_COLOR,
    DwmSetWindowAttribute,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows::core::w;

/// Colours the title bar of the window `hwnd` (Tauri's `Window::hwnd`) for
/// it being `active`.
pub fn apply(hwnd: Option<*mut c_void>, active: bool) {
    let Some(raw) = hwnd else { return };
    let (caption, text) = match accent().filter(|_| active) {
        Some(colors) => colors,
        None => (DWMWA_COLOR_DEFAULT, DWMWA_COLOR_DEFAULT),
    };
    for (attribute, value) in [
        (DWMWA_CAPTION_COLOR, caption),
        (DWMWA_BORDER_COLOR, caption),
        (DWMWA_TEXT_COLOR, text),
    ] {
        // SAFETY: a COLORREF-sized value for a window of this process.
        // Failing (before Windows 11) leaves Windows' own colours.
        let _ = unsafe {
            DwmSetWindowAttribute(
                HWND(raw),
                attribute,
                (&value as *const u32).cast(),
                size_of::<u32>() as u32,
            )
        };
    }
}

/// The accent and a text colour for it (COLORREFs), or `None` when title
/// bars aren't meant to be coloured.
fn accent() -> Option<(u32, u32)> {
    if !accent_on_title_bars() {
        return None;
    }
    let c = UISettings::new()
        .ok()?
        .GetColorValue(UIColorType::Accent)
        .ok()?;
    Some((colorref(c.R, c.G, c.B), text_for(c.R, c.G, c.B)))
}

fn colorref(r: u8, g: u8, b: u8) -> u32 {
    u32::from(r) | (u32::from(g) << 8) | (u32::from(b) << 16)
}

/// Black on light accents, white on dark ones, by the test Microsoft's
/// theming guidance gives (`IsColorLight`), so the text matches Windows'.
fn text_for(r: u8, g: u8, b: u8) -> u32 {
    let light = 5 * u32::from(g) + 2 * u32::from(r) + u32::from(b) > 8 * 128;
    if light {
        colorref(0, 0, 0)
    } else {
        colorref(255, 255, 255)
    }
}

/// Settings → Personalization → Colors → "Show accent color on title bars
/// and window borders".
fn accent_on_title_bars() -> bool {
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: a DWORD read into `value`, of the size given.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\DWM"),
            w!("ColorPrevalence"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast()),
            Some(&mut size),
        )
    };
    rc == ERROR_SUCCESS && value == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_contrasts_with_the_accent() {
        // Purple and Windows' default blue take white; yellow takes black.
        assert_eq!(text_for(0x74, 0x4d, 0xa9), colorref(255, 255, 255));
        assert_eq!(text_for(0x00, 0x78, 0xd4), colorref(255, 255, 255));
        assert_eq!(text_for(0xff, 0xb9, 0x00), colorref(0, 0, 0));
        assert_eq!(colorref(0x74, 0x4d, 0xa9), 0x00a9_4d74);
    }
}
