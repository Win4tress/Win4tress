//! Executable icons as PNG data URLs, for the app lists.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use base64::Engine;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, GetDIBits, GetObjectW, HBITMAP,
};
use windows::Win32::UI::Shell::ExtractIconExW;
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};
use windows::core::PCWSTR;

/// Paths already looked up, including misses, so each file is read once.
#[derive(Default)]
pub struct IconCache(Mutex<HashMap<String, Option<String>>>);

impl IconCache {
    pub fn get(&self, path: &str) -> Option<Option<String>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(path)
            .cloned()
    }

    pub fn insert(&self, path: String, url: Option<String>) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(path, url);
    }
}

/// Only local executables (`X:\...\name.exe`). UNC paths are refused: asking
/// Windows for an icon on `\\server\share` can trigger an outbound SMB logon.
pub fn is_local_exe(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 7
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && path.to_ascii_lowercase().ends_with(".exe")
}

/// `data:image/png;base64,...` for the executable's main icon, if it has one.
pub fn data_url(path: &str) -> Option<String> {
    let png = icon_png(path)?;
    Some(format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    ))
}

fn icon_png(path: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut icon = HICON::default();
    // SAFETY: `wide` is NUL-terminated; one large icon is written to `icon`.
    let count = unsafe { ExtractIconExW(PCWSTR(wide.as_ptr()), 0, Some(&mut icon), None, 1) };
    if count == 0 || icon.is_invalid() {
        return None;
    }
    let png = icon_to_png(icon);
    // SAFETY: the icon came from ExtractIconExW and is destroyed exactly once.
    let _ = unsafe { DestroyIcon(icon) };
    png
}

fn icon_to_png(icon: HICON) -> Option<Vec<u8>> {
    let mut info = ICONINFO::default();
    // SAFETY: `icon` is a valid icon handle; GetIconInfo creates two bitmaps we delete below.
    unsafe { GetIconInfo(icon, &mut info) }.ok()?;
    let result = (!info.hbmColor.is_invalid())
        .then(|| {
            let (width, height, mut bgra) = read_bitmap(info.hbmColor)?;
            let (pixels, _) = bgra.as_chunks_mut::<4>();
            // Old icons have no alpha channel; take transparency from the mask instead.
            if pixels.iter().all(|px| px[3] == 0) {
                let (_, _, mask) = read_bitmap(info.hbmMask)?;
                for (px, m) in pixels.iter_mut().zip(mask.as_chunks::<4>().0) {
                    px[3] = if m[0] == 0 { 255 } else { 0 };
                }
            }
            for px in pixels.iter_mut() {
                px.swap(0, 2); // BGRA -> RGBA
            }
            encode_png(width, height, &bgra)
        })
        .flatten();
    // SAFETY: both bitmaps were created by GetIconInfo for us to delete.
    unsafe {
        let _ = DeleteObject(info.hbmColor.into());
        let _ = DeleteObject(info.hbmMask.into());
    }
    result
}

/// Pixels of a bitmap as top-down 32-bit BGRA.
fn read_bitmap(bitmap: HBITMAP) -> Option<(u32, u32, Vec<u8>)> {
    let mut bm = BITMAP::default();
    // SAFETY: `bm` is a BITMAP of the size passed.
    let got = unsafe {
        GetObjectW(
            bitmap.into(),
            size_of::<BITMAP>() as i32,
            Some((&mut bm as *mut BITMAP).cast::<c_void>()),
        )
    };
    if got == 0 || bm.bmWidth <= 0 || bm.bmHeight <= 0 {
        return None;
    }
    let (width, height) = (bm.bmWidth as u32, bm.bmHeight as u32);
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32), // negative: top-down rows
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = vec![0u8; (width * height * 4) as usize];
    // SAFETY: a memory DC is created and deleted here; `pixels` holds width*height 32-bit pixels.
    let lines = unsafe {
        let dc = CreateCompatibleDC(None);
        let lines = GetDIBits(
            dc,
            bitmap,
            0,
            height,
            Some(pixels.as_mut_ptr().cast()),
            &mut info,
            DIB_RGB_COLORS,
        );
        let _ = DeleteDC(dc);
        lines
    };
    (lines as u32 == height).then_some((width, height, pixels))
}

fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(rgba).ok()?;
    writer.finish().ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_executables() {
        assert!(is_local_exe(r"C:\Windows\System32\notepad.exe"));
        assert!(is_local_exe(r"d:\Tools\CURL.EXE"));
        assert!(!is_local_exe(r"\\server\share\evil.exe"));
        assert!(!is_local_exe(r"C:\Windows\System32\kernel32.dll"));
        assert!(!is_local_exe("System"));
    }

    #[test]
    fn extracts_an_icon_from_a_windows_executable() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let url = data_url(&format!(r"{windir}\explorer.exe")).expect("explorer.exe has an icon");
        assert!(url.starts_with("data:image/png;base64,"));
        assert!(url.len() > 200);
    }
}
