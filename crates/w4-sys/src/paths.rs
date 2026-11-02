//! NT device paths (`\Device\HarddiskVolume3\...`) to Win32 paths (`C:\...`).
//! Kernel-Process events report device paths.

use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::{from_wide, wide};

pub struct DevicePaths {
    /// (device prefix, drive), e.g. (`\Device\HarddiskVolume3`, `C:`).
    map: Vec<(String, String)>,
}

impl DevicePaths {
    /// Reads the current drive-letter mappings.
    pub fn load() -> Self {
        let mut map = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let name = wide(&drive);
            let mut buf = [0u16; 512];
            // SAFETY: `name` is NUL-terminated; `buf` is writable for its length.
            let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) };
            if len > 0 {
                // The result is a multi-string; the first entry is the active target.
                map.push((from_wide(&buf), drive));
            }
        }
        Self::from_pairs(map)
    }

    pub fn from_pairs(map: Vec<(String, String)>) -> Self {
        DevicePaths { map }
    }

    /// Converts a device path to a Win32 path; returns it unchanged if no drive matches.
    pub fn to_win32(&self, path: &str) -> String {
        for (device, drive) in &self.map {
            let Some(head) = path.get(..device.len()) else {
                continue;
            };
            let rest = &path[device.len()..];
            if head.eq_ignore_ascii_case(device) && rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> DevicePaths {
        DevicePaths::from_pairs(vec![
            (r"\Device\HarddiskVolume3".into(), "C:".into()),
            (r"\Device\HarddiskVolume30".into(), "D:".into()),
        ])
    }

    #[test]
    fn maps_device_prefix() {
        assert_eq!(
            paths().to_win32(r"\Device\HarddiskVolume3\Windows\System32\curl.exe"),
            r"C:\Windows\System32\curl.exe"
        );
    }

    #[test]
    fn does_not_match_longer_volume_number() {
        assert_eq!(
            paths().to_win32(r"\Device\HarddiskVolume30\x.exe"),
            r"D:\x.exe"
        );
    }

    #[test]
    fn unknown_device_is_unchanged() {
        assert_eq!(
            paths().to_win32(r"\Device\Mup\server\x.exe"),
            r"\Device\Mup\server\x.exe"
        );
    }
}
