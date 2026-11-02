//! Executable metadata from the version resource (FileDescription, CompanyName,
//! file version).

use std::ffi::c_void;

use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows::core::PCWSTR;

use crate::{from_wide, wide};

/// `VS_FIXEDFILEINFO::dwSignature`.
const FIXED_INFO_SIGNATURE: u32 = 0xFEEF_04BD;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub description: Option<String>,
    pub company: Option<String>,
    pub product: Option<String>,
    /// Numeric file version, e.g. `10.0.26100.8737`; `None` when it's 0.0.0.0.
    pub version: Option<String>,
}

/// Reads the version resource of an executable. `None` if it has none.
///
/// The calling executable needs a manifest that declares Windows 10 support
/// (see `bins/*/build.rs`). Without one, Windows reports its own files as
/// version 6.2 instead of 10.0.
pub fn file_info(path: &str) -> Option<FileInfo> {
    let path_w = wide(path);
    // SAFETY: `path_w` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path_w.as_ptr()), None) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: `data` is writable for `size` bytes.
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(path_w.as_ptr()),
            None,
            size,
            data.as_mut_ptr().cast(),
        )
    }
    .ok()?;

    // Try the file's own language first, then US English (Unicode, then Windows-1252).
    let mut prefixes: Vec<String> = translations(&data)
        .into_iter()
        .map(|(lang, cp)| format!("{lang:04x}{cp:04x}"))
        .collect();
    prefixes.extend(["040904b0".to_string(), "040904e4".to_string()]);

    let get = |key: &str| {
        prefixes
            .iter()
            .find_map(|p| query_string(&data, &format!("\\StringFileInfo\\{p}\\{key}")))
    };
    Some(FileInfo {
        description: get("FileDescription"),
        company: get("CompanyName"),
        product: get("ProductName"),
        version: fixed_version(&data),
    })
}

/// The binary file version. The `FileVersion` string often carries extra text,
/// e.g. `10.0.26100.1 (WinBuild.160101.0800)`.
fn fixed_version(data: &[u8]) -> Option<String> {
    let (ptr, len) = query_value(data, "\\")?;
    if (len as usize) < size_of::<VS_FIXEDFILEINFO>() {
        return None;
    }
    // SAFETY: VerQueryValueW returned a pointer into `data` covering `len` bytes,
    // at least one VS_FIXEDFILEINFO; read_unaligned avoids alignment assumptions.
    let info = unsafe { ptr.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    if info.dwSignature != FIXED_INFO_SIGNATURE {
        return None;
    }
    let (ms, ls) = (info.dwFileVersionMS, info.dwFileVersionLS);
    if ms == 0 && ls == 0 {
        return None;
    }
    Some(format!(
        "{}.{}.{}.{}",
        ms >> 16,
        ms & 0xffff,
        ls >> 16,
        ls & 0xffff
    ))
}

fn translations(data: &[u8]) -> Vec<(u16, u16)> {
    let Some((ptr, len)) = query_value(data, "\\VarFileInfo\\Translation") else {
        return Vec::new();
    };
    let count = len as usize / 4;
    // SAFETY: VerQueryValueW returned a pointer into `data` covering `len` bytes of
    // (language, code page) u16 pairs. read_unaligned avoids alignment assumptions.
    (0..count)
        .map(|i| unsafe {
            let pair = ptr.cast::<u16>().add(i * 2);
            (pair.read_unaligned(), pair.add(1).read_unaligned())
        })
        .collect()
}

fn query_string(data: &[u8], sub_block: &str) -> Option<String> {
    let (ptr, len) = query_value(data, sub_block)?;
    if len == 0 {
        return None;
    }
    // SAFETY: for string values `len` is in characters and points into `data`.
    let chars = unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize) };
    let text = from_wide(chars).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn query_value(data: &[u8], sub_block: &str) -> Option<(*const c_void, u32)> {
    let sub_w = wide(sub_block);
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `data` is a version-info block from GetFileVersionInfoW; the returned
    // pointer stays within it and is only used while `data` is borrowed.
    let found = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(sub_w.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };
    (found.as_bool() && !ptr.is_null()).then_some((ptr.cast_const(), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_notepad_info() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let info = file_info(&format!(r"{windir}\System32\notepad.exe"));
        // notepad.exe may be a stub on some builds, but kernel32 always has a version resource.
        let info = info
            .or_else(|| file_info(&format!(r"{windir}\System32\kernel32.dll")))
            .unwrap();
        assert!(info.company.unwrap().contains("Microsoft"));
        // Test binaries have no manifest, so Windows may report 6.2 for 10.0;
        // the build number is reported as is.
        let version = info.version.expect("Windows binaries have a file version");
        let parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap()).collect();
        assert_eq!(parts.len(), 4, "{version}");
        assert!(parts[2] >= 10_240, "Windows 10 or later build: {version}");
    }

    #[test]
    fn missing_file_is_none() {
        assert_eq!(file_info(r"C:\definitely\not\here.exe"), None);
    }
}
