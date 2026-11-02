//! "Scan with installed antivirus" (SPEC §12 tier 3): every antivirus that
//! registers with Windows' Attachment Manager (the IOfficeAntiVirus interface,
//! component category CATID_MSOfficeAntiVirus) scans the file, as Windows asks
//! them to for downloads. Microsoft Defender registers, and so do most others.
//! The scan is read-only: the antivirus reports, and acts by its own policy.

use std::ffi::c_void;

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    ICatInformation,
};
use windows::Win32::System::Registry::{HKEY_CLASSES_ROOT, RRF_RT_REG_SZ, RegGetValueW};
use windows::core::{GUID, HRESULT, HSTRING, IUnknown, Interface, PCWSTR};

/// CATID_MSOfficeAntiVirus, which is also IOfficeAntiVirus' interface id.
const OFFICE_ANTIVIRUS: GUID = GUID::from_u128(0x56ffcc30_d398_11d0_b2ae_00a0c908fa49);
const STD_COMPONENT_CATEGORIES_MGR: GUID = GUID::from_u128(0x0002e005_0000_0000_c000_000000000046);

/// MSOAVINFO.
#[repr(C)]
struct MsoAvInfo {
    cb_size: i32,
    /// fPath (1), fReadOnlyRequest (2), fInstalled (4), fHttpDownload (8).
    flags: u32,
    hwnd: *mut c_void,
    full_path: *const u16,
    host_name: *const u16,
    orig_url: *const u16,
}

/// IOfficeAntiVirus: IUnknown's three methods, then Scan.
#[repr(C)]
struct OfficeAntiVirusVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    scan: unsafe extern "system" fn(*mut c_void, *mut MsoAvInfo) -> HRESULT,
}

const FLAG_PATH: u32 = 1;
const FLAG_READ_ONLY: u32 = 2;
/// HRESULT_FROM_WIN32(ERROR_VIRUS_INFECTED) and (ERROR_VIRUS_DELETED).
const VIRUS_INFECTED: HRESULT = HRESULT(0x800700E1_u32 as i32);
const VIRUS_DELETED: HRESULT = HRESULT(0x800700E2_u32 as i32);
const E_FAIL: HRESULT = HRESULT(0x80004005_u32 as i32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    /// A threat was found; `cleaned` if the antivirus says it cleaned the file.
    Threat {
        cleaned: bool,
    },
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    /// The antivirus' registered name, e.g. "Windows Defender IOfficeAntiVirus implementation".
    pub scanner: String,
    pub outcome: Outcome,
}

/// IOfficeAntiVirus::Scan's answers (msoav.h): S_OK clean, S_FALSE found and
/// cleaned, E_FAIL found and not cleaned; some antivirus use the Win32 virus
/// errors instead.
fn outcome(hr: HRESULT) -> Outcome {
    match hr {
        HRESULT(0) => Outcome::Clean,
        HRESULT(1) => Outcome::Threat { cleaned: true },
        h if h == E_FAIL || h == VIRUS_INFECTED => Outcome::Threat { cleaned: false },
        h if h == VIRUS_DELETED => Outcome::Threat { cleaned: true },
        h => Outcome::Failed(h.message().to_string()),
    }
}

/// The class's name from the registry, or its id.
fn class_name(clsid: &GUID) -> String {
    let key = HSTRING::from(format!("CLSID\\{{{clsid:?}}}"));
    let mut buffer = [0u16; 260];
    let mut size = (buffer.len() * 2) as u32;
    // SAFETY: `buffer` is writable for `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CLASSES_ROOT,
            &key,
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if rc.is_ok() {
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        let name = String::from_utf16_lossy(&buffer[..len]);
        if !name.trim().is_empty() {
            return name;
        }
    }
    format!("{{{clsid:?}}}")
}

/// The registered antivirus classes.
///
/// # Safety
/// COM must be initialised on this thread.
unsafe fn scanners() -> Result<Vec<GUID>, String> {
    // SAFETY: plain COM calls; COM is initialised (the caller's contract).
    unsafe {
        let categories: ICatInformation =
            CoCreateInstance(&STD_COMPONENT_CATEGORIES_MGR, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| format!("component categories: {e}"))?;
        let found = categories
            .EnumClassesOfCategories(&[OFFICE_ANTIVIRUS], &[])
            .map_err(|e| format!("listing antivirus: {e}"))?;
        let mut out = Vec::new();
        loop {
            let mut batch = [GUID::zeroed(); 8];
            let mut fetched = 0u32;
            let _ = found.Next(&mut batch, Some(&mut fetched));
            if fetched == 0 {
                break;
            }
            out.extend_from_slice(&batch[..fetched as usize]);
        }
        Ok(out)
    }
}

/// One antivirus scans `path`.
///
/// # Safety
/// COM must be initialised on this thread.
unsafe fn scan_with(clsid: &GUID, path: &[u16], host: &[u16]) -> Outcome {
    // SAFETY: the object implements IOfficeAntiVirus (its category says so,
    // and QueryInterface confirms); MSOAVINFO's strings outlive the call.
    unsafe {
        let unknown: IUnknown = match CoCreateInstance(clsid, None, CLSCTX_INPROC_SERVER) {
            Ok(u) => u,
            Err(e) => return Outcome::Failed(format!("can't start it: {e}")),
        };
        let mut raw: *mut c_void = std::ptr::null_mut();
        if unknown.query(&OFFICE_ANTIVIRUS, &mut raw).is_err() || raw.is_null() {
            return Outcome::Failed("it doesn't offer scanning".into());
        }
        let vtbl = *(raw as *const *const OfficeAntiVirusVtbl);
        let mut info = MsoAvInfo {
            cb_size: size_of::<MsoAvInfo>() as i32,
            flags: FLAG_PATH | FLAG_READ_ONLY,
            hwnd: std::ptr::null_mut(),
            full_path: path.as_ptr(),
            host_name: host.as_ptr(),
            orig_url: std::ptr::null(),
        };
        let hr = ((*vtbl).scan)(raw, &mut info);
        ((*vtbl).release)(raw);
        outcome(hr)
    }
}

/// Every registered antivirus scans the file. An empty list means none is
/// registered. Blocking: a large file can take a while.
pub fn scan(path: &str) -> Result<Vec<ScanResult>, String> {
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let (path, host) = (wide(path), wide("win4tress"));
    // SAFETY: COM is initialised for this call and uninitialised after, when
    // this call did it; the interfaces are released before that.
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED);
        let result = scanners().map(|classes| {
            classes
                .iter()
                .map(|c| ScanResult {
                    scanner: class_name(c),
                    outcome: scan_with(c, &path, &host),
                })
                .collect()
        });
        if init.is_ok() {
            CoUninitialize();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_map_to_outcomes() {
        assert_eq!(outcome(HRESULT(0)), Outcome::Clean);
        assert_eq!(outcome(HRESULT(1)), Outcome::Threat { cleaned: true });
        assert_eq!(outcome(E_FAIL), Outcome::Threat { cleaned: false });
        assert_eq!(outcome(VIRUS_INFECTED), Outcome::Threat { cleaned: false });
        assert!(matches!(
            outcome(HRESULT(0x80070005_u32 as i32)),
            Outcome::Failed(_)
        ));
    }

    #[test]
    fn the_info_block_is_laid_out_as_msoav_h() {
        // int + bit fields + HWND + three pointers on x64.
        assert_eq!(size_of::<MsoAvInfo>(), 40);
    }

    /// Scans notepad.exe with whatever antivirus is registered (Defender on a
    /// stock install). `cargo test -p w4-sys av -- --ignored --nocapture`
    #[test]
    #[ignore = "uses the installed antivirus"]
    fn scans_a_clean_system_file() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let started = std::time::Instant::now();
        let results = scan(&format!(r"{root}\System32\notepad.exe")).unwrap();
        println!("{results:?} in {:?}", started.elapsed());
        assert!(results.iter().all(|r| r.outcome == Outcome::Clean));
    }
}
