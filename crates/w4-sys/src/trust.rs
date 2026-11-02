//! What's known about an executable for trust (SPEC §12, tier 1): its
//! Authenticode signature (in the file, or in a Windows catalog as most of
//! Windows' own files are) and signer, its SHA-256, where it lives, and its
//! Mark of the Web. Revocation isn't checked online: no network per file.

use std::io::Read;

use w4_core::trust::{DownloadOrigin, PathClass, Signature, Trust};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash,
    BCryptFinishHash, BCryptHashData, BCryptOpenAlgorithmProvider, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CertGetNameStringW,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::{HSTRING, PCWSTR, w};

use crate::{from_wide, wide};

/// No signature in the file (WinTrust's TRUST_E_NOSIGNATURE and kin): look in
/// the catalogs.
const NO_EMBEDDED_SIGNATURE: [u32; 3] = [0x800B_0100, 0x800B_0003, 0x800B_0001];

/// Everything about the file at `path` that can be read now.
pub fn read(path: &str) -> Trust {
    let (signature, signer) = match signature(path) {
        Some((s, signer)) => (Some(s), signer),
        None => (None, None),
    };
    Trust {
        signature,
        signer,
        sha256: sha256(path),
        origin: mark_of_the_web(path),
    }
}

/// The file's signature and signer; `None` if the file can't be read.
pub fn signature(path: &str) -> Option<(Signature, Option<String>)> {
    std::fs::metadata(path).ok()?;
    let embedded = embedded(path);
    if !NO_EMBEDDED_SIGNATURE.contains(&embedded.0) {
        return Some(match embedded {
            (0, signer) => (Signature::Signed, signer),
            (_, signer) => (Signature::Invalid, signer),
        });
    }
    match catalog(path) {
        Some((0, signer)) => Some((Signature::Signed, signer)),
        Some((_, signer)) => Some((Signature::Invalid, signer)),
        None => Some((Signature::Unsigned, None)),
    }
}

/// WinVerifyTrust on `data`, then the signer's name, then the state closed.
///
/// # Safety
/// `data` must describe a valid file or catalog subject.
unsafe fn verify(data: &mut WINTRUST_DATA) -> (u32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // SAFETY: the caller guarantees `data`; no UI is shown.
    unsafe {
        let status = WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut action,
            std::ptr::from_mut(data).cast(),
        ) as u32;
        let mut signer = None;
        if !data.hWVTStateData.is_invalid() && !data.hWVTStateData.0.is_null() {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            let sgnr = if prov.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvSignerFromChain(prov, 0, false, 0)
            };
            if let Some(s) = sgnr.as_ref()
                && s.csCertChain > 0
                && let Some(cert) = s.pasCertChain.as_ref()
                && !cert.pCert.is_null()
            {
                let mut buf = [0u16; 512];
                let n = CertGetNameStringW(
                    cert.pCert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut buf),
                );
                if n > 1 {
                    signer = Some(from_wide(&buf));
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut action,
            std::ptr::from_mut(data).cast(),
        );
        (status, signer)
    }
}

fn base_data(
    choice: windows::Win32::Security::WinTrust::WINTRUST_DATA_UNION_CHOICE,
    anon: WINTRUST_DATA_0,
) -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: anon,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    }
}

/// The file's own (embedded) signature.
fn embedded(path: &str) -> (u32, Option<String>) {
    let wpath = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = base_data(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut file });
    // SAFETY: `data` points at `file`, which points at `wpath`; all outlive the call.
    unsafe { verify(&mut data) }
}

/// A Windows catalog signature: the file's hash listed in a signed catalog.
/// `None` if no catalog lists it.
fn catalog(path: &str) -> Option<(u32, Option<String>)> {
    // SAFETY: every handle opened here is closed before returning; the
    // buffers passed to WinTrust outlive the calls.
    unsafe {
        let file = CreateFileW(
            &HSTRING::from(path),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;
        let mut result = None;
        // Newer catalogs list SHA-256 hashes, older ones SHA-1.
        for algorithm in [w!("SHA256"), w!("SHA1")] {
            result = catalog_with(file, path, algorithm);
            if result.is_some() {
                break;
            }
        }
        let _ = CloseHandle(file);
        result
    }
}

/// # Safety
/// `file` must be an open handle to `path`.
unsafe fn catalog_with(
    file: HANDLE,
    path: &str,
    algorithm: PCWSTR,
) -> Option<(u32, Option<String>)> {
    // SAFETY: as the caller guarantees; the catalog contexts are released here.
    unsafe {
        let mut admin: isize = 0;
        CryptCATAdminAcquireContext2(&mut admin, None, algorithm, None, None).ok()?;
        let mut hash = [0u8; 64];
        let mut size = hash.len() as u32;
        let hashed = CryptCATAdminCalcHashFromFileHandle2(
            admin,
            file,
            &mut size,
            Some(hash.as_mut_ptr()),
            None,
        );
        let mut out = None;
        if hashed.is_ok() {
            let hash = &hash[..size as usize];
            let cat = CryptCATAdminEnumCatalogFromHash(admin, hash, None, None);
            if cat != 0 {
                let mut info = CATALOG_INFO {
                    cbStruct: size_of::<CATALOG_INFO>() as u32,
                    wszCatalogFile: [0; 260],
                };
                if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
                    let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
                    let wtag = wide(&tag);
                    let wpath = wide(path);
                    let mut member = WINTRUST_CATALOG_INFO {
                        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                        pcwszMemberTag: PCWSTR(wtag.as_ptr()),
                        pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                        hMemberFile: file,
                        pbCalculatedFileHash: hash.as_ptr().cast_mut(),
                        cbCalculatedFileHash: hash.len() as u32,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut data = base_data(
                        WTD_CHOICE_CATALOG,
                        WINTRUST_DATA_0 {
                            pCatalog: &mut member,
                        },
                    );
                    out = Some(verify(&mut data));
                }
                let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            }
        }
        let _ = CryptCATAdminReleaseContext(admin, 0);
        out
    }
}

/// SHA-256 of the file's contents, lower-case hex.
pub fn sha256(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    // SAFETY: BCrypt handles are created and destroyed here; buffers outlive calls.
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            PCWSTR::null(),
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
        .ok()
        .ok()?;
        let mut hash = BCRYPT_HASH_HANDLE::default();
        let mut digest = [0u8; 32];
        let mut ok = BCryptCreateHash(alg, &mut hash, None, None, 0).is_ok();
        let mut buf = vec![0u8; 1 << 16];
        while ok {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => ok = BCryptHashData(hash, &buf[..n], 0).is_ok(),
                Err(_) => ok = false,
            }
        }
        ok = ok && BCryptFinishHash(hash, &mut digest, 0).is_ok();
        if !hash.is_invalid() {
            let _ = BCryptDestroyHash(hash);
        }
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        ok.then(|| digest.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// The `Zone.Identifier` stream Windows writes on downloaded files.
pub fn mark_of_the_web(path: &str) -> Option<DownloadOrigin> {
    let text = std::fs::read_to_string(format!("{path}:Zone.Identifier")).ok()?;
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Some(DownloadOrigin {
        zone: field("ZoneId")?.parse().ok()?,
        host_url: field("HostUrl"),
        referrer_url: field("ReferrerUrl"),
    })
}

/// Where an executable lives, by who can write there.
pub fn path_class(path: &str) -> PathClass {
    let var = |name: &str| {
        std::env::var(name)
            .map(|v| v.trim_end_matches('\\').to_lowercase())
            .unwrap_or_default()
    };
    let windows = match var("SystemRoot") {
        v if v.is_empty() => r"c:\windows".to_string(),
        v => v,
    };
    let programs: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .map(|v| var(v))
        .filter(|v| !v.is_empty())
        .collect();
    PathClass::of(path, &windows, &programs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(file: &str) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{root}\System32\{file}")
    }

    #[test]
    fn windows_files_are_signed_by_catalog_or_in_the_file() {
        // cmd.exe is catalog-signed; ntoskrnl.exe carries its own signature.
        for file in ["cmd.exe", "ntoskrnl.exe"] {
            let (sig, signer) = signature(&system(file)).expect("readable");
            assert_eq!(sig, Signature::Signed, "{file}");
            assert!(signer.unwrap_or_default().contains("Microsoft"), "{file}");
        }
    }

    #[test]
    fn an_unsigned_file_and_a_missing_one() {
        let me = std::env::current_exe().unwrap();
        assert_eq!(
            signature(&me.display().to_string()),
            Some((Signature::Unsigned, None))
        );
        assert_eq!(signature(r"C:\no\such\file.exe"), None);
    }

    #[test]
    fn hash_and_mark_of_the_web() {
        let dir = std::env::temp_dir().join(format!("w4-trust-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("abc.txt");
        std::fs::write(&file, "abc").unwrap();
        let path = file.display().to_string();
        assert_eq!(
            sha256(&path).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(mark_of_the_web(&path), None);
        std::fs::write(
            format!("{path}:Zone.Identifier"),
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/abc.txt\r\n",
        )
        .unwrap();
        let origin = mark_of_the_web(&path).unwrap();
        assert!(origin.from_internet());
        assert_eq!(
            origin.host_url.as_deref(),
            Some("https://example.com/abc.txt")
        );
        assert_eq!(origin.referrer_url, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn this_pcs_folders() {
        assert_eq!(path_class(&system("cmd.exe")), PathClass::Windows);
        let programs = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        assert_eq!(
            path_class(&format!(r"{programs}\App\app.exe")),
            PathClass::ProgramFiles
        );
    }
}
