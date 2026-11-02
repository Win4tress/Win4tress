//! Secrets at rest (reputation API keys, SPEC §12): DPAPI with the machine's
//! key, so the service (SYSTEM) and a console run (an administrator) both read
//! them. The database that holds them is readable only by administrators.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::core::w;

/// Copies DPAPI's output and frees it.
///
/// # Safety
/// `blob` must come from a successful CryptProtectData/CryptUnprotectData.
unsafe fn take(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: per the contract, `pbData` holds `cbData` bytes from LocalAlloc.
    unsafe {
        let out = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(blob.pbData.cast())));
        out
    }
}

fn input(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, String> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| "too large")?,
        pbData: data.as_ptr().cast_mut(),
    })
}

pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    let blob = input(plain)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `blob` points into `plain`, which DPAPI only reads; `out` is
    // filled by DPAPI and taken over by `take`.
    unsafe {
        CryptProtectData(
            &blob,
            w!("win4tress"),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| format!("encrypting: {e}"))?;
        Ok(take(out))
    }
}

pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>, String> {
    let blob = input(sealed)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    unsafe {
        CryptUnprotectData(
            &blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| format!("decrypting: {e}"))?;
        Ok(take(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_hides_the_text() {
        let sealed = protect(b"0123456789abcdef").unwrap();
        assert!(!sealed.windows(16).any(|w| w == b"0123456789abcdef"));
        assert_eq!(unprotect(&sealed).unwrap(), b"0123456789abcdef");
        assert!(unprotect(b"not a blob").is_err());
    }
}
