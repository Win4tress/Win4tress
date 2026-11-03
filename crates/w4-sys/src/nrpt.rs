//! Routing internet lookups to the local resolver with a Name Resolution
//! Policy Table rule (SPEC §13, spike 0.7): every top-level domain in the root
//! zone → `127.0.0.1;::1`, under a key of win4tress's own. Not `.`: with that,
//! Windows took one-label names (`\\server`) for DNS names, refused them as
//! invalid and never looked on the local network. Names under no public
//! top-level domain (one label, `.local`, `.lan`) and reverse lookups go the
//! usual way. Adapters' DNS settings are left alone, so their servers stay
//! visible as the resolver's upstream; more specific rules (a VPN's,
//! Tailscale's) still win. Removing the key puts Windows back as it was.
//! The key is volatile: Windows discards it at restart, so a service that
//! died with the rule in place can't leave a restarted PC without DNS.
//!
//! `tlds.txt` is IANA's list, refreshed with
//! `curl -o crates/w4-sys/src/tlds.txt https://data.iana.org/TLD/tlds-alpha-by-domain.txt`.

use std::net::IpAddr;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
    REG_OPEN_CREATE_OPTIONS, REG_OPTION_NON_VOLATILE, REG_OPTION_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR};

const BASE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
/// win4tress's rule, found again by this fixed name.
pub const RULE: &str = "{4F1E5C7A-7A1D-4D92-9C3E-77A3B0F0D453}";
/// "Generic DNS servers" in an NRPT rule's ConfigOptions.
const GENERIC_SERVERS: u32 = 8;
const TLDS: &str = include_str!("tlds.txt");

/// The rule's namespaces: `.com`, `.net` and every other top-level domain,
/// but `arpa`.
pub fn namespaces() -> Vec<String> {
    TLDS.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.eq_ignore_ascii_case("arpa"))
        .map(|tld| format!(".{}", tld.to_ascii_lowercase()))
        .collect()
}

#[link(name = "dnsapi", kind = "raw-dylib")]
unsafe extern "system" {
    /// What `ipconfig /flushdns` calls; not in the SDK headers.
    fn DnsFlushResolverCache() -> i32;
}

/// Empties Windows' DNS cache, so a routing change applies to every name at once.
pub fn flush_cache() -> bool {
    // SAFETY: no arguments, no memory passed.
    unsafe { DnsFlushResolverCache() != 0 }
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// REG_MULTI_SZ: each string NUL-terminated, then one more NUL.
fn multi<S: AsRef<str>>(strings: &[S]) -> Vec<u8> {
    let mut out: Vec<u8> = strings.iter().flat_map(|s| wide(s.as_ref())).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

fn key_path() -> HSTRING {
    HSTRING::from(format!(r"{BASE}\{RULE}"))
}

/// Creates (or opens) `path` under HKLM for writing.
fn create(path: &HSTRING, options: REG_OPEN_CREATE_OPTIONS) -> Result<HKEY, String> {
    let mut hkey = HKEY::default();
    // SAFETY: `hkey` receives the key; callers close it.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path,
            None,
            PCWSTR::null(),
            options,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "creating the NRPT rule: {}",
            rc.to_hresult().message()
        ));
    }
    Ok(hkey)
}

/// Routes every name under a public top-level domain to `servers` (the
/// resolver's loopback addresses). Needs administrators.
pub fn set(servers: &[IpAddr]) -> Result<(), String> {
    let list = servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";");
    // A stable key from before stays stable when opened again: start afresh.
    let _ = remove();
    // The parent stays an ordinary key: other software's rules (a VPN's) go
    // there too, and a volatile key can't hold them.
    let parent = create(&HSTRING::from(BASE), REG_OPTION_NON_VOLATILE)?;
    // SAFETY: opened just above, closed once.
    let _ = unsafe { RegCloseKey(parent) };
    let hkey = create(&key_path(), REG_OPTION_VOLATILE)?;
    // SAFETY: `hkey` was just created; it's written and closed here.
    unsafe {
        let values: [(&str, _, Vec<u8>); 5] = [
            ("Version", REG_DWORD, 1u32.to_le_bytes().to_vec()),
            ("Name", REG_MULTI_SZ, multi(&namespaces())),
            ("GenericDNSServers", REG_SZ, wide(&list)),
            (
                "ConfigOptions",
                REG_DWORD,
                GENERIC_SERVERS.to_le_bytes().to_vec(),
            ),
            ("Comment", REG_SZ, wide("win4tress DNS filtering")),
        ];
        let mut failed = None;
        for (name, kind, data) in &values {
            let rc = RegSetValueExW(hkey, &HSTRING::from(*name), None, *kind, Some(data));
            if rc != ERROR_SUCCESS {
                failed = Some(format!(
                    "writing the NRPT rule's {name}: {}",
                    rc.to_hresult().message()
                ));
            }
        }
        let _ = RegCloseKey(hkey);
        if let Some(e) = failed {
            let _ = remove();
            return Err(e);
        }
    }
    flush_cache();
    Ok(())
}

/// Removes win4tress's rule; `Ok(false)` if there wasn't one.
pub fn remove() -> Result<bool, String> {
    // SAFETY: deletes win4tress's own key and its values.
    let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &key_path()) };
    let existed = match rc {
        ERROR_SUCCESS => true,
        ERROR_FILE_NOT_FOUND => false,
        _ => {
            return Err(format!(
                "removing the NRPT rule: {}",
                rc.to_hresult().message()
            ));
        }
    };
    if existed {
        // In case the tree delete left the (empty) key itself.
        // SAFETY: as above.
        let _ = unsafe {
            windows::Win32::System::Registry::RegDeleteKeyW(HKEY_LOCAL_MACHINE, &key_path())
        };
    }
    flush_cache();
    Ok(existed)
}

/// Whether win4tress's rule is in place.
pub fn present() -> bool {
    let mut hkey = HKEY::default();
    // SAFETY: opened read-only and closed.
    unsafe {
        let rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, &key_path(), None, KEY_READ, &mut hkey);
        if rc == ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_strings_end_with_two_nuls() {
        assert_eq!(multi(&["."]), vec![b'.', 0, 0, 0, 0, 0]);
        assert_eq!(wide("a"), vec![b'a', 0, 0, 0]);
    }

    #[test]
    fn the_rule_covers_public_tlds_only() {
        let names = namespaces();
        assert!(names.len() > 1000);
        for public in [".com", ".net", ".uk", ".xn--p1ai"] {
            assert!(names.iter().any(|n| n == public), "{public}");
        }
        // Local names and reverse lookups go Windows' usual way.
        for private in [".", ".local", ".lan", ".home", ".internal", ".arpa"] {
            assert!(!names.iter().any(|n| n == private), "{private}");
        }
        assert!(
            names
                .iter()
                .all(|n| n.starts_with('.') && *n == n.to_ascii_lowercase())
        );
    }

    #[test]
    fn reading_needs_no_admin() {
        // Present or not depends on the machine; it mustn't fail either way.
        let _ = present();
    }
}
