//! Proxy settings (SPEC §11 "Proxy changed"): WinHTTP's, which are machine-wide
//! and used by services, and the signed-in user's (WinINet, the ones browsers
//! and most apps follow), which only a process running as that user can read.

use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
    WinHttpGetDefaultProxyConfiguration, WinHttpGetIEProxyConfigForCurrentUser,
};
use windows::core::PWSTR;

/// Takes a string WinHTTP allocated, freeing it.
///
/// # Safety
/// `p` must be null or a string WinHTTP allocated with GlobalAlloc.
unsafe fn take(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: per the caller, a NUL-terminated string to free once read.
    unsafe {
        let s = p.to_string().ok();
        let _ = GlobalFree(Some(HGLOBAL(p.0.cast())));
        s.filter(|s| !s.is_empty())
    }
}

/// WinHTTP's machine-wide proxy, as one line: "direct" or "proxy … (bypass …)".
pub fn machine() -> Option<String> {
    let mut info = WINHTTP_PROXY_INFO::default();
    // SAFETY: `info` receives strings allocated by WinHTTP, freed by `take`.
    unsafe {
        WinHttpGetDefaultProxyConfiguration(&mut info).ok()?;
        let proxy = take(info.lpszProxy);
        let bypass = take(info.lpszProxyBypass);
        Some(if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
            describe(false, None, proxy, bypass)
        } else {
            "direct".into()
        })
    }
}

/// The current user's proxy settings, as one line.
pub fn current_user() -> Option<String> {
    let mut c = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    // SAFETY: `c` receives strings allocated by WinHTTP, freed by `take`.
    unsafe {
        WinHttpGetIEProxyConfigForCurrentUser(&mut c).ok()?;
        let pac = take(c.lpszAutoConfigUrl);
        let proxy = take(c.lpszProxy);
        let bypass = take(c.lpszProxyBypass);
        Some(describe(c.fAutoDetect.as_bool(), pac, proxy, bypass))
    }
}

/// e.g. "automatic detection; script http://wpad/wpad.dat; proxy 10.0.0.1:8080 (bypass <local>)".
pub fn describe(
    auto_detect: bool,
    pac: Option<String>,
    proxy: Option<String>,
    bypass: Option<String>,
) -> String {
    let mut parts = Vec::new();
    if auto_detect {
        parts.push("automatic detection".to_string());
    }
    if let Some(pac) = pac {
        parts.push(format!("script {pac}"));
    }
    if let Some(proxy) = proxy {
        parts.push(match bypass {
            Some(b) => format!("proxy {proxy} (bypass {b})"),
            None => format!("proxy {proxy}"),
        });
    }
    if parts.is_empty() {
        "direct".into()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_read_and_describe() {
        assert!(machine().is_some());
        assert!(current_user().is_some());
        assert_eq!(describe(false, None, None, None), "direct");
        assert_eq!(
            describe(
                true,
                None,
                Some("10.0.0.1:8080".into()),
                Some("<local>".into())
            ),
            "automatic detection; proxy 10.0.0.1:8080 (bypass <local>)"
        );
    }
}
