//! Which Windows this is, for Settings → About and the details it copies:
//! "Windows 11 Pro 24H2 (build 26100.4652)". From the registry, where Windows
//! keeps it; its ProductName still says "Windows 10" on Windows 11, so the
//! name comes from the build number instead.

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::core::{PCWSTR, w};

const KEY: PCWSTR = w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

fn text(name: PCWSTR) -> Option<String> {
    let mut data = [0u16; 128];
    let mut size = size_of_val(&data) as u32;
    // SAFETY: `data` holds `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            KEY,
            name,
            RRF_RT_REG_SZ,
            None,
            Some(data.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    // `size` counts the terminating NUL.
    let len = (size as usize / 2).saturating_sub(1);
    (rc == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&data[..len]))
}

fn number(name: PCWSTR) -> Option<u32> {
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: a DWORD read into `value`, of the size given.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            KEY,
            name,
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast()),
            Some(&mut size),
        )
    };
    (rc == ERROR_SUCCESS).then_some(value)
}

/// "Windows 11 Pro 24H2 (build 26100.4652)", leaving out what isn't known.
pub fn describe() -> String {
    let build = text(w!("CurrentBuildNumber")).unwrap_or_default();
    let name = match build.parse::<u32>() {
        Ok(b) if b >= 22000 => "Windows 11",
        Ok(_) => "Windows 10",
        Err(_) => "Windows",
    };
    let mut out = name.to_string();
    if let Some(e) = text(w!("EditionID")) {
        out = format!("{out} {}", edition(&e));
    }
    if let Some(v) = text(w!("DisplayVersion")) {
        out = format!("{out} {v}");
    }
    if !build.is_empty() {
        match number(w!("UBR")) {
            Some(ubr) => out = format!("{out} (build {build}.{ubr})"),
            None => out = format!("{out} (build {build})"),
        }
    }
    out
}

/// The edition's name as Windows shows it, from its EditionID.
fn edition(id: &str) -> &str {
    match id {
        "Core" | "CoreSingleLanguage" | "CoreCountrySpecific" => "Home",
        "Professional" => "Pro",
        "ProfessionalEducation" => "Pro Education",
        "ProfessionalWorkstation" => "Pro for Workstations",
        "EnterpriseS" => "Enterprise LTSC",
        "IoTEnterpriseS" => "IoT Enterprise LTSC",
        "IoTEnterprise" => "IoT Enterprise",
        "ServerRdsh" => "Enterprise multi-session",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_editions() {
        assert_eq!(edition("Professional"), "Pro");
        assert_eq!(edition("Core"), "Home");
        assert_eq!(edition("Enterprise"), "Enterprise");
    }

    #[test]
    fn describes_this_pc() {
        let d = describe();
        assert!(d.starts_with("Windows"), "{d}");
        assert!(d.contains("(build "), "{d}");
    }
}
