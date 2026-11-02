//! What else decides how much win4tress can enforce (SPEC §7.7, spike 0.5):
//! another firewall registered with Security Center, and Group Policy or MDM
//! settings for Windows Firewall. Read-only; needs no elevation.

use w4_core::firewall::Environment;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSC_SECURITY_PRODUCT_STATE_ON, WSC_SECURITY_PROVIDER_FIREWALL, WSCProductList,
};
use windows::core::HSTRING;

use crate::{Error, Result};

/// A firewall product registered with Security Center.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallProduct {
    pub name: String,
    pub on: bool,
    /// Windows Firewall lists itself with "NULL" here (spike 0.5).
    pub guid: String,
}

impl FirewallProduct {
    fn is_windows(&self) -> bool {
        self.guid.is_empty() || self.guid.eq_ignore_ascii_case("NULL")
    }
}

/// One profile's policy settings: `None` where policy doesn't set it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProfilePolicy {
    pub allow_local_rules: Option<bool>,
    pub outbound_block: Option<bool>,
}

/// The conclusions (pure, for tests). `active` are the profiles in use, as
/// "domain", "private", "public"; `policies` per source and profile.
pub fn assess(
    products: &[FirewallProduct],
    policies: &[(&str, &str, ProfilePolicy)],
    active: &[&str],
) -> Environment {
    let mut env = Environment {
        other_firewalls: products
            .iter()
            .filter(|p| p.on && !p.is_windows())
            .map(|p| p.name.clone())
            .collect(),
        ..Default::default()
    };
    let add = |list: &mut Vec<String>, source: &str| {
        if !list.iter().any(|s| s == source) {
            list.push(source.to_string());
        }
    };
    for &(source, profile, policy) in policies {
        if !active.contains(&profile) {
            continue;
        }
        if policy.allow_local_rules == Some(false) {
            add(&mut env.local_rules_ignored_by, source);
        }
        if policy.outbound_block.is_some() {
            add(&mut env.outbound_default_forced_by, source);
        }
    }
    env
}

/// Reads Security Center and the policy registry keys now.
pub fn detect(active: &[&str]) -> Result<Environment> {
    let active: Vec<String> = active.iter().map(|s| s.to_string()).collect();
    let products = std::thread::Builder::new()
        .name("w4-environment".into())
        .spawn(firewall_products)
        .map_err(|e| Error::Invalid(format!("starting the environment check: {e}")))?
        .join()
        .map_err(|_| Error::Invalid("the environment check panicked".into()))??;
    let mut policies = Vec::new();
    for (source, base) in POLICY_KEYS {
        for (profile, key) in PROFILE_KEYS {
            let path = format!(r"{base}\{key}");
            policies.push((
                source,
                profile,
                ProfilePolicy {
                    allow_local_rules: dword(&path, "AllowLocalPolicyMerge").map(|v| v != 0),
                    outbound_block: dword(&path, "DefaultOutboundAction").map(|v| v != 0),
                },
            ));
        }
    }
    let active: Vec<&str> = active.iter().map(String::as_str).collect();
    Ok(assess(&products, &policies, &active))
}

const POLICY_KEYS: [(&str, &str); 2] = [
    (
        "Group Policy",
        r"SOFTWARE\Policies\Microsoft\WindowsFirewall",
    ),
    (
        "MDM",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm",
    ),
];

const PROFILE_KEYS: [(&str, &str); 3] = [
    ("domain", "DomainProfile"),
    ("private", "StandardProfile"),
    ("public", "PublicProfile"),
];

fn dword(path: &str, value: &str) -> Option<u32> {
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `data` and `size` are valid for the call; the value is a DWORD.
    unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(path),
            &HSTRING::from(value),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(data).cast()),
            Some(&mut size),
        )
    }
    .ok()
    .ok()?;
    Some(data)
}

/// On its own thread: Security Center's product list is an apartment object.
fn firewall_products() -> Result<Vec<FirewallProduct>> {
    // SAFETY: COM is initialised and torn down on this thread; the product
    // list is used only here.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .map_err(|e| Error::windows("CoInitializeEx", e))?;
        let result = (|| {
            let list: IWSCProductList =
                CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER)
                    .map_err(|e| Error::windows("creating WSCProductList", e))?;
            list.Initialize(WSC_SECURITY_PROVIDER_FIREWALL)
                .map_err(|e| Error::windows("WSCProductList::Initialize", e))?;
            let count = list
                .Count()
                .map_err(|e| Error::windows("WSCProductList::Count", e))?;
            let mut out = Vec::new();
            for i in 0..count.max(0) as u32 {
                let p = list
                    .get_Item(i)
                    .map_err(|e| Error::windows("WSCProductList::Item", e))?;
                out.push(FirewallProduct {
                    name: p.ProductName().map(|b| b.to_string()).unwrap_or_default(),
                    on: p
                        .ProductState()
                        .is_ok_and(|s| s == WSC_SECURITY_PRODUCT_STATE_ON),
                    guid: p.ProductGuid().map(|b| b.to_string()).unwrap_or_default(),
                });
            }
            Ok(out)
        })();
        CoUninitialize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product(name: &str, on: bool, guid: &str) -> FirewallProduct {
        FirewallProduct {
            name: name.into(),
            on,
            guid: guid.into(),
        }
    }

    #[test]
    fn another_firewall_takes_charge() {
        let windows = product("Windows Firewall", true, "NULL");
        assert!(
            assess(std::slice::from_ref(&windows), &[], &["private"])
                .monitoring_only()
                .is_none()
        );
        let other = product(
            "Example Security Firewall",
            true,
            "{0B1C2D3E-0000-0000-0000-000000000000}",
        );
        let env = assess(&[windows.clone(), other.clone()], &[], &["private"]);
        assert_eq!(env.other_firewalls, ["Example Security Firewall"]);
        assert!(
            env.monitoring_only()
                .unwrap()
                .starts_with("Example Security Firewall is in charge")
        );
        // Registered but off: Windows Firewall is in charge.
        let off = product("Example Security Firewall", false, "{0B1C}");
        assert!(
            assess(&[windows, off], &[], &["private"])
                .other_firewalls
                .is_empty()
        );
    }

    #[test]
    fn policies_count_for_profiles_in_use() {
        let no_merge = ProfilePolicy {
            allow_local_rules: Some(false),
            outbound_block: None,
        };
        let forced = ProfilePolicy {
            allow_local_rules: Some(true),
            outbound_block: Some(false),
        };
        let policies = [
            ("Group Policy", "domain", no_merge),
            ("MDM", "private", forced),
            ("MDM", "domain", no_merge),
        ];
        // On a private network, only the MDM outbound setting applies.
        let home = assess(&[], &policies, &["private"]);
        assert!(home.local_rules_ignored_by.is_empty());
        assert_eq!(home.outbound_default_forced_by, ["MDM"]);
        assert!(home.monitoring_only().is_none());
        // On the domain network, local rules are ignored: monitoring only.
        let office = assess(&[], &policies, &["domain", "private"]);
        assert_eq!(
            office.monitoring_only().unwrap(),
            "Group Policy and MDM tell Windows Firewall to ignore local rules, win4tress's included"
        );
        let gp_only = assess(&[], &policies[..1], &["domain"]);
        assert_eq!(
            gp_only.monitoring_only().unwrap(),
            "Group Policy tells Windows Firewall to ignore local rules, win4tress's included"
        );
    }

    /// Reading needs no elevation, so this runs everywhere.
    #[test]
    fn detects_this_pc() {
        let env = detect(&["private", "public"]).expect("detection runs");
        // The dev PC runs Windows Firewall only (spike 0.5).
        assert!(env.other_firewalls.is_empty(), "{env:?}");
    }
}
