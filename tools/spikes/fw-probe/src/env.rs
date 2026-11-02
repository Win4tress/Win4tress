//! Spike 0.5: what the firewall environment is (SPEC §7.7). Read-only.

use std::path::Path;
use std::process::Command;

use anyhow::Result;
use serde::Serialize;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSC_SECURITY_PRODUCT_STATE_ON, WSC_SECURITY_PROVIDER,
    WSC_SECURITY_PROVIDER_ANTIVIRUS, WSC_SECURITY_PROVIDER_FIREWALL, WSC_SECURITY_PROVIDER_HEALTH,
    WSCProductList, WscGetSecurityProviderHealth,
};

use crate::fw::Firewall;
use crate::{Report, write_report};

#[derive(Debug, Serialize)]
struct Product {
    name: String,
    on: bool,
    default: bool,
    guid: String,
}

/// Products registered with Windows Security Center for one provider kind.
fn products(kind: WSC_SECURITY_PROVIDER) -> Result<Vec<Product>> {
    // SAFETY: plain COM activation and getters on this thread.
    unsafe {
        let list: IWSCProductList = CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER)?;
        list.Initialize(kind)?;
        let mut out = Vec::new();
        for i in 0..list.Count()?.max(0) as u32 {
            let p = list.get_Item(i)?;
            out.push(Product {
                name: p.ProductName().map(|b| b.to_string()).unwrap_or_default(),
                on: p
                    .ProductState()
                    .is_ok_and(|s| s == WSC_SECURITY_PRODUCT_STATE_ON),
                default: p.ProductIsDefault().is_ok_and(|b| b.as_bool()),
                guid: p.ProductGuid().map(|b| b.to_string()).unwrap_or_default(),
            });
        }
        Ok(out)
    }
}

fn health(kind: WSC_SECURITY_PROVIDER) -> String {
    let mut h = WSC_SECURITY_PROVIDER_HEALTH::default();
    // SAFETY: `h` is a valid out pointer.
    match unsafe { WscGetSecurityProviderHealth(kind.0 as u32, &mut h) } {
        Ok(()) => match h.0 {
            0 => "good".into(),
            1 => "not monitored".into(),
            2 => "poor".into(),
            3 => "snoozed".into(),
            n => format!("{n}"),
        },
        Err(e) => format!("unavailable: {e}"),
    }
}

/// `reg query` output for a key, or None if it doesn't exist.
fn reg(key: &str) -> Option<String> {
    let out = Command::new("reg")
        .args(["query", key, "/s"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn run(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    // SAFETY: COM for this thread (Security Center); the firewall wrapper also
    // initialises, which is harmless on the same apartment.
    let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let mut r = Report::default();

    r.info(
        "Security Center: firewall health",
        health(WSC_SECURITY_PROVIDER_FIREWALL),
        None,
    );
    r.info(
        "Security Center: antivirus health",
        health(WSC_SECURITY_PROVIDER_ANTIVIRUS),
        None,
    );
    let firewalls = products(WSC_SECURITY_PROVIDER_FIREWALL);
    match &firewalls {
        Ok(list) => r.info(
            "Security Center: firewall products",
            format!("{list:?}"),
            None,
        ),
        Err(e) => r.check(
            "Security Center: firewall products",
            false,
            format!("{e:#}"),
            None,
        ),
    }
    match products(WSC_SECURITY_PROVIDER_ANTIVIRUS) {
        Ok(list) => r.info(
            "Security Center: antivirus products",
            format!("{list:?}"),
            None,
        ),
        Err(e) => r.check(
            "Security Center: antivirus products",
            false,
            format!("{e:#}"),
            None,
        ),
    }

    let fw = Firewall::open()?;
    let status = fw.status()?;
    r.info(
        "Windows Firewall",
        format!(
            "modify state {}; {}",
            status.modify_state,
            status
                .profiles
                .iter()
                .map(|p| format!(
                    "{}{}: {}, out default {}",
                    p.name,
                    if p.active { " (active)" } else { "" },
                    if p.firewall_on { "on" } else { "off" },
                    if p.default_outbound_block {
                        "block"
                    } else {
                        "allow"
                    }
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        None,
    );

    let gp = reg(r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall");
    r.info(
        "Group Policy firewall settings",
        gp.clone().unwrap_or_else(|| "none".into()),
        None,
    );
    let mdm = reg(r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall");
    r.info(
        "MDM firewall settings",
        mdm.clone().unwrap_or_else(|| "none".into()),
        None,
    );

    // What win4tress would conclude (SPEC §7.7).
    let gp_text = gp.unwrap_or_default().to_ascii_lowercase();
    let third_party: Vec<String> = firewalls
        .as_ref()
        .map(|l| {
            l.iter()
                .filter(|p| p.on && !p.name.to_ascii_lowercase().contains("windows"))
                .map(|p| p.name.clone())
                .collect()
        })
        .unwrap_or_default();
    let conclusions = [
        (
            "third-party firewall in charge",
            if third_party.is_empty() {
                "no".to_string()
            } else {
                format!("yes: {third_party:?}")
            },
        ),
        (
            "Windows Firewall off for an active profile",
            format!(
                "{}",
                !status
                    .profiles
                    .iter()
                    .filter(|p| p.active)
                    .all(|p| p.firewall_on)
            ),
        ),
        (
            "local rule merging disabled by policy",
            format!(
                "{}",
                gp_text.contains("allowlocalpolicymerge") && gp_text.contains("0x0")
            ),
        ),
        (
            "outbound default forced by policy",
            format!("{}", gp_text.contains("defaultoutboundaction")),
        ),
        (
            "local changes overridden (modify state)",
            format!("{}", status.modify_state != 0),
        ),
    ];
    for (what, answer) in conclusions {
        r.info(&format!("conclusion: {what}"), answer, None);
    }
    r.check(
        "Security Center lists products without error",
        firewalls.is_ok(),
        "",
        None,
    );

    write_report(out, &r)?;
    println!("\nResults in {}", out.display());
    Ok(())
}
