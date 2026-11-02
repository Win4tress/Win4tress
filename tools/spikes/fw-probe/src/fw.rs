//! Thin wrapper over the Windows Firewall COM API (INetFwPolicy2 / INetFwRule3).

use anyhow::{Context, Result};
use serde::Serialize;
use windows::Win32::Foundation::{HLOCAL, LocalFree, VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
pub use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRule3, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};

pub const PROFILES: [(&str, NET_FW_PROFILE_TYPE2); 3] = [
    ("domain", NET_FW_PROFILE2_DOMAIN),
    ("private", NET_FW_PROFILE2_PRIVATE),
    ("public", NET_FW_PROFILE2_PUBLIC),
];
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::FreeSid;
use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};
use windows::core::{BSTR, HSTRING, Interface, PWSTR};

pub struct Firewall {
    policy: INetFwPolicy2,
    rules: INetFwRules,
}

/// What to create. `None` leaves the condition at "any".
#[derive(Clone, Debug, Default)]
pub struct RuleSpec {
    pub name: String,
    pub group: String,
    pub inbound: bool,
    pub allow: bool,
    pub program: Option<String>,
    pub service: Option<String>,
    pub package_sid: Option<String>,
    pub remote_addresses: Option<String>,
    pub enabled: bool,
}

/// A rule as Windows reports it back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleView {
    pub name: String,
    pub group: String,
    pub inbound: bool,
    pub allow: bool,
    pub program: String,
    pub service: String,
    pub package_sid: String,
    pub remote_addresses: String,
    pub enabled: bool,
    pub profiles: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileStatus {
    pub name: &'static str,
    pub active: bool,
    pub firewall_on: bool,
    pub default_inbound_block: bool,
    pub default_outbound_block: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyStatus {
    pub profiles: Vec<ProfileStatus>,
    /// NET_FW_MODIFY_STATE: 0 ok, 1 group policy overrides, 2 inbound blocked by policy.
    pub modify_state: i32,
    pub rule_count: i32,
}

fn vbool(b: bool) -> VARIANT_BOOL {
    if b { VARIANT_TRUE } else { VARIANT_FALSE }
}

impl Firewall {
    pub fn open() -> Result<Firewall> {
        // SAFETY: plain COM initialisation and activation on this thread.
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .context("CoInitializeEx")?;
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
                .context("creating NetFwPolicy2")?;
            let rules = policy.Rules().context("INetFwPolicy2::Rules")?;
            Ok(Firewall { policy, rules })
        }
    }

    pub fn status(&self) -> Result<PolicyStatus> {
        // SAFETY: getters on a live COM object.
        unsafe {
            let current = self.policy.CurrentProfileTypes()?;
            let mut profiles = Vec::new();
            for (name, p) in [
                ("domain", NET_FW_PROFILE2_DOMAIN),
                ("private", NET_FW_PROFILE2_PRIVATE),
                ("public", NET_FW_PROFILE2_PUBLIC),
            ] {
                profiles.push(ProfileStatus {
                    name,
                    active: current & p.0 != 0,
                    firewall_on: self.policy.get_FirewallEnabled(p)?.as_bool(),
                    default_inbound_block: self.policy.get_DefaultInboundAction(p)?
                        == NET_FW_ACTION_BLOCK,
                    default_outbound_block: self.policy.get_DefaultOutboundAction(p)?
                        == NET_FW_ACTION_BLOCK,
                });
            }
            Ok(PolicyStatus {
                profiles,
                modify_state: self.policy.LocalPolicyModifyState()?.0,
                rule_count: self.rules.Count()?,
            })
        }
    }

    /// Whether the firewall is on for every active profile (block rules only bite then).
    pub fn enforcing(&self) -> Result<bool> {
        Ok(self
            .status()?
            .profiles
            .iter()
            .filter(|p| p.active)
            .all(|p| p.firewall_on))
    }

    pub fn add(&self, spec: &RuleSpec) -> Result<()> {
        // SAFETY: activation and setters on live COM objects; BSTRs are owned.
        unsafe {
            let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                .context("creating NetFwRule")?;
            rule.SetName(&BSTR::from(spec.name.as_str()))?;
            rule.SetDescription(&BSTR::from("win4tress spike 0.2 test rule"))?;
            rule.SetGrouping(&BSTR::from(spec.group.as_str()))?;
            rule.SetDirection(if spec.inbound {
                NET_FW_RULE_DIR_IN
            } else {
                NET_FW_RULE_DIR_OUT
            })?;
            rule.SetAction(if spec.allow {
                NET_FW_ACTION_ALLOW
            } else {
                NET_FW_ACTION_BLOCK
            })?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            if let Some(p) = &spec.program {
                rule.SetApplicationName(&BSTR::from(p.as_str()))
                    .context("ApplicationName")?;
            }
            if let Some(s) = &spec.service {
                rule.SetServiceName(&BSTR::from(s.as_str()))
                    .context("ServiceName")?;
            }
            if let Some(sid) = &spec.package_sid {
                let rule3: INetFwRule3 = rule.cast().context("INetFwRule3")?;
                rule3
                    .SetLocalAppPackageId(&BSTR::from(sid.as_str()))
                    .context("LocalAppPackageId")?;
            }
            if let Some(a) = &spec.remote_addresses {
                rule.SetRemoteAddresses(&BSTR::from(a.as_str()))
                    .context("RemoteAddresses")?;
            }
            rule.SetEnabled(vbool(spec.enabled))?;
            self.rules.Add(&rule).context("INetFwRules::Add")?;
        }
        Ok(())
    }

    /// The first rule with this name.
    pub fn get(&self, name: &str) -> Result<INetFwRule> {
        // SAFETY: lookup on a live COM object.
        unsafe { Ok(self.rules.Item(&BSTR::from(name))?) }
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        // SAFETY: removal on a live COM object.
        unsafe { Ok(self.rules.Remove(&BSTR::from(name))?) }
    }

    pub fn set_remote_addresses(&self, name: &str, addrs: &str) -> Result<()> {
        // SAFETY: setter on a live COM object.
        unsafe { Ok(self.get(name)?.SetRemoteAddresses(&BSTR::from(addrs))?) }
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        // SAFETY: setter on a live COM object.
        unsafe { Ok(self.get(name)?.SetEnabled(vbool(enabled))?) }
    }

    pub fn default_outbound_block(&self, profile: NET_FW_PROFILE_TYPE2) -> Result<bool> {
        // SAFETY: getter on a live COM object.
        unsafe { Ok(self.policy.get_DefaultOutboundAction(profile)? == NET_FW_ACTION_BLOCK) }
    }

    pub fn set_default_outbound_block(
        &self,
        profile: NET_FW_PROFILE_TYPE2,
        block: bool,
    ) -> Result<()> {
        // SAFETY: setter on a live COM object.
        unsafe {
            Ok(self.policy.put_DefaultOutboundAction(
                profile,
                if block {
                    NET_FW_ACTION_BLOCK
                } else {
                    NET_FW_ACTION_ALLOW
                },
            )?)
        }
    }

    pub fn enable_group(&self, group: &str, enable: bool) -> Result<()> {
        // SAFETY: call on a live COM object.
        unsafe {
            Ok(self.policy.EnableRuleGroup(
                NET_FW_PROFILE2_ALL.0,
                &BSTR::from(group),
                vbool(enable),
            )?)
        }
    }

    pub fn group_enabled(&self, group: &str) -> Result<bool> {
        // SAFETY: getter on a live COM object.
        unsafe {
            Ok(self
                .policy
                .IsRuleGroupEnabled(NET_FW_PROFILE2_ALL.0, &BSTR::from(group))?
                .as_bool())
        }
    }

    /// Every rule, in the order Windows returns them.
    pub fn all(&self) -> Result<Vec<INetFwRule>> {
        // SAFETY: standard IEnumVARIANT walk; each VARIANT owns its IDispatch and
        // is dropped (released) after we take our own reference.
        unsafe {
            let en: IEnumVARIANT = self.rules._NewEnum()?.cast()?;
            let mut out = Vec::new();
            loop {
                let mut batch = [
                    VARIANT::default(),
                    VARIANT::default(),
                    VARIANT::default(),
                    VARIANT::default(),
                ];
                let mut fetched = 0u32;
                let _ = en.Next(&mut batch, &mut fetched);
                if fetched == 0 {
                    break;
                }
                for v in &batch[..fetched as usize] {
                    let inner = &v.Anonymous.Anonymous;
                    if inner.vt == VT_DISPATCH
                        && let Some(disp) = (*inner.Anonymous.pdispVal).clone()
                    {
                        out.push(disp.cast::<INetFwRule>()?);
                    }
                }
            }
            Ok(out)
        }
    }

    /// Rules whose Grouping is exactly `group`.
    pub fn in_group(&self, group: &str) -> Result<Vec<RuleView>> {
        let mut out = Vec::new();
        for r in self.all()? {
            let v = view(&r)?;
            if v.group == group {
                out.push(v);
            }
        }
        Ok(out)
    }

    /// Removes every rule in `group`. Remove-by-name may leave same-named rules,
    /// so it repeats until none are left (bounded).
    pub fn clear_group(&self, group: &str) -> Result<usize> {
        let mut removed = 0;
        for _ in 0..10 {
            let rules = self.in_group(group)?;
            if rules.is_empty() {
                break;
            }
            for r in rules {
                if self.remove(&r.name).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    pub fn count(&self) -> Result<i32> {
        // SAFETY: getter on a live COM object.
        unsafe { Ok(self.rules.Count()?) }
    }
}

pub fn view(rule: &INetFwRule) -> Result<RuleView> {
    // SAFETY: getters on a live COM object.
    unsafe {
        let package_sid = match rule.cast::<INetFwRule3>() {
            Ok(r3) => r3
                .LocalAppPackageId()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            Err(_) => String::new(),
        };
        Ok(RuleView {
            name: rule.Name()?.to_string(),
            group: rule.Grouping().map(|b| b.to_string()).unwrap_or_default(),
            inbound: rule.Direction()? == NET_FW_RULE_DIR_IN,
            allow: rule.Action()? == NET_FW_ACTION_ALLOW,
            program: rule
                .ApplicationName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            service: rule
                .ServiceName()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            package_sid,
            remote_addresses: rule
                .RemoteAddresses()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            enabled: rule.Enabled()?.as_bool(),
            profiles: rule.Profiles()?,
        })
    }
}

/// The AppContainer SID string of a Store package family, e.g. "S-1-15-2-…".
pub fn package_sid(family_name: &str) -> Result<String> {
    // SAFETY: the SID is freed with FreeSid and the string with LocalFree.
    unsafe {
        let sid = DeriveAppContainerSidFromAppContainerName(&HSTRING::from(family_name))
            .context("DeriveAppContainerSidFromAppContainerName")?;
        let mut text = PWSTR::null();
        let converted = ConvertSidToStringSidW(sid, &mut text);
        FreeSid(sid);
        converted.context("ConvertSidToStringSidW")?;
        let s = text.to_string().context("SID string")?;
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        Ok(s)
    }
}
