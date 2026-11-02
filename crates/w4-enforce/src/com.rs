//! Windows Firewall through its COM API (INetFwPolicy2 / INetFwRule3), validated
//! by spike 0.2. COM objects stay on one dedicated thread; callers send it jobs.

use std::sync::mpsc;

use w4_core::firewall::{FirewallState, ProfileState};
use windows::Win32::Foundation::{HLOCAL, LocalFree, VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRule3, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::FreeSid;
use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};
use windows::core::{BSTR, HSTRING, Interface, PWSTR};

use crate::address::AddressSet;
use crate::model::{ActualRule, PROFILES_ALL, PROTOCOL_ANY, WindowsRule};
use crate::plan::Change;
use crate::{EnforcementBackend, Error, Result};

type Job = Box<dyn FnOnce(&Session) + Send>;

/// Windows Firewall, for one rule group. Cheap to call from any thread.
pub struct ComFirewall {
    jobs: mpsc::Sender<Job>,
    group: String,
}

impl ComFirewall {
    /// Starts the COM thread. `group` is the only group this instance reads or changes.
    pub fn start(group: impl Into<String>) -> Result<ComFirewall> {
        let (jobs, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("w4-firewall".into())
            .spawn(move || {
                // SAFETY: COM is initialised and torn down on this thread only.
                if let Err(e) = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok() {
                    let _ = ready_tx.send(Err(Error::windows("CoInitializeEx", e)));
                    return;
                }
                match Session::open() {
                    Ok(session) => {
                        let _ = ready_tx.send(Ok(()));
                        for job in rx {
                            job(&session);
                        }
                        drop(session);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
                // SAFETY: matches the successful CoInitializeEx above.
                unsafe { CoUninitialize() };
            })
            .map_err(|e| Error::Invalid(format!("starting the firewall thread: {e}")))?;
        ready_rx.recv().map_err(|_| Error::Stopped)??;
        Ok(ComFirewall {
            jobs,
            group: group.into(),
        })
    }

    fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Session) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.jobs
            .send(Box::new(move |s| {
                let _ = tx.send(f(s));
            }))
            .map_err(|_| Error::Stopped)?;
        rx.recv().map_err(|_| Error::Stopped)?
    }
}

impl EnforcementBackend for ComFirewall {
    fn group(&self) -> &str {
        &self.group
    }

    fn list(&self) -> Result<Vec<ActualRule>> {
        let group = self.group.clone();
        self.call(move |s| s.list(&group))
    }

    fn apply(&self, change: &Change) -> Result<()> {
        let group = self.group.clone();
        let change = change.clone();
        self.call(move |s| match &change {
            Change::Create(rule) => s.create(rule, &group),
            Change::Update { name, rule } => s.update(name, rule),
            Change::Recreate { name, rule } => {
                s.delete(name)?;
                s.create(rule, &group)
            }
            Change::Delete { name } => s.delete(name),
        })
    }

    fn set_group_enabled(&self, enabled: bool) -> Result<()> {
        let group = self.group.clone();
        self.call(move |s| s.set_group_enabled(&group, enabled))
    }

    fn state(&self) -> Result<FirewallState> {
        self.call(|s| s.state())
    }

    fn others(&self) -> Result<Vec<ActualRule>> {
        let group = self.group.clone();
        self.call(move |s| s.others(&group))
    }

    fn turn_on(&self, profile: &str) -> Result<()> {
        let p = profile_type(profile)?;
        self.call(move |s| {
            // SAFETY: a setter on a live COM object, on the COM thread.
            unsafe { s.policy.put_FirewallEnabled(p, VARIANT_TRUE) }
                .map_err(|e| Error::windows("FirewallEnabled", e))
        })
    }

    fn set_defaults(&self, profile: &str, inbound_block: bool, outbound_block: bool) -> Result<()> {
        let p = profile_type(profile)?;
        let action = |block: bool| {
            if block {
                NET_FW_ACTION_BLOCK
            } else {
                NET_FW_ACTION_ALLOW
            }
        };
        self.call(move |s| {
            // SAFETY: setters on a live COM object, on the COM thread.
            unsafe {
                s.policy
                    .put_DefaultInboundAction(p, action(inbound_block))
                    .map_err(|e| Error::windows("DefaultInboundAction", e))?;
                s.policy
                    .put_DefaultOutboundAction(p, action(outbound_block))
                    .map_err(|e| Error::windows("DefaultOutboundAction", e))
            }
        })
    }
}

fn profile_type(name: &str) -> Result<NET_FW_PROFILE_TYPE2> {
    match name {
        "domain" => Ok(NET_FW_PROFILE2_DOMAIN),
        "private" => Ok(NET_FW_PROFILE2_PRIVATE),
        "public" => Ok(NET_FW_PROFILE2_PUBLIC),
        other => Err(Error::Invalid(format!(
            "no firewall profile called {other:?}"
        ))),
    }
}

fn vbool(b: bool) -> VARIANT_BOOL {
    if b { VARIANT_TRUE } else { VARIANT_FALSE }
}

fn opt(b: windows::core::Result<BSTR>) -> Option<String> {
    b.ok().map(|b| b.to_string()).filter(|s| !s.is_empty())
}

struct Session {
    policy: INetFwPolicy2,
    rules: INetFwRules,
}

impl Session {
    fn open() -> Result<Session> {
        // SAFETY: plain COM activation on the firewall thread.
        unsafe {
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| Error::windows("creating NetFwPolicy2", e))?;
            let rules = policy
                .Rules()
                .map_err(|e| Error::windows("INetFwPolicy2::Rules", e))?;
            Ok(Session { policy, rules })
        }
    }

    fn state(&self) -> Result<FirewallState> {
        // SAFETY: getters on live COM objects.
        unsafe {
            let w = |what, e| Error::windows(what, e);
            let current = self
                .policy
                .CurrentProfileTypes()
                .map_err(|e| w("CurrentProfileTypes", e))?;
            let mut profiles = Vec::new();
            for (name, p) in [
                ("domain", NET_FW_PROFILE2_DOMAIN),
                ("private", NET_FW_PROFILE2_PRIVATE),
                ("public", NET_FW_PROFILE2_PUBLIC),
            ] {
                profiles.push(ProfileState {
                    name: name.into(),
                    active: current & p.0 != 0,
                    firewall_on: self
                        .policy
                        .get_FirewallEnabled(p)
                        .map_err(|e| w("FirewallEnabled", e))?
                        .as_bool(),
                    inbound_default_block: self
                        .policy
                        .get_DefaultInboundAction(p)
                        .map_err(|e| w("DefaultInboundAction", e))?
                        == NET_FW_ACTION_BLOCK,
                    outbound_default_block: self
                        .policy
                        .get_DefaultOutboundAction(p)
                        .map_err(|e| w("DefaultOutboundAction", e))?
                        == NET_FW_ACTION_BLOCK,
                });
            }
            Ok(FirewallState {
                profiles,
                policy_override: self
                    .policy
                    .LocalPolicyModifyState()
                    .map_err(|e| w("LocalPolicyModifyState", e))?
                    != NET_FW_MODIFY_STATE_OK,
                rule_count: self.rules.Count().map_err(|e| w("Rules::Count", e))?.max(0) as u32,
            })
        }
    }

    /// Every rule in `group`, read back.
    fn list(&self, group: &str) -> Result<Vec<ActualRule>> {
        let mut out = Vec::new();
        for rule in self.all()? {
            // SAFETY: getters on a live COM object.
            let in_group = unsafe { rule.Grouping() }.is_ok_and(|g| g == group);
            if in_group {
                out.push(read(&rule)?);
            }
        }
        Ok(out)
    }

    /// Every rule outside `group`. One that can't be read is skipped.
    fn others(&self, group: &str) -> Result<Vec<ActualRule>> {
        Ok(self
            .all()?
            .iter()
            // SAFETY: a getter on a live COM object.
            .filter(|rule| unsafe { rule.Grouping() }.map_or(true, |g| g != group))
            .filter_map(|rule| read(rule).ok())
            .collect())
    }

    fn all(&self) -> Result<Vec<INetFwRule>> {
        // SAFETY: standard IEnumVARIANT walk; each VARIANT owns its IDispatch and
        // releases it when dropped, after we've taken our own reference.
        unsafe {
            let en: IEnumVARIANT = self
                .rules
                ._NewEnum()
                .and_then(|u| u.cast())
                .map_err(|e| Error::windows("enumerating rules", e))?;
            let mut out = Vec::new();
            loop {
                let mut batch: [VARIANT; 16] = Default::default();
                let mut fetched = 0u32;
                let _ = en.Next(&mut batch, &mut fetched);
                if fetched == 0 {
                    break;
                }
                for v in &batch[..fetched as usize] {
                    let inner = &v.Anonymous.Anonymous;
                    if inner.vt == VT_DISPATCH
                        && let Some(disp) = (*inner.Anonymous.pdispVal).clone()
                        && let Ok(rule) = disp.cast::<INetFwRule>()
                    {
                        out.push(rule);
                    }
                }
            }
            Ok(out)
        }
    }

    fn create(&self, r: &WindowsRule, group: &str) -> Result<()> {
        let w = |what, e| Error::windows(what, e);
        // SAFETY: activation and setters on live COM objects; BSTRs are owned.
        unsafe {
            let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| w("creating NetFwRule", e))?;
            rule.SetName(&BSTR::from(r.name.as_str()))
                .map_err(|e| w("Name", e))?;
            rule.SetDescription(&BSTR::from(r.key.description()))
                .map_err(|e| w("Description", e))?;
            rule.SetGrouping(&BSTR::from(group))
                .map_err(|e| w("Grouping", e))?;
            rule.SetDirection(if r.inbound {
                NET_FW_RULE_DIR_IN
            } else {
                NET_FW_RULE_DIR_OUT
            })
            .map_err(|e| w("Direction", e))?;
            rule.SetAction(if r.block {
                NET_FW_ACTION_BLOCK
            } else {
                NET_FW_ACTION_ALLOW
            })
            .map_err(|e| w("Action", e))?;
            rule.SetProfiles(PROFILES_ALL)
                .map_err(|e| w("Profiles", e))?;
            if let Some(p) = &r.program {
                rule.SetApplicationName(&BSTR::from(p.as_str()))
                    .map_err(|e| w("ApplicationName", e))?;
            }
            if let Some(s) = &r.service {
                rule.SetServiceName(&BSTR::from(s.as_str()))
                    .map_err(|e| w("ServiceName", e))?;
            }
            if let Some(sid) = &r.package_sid {
                let rule3: INetFwRule3 = rule.cast().map_err(|e| w("INetFwRule3", e))?;
                rule3
                    .SetLocalAppPackageId(&BSTR::from(sid.as_str()))
                    .map_err(|e| w("LocalAppPackageId", e))?;
            }
            // Ports need a protocol, so it's set first.
            if r.protocol != PROTOCOL_ANY {
                rule.SetProtocol(r.protocol).map_err(|e| w("Protocol", e))?;
            }
            if !r.remote_ports.is_empty() {
                rule.SetRemotePorts(&BSTR::from(r.remote_ports.as_str()))
                    .map_err(|e| w("RemotePorts", e))?;
            }
            rule.SetRemoteAddresses(&BSTR::from(r.remote.to_windows()))
                .map_err(|e| w("RemoteAddresses", e))?;
            rule.SetEnabled(vbool(r.enabled))
                .map_err(|e| w("Enabled", e))?;
            self.rules.Add(&rule).map_err(|e| w("adding the rule", e))?;
        }
        Ok(())
    }

    fn update(&self, name: &str, r: &WindowsRule) -> Result<()> {
        let w = |what, e| Error::windows(what, e);
        // SAFETY: lookup and setters on live COM objects.
        unsafe {
            let rule = self
                .rules
                .Item(&BSTR::from(name))
                .map_err(|e| w("finding the rule", e))?;
            rule.SetAction(if r.block {
                NET_FW_ACTION_BLOCK
            } else {
                NET_FW_ACTION_ALLOW
            })
            .map_err(|e| w("Action", e))?;
            rule.SetRemoteAddresses(&BSTR::from(r.remote.to_windows()))
                .map_err(|e| w("RemoteAddresses", e))?;
            rule.SetEnabled(vbool(r.enabled))
                .map_err(|e| w("Enabled", e))?;
            if name != r.name {
                rule.SetName(&BSTR::from(r.name.as_str()))
                    .map_err(|e| w("Name", e))?;
            }
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        // SAFETY: removal on a live COM object.
        unsafe { self.rules.Remove(&BSTR::from(name)) }
            .map_err(|e| Error::windows("removing the rule", e))
    }

    fn set_group_enabled(&self, group: &str, enabled: bool) -> Result<()> {
        // SAFETY: call on a live COM object.
        unsafe {
            self.policy
                .EnableRuleGroup(PROFILES_ALL, &BSTR::from(group), vbool(enabled))
        }
        .map_err(|e| Error::windows("EnableRuleGroup", e))
    }
}

fn read(rule: &INetFwRule) -> Result<ActualRule> {
    let w = |what, e| Error::windows(what, e);
    // SAFETY: getters on a live COM object.
    unsafe {
        let package_sid = rule
            .cast::<INetFwRule3>()
            .ok()
            .and_then(|r3| opt(r3.LocalAppPackageId()));
        Ok(ActualRule {
            name: rule.Name().map_err(|e| w("Name", e))?.to_string(),
            description: rule
                .Description()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            inbound: rule.Direction().map_err(|e| w("Direction", e))? == NET_FW_RULE_DIR_IN,
            block: rule.Action().map_err(|e| w("Action", e))? == NET_FW_ACTION_BLOCK,
            program: opt(rule.ApplicationName()),
            service: opt(rule.ServiceName()),
            package_sid,
            remote: AddressSet::parse(
                &rule
                    .RemoteAddresses()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
            ),
            local: AddressSet::parse(
                &rule
                    .LocalAddresses()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
            ),
            protocol: rule.Protocol().unwrap_or(PROTOCOL_ANY),
            local_ports: rule.LocalPorts().map(|b| b.to_string()).unwrap_or_default(),
            remote_ports: rule
                .RemotePorts()
                .map(|b| b.to_string())
                .unwrap_or_default(),
            enabled: rule.Enabled().map_err(|e| w("Enabled", e))?.as_bool(),
            profiles: rule.Profiles().unwrap_or(PROFILES_ALL),
        })
    }
}

/// `%SystemRoot%\x` → `C:\Windows\x`, from this process's environment. Windows
/// Firewall keeps program paths with such variables in them.
pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = HSTRING::from(s);
    // SAFETY: a size query, then a call into a buffer of that size.
    unsafe {
        let needed = ExpandEnvironmentStringsW(&src, None);
        if needed == 0 {
            return s.to_string();
        }
        let mut buf = vec![0u16; needed as usize];
        let written = ExpandEnvironmentStringsW(&src, Some(&mut buf)) as usize;
        if written == 0 || written > buf.len() {
            return s.to_string();
        }
        // `written` counts the terminating NUL.
        String::from_utf16_lossy(&buf[..written - 1])
    }
}

/// The AppContainer SID of a Store package family, e.g. "S-1-15-2-…".
pub fn package_sid(family: &str) -> Option<String> {
    // SAFETY: the SID is freed with FreeSid and the string with LocalFree.
    unsafe {
        let sid = DeriveAppContainerSidFromAppContainerName(&HSTRING::from(family)).ok()?;
        let mut text = PWSTR::null();
        let converted = ConvertSidToStringSidW(sid, &mut text);
        FreeSid(sid);
        converted.ok()?;
        let s = text.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_sid_is_derived_without_the_package_running() {
        let sid = package_sid("Microsoft.WindowsCalculator_8wekyb3d8bbwe").expect("derivable");
        assert!(sid.starts_with("S-1-15-2-"), "{sid}");
    }

    /// Reading needs no elevation (spike 0.2), so this runs everywhere.
    #[test]
    fn reads_firewall_state_and_an_empty_group() {
        let fw =
            ComFirewall::start("win4tress unit test (never created)").expect("COM thread starts");
        let state = fw.state().expect("state");
        assert_eq!(state.profiles.len(), 3);
        assert!(fw.list().expect("list").is_empty());
        // Everything else is "others": Windows ships hundreds of rules.
        let others = fw.others().expect("others");
        assert!(others.len() > 50, "{} rules", others.len());
        assert!(others.iter().any(|r| {
            r.program.as_deref().is_some_and(|p| {
                p.to_ascii_lowercase().contains("%systemroot%")
                    || p.to_ascii_lowercase().contains(r"\windows\")
            })
        }));
    }

    #[test]
    fn expands_environment_variables() {
        let expanded = expand_env(r"%SystemRoot%\System32\svchost.exe");
        assert!(!expanded.contains('%'), "{expanded}");
        assert!(
            expanded
                .to_ascii_lowercase()
                .ends_with(r"\system32\svchost.exe")
        );
        assert_eq!(expand_env(r"C:\Plain\path.exe"), r"C:\Plain\path.exe");
    }
}
