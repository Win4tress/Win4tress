//! Which WFP filter dropped a connection, as a cause the user can read (SPEC
//! §7.9, spike 0.4). Windows Firewall gives each filter its rule's name, so
//! the name leads to the rule. Needs the BFE engine handle: administrators.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use w4_core::firewall::{BlockedBy, BlockedByKind};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER0, FWPM_PROVIDER_MPSSVC_WF, FWPM_PROVIDER_MPSSVC_WSH, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterGetById0, FwpmFreeMemory0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR};

use crate::model::NAME_PREFIX;
use crate::{Error, Result};

/// Filter ids are looked up once; beyond this many, the cache starts over.
const CACHE_MAX: usize = 10_000;
/// A filter that couldn't be looked up is tried again after this long: it may
/// be missing only while Windows Firewall rebuilds its filters (a lookup per
/// drop would be too many in a flood).
const MISS_RETRY: Duration = Duration::from_secs(5);

/// What a filter's name and provider say it is (pure, for tests).
pub fn classify(name: &str, provider: Option<&GUID>) -> BlockedBy {
    let kind = match provider {
        _ if name.starts_with(NAME_PREFIX) => BlockedByKind::Win4tress,
        // "Default Outbound", "Default Inbound": no rule allowed it.
        Some(p) if *p == FWPM_PROVIDER_MPSSVC_WF && name.starts_with("Default ") => {
            BlockedByKind::WindowsDefault
        }
        Some(p) if *p == FWPM_PROVIDER_MPSSVC_WF => BlockedByKind::WindowsRule,
        _ => BlockedByKind::Other,
    };
    let name = match provider {
        Some(p) if *p == FWPM_PROVIDER_MPSSVC_WSH => format!("Windows Service Hardening: {name}"),
        _ if name.is_empty() => "an unnamed filter".into(),
        _ => name.to_string(),
    };
    BlockedBy { kind, name }
}

/// A drop whose filter can't be named (pure, for tests).
pub fn unknown(id: u64) -> BlockedBy {
    BlockedBy {
        kind: BlockedByKind::Other,
        name: if id == 0 {
            "a drop that names no filter".into()
        } else {
            format!("a filter that couldn't be looked up (#{id})")
        },
    }
}

/// A WFP engine session, for looking up filters by id.
pub struct Filters {
    engine: HANDLE,
    cache: HashMap<u64, BlockedBy>,
    /// Ids that couldn't be looked up, and when that was last tried.
    misses: HashMap<u64, Instant>,
}

// SAFETY: the engine handle is used only through the thread-safe WFP API.
unsafe impl Send for Filters {}

impl Filters {
    pub fn open() -> Result<Filters> {
        let mut engine = HANDLE::default();
        // SAFETY: a local engine, default session; `engine` receives the handle.
        let code =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) };
        if code != 0 {
            return Err(Error::Invalid(format!(
                "opening the WFP engine failed: 0x{code:08x}"
            )));
        }
        Ok(Filters {
            engine,
            cache: HashMap::new(),
            misses: HashMap::new(),
        })
    }

    /// What filter `id` is. Look it up as soon as the drop is seen: Windows
    /// Firewall rebuilds its filters when rules or defaults change. A failed
    /// lookup isn't kept: the filter may be readable a moment later.
    pub fn lookup(&mut self, id: u64) -> BlockedBy {
        if let Some(hit) = self.cache.get(&id) {
            return hit.clone();
        }
        if id == 0
            || self
                .misses
                .get(&id)
                .is_some_and(|t| t.elapsed() < MISS_RETRY)
        {
            return unknown(id);
        }
        let Some(by) = self.read(id) else {
            if self.misses.len() >= CACHE_MAX {
                self.misses.clear();
            }
            self.misses.insert(id, Instant::now());
            tracing::debug!(filter = id, "a drop's filter couldn't be looked up");
            return unknown(id);
        };
        self.misses.remove(&id);
        if self.cache.len() >= CACHE_MAX {
            self.cache.clear();
        }
        self.cache.insert(id, by.clone());
        by
    }

    fn read(&self, id: u64) -> Option<BlockedBy> {
        let mut f: *mut FWPM_FILTER0 = std::ptr::null_mut();
        // SAFETY: WFP allocates `f`, which is read and then freed here.
        unsafe {
            if FwpmFilterGetById0(self.engine, id, &mut f) != 0 || f.is_null() {
                return None;
            }
            let filter = &*f;
            let name = if filter.displayData.name.is_null() {
                String::new()
            } else {
                filter.displayData.name.to_string().unwrap_or_default()
            };
            let provider = filter.providerKey.as_ref().copied();
            let by = classify(&name, provider.as_ref());
            FwpmFreeMemory0(std::ptr::addr_of_mut!(f).cast());
            Some(by)
        }
    }
}

impl Drop for Filters {
    fn drop(&mut self) {
        // SAFETY: closing the handle opened in `open`.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes() {
        let wf = Some(&FWPM_PROVIDER_MPSSVC_WF);
        let kind = |name, provider| classify(name, provider).kind;
        assert_eq!(
            kind("win4tress: curl (Out, Block) #3", wf),
            BlockedByKind::Win4tress
        );
        assert_eq!(
            kind("win4tress: Block All (Out)", wf),
            BlockedByKind::Win4tress
        );
        assert_eq!(kind("Default Outbound", wf), BlockedByKind::WindowsDefault);
        assert_eq!(kind("Steam Web Helper", wf), BlockedByKind::WindowsRule);
        assert_eq!(kind("Something", None), BlockedByKind::Other);
        assert_eq!(
            classify("Block outbound", Some(&FWPM_PROVIDER_MPSSVC_WSH)).name,
            "Windows Service Hardening: Block outbound"
        );
    }

    #[test]
    fn unknown_filters_say_so() {
        assert_eq!(unknown(0).name, "a drop that names no filter");
        assert_eq!(
            unknown(68412).name,
            "a filter that couldn't be looked up (#68412)"
        );
        assert_eq!(unknown(68412).kind, BlockedByKind::Other);
    }
}
