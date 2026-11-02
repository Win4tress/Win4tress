//! Windows Filtering Platform: drop notifications (net events) and filter lookup.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::Serialize;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_FILTER_ENUM_OVERLAPPING,
    FWP_IP_VERSION_V4, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0, FWPM_ENGINE_COLLECT_NET_EVENTS,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_ENGINE_OPTION, FWPM_FILTER_ENUM_TEMPLATE0,
    FWPM_FILTER0, FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT5,
    FWPM_PROVIDER_MPSSVC_WF, FWPM_PROVIDER_MPSSVC_WSH, FwpmEngineClose0, FwpmEngineGetOption0,
    FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFilterGetById0, FwpmFreeMemory0,
    FwpmNetEventSubscribe4, FwpmNetEventUnsubscribe0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

/// A connection or packet WFP dropped, as the net event reported it.
#[derive(Clone, Debug, Serialize)]
pub struct DropEvent {
    /// When WFP dropped it (event timestamp), Unix ms.
    pub event_ms: f64,
    /// When our callback ran, Unix ms.
    pub received_ms: f64,
    pub filter_id: u64,
    pub layer_id: u16,
    /// FWP_DIRECTION: 0 outbound, 1 inbound (in ALE layers).
    pub direction: u32,
    pub protocol: u8,
    pub remote: String,
    pub remote_port: u16,
    pub local_port: u16,
    /// NT path of the app, e.g. `\device\harddiskvolume3\...\curl.exe`.
    pub app: String,
    pub loopback: bool,
}

/// A WFP filter, enough to say what it is and who made it.
#[derive(Clone, Debug, Serialize)]
pub struct FilterInfo {
    pub id: u64,
    pub name: String,
    pub description: String,
    /// "Windows Firewall", "Windows Service Hardening", another GUID, or "".
    pub provider: String,
    pub layer: String,
    pub action: String,
    pub provider_data: String,
}

pub struct Engine(HANDLE);

// SAFETY: the engine handle is only used through the thread-safe WFP API.
unsafe impl Send for Engine {}
// SAFETY: as above; WFP serialises calls on one engine handle itself.
unsafe impl Sync for Engine {}

fn check(code: u32, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        bail!("{what} failed: 0x{code:08x}")
    }
}

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}

/// FILETIME (100 ns since 1601) to Unix ms.
fn filetime_ms(ft: FILETIME) -> f64 {
    let t = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    (t as f64 - 116_444_736_000_000_000.0) / 10_000.0
}

/// SAFETY: `p` must be null or a NUL-terminated UTF-16 string.
unsafe fn wide(p: PWSTR) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: the caller guarantees a NUL-terminated string.
        unsafe { p.to_string().unwrap_or_default() }
    }
}

/// SAFETY: `blob.data` must point to `blob.size` readable bytes (or be null).
unsafe fn blob_utf16(blob: &FWP_BYTE_BLOB) -> String {
    if blob.data.is_null() || blob.size < 2 {
        return String::new();
    }
    // SAFETY: the caller guarantees `size` readable bytes at `data`; WFP blobs of
    // text are UTF-16 and 2-byte aligned.
    let words =
        unsafe { std::slice::from_raw_parts(blob.data.cast::<u16>(), blob.size as usize / 2) };
    let end = words.iter().position(|&w| w == 0).unwrap_or(words.len());
    String::from_utf16_lossy(&words[..end])
}

fn guid_name(g: &GUID) -> String {
    match *g {
        FWPM_PROVIDER_MPSSVC_WF => "Windows Firewall".into(),
        FWPM_PROVIDER_MPSSVC_WSH => "Windows Service Hardening".into(),
        other => format!("{other:?}"),
    }
}

impl Engine {
    pub fn open() -> Result<Engine> {
        let mut h = HANDLE::default();
        // SAFETY: local engine, default session; `h` receives the handle.
        let code =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut h) };
        check(code, "FwpmEngineOpen0")?;
        Ok(Engine(h))
    }

    pub fn option(&self, option: FWPM_ENGINE_OPTION) -> Result<u32> {
        let mut value: *mut FWP_VALUE0 = std::ptr::null_mut();
        // SAFETY: WFP allocates `value`; we read it and free it with FwpmFreeMemory0.
        unsafe {
            check(
                FwpmEngineGetOption0(self.0, option, &mut value),
                "FwpmEngineGetOption0",
            )?;
            let v = if (*value).r#type == FWP_UINT32 {
                (*value).Anonymous.uint32
            } else {
                0
            };
            FwpmFreeMemory0(std::ptr::addr_of_mut!(value).cast());
            Ok(v)
        }
    }

    pub fn set_option(&self, option: FWPM_ENGINE_OPTION, v: u32) -> Result<()> {
        let value = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: v },
        };
        // SAFETY: `value` lives for the call.
        check(
            unsafe { FwpmEngineSetOption0(self.0, option, &value) },
            "FwpmEngineSetOption0",
        )
    }

    pub fn collect_net_events(&self) -> Result<u32> {
        self.option(FWPM_ENGINE_COLLECT_NET_EVENTS)
    }

    pub fn set_collect_net_events(&self, on: bool) -> Result<()> {
        self.set_option(FWPM_ENGINE_COLLECT_NET_EVENTS, u32::from(on))
    }

    pub fn keywords(&self) -> Result<u32> {
        self.option(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS)
    }

    /// SAFETY: `f` must point to a valid FWPM_FILTER0 from WFP.
    unsafe fn info(f: &FWPM_FILTER0) -> FilterInfo {
        // SAFETY: the caller guarantees `f` came from WFP, so its strings, provider
        // key and blob are valid for reading.
        unsafe {
            FilterInfo {
                id: f.filterId,
                name: wide(f.displayData.name),
                description: wide(f.displayData.description),
                provider: if f.providerKey.is_null() {
                    String::new()
                } else {
                    guid_name(&*f.providerKey)
                },
                layer: format!("{:?}", f.layerKey),
                action: match f.action.r#type {
                    FWP_ACTION_BLOCK => "block".into(),
                    FWP_ACTION_PERMIT => "permit".into(),
                    other => format!("0x{:x}", other.0),
                },
                provider_data: blob_utf16(&f.providerData),
            }
        }
    }

    pub fn filter(&self, id: u64) -> Result<FilterInfo> {
        let mut f: *mut FWPM_FILTER0 = std::ptr::null_mut();
        // SAFETY: WFP allocates `f`; freed below.
        unsafe {
            check(FwpmFilterGetById0(self.0, id, &mut f), "FwpmFilterGetById0")?;
            let info = Self::info(&*f);
            FwpmFreeMemory0(std::ptr::addr_of_mut!(f).cast());
            Ok(info)
        }
    }

    /// Every filter at `layer`.
    pub fn filters_at(&self, layer: GUID) -> Result<Vec<FilterInfo>> {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: 0xFFFF_FFFF,
            ..Default::default()
        };
        let mut h = HANDLE::default();
        let mut out = Vec::new();
        // SAFETY: standard WFP enumeration; entries are freed with FwpmFreeMemory0.
        unsafe {
            check(
                FwpmFilterCreateEnumHandle0(self.0, Some(&template), &mut h),
                "FwpmFilterCreateEnumHandle0",
            )?;
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut n = 0u32;
                let code = FwpmFilterEnum0(self.0, h, 500, &mut entries, &mut n);
                if code != 0 {
                    FwpmFilterDestroyEnumHandle0(self.0, h);
                    check(code, "FwpmFilterEnum0")?;
                }
                for i in 0..n as usize {
                    out.push(Self::info(&**entries.add(i)));
                }
                if !entries.is_null() {
                    FwpmFreeMemory0(std::ptr::addr_of_mut!(entries).cast());
                }
                if n < 500 {
                    break;
                }
            }
            FwpmFilterDestroyEnumHandle0(self.0, h);
        }
        Ok(out)
    }

    /// Starts delivering classify-drop events into `sink`.
    pub fn subscribe(&self, sink: Arc<Mutex<Vec<DropEvent>>>) -> Result<Subscription> {
        let ctx = Arc::into_raw(sink) as *const c_void;
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut h = HANDLE::default();
        // SAFETY: `ctx` stays alive until Subscription::drop reclaims it after
        // unsubscribing; a null enum template means "all events".
        let code = unsafe {
            FwpmNetEventSubscribe4(self.0, &subscription, Some(on_event), Some(ctx), &mut h)
        };
        if code != 0 {
            // SAFETY: reclaim the Arc we leaked above; WFP never got it.
            drop(unsafe { Arc::from_raw(ctx.cast::<Mutex<Vec<DropEvent>>>()) });
            check(code, "FwpmNetEventSubscribe4")?;
        }
        Ok(Subscription {
            engine: self.0,
            handle: h,
            ctx,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: closing the handle we opened.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

pub struct Subscription {
    engine: HANDLE,
    handle: HANDLE,
    ctx: *const c_void,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: after unsubscribing no more callbacks run, so the context Arc
        // can be reclaimed.
        unsafe {
            FwpmNetEventUnsubscribe0(self.engine, self.handle);
            drop(Arc::from_raw(self.ctx.cast::<Mutex<Vec<DropEvent>>>()));
        }
    }
}

/// Runs on a WFP thread for every net event.
unsafe extern "system" fn on_event(ctx: *mut c_void, event: *const FWPM_NET_EVENT5) {
    let received_ms = now_ms();
    // SAFETY: WFP passes a valid event for the duration of the call, and `ctx`
    // is the Arc<Mutex<Vec<DropEvent>>> given at subscribe time.
    unsafe {
        let Some(ev) = event.as_ref() else { return };
        if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || ev.Anonymous.classifyDrop.is_null() {
            return;
        }
        let drop_info = &*ev.Anonymous.classifyDrop;
        let h = &ev.header;
        let remote: IpAddr = if h.ipVersion == FWP_IP_VERSION_V4 {
            Ipv4Addr::from(h.Anonymous2.remoteAddrV4).into()
        } else {
            Ipv6Addr::from(h.Anonymous2.remoteAddrV6.byteArray16).into()
        };
        let e = DropEvent {
            event_ms: filetime_ms(h.timeStamp),
            received_ms,
            filter_id: drop_info.filterId,
            layer_id: drop_info.layerId,
            direction: drop_info.msFwpDirection,
            protocol: h.ipProtocol,
            remote: remote.to_string(),
            remote_port: h.remotePort,
            local_port: h.localPort,
            app: blob_utf16(&h.appId),
            loopback: drop_info.isLoopback.as_bool(),
        };
        let sink = &*(ctx as *const Mutex<Vec<DropEvent>>);
        if let Ok(mut v) = sink.lock() {
            v.push(e);
        }
    }
}
