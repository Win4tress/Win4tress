//! Wi-Fi as Windows sees it (SPEC §11 "Wi-Fi evil twin"): the network each
//! interface is connected to and the networks in range, with their security.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGORITHM, DOT11_SSID, WLAN_AVAILABLE_NETWORK_LIST, WLAN_CONNECTION_ATTRIBUTES,
    WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
    WlanGetAvailableNetworkList, WlanOpenHandle, WlanQueryInterface,
    wlan_interface_state_connected, wlan_intf_opcode_current_connection,
};

/// A Wi-Fi network: its name and how it's secured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiNetwork {
    pub ssid: String,
    /// The access point, for the connected network.
    pub bssid: Option<String>,
    /// The adapter's GUID ("{…}", as `AdapterInfo::id` has it), for the
    /// connected network.
    pub interface: Option<String>,
    /// e.g. "Open", "WPA2-Personal", "WPA3-Personal", "WPA2-Enterprise".
    pub security: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WifiState {
    pub connected: Vec<WifiNetwork>,
    pub visible: Vec<WifiNetwork>,
}

fn ssid(s: &DOT11_SSID) -> String {
    let len = (s.uSSIDLength as usize).min(32);
    String::from_utf8_lossy(&s.ucSSID[..len]).into_owned()
}

/// DOT11_AUTH_ALGORITHM as a name (values from wlantypes.h).
fn security(auth: DOT11_AUTH_ALGORITHM, secured: bool) -> String {
    match auth.0 {
        1 if !secured => "Open",
        1 => "Open (WEP)",
        2 => "Shared key (WEP)",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise (192-bit)",
        9 => "WPA3-Personal",
        10 => "OWE",
        11 => "WPA3-Enterprise",
        _ => "Other",
    }
    .to_string()
}

/// Every Wi-Fi interface's connection and the networks in range; empty on a
/// PC without Wi-Fi (or without the WLAN service).
pub fn state() -> WifiState {
    let mut out = WifiState::default();
    let mut version = 0u32;
    let mut handle = HANDLE::default();
    // SAFETY: WLAN API calls on a handle opened here and closed at the end;
    // every list it returns is freed with WlanFreeMemory after reading.
    unsafe {
        if WlanOpenHandle(2, None, &mut version, &mut handle) != 0 {
            return out;
        }
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        if WlanEnumInterfaces(handle, None, &mut list) == 0 && !list.is_null() {
            let interfaces = std::slice::from_raw_parts(
                (*list).InterfaceInfo.as_ptr(),
                (*list).dwNumberOfItems as usize,
            );
            for i in interfaces {
                if i.isState == wlan_interface_state_connected {
                    let mut size = 0u32;
                    let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
                    if WlanQueryInterface(
                        handle,
                        &i.InterfaceGuid,
                        wlan_intf_opcode_current_connection,
                        None,
                        &mut size,
                        &mut data,
                        None,
                    ) == 0
                        && !data.is_null()
                    {
                        let c = &*data.cast::<WLAN_CONNECTION_ATTRIBUTES>();
                        let a = &c.wlanAssociationAttributes;
                        out.connected.push(WifiNetwork {
                            ssid: ssid(&a.dot11Ssid),
                            bssid: crate::netinfo::mac_text(&a.dot11Bssid),
                            interface: Some(format!("{{{:?}}}", i.InterfaceGuid)),
                            security: security(
                                c.wlanSecurityAttributes.dot11AuthAlgorithm,
                                c.wlanSecurityAttributes.bSecurityEnabled.as_bool(),
                            ),
                        });
                        WlanFreeMemory(data);
                    }
                }
                let mut networks: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
                if WlanGetAvailableNetworkList(handle, &i.InterfaceGuid, 0, None, &mut networks)
                    == 0
                    && !networks.is_null()
                {
                    let items = std::slice::from_raw_parts(
                        (*networks).Network.as_ptr(),
                        (*networks).dwNumberOfItems as usize,
                    );
                    for n in items {
                        out.visible.push(WifiNetwork {
                            ssid: ssid(&n.dot11Ssid),
                            bssid: None,
                            interface: None,
                            security: security(
                                n.dot11DefaultAuthAlgorithm,
                                n.bSecurityEnabled.as_bool(),
                            ),
                        });
                    }
                    WlanFreeMemory(networks.cast());
                }
            }
            WlanFreeMemory(list.cast());
        }
        WlanCloseHandle(handle, None);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn reading_wifi_does_not_fail() {
        // A PC (or VM) without Wi-Fi gives an empty state.
        let _ = super::state();
        assert_eq!(
            super::security(
                windows::Win32::NetworkManagement::WiFi::DOT11_AUTH_ALGORITHM(7),
                true
            ),
            "WPA2-Personal"
        );
        assert_eq!(
            super::security(
                windows::Win32::NetworkManagement::WiFi::DOT11_AUTH_ALGORITHM(1),
                false
            ),
            "Open"
        );
    }
}
