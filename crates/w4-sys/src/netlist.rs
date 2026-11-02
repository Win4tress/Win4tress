//! The networks Windows knows, as Network List Manager names them, for
//! switching firewall profiles by network (SPEC §7.6). A network is what
//! Windows asks "public or private?" about: a Wi-Fi network, or a wired one
//! told apart by its gateway.

use w4_core::firewall::NetworkCategory;
use windows::Win32::Networking::NetworkListManager::{
    INetwork, INetworkListManager, NLM_CONNECTIVITY_IPV4_INTERNET, NLM_CONNECTIVITY_IPV6_INTERNET,
    NLM_ENUM_NETWORK_ALL, NLM_ENUM_NETWORK_CONNECTED, NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED,
    NLM_NETWORK_CATEGORY_PRIVATE, NetworkListManager,
};
use windows::Win32::System::Com::{
    CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownNetwork {
    /// Windows' id for the network, "{…}"; it stays the same from one
    /// connection to the next.
    pub id: String,
    /// The Wi-Fi network's name, or "Network 2" and the like for wired ones.
    pub name: String,
    pub category: NetworkCategory,
    pub connected: bool,
    /// Windows says the internet is reachable through it.
    pub internet: bool,
}

fn read(n: &INetwork) -> Option<KnownNetwork> {
    // SAFETY: plain COM calls on a live interface.
    unsafe {
        let category = match n.GetCategory().ok()? {
            NLM_NETWORK_CATEGORY_PRIVATE => NetworkCategory::Private,
            NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED => NetworkCategory::Domain,
            _ => NetworkCategory::Public,
        };
        let connectivity = n.GetConnectivity().map(|c| c.0).unwrap_or(0);
        Some(KnownNetwork {
            id: format!("{{{:?}}}", n.GetNetworkId().ok()?),
            name: n.GetName().map(|b| b.to_string()).unwrap_or_default(),
            category,
            connected: n.IsConnected().is_ok_and(|c| c.as_bool()),
            internet: connectivity
                & (NLM_CONNECTIVITY_IPV4_INTERNET.0 | NLM_CONNECTIVITY_IPV6_INTERNET.0)
                != 0,
        })
    }
}

/// The networks connected now, or every one Windows remembers with `all`;
/// empty if Network List Manager can't be asked. Uses COM on the calling
/// thread.
pub fn networks(all: bool) -> Vec<KnownNetwork> {
    let mut out = Vec::new();
    // SAFETY: COM is initialised for this thread first (already being so is
    // fine); the interfaces are released when dropped.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let Ok(manager) =
            CoCreateInstance::<_, INetworkListManager>(&NetworkListManager, None, CLSCTX_ALL)
        else {
            return out;
        };
        let flags = if all {
            NLM_ENUM_NETWORK_ALL
        } else {
            NLM_ENUM_NETWORK_CONNECTED
        };
        let Ok(list) = manager.GetNetworks(flags) else {
            return out;
        };
        loop {
            let mut item = [None];
            let mut fetched = 0u32;
            if list.Next(&mut item, Some(&mut fetched)).is_err() || fetched == 0 {
                break;
            }
            if let Some(network) = item[0].take().as_ref().and_then(read) {
                out.push(network);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_pc_knows_its_networks() {
        let connected = super::networks(false);
        let all = super::networks(true);
        // Every connected network is among those remembered.
        for n in &connected {
            assert!(n.connected, "{n:?}");
            assert!(n.id.starts_with('{') && n.id.ends_with('}'), "{n:?}");
            assert!(all.iter().any(|a| a.id == n.id), "{n:?} not in {all:?}");
        }
    }
}
