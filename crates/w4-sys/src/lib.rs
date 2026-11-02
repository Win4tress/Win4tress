//! Win32 helpers shared by the service and tools.

pub mod adapters;
pub mod av;
pub mod eventlog;
pub mod fs;
pub mod http;
pub mod net;
pub mod netinfo;
pub mod netlist;
pub mod nrpt;
pub mod paths;
pub mod process;
pub mod proxy;
pub mod random;
pub mod secret;
pub mod services;
pub mod time;
pub mod trust;
pub mod version;
pub mod wifi;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn from_wide(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}
