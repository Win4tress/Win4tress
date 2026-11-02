//! Adapter byte counters from `GetIfTable2`, the reference we compare ETW against.

use anyhow::{Context, Result};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IF_TYPE_SOFTWARE_LOOPBACK, MIB_IF_ROW2, MIB_IF_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

#[derive(Clone, Debug)]
pub struct IfRow {
    pub luid: u64,
    pub alias: String,
    pub description: String,
    pub filter: bool,
    pub connector: bool,
    pub loopback: bool,
    pub up: bool,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_pkts: u64,
    pub out_pkts: u64,
}

impl IfRow {
    /// Real NICs (Ethernet, Wi-Fi). Excludes NDIS filter rows, which repeat the
    /// counts of the adapter they sit on, and virtual adapters with no connector.
    pub fn is_physical(&self) -> bool {
        self.up && self.connector && !self.filter && !self.loopback
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IfDelta {
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_pkts: u64,
    pub out_pkts: u64,
}

pub fn snapshot() -> Result<Vec<IfRow>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table; it is released with FreeMibTable below.
    unsafe { GetIfTable2(&mut table) }
        .ok()
        .context("GetIfTable2 failed")?;

    // SAFETY: on success `table` points to NumEntries contiguous MIB_IF_ROW2 entries.
    let rows: &[MIB_IF_ROW2] = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let result = rows.iter().map(to_row).collect();

    // SAFETY: `table` was allocated by GetIfTable2 and is not used after this.
    unsafe { FreeMibTable(table as *const _) };
    Ok(result)
}

fn to_row(row: &MIB_IF_ROW2) -> IfRow {
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    IfRow {
        // SAFETY: every bit pattern of the NET_LUID union is a valid u64.
        luid: unsafe { row.InterfaceLuid.Value },
        alias: wide_to_string(&row.Alias),
        description: wide_to_string(&row.Description),
        // Bit 0 is HardwareInterface, unused here.
        filter: flags & 0b010 != 0,
        connector: flags & 0b100 != 0,
        loopback: row.Type == IF_TYPE_SOFTWARE_LOOPBACK,
        up: row.OperStatus == IfOperStatusUp,
        in_octets: row.InOctets,
        out_octets: row.OutOctets,
        in_pkts: row.InUcastPkts + row.InNUcastPkts,
        out_pkts: row.OutUcastPkts + row.OutNUcastPkts,
    }
}

fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// Sum of counter growth on physical adapters present in both snapshots.
pub fn physical_delta(prev: &[IfRow], cur: &[IfRow]) -> IfDelta {
    let mut d = IfDelta::default();
    for c in cur.iter().filter(|r| r.is_physical()) {
        if let Some(p) = prev.iter().find(|p| p.luid == c.luid) {
            d.in_octets += c.in_octets.saturating_sub(p.in_octets);
            d.out_octets += c.out_octets.saturating_sub(p.out_octets);
            d.in_pkts += c.in_pkts.saturating_sub(p.in_pkts);
            d.out_pkts += c.out_pkts.saturating_sub(p.out_pkts);
        }
    }
    d
}
