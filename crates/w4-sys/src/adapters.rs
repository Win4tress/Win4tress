//! Adapter byte counters (`GetIfTable2`). These count whole frames, so the
//! difference from per-app payload is protocol overhead (SPEC §8.2).

use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IF_TYPE_SOFTWARE_LOOPBACK, MIB_IF_ROW2, MIB_IF_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

use crate::from_wide;

#[derive(Clone, Debug)]
pub struct Adapter {
    pub luid: u64,
    pub alias: String,
    pub description: String,
    pub filter: bool,
    pub connector: bool,
    pub loopback: bool,
    pub up: bool,
    pub in_octets: u64,
    pub out_octets: u64,
}

impl Adapter {
    /// Real NICs (Ethernet, Wi-Fi). Excludes NDIS filter rows, which repeat the
    /// counts of the adapter they sit on, and virtual adapters with no connector.
    pub fn is_physical(&self) -> bool {
        self.up && self.connector && !self.filter && !self.loopback
    }
}

pub fn snapshot() -> windows::core::Result<Vec<Adapter>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table; it is released with FreeMibTable below.
    unsafe { GetIfTable2(&mut table) }.ok()?;
    // SAFETY: on success `table` points to NumEntries contiguous MIB_IF_ROW2 entries.
    let rows: &[MIB_IF_ROW2] = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let result = rows.iter().map(to_adapter).collect();
    // SAFETY: `table` was allocated by GetIfTable2 and is not used after this.
    unsafe { FreeMibTable(table as *const _) };
    Ok(result)
}

fn to_adapter(row: &MIB_IF_ROW2) -> Adapter {
    // Bit 0 HardwareInterface, bit 1 FilterInterface, bit 2 ConnectorPresent.
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    Adapter {
        // SAFETY: every bit pattern of the NET_LUID union is a valid u64.
        luid: unsafe { row.InterfaceLuid.Value },
        alias: from_wide(&row.Alias),
        description: from_wide(&row.Description),
        filter: flags & 0b010 != 0,
        connector: flags & 0b100 != 0,
        loopback: row.Type == IF_TYPE_SOFTWARE_LOOPBACK,
        up: row.OperStatus == IfOperStatusUp,
        in_octets: row.InOctets,
        out_octets: row.OutOctets,
    }
}

/// Bytes moved on physical adapters between two snapshots.
pub fn physical_delta(earlier: &[Adapter], later: &[Adapter]) -> w4_core::Bytes {
    let mut total = w4_core::Bytes::default();
    for now in later.iter().filter(|a| a.is_physical()) {
        if let Some(then) = earlier.iter().find(|a| a.luid == now.luid) {
            total.recv += now.in_octets.saturating_sub(then.in_octets);
            total.sent += now.out_octets.saturating_sub(then.out_octets);
        }
    }
    total
}
