//! Session health (lost events and buffers) via `ControlTraceW(QUERY)`.
//! ferrisetw doesn't expose these counters.

use anyhow::{Context, Result};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
};
use windows::core::PCWSTR;

#[derive(Clone, Copy, Debug, Default)]
pub struct SessionStats {
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    pub buffers_written: u32,
    pub buffers: u32,
    pub free_buffers: u32,
}

pub fn query(name: &str) -> Result<SessionStats> {
    // EVENT_TRACE_PROPERTIES is followed by room for the logger and log file names.
    const NAME_BYTES: usize = 1024 * size_of::<u16>();
    let base = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = base + 2 * NAME_BYTES;
    let mut buf = vec![0u64; total.div_ceil(8)];
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    // SAFETY: `buf` is zeroed, 8-byte aligned and at least `total` bytes long.
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = base as u32;
        (*props).LogFileNameOffset = (base + NAME_BYTES) as u32;
    }

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `props` describes a buffer of `total` bytes; `wide` is NUL-terminated.
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wide.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    }
    .ok()
    .with_context(|| format!("querying ETW session {name}"))?;

    // SAFETY: ControlTraceW filled in the structure.
    let p = unsafe { &*props };
    Ok(SessionStats {
        events_lost: p.EventsLost,
        realtime_buffers_lost: p.RealTimeBuffersLost,
        buffers_written: p.BuffersWritten,
        buffers: p.NumberOfBuffers,
        free_buffers: p.FreeBuffers,
    })
}
