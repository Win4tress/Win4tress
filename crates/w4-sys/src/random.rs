//! Random numbers from the operating system's generator, where they must not
//! be guessable (DNS query ids and source ports against spoofed answers).

use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

/// Fills `buf`; falls back to a time-based value only if the system
/// generator fails, which it doesn't on supported Windows.
pub fn fill(buf: &mut [u8]) {
    // SAFETY: `buf` is a valid, writable slice.
    let status = unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> ((i % 16) * 8)) as u8;
        }
    }
}

pub fn u16() -> u16 {
    let mut b = [0u8; 2];
    fill(&mut b);
    u16::from_le_bytes(b)
}

pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn values_differ() {
        assert_ne!(super::u64(), super::u64());
    }
}
