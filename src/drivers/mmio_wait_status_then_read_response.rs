//! `mmio_wait_low_three_status_bits_then_read_response` — original:
//! `FUN_0836d8c8` @ 0x0836d8c8 (**24 bytes**,
//! 0x0836d8c8..0x0836d8e0: five A32 instructions followed by the
//! `0x3c10_0000` literal; the next function starts with `push {r4-r10,lr}`).
//!
//! **2 direct `bl` call sites, both unconditional** (`0x08054974` and
//! `0x08054984`); **0 predicated `bl` call sites**, verified by decoding every
//! ARM `B`/`BL` word in `work/firmware/osos.dec`. The body itself has no calls.
//!
//! Polls the volatile status word at 0x3c10_0000 until one of its low three
//! bits is set, then returns one volatile sample from the adjacent response
//! word at +4. The register block has no established identity in `names.yaml`,
//! so this port deliberately names only the verified register behavior.
//!
//! # Deviation
//!
//! Host builds use deterministic atomic status and response words because the
//! physical MMIO block is unavailable; the target retains the two volatile
//! reads and the unbounded busy-wait exactly.

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

const MMIO_STATUS: *const u32 = 0x3c10_0000 as *const u32;
const MMIO_RESPONSE: *const u32 = 0x3c10_0004 as *const u32;
const STATUS_READY_MASK: u32 = 7;

#[cfg(not(target_os = "none"))]
static HOST_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_RESPONSE: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
unsafe fn status_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { MMIO_STATUS.read_volatile() }
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_STATUS.load(Ordering::Relaxed)
    }
}

#[inline(always)]
unsafe fn response_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { MMIO_RESPONSE.read_volatile() }
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_RESPONSE.load(Ordering::Relaxed)
    }
}

/// Polls the low three status bits, then returns the adjacent response word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mmio_wait_low_three_status_bits_then_read_response() -> u32 {
    while unsafe { status_word() } & STATUS_READY_MASK == 0 {}
    unsafe { response_word() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_response_for_each_ready_status_bit_and_ignores_high_bits() {
        for (status, response) in [
            (1, 0),
            (2, u32::MAX),
            (4, 0x1234_5678),
            (0x8000_0001, 0x89ab_cdef),
        ] {
            HOST_STATUS.store(status, Ordering::Relaxed);
            HOST_RESPONSE.store(response, Ordering::Relaxed);
            assert_eq!(unsafe { mmio_wait_low_three_status_bits_then_read_response() }, response);
        }
    }
}
