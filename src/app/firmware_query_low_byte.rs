//! Low-byte wrapper for an otherwise unnamed firmware status query.
//!
//! `firmware_query_low_byte` — original: `FUN_080547b0` @ **0x080547b0**
//! (**16 bytes**; the next distinct function starts with `push {r4-r9,sl,lr}`
//! at 0x080547c0). Decoding every ARM `B`/`BL` word in `osos.dec` finds
//! **10 direct, unconditional `bl` call sites**, with no predicated calls or
//! direct `b` tail callers.
//!
//! Algorithm: call the unnamed zero-argument predicate at 0x080b4eb4, then
//! return only its low byte (`and r0,r0,#0xff`). Raw decoding of that callee
//! establishes that it returns zero or one, but this wrapper's mask is kept so
//! its ABI-visible behavior remains exact.
//!
//! Deliberate deviation: 0x080b4eb4 is not ported and has no recovered
//! identity. Firmware builds call that verified address directly; host tests
//! install a query seam rather than assigning it an invented identity.

#[cfg(test)]
extern crate std;

#[cfg(target_os = "none")]
use core::mem;
#[cfg(not(target_os = "none"))]
use core::ptr;

type FirmwareQuery = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
const FIRMWARE_QUERY_ADDRESS: usize = 0x080b_4eb4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_query() -> u32 {
    let query: FirmwareQuery = mem::transmute(FIRMWARE_QUERY_ADDRESS);
    query()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_firmware_query() -> u32 {
    0
}

/// Host replacement for the unported 0x080b4eb4 predicate.
#[cfg(not(target_os = "none"))]
static mut HOST_FIRMWARE_QUERY: FirmwareQuery = unavailable_firmware_query;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn firmware_query() -> u32 {
    let query = ptr::read_volatile(ptr::addr_of!(HOST_FIRMWARE_QUERY));
    query()
}

/// firmware_query_low_byte — original: `FUN_080547b0` @ 0x080547b0 (16 bytes;
/// 10 direct unconditional `bl` call sites).
///
/// Invokes the otherwise unnamed firmware predicate at 0x080b4eb4 and returns
/// the low eight bits of its result. No argument, NULL, or error handling is
/// added because the ARM wrapper has none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn firmware_query_low_byte() -> u8 {
    firmware_query() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    static HOST_FIRMWARE_QUERY_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn query_zero() -> u32 {
        0
    }

    unsafe extern "C" fn query_high_bits_set() -> u32 {
        0x1234_56a5
    }

    #[test]
    fn preserves_a_zero_predicate_result() {
        let _lock = HOST_FIRMWARE_QUERY_LOCK.lock();
        unsafe {
            let previous = HOST_FIRMWARE_QUERY;
            HOST_FIRMWARE_QUERY = query_zero;
            assert_eq!(firmware_query_low_byte(), 0);
            HOST_FIRMWARE_QUERY = previous;
        }
    }

    #[test]
    fn masks_the_unported_query_to_its_low_byte() {
        let _lock = HOST_FIRMWARE_QUERY_LOCK.lock();
        unsafe {
            let previous = HOST_FIRMWARE_QUERY;
            HOST_FIRMWARE_QUERY = query_high_bits_set;
            assert_eq!(firmware_query_low_byte(), 0xa5);
            HOST_FIRMWARE_QUERY = previous;
        }
    }
}
