//! Low-byte wrapper for the PMU mode-status availability predicate.
//!
//! `firmware_query_low_byte` — original: `FUN_080547b0` @ **0x080547b0**
//! (**16 bytes**; the next distinct function starts with `push {r4-r9,sl,lr}`
//! at 0x080547c0). Decoding every ARM `B`/`BL` word in `osos.dec` finds
//! **10 direct, unconditional `bl` call sites**, with no predicated calls or
//! direct `b` tail callers.
//!
//! Algorithm: call `pmu_mode_status_available`, then return only its low byte
//! (`and r0,r0,#0xff`). The predicate returns zero or one, but this wrapper's
//! mask remains for ABI parity.
//!
//! Deliberate deviation: none. The wrapper forwards the otherwise-undeclared
//! inbound register words because incoming r3 reaches the PMU calls'
//! failed-I2C scratch-byte paths.


use crate::app::pmu_mode_status_available::pmu_mode_status_available;

/// firmware_query_low_byte — original: `FUN_080547b0` @ 0x080547b0 (16 bytes;
/// 10 direct unconditional `bl` call sites).
///
/// Invokes the ported PMU mode-status availability predicate, forwarding the
/// inbound register words, then masks the result to its low eight bits.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn firmware_query_low_byte(
    incoming_r0: u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    pmu_mode_status_available(incoming_r0, incoming_r1, incoming_r2, incoming_r3) & 0xff
}

