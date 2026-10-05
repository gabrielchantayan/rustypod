//! Device-state zero predicate — `FUN_081c91b4` @ 0x081c91b4.
//!
//! True extent: 24 bytes, 0x081c91b4..0x081c91cc: five A32
//! instructions and the pointer literal at 0x081c91c8. Whole-image raw
//! decoding finds two inbound plain BLs (0x081c91f0, 0x081c922c), zero
//! predicated inbound BLs, and zero outbound BLs of either kind.
//! Read the device-state byte at 0x089caf44 and return one exactly when
//! it is zero. RSBS followed by MOVCC clamps all values above one to zero.
//! The second caller switches on the unchanged r1 event code after BL.
//! Deliberate deviation: model that register preservation explicitly as
//! the high word of a u64 return; ignored r0 input remains an ABI argument.
//! A volatile byte read retains the mutable retail global load. The state
//! byte's broader meaning is unrecovered; no callee seams are required.

const DEVICE_STATE_ADDRESS: usize = 0x089c_af44;

#[inline(always)]
unsafe fn query_state(state: *const u8, event: u32) -> u64 {
    ((event as u64) << 32) | (state.read_volatile() == 0) as u64
}

/// Return the zero-state predicate in r0 and preserve the event code in r1.
///
/// # Safety
/// The retail device-state byte must be mapped and readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn device_state_is_clear(_context: u32, event: u32) -> u64 {
    query_state(DEVICE_STATE_ADDRESS as *const u8, event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_byte_values_match_unsigned_subtract_and_carry() {
        for state in 0..=u8::MAX {
            for event in [0, 0x10001, 0x10005, 0x8000_0000, u32::MAX] {
                let subtract = 1u32.wrapping_sub(state as u32);
                let expected = if state > 1 { 0 } else { subtract };
                let result = unsafe { query_state(&state, event) };
                assert_eq!(result as u32, expected);
                assert_eq!((result >> 32) as u32, event);
            }
        }
    }

    #[test]
    fn changes_are_observed_without_touching_adjacent_bytes() {
        let mut bytes = [0xa5, 0, 0x5a];
        let state = unsafe { bytes.as_mut_ptr().add(1) };
        for value in [0, 1, 2, 255, 0] {
            unsafe {
                state.write_volatile(value);
                assert_eq!(query_state(state, 0x10003), (0x10003u64 << 32) | (value == 0) as u64);
            }
            assert_eq!(bytes, [0xa5, value, 0x5a]);
        }
    }
}
