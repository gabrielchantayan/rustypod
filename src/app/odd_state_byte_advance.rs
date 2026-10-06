//! Byte-state transition: `FUN_0817de08` @ load address `0x0817de08`.
//!
//! True extent: 36 bytes, [0x0817de08, 0x0817de2c), ending in `bx lr`
//! before the next function's push prologue. Raw A32 decoding finds two
//! incoming plain BLs (0x0817ab18, 0x0817ab20), zero predicated incoming
//! BLs, and zero outgoing BLs of either kind.
//!
//! Read the first byte, change 1 to 2 or 3 to 4, and leave every other
//! value untouched. The caller selects objects at +0x54 or +0x58; their
//! state meanings are not established. Volatile access preserves the single
//! byte load and conditional store. No deliberate behavioral deviations;
//! expose the caller-observed void API rather than promise r0 passthrough.

/// Advance the two recognized odd states to their paired even states.
///
/// # Safety
/// `state` must be readable for one byte and writable when its value is
/// 1 or 3. Access must not race or conflict with live references.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn odd_state_byte_advance(state: *mut u8) {
    let value = state.read_volatile();
    if value == 1 {
        state.write_volatile(2);
    } else if value == 3 {
        state.write_volatile(4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_states_preserve_neighbors_and_settle_after_one_transition() {
        for offset in 0..4 {
            for value in 0..=u8::MAX {
                let mut bytes = [0xa5; 6];
                bytes[offset + 1] = value;
                let mut expected = bytes;
                expected[offset + 1] = match value {
                    1 => 2,
                    3 => 4,
                    other => other,
                };
                unsafe { odd_state_byte_advance(bytes.as_mut_ptr().add(offset + 1)); }
                assert_eq!(bytes, expected);
                unsafe { odd_state_byte_advance(bytes.as_mut_ptr().add(offset + 1)); }
                assert_eq!(bytes, expected);
            }
        }
    }

    #[test]
    fn minimum_one_byte_object() {
        let mut state = 3u8;
        unsafe { odd_state_byte_advance(&mut state); }
        assert_eq!(state, 4);
    }
}
