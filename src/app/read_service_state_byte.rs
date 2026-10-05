//! Service state byte reader: `FUN_081af73c` @ load address `0x081af73c`.
//!
//! True extent: 16 bytes, `0x081af73c..0x081af74c`; the next function is
//! a separate pair-field setter (`str r1,[r0,#12]; str r2,[r0,#16]; bx lr`).
//! Raw words: e5d00008, e5c10000, e3a00000, e12fff1e. Whole-image aligned
//! A32 BL decoding finds two plain incoming calls (0x081c8430, 0x081c8470),
//! zero predicated incoming calls, and zero outgoing calls of either kind.
//!
//! Copy the embedded state's byte at +8 to the caller's output, then return
//! zero. Both verified callers pass service+0xcb0, so the source is the
//! service byte at +0xcb8. No NULL guard or boolean normalization exists.
//! Volatile byte accesses preserve the stock single load/store, including
//! overlapping output; no deliberate behavioral deviations.

/// Copy the service state's byte into `output` and return success.
///
/// # Safety
/// `state` must be readable at byte offset 8 and `output` must be writable
/// for one byte. They may overlap. Neither access may race with another
/// thread, and no live reference may conflict with the output write.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_service_state_byte(state: *const u8, output: *mut u8) -> i32 {
    let value = state.add(8).read_volatile();
    output.write_volatile(value);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_byte_values_without_touching_neighbors() {
        for shift in 0..4 {
            for value in 0..=u8::MAX {
                let mut state = [0xa5; 12];
                state[shift + 8] = value;
                let before = state;
                let mut output = [0x5a; 3];
                assert_eq!(unsafe {
                    read_service_state_byte(state.as_ptr().add(shift), output.as_mut_ptr().add(1))
                }, 0);
                assert_eq!(output, [0x5a, value, 0x5a]);
                assert_eq!(state, before);
            }
        }
    }

    #[test]
    fn permits_output_including_source_inside_minimum_object() {
        for offset in 0..9 {
            let mut state = [0xa5; 9];
            state[8] = 0x81;
            let mut expected = state;
            expected[offset] = 0x81;
            let base = state.as_mut_ptr();
            assert_eq!(unsafe { read_service_state_byte(base, base.add(offset)) }, 0);
            assert_eq!(state, expected);
        }
    }
}
