//! `mode_selected_extent` — original: `FUN_0822ad9c` @ `0x0822ad9c`
//! (**20 bytes**, `0x0822ad9c..0x0822adac`). The next separately linked
//! function begins at `0x0822adb0`.
//!
//! Raw ARM is `ldrb r1,[r0,#0x5f8]; tst r1,#1; ldreq r0,[r0,#0x5e8];
//! ldrne r0,[r0,#0x2f0]; bx lr`. It selects the active extent word from one
//! of two embedded backends: the byte at `+0x5f8` selects `+0x2f0` when bit 0
//! is set and `+0x5e8` when it is clear. The wider state object's class and
//! the semantic unit of the extent are unidentified, so this module
//! deliberately makes only the observed mode-selected-extent claim.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds five direct `bl`
//! call sites: four unconditional calls at `0x081cbc18`, `0x081cc278`,
//! `0x0822b26c`, and `0x0822b464`, plus one predicated `bleq` at `0x0822b09c`.
//! No direct tail branch reaches this entry.
//!
//! Deliberate deviations: none.

/// Returns the active backend's extent.
///
/// # Safety
///
/// `state` must be non-NULL and four-byte aligned, with readable words at
/// `+0x2f0` and `+0x5e8` and a readable byte at `+0x5f8`. This is the
/// alignment and readable extent required by the retail ARM `ldr`/`ldrb`
/// sequence; there is no NULL or bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_selected_extent(state: *const u8) -> u32 {
    if state.add(0x5f8).read() & 1 == 0 {
        state.add(0x5e8).cast::<u32>().read()
    } else {
        state.add(0x2f0).cast::<u32>().read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODE_EXTENT_OFFSET: usize = 0x2f0;
    const DEFAULT_EXTENT_OFFSET: usize = 0x5e8;
    const FLAGS_OFFSET: usize = 0x5f8;
    const STATE_BYTES: usize = FLAGS_OFFSET + 1;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    unsafe fn write_word(state: &mut State, offset: usize, value: u32) {
        state.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn selects_extent_only_from_mode_flag_bit_zero() {
        let mut state = State([0xa5; STATE_BYTES]);
        unsafe {
            write_word(&mut state, MODE_EXTENT_OFFSET, 0xffff_fffe);
            write_word(&mut state, DEFAULT_EXTENT_OFFSET, 0x0123_4567);
        }

        for (flags, expected) in [
            (0x00, 0x0123_4567),
            (0x01, 0xffff_fffe),
            (0x02, 0x0123_4567),
            (0x03, 0xffff_fffe),
            (0xfe, 0x0123_4567),
            (0xff, 0xffff_fffe),
        ] {
            state.0[FLAGS_OFFSET] = flags;
            let before = state.0;

            assert_eq!(unsafe { mode_selected_extent(state.0.as_ptr()) }, expected, "flags={flags:#04x}");
            assert_eq!(state.0, before, "read changed state for flags={flags:#04x}");
        }
    }

    #[test]
    fn selection_preserves_each_full_width_extent_value() {
        let cases = [(0, 0, u32::MAX), (1, u32::MAX, 0), (0x80, 0x8000_0000, 1), (0x81, 1, 0x8000_0000)];

        for (flags, mode_extent, default_extent) in cases {
            let mut state = State([0; STATE_BYTES]);
            unsafe {
                write_word(&mut state, MODE_EXTENT_OFFSET, mode_extent);
                write_word(&mut state, DEFAULT_EXTENT_OFFSET, default_extent);
            }
            state.0[FLAGS_OFFSET] = flags;

            let expected = if flags & 1 == 0 { default_extent } else { mode_extent };
            assert_eq!(unsafe { mode_selected_extent(state.0.as_ptr()) }, expected, "flags={flags:#04x}");
        }
    }
}
