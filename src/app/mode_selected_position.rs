//! `mode_selected_position` — original: `FUN_0822aecc` @ `0x0822aecc`
//! (**20 bytes**, `0x0822aecc..0x0822aee0`).
//!
//! Raw ARM is `ldrb r1,[r0,#0x5f8]; tst r1,#1; ldreq r0,[r0,#0x5e4];
//! ldrne r0,[r0,#0x2ec]; bx lr`. It selects the current position from one of
//! two embedded backends: the byte at `+0x5f8` selects `+0x2ec` when bit 0 is
//! set and `+0x5e4` when it is clear. The wider state object's class and the
//! remaining flag bits are unidentified, so this module deliberately makes
//! only the observed mode-selected-position claim.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds 11 direct `bl` call
//! sites, all unconditional, with zero predicated forms: `0x081cbc30`,
//! `0x081cc090`, `0x081cc5e4`, `0x081cd0c4`, `0x081cd0d8`, `0x08220330`,
//! `0x082203c8`, `0x0822b43c`, `0x0822b524`, `0x0822b618`, and `0x0822b62c`.
//! A separately linked thunk at `0x0820a49c` tail-branches here. The next
//! function begins at `0x0822aee0`.
//!
//! Deliberate deviations: none.

/// Returns the active backend's current position.
///
/// # Safety
///
/// `state` must be non-NULL and four-byte aligned, with readable words at
/// `+0x2ec` and `+0x5e4` and a readable byte at `+0x5f8`. This is the
/// alignment and readable extent required by the retail ARM `ldr`/`ldrb`
/// sequence; there is no NULL or bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_selected_position(state: *const u8) -> u32 {
    if state.add(0x5f8).read() & 1 == 0 {
        state.add(0x5e4).cast::<u32>().read()
    } else {
        state.add(0x2ec).cast::<u32>().read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODE_POSITION_OFFSET: usize = 0x2ec;
    const DEFAULT_POSITION_OFFSET: usize = 0x5e4;
    const FLAGS_OFFSET: usize = 0x5f8;
    const STATE_BYTES: usize = FLAGS_OFFSET + 1;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    unsafe fn write_word(state: &mut State, offset: usize, value: u32) {
        state.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn selects_position_only_from_mode_flag_bit_zero() {
        let mut state = State([0xa5; STATE_BYTES]);
        unsafe {
            write_word(&mut state, MODE_POSITION_OFFSET, 0xffff_fffe);
            write_word(&mut state, DEFAULT_POSITION_OFFSET, 0x0123_4567);
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

            assert_eq!(unsafe { mode_selected_position(state.0.as_ptr()) }, expected, "flags={flags:#04x}");
            assert_eq!(state.0, before, "read changed state for flags={flags:#04x}");
        }
    }

    #[test]
    fn selection_preserves_each_full_width_position_value() {
        let cases = [(0, 0, u32::MAX), (1, u32::MAX, 0), (0x80, 0x8000_0000, 1), (0x81, 1, 0x8000_0000)];

        for (flags, mode_position, default_position) in cases {
            let mut state = State([0; STATE_BYTES]);
            unsafe {
                write_word(&mut state, MODE_POSITION_OFFSET, mode_position);
                write_word(&mut state, DEFAULT_POSITION_OFFSET, default_position);
            }
            state.0[FLAGS_OFFSET] = flags;

            let expected = if flags & 1 == 0 { default_position } else { mode_position };
            assert_eq!(unsafe { mode_selected_position(state.0.as_ptr()) }, expected, "flags={flags:#04x}");
        }
    }
}
