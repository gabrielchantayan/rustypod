//! `mode_selected_byte` — original: `FUN_0822b684` @ `0x0822b684`
//! (**20 bytes**, `0x0822b684..0x0822b698`).
//!
//! Raw ARM is `ldrb r1,[r0,#0x5f8]; tst r1,#1; ldrbeq r0,[r0,#0x5ec];
//! ldrbne r0,[r0,#0x2f4]; bx lr`. It selects one of two state bytes: bit 0 of
//! the mode flags at `+0x5f8` selects the byte at `+0x2f4` when set and the
//! byte at `+0x5ec` when clear. The wider state object's class, the bytes'
//! semantic roles, and the remaining flag bits are unidentified, so this
//! module deliberately makes only the observed mode-selected-byte claim.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds nine direct `bl` call
//! sites, all unconditional, with zero predicated forms: `0x0822aa40`,
//! `0x0822ac08`, `0x0822aef0`, `0x0822af70`, `0x0822b158`, `0x0822b2ec`,
//! `0x0822b554`, `0x0822b6dc`, and `0x0822b800`. The next separately linked
//! function begins at `0x0822b698`.
//!
//! Deliberate deviations: none.

/// Returns the byte selected by bit zero of the mode flags.
///
/// # Safety
///
/// `state` must be non-NULL with readable bytes at `+0x2f4`, `+0x5ec`, and
/// `+0x5f8`. The retail function has no NULL or bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_selected_byte(state: *const u8) -> u8 {
    if state.add(0x5f8).read() & 1 == 0 {
        state.add(0x5ec).read()
    } else {
        state.add(0x2f4).read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODE_BYTE_OFFSET: usize = 0x2f4;
    const DEFAULT_BYTE_OFFSET: usize = 0x5ec;
    const FLAGS_OFFSET: usize = 0x5f8;
    const STATE_BYTES: usize = FLAGS_OFFSET + 1;

    #[test]
    fn selects_byte_only_from_mode_flag_bit_zero() {
        let mut state = [0xa5; STATE_BYTES];
        state[MODE_BYTE_OFFSET] = 0xff;
        state[DEFAULT_BYTE_OFFSET] = 0;

        for (flags, expected) in [
            (0x00, 0),
            (0x01, 0xff),
            (0x02, 0),
            (0x03, 0xff),
            (0xfe, 0),
            (0xff, 0xff),
        ] {
            state[FLAGS_OFFSET] = flags;
            let before = state;

            assert_eq!(unsafe { mode_selected_byte(state.as_ptr()) }, expected, "flags={flags:#04x}");
            assert_eq!(state, before, "read changed state for flags={flags:#04x}");
        }
    }

    #[test]
    fn selection_preserves_each_byte_value() {
        for (flags, mode_byte, default_byte) in [
            (0x00, 0x00, 0xff),
            (0x01, 0x00, 0xff),
            (0x80, 0x7f, 0x80),
            (0x81, 0x7f, 0x80),
        ] {
            let mut state = [0; STATE_BYTES];
            state[MODE_BYTE_OFFSET] = mode_byte;
            state[DEFAULT_BYTE_OFFSET] = default_byte;
            state[FLAGS_OFFSET] = flags;

            let expected = if flags & 1 == 0 { default_byte } else { mode_byte };
            assert_eq!(unsafe { mode_selected_byte(state.as_ptr()) }, expected, "flags={flags:#04x}");
        }
    }
}
