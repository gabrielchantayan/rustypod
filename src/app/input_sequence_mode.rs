//! Input-sequence mode predicate — FUN_08129b58 @ 0x08129b58.
//!
//! Verified raw extent [0x08129b58, 0x08129b6c): 20 bytes. The next
//! function loads the action index at state + 0xb4. Two inbound plain BLs
//! (0x0812962c, 0x08129720), zero predicated BLs; no outgoing calls.
//! CMP mode,#23; CMPNE mode,#31; MOVEQ r0,#1; MOVNE r0,#0; BX lr.
//! Classifies the input-sequence mode as 23 or 31. Callers supply the byte
//! at state + 0xa2 or the incoming event byte; the predicate itself compares
//! all 32 bits. The meanings of the two mode values remain unverified.
//! Deliberate deviations: none.

/// Returns one for input-sequence modes 23 and 31, zero for every other word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn input_sequence_mode_is_23_or_31(mode: u32) -> u32 {
    u32::from(mode == 23 || mode == 31)
}

#[cfg(test)]
mod tests {
    use super::input_sequence_mode_is_23_or_31;

    #[test]
    fn classifies_every_input_mode_byte() {
        for mode in 0..=255 {
            let expected = match mode {
                23 | 31 => 1,
                _ => 0,
            };
            assert_eq!(input_sequence_mode_is_23_or_31(mode), expected, "mode {mode}");
        }
    }

    #[test]
    fn does_not_truncate_full_width_arguments() {
        for mode in [0x117, 0x11f, 0x8000_0017, 0x8000_001f, u32::MAX] {
            assert_eq!(input_sequence_mode_is_23_or_31(mode), 0, "mode {mode:#x}");
        }
    }
}
