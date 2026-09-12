//! ASCII lowercase-to-uppercase conversion — `FUN_082e0180` @ 0x082e0180
//! (20 bytes; 8 verified `bl` call sites).
//!
//! Raw ARM words at 0x082e0180..0x082e0190 are `sub r1,r0,#0x61`,
//! `cmp r1,#25`, `subls r0,r0,#0x20`, `andls r0,r0,#0xff`, and `bx lr`.
//! Thus it compares the complete u32 input against the ASCII `a`..=`z`
//! interval using unsigned wraparound. Only an input in that interval becomes
//! its ASCII uppercase byte; every other u32, including a value whose low byte
//! is lowercase but whose upper bits are nonzero, passes through unchanged.
//! All eight decoded inbound branches are unconditional `bl` instructions
//! (0x081bc9a4, 0x081bd384, 0x081bd9f0, 0x081bdb04, 0x081bdd9c,
//! 0x082e37a0, 0x082e39ac, and 0x082e39b8); there are no predicated calls or
//! direct branch entries. No deliberate deviations.

/// Converts a standalone ASCII lowercase code point to uppercase.
///
/// This is a u32 operation, not a byte operation: nonzero upper bits prevent
/// the lowercase-range comparison from matching and are preserved.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ascii_to_uppercase(value: u32) -> u32 {
    if value.wrapping_sub(b'a' as u32) <= (b'z' - b'a') as u32 {
        value.wrapping_sub(0x20) & 0xff
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_every_ascii_lowercase_letter() {
        for value in b'a'..=b'z' {
            assert_eq!(ascii_to_uppercase(value as u32), (value - 0x20) as u32);
        }
    }

    #[test]
    fn preserves_all_other_single_byte_values() {
        for value in 0u32..=0xff {
            let expected = if (b'a' as u32..=b'z' as u32).contains(&value) {
                value - 0x20
            } else {
                value
            };
            assert_eq!(ascii_to_uppercase(value), expected, "value {value:#04x}");
        }
    }

    #[test]
    fn preserves_word_values_outside_the_full_u32_interval() {
        assert_eq!(ascii_to_uppercase(0x0000_0161), 0x0000_0161);
        assert_eq!(ascii_to_uppercase(0xffff_ff61), 0xffff_ff61);
        assert_eq!(ascii_to_uppercase(u32::MAX), u32::MAX);
    }
}
