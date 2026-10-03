//! ASCII hex-digit value — `FUN_08268378` @ 0x08268378.
//! True size: 56 bytes (0x08268378..0x082683b0); the next body is `bx lr`.
//! Verified calls: two inbound plain BLs (0x08267f34, 0x08267f40), zero
//! predicated inbound BLs, and zero outbound BLs of either kind.
//!
//! Unsigned wrapping range checks convert ASCII 0..9, A..F and a..f to
//! 0..15. All other full-width u32 inputs pass through unchanged, without
//! truncation or an error sentinel. The caller at 0x08267e8c combines two
//! converted bytes as low | (high << 4). Raw ARM bytes confirm the three
//! ranges and the shared final byte mask. No callee seams or deliberate
//! behavioral deviations.

/// Converts an ASCII hexadecimal digit, preserving every other word value.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ascii_hex_digit_value(value: u32) -> u32 {
    let decimal = value.wrapping_sub(b'0' as u32);
    if decimal <= 9 {
        decimal & 0xff
    } else if value.wrapping_sub(b'A' as u32) <= 5 {
        value.wrapping_sub(0x37) & 0xff
    } else if value.wrapping_sub(b'a' as u32) <= 5 {
        value.wrapping_sub(0x57) & 0xff
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: u32) -> u32 {
        match value {
            0x30..=0x39 => value - 0x30,
            0x41..=0x46 => value - 0x37,
            0x61..=0x66 => value - 0x57,
            _ => value,
        }
    }

    #[test]
    fn all_byte_values_include_digits_and_range_boundaries() {
        for value in 0..=255 {
            assert_eq!(ascii_hex_digit_value(value), reference(value), "{value:#x}");
        }
    }

    #[test]
    fn upper_bits_and_unsigned_wraparound_do_not_alias_digits() {
        for high in [0x100, 0x1_0000, 0x8000_0000, 0xffff_ff00] {
            for low in 0..=255 {
                let value = high | low;
                assert_eq!(ascii_hex_digit_value(value), value, "{value:#x}");
            }
        }
    }
}
