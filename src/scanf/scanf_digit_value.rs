//! scanf digit conversion — `FUN_080eb814` @ 0x080eb814.
//! True size: 152 bytes (0x080eb814..0x080eb8ac), ending in bx lr;
//! the next function starts with push {r0, r1, r2, r3, r4, lr}.
//! Verified calls: two incoming plain BLs (0x080ee19c, 0x080ee1dc),
//! zero incoming predicated BLs, zero outgoing BLs of either kind.
//!
//! For format 'x', map ASCII A..F and a..f to 10..15. Otherwise return
//! the full input word minus '0', wrapping at 32 bits, without validation.
//! Caller 0x080edc48 validates characters before accumulating hexadecimal
//! input in its bounded and unbounded scanf paths. No callee seams.
//! Deliberate codegen deviation: arithmetic range conversion replaces the
//! original branch tables and six constant-return blocks; behavior is unchanged.

/// Converts a scanf numeric character using the conversion-format character.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn scanf_digit_value(value: u32, format: u32) -> u32 {
    if format == b'x' as u32 {
        let uppercase = value.wrapping_sub(b'A' as u32);
        if uppercase <= 5 {
            return uppercase + 10;
        }
        let lowercase = value.wrapping_sub(b'a' as u32);
        if lowercase <= 5 {
            return lowercase + 10;
        }
    }
    value.wrapping_sub(b'0' as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: u32, format: u32) -> u32 {
        if format == 0x78 {
            match value {
                0x41 | 0x61 => return 10,
                0x42 | 0x62 => return 11,
                0x43 | 0x63 => return 12,
                0x44 | 0x64 => return 13,
                0x45 | 0x65 => return 14,
                0x46 | 0x66 => return 15,
                _ => {}
            }
        }
        value.wrapping_sub(0x30)
    }

    #[test]
    fn all_bytes_and_formats_preserve_unvalidated_fallback() {
        for format in 0..=255 {
            for value in 0..=255 {
                assert_eq!(scanf_digit_value(value, format), reference(value, format),
                           "value={value:#x}, format={format:#x}");
            }
        }
    }

    #[test]
    fn full_width_values_and_formats_do_not_alias_ascii() {
        for format in [0x78, 0x178, 0x10078, 0x80000078, u32::MAX] {
            for high in [0, 0x100, 0x10000, 0x7fffff00, 0x80000000, 0xffffff00] {
                for low in 0..=255 {
                    let value = high | low;
                    assert_eq!(scanf_digit_value(value, format), reference(value, format),
                               "value={value:#x}, format={format:#x}");
                }
            }
        }
    }
}
