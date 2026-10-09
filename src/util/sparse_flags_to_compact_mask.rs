//! Sparse-to-compact flag mapping — `FUN_080c065c` @ 0x080c065c.
//!
//! True extent: 84 bytes, 0x080c065c..0x080c06b0; `bx lr` at
//! 0x080c06ac precedes the next function's push at 0x080c06b0.
//! Whole-image A32 decoding verifies two plain incoming BLs (0x0813dadc,
//! 0x0813daec), zero predicated incoming BLs, and zero outgoing BLs.
//! Preserve bits 0..3, 8, and 21; map input bits 5, 6, and 15 to output
//! bits 4, 5, and 7, discarding every other bit. The caller converts the
//! words at object->state+0xe30 and +0xe34 into two output masks.
//! Deliberate deviations: replace conditional tests/ORs with equivalent
//! masks and shifts. Flag meanings are unknown; notably bit 8 is preserved,
//! not mapped to bit 6 as a presumed inverse of 0x080c0608 would suggest.

/// Converts the sparse flag word into the firmware's compact output mask.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn sparse_flags_to_compact_mask(flags: u32) -> u32 {
    (flags & 0x0020_010f) | ((flags & 0x60) >> 1) | ((flags & 0x8000) >> 8)
}

#[cfg(test)]
mod tests {
    use super::sparse_flags_to_compact_mask;

    const MAPPING: [(u32, u32); 9] = [
        (1, 1), (2, 2), (4, 4), (8, 8),
        (0x20, 0x10), (0x40, 0x20), (0x100, 0x100),
        (0x8000, 0x80), (0x20_0000, 0x20_0000),
    ];

    fn reference(flags: u32) -> u32 {
        let mut mask = 0;
        for (input, output) in MAPPING {
            if flags & input != 0 {
                mask |= output;
            }
        }
        mask
    }

    #[test]
    fn each_input_bit_maps_or_is_discarded() {
        assert_eq!(sparse_flags_to_compact_mask(0), 0);
        for bit in 0..32 {
            let flags = 1u32 << bit;
            assert_eq!(sparse_flags_to_compact_mask(flags), reference(flags), "bit {bit}");
        }
        assert_eq!(sparse_flags_to_compact_mask(u32::MAX), 0x20_01bf);
    }

    #[test]
    fn all_supported_combinations_ignore_unrelated_bits() {
        let supported = MAPPING.iter().fold(0, |mask, &(input, _)| mask | input);
        for combination in 0..512 {
            let mut flags = 0;
            for (bit, &(input, _)) in MAPPING.iter().enumerate() {
                if combination & (1 << bit) != 0 {
                    flags |= input;
                }
            }
            let expected = reference(flags);
            assert_eq!(sparse_flags_to_compact_mask(flags), expected);
            assert_eq!(sparse_flags_to_compact_mask(flags | !supported), expected);
        }
    }
}
