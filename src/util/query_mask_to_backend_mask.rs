//! Query-to-backend mask translation — `FUN_080c0608` @ `0x080c0608`.
//!
//! True extent: 84 bytes, [0x080c0608, 0x080c065c); `bx lr` at
//! 0x080c0658 precedes the next independent converter at 0x080c065c.
//! Whole-image aligned A32 decoding verifies two plain incoming BLs at
//! 0x0813d074 and 0x0813d080, zero predicated incoming BLs, and zero
//! outgoing BLs. Preserve bits 0..3 and 21; map bits 4/5/6/7 to
//! 5/6/8/15, discarding all other bits. The caller translates two query
//! masks before storing them at backend +0xe30 and +0xe34.
//! Deliberate deviation: equivalent masks and shifts replace conditional
//! tests/ORs. Flag meanings are unknown; this is not the exact inverse
//! of 0x080c065c, which preserves bit 8 rather than mapping it to bit 6.

/// Converts a query mask into the firmware backend's sparse flag word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn query_mask_to_backend_mask(mask: u32) -> u32 {
    (mask & 0x0020_000f) | ((mask & 0x30) << 1)
        | ((mask & 0x40) << 2) | ((mask & 0x80) << 8)
}

#[cfg(test)]
mod tests {
    use super::query_mask_to_backend_mask;

    const MAPPING: [(u32, u32); 9] = [
        (1, 1), (2, 2), (4, 4), (8, 8),
        (0x10, 0x20), (0x20, 0x40), (0x40, 0x100),
        (0x80, 0x8000), (0x20_0000, 0x20_0000),
    ];

    fn reference(mask: u32) -> u32 {
        let mut flags = 0;
        for (input, output) in MAPPING {
            if mask & input != 0 { flags |= output; }
        }
        flags
    }

    #[test]
    fn each_input_bit_maps_or_is_discarded() {
        assert_eq!(query_mask_to_backend_mask(0), 0);
        for bit in 0..32 {
            let mask = 1u32 << bit;
            assert_eq!(query_mask_to_backend_mask(mask), reference(mask), "bit {bit}");
        }
        assert_eq!(query_mask_to_backend_mask(u32::MAX), 0x20_816f);
    }

    #[test]
    fn all_supported_combinations_ignore_unrelated_bits() {
        let supported = MAPPING.iter().fold(0, |mask, &(input, _)| mask | input);
        for combination in 0..512 {
            let mut mask = 0;
            for (bit, &(input, _)) in MAPPING.iter().enumerate() {
                if combination & (1 << bit) != 0 { mask |= input; }
            }
            let expected = reference(mask);
            assert_eq!(query_mask_to_backend_mask(mask), expected);
            assert_eq!(query_mask_to_backend_mask(mask | !supported), expected);
        }
    }
}
