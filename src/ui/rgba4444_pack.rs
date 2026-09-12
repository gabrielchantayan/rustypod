//! `rgba8_to_rgba4444` — original: `FUN_082a009c` @ `0x082a009c` (48 bytes;
//! **8 unconditional `bl` call sites**, no predicated or tail-branch callers,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The raw body starts with `ldrb r1,[r0]` and ends with `bx lr` at
//! `0x082a00c8`; the distinct RGB555A1 packer begins at `0x082a00cc`, so the
//! 48-byte extent contains no literal pool. It reads the four RGBA8 bytes in
//! order, retains each high nibble, and packs them into bits 15..12, 11..8,
//! 7..4, and 3..0 respectively. It has no NULL or bounds guard.
//!
//! # Deliberate deviations
//!
//! The ARM ABI returns the 16-bit packed value in `r0`; this port represents
//! that unchanged register value as `u32`. It performs no validation, matching
//! the original pure bitwise leaf.

/// Packs four RGBA8 component bytes into a 16-bit RGBA4444 value.
///
/// # Safety
///
/// `components` must identify four readable bytes in R, G, B, A order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba8_to_rgba4444(components: *const u8) -> u32 {
    let red = u32::from(*components);
    let green = u32::from(*components.add(1));
    let blue = u32::from(*components.add(2));
    let alpha = u32::from(*components.add(3));

    ((red & 0xf0) << 8)
        | ((green & 0xf0) << 4)
        | (blue & 0xf0)
        | (alpha >> 4)
}

#[cfg(test)]
mod tests {
    use super::rgba8_to_rgba4444;

    #[test]
    fn packs_each_component_high_nibble_in_rgba_order() {
        let components = [0xab, 0xcd, 0xef, 0x12];

        assert_eq!(unsafe { rgba8_to_rgba4444(components.as_ptr()) }, 0xace1);
    }

    #[test]
    fn discards_low_nibbles_and_reads_an_offset_record() {
        let record = [0xa5, 0x0f, 0xf0, 0x9a, 0xb3, 0x5a];

        assert_eq!(unsafe { rgba8_to_rgba4444(record.as_ptr().add(1)) }, 0x0f9b);
    }

    #[test]
    fn preserves_all_set_component_nibbles() {
        let components = [0xff; 4];

        assert_eq!(unsafe { rgba8_to_rgba4444(components.as_ptr()) }, 0xffff);
    }
}
