//! `rgba8_to_rgb555a1` — original: `FUN_082a00cc` @ `0x082a00cc` (52 bytes;
//! **6 unconditional `bl` call sites**, no predicated or tail-branch callers,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The raw body starts with `ldrb r1,[r0,#2]` and ends with `bx lr` at
//! `0x082a00fc`; the distinct four-byte RGBA loader begins at `0x082a0100`,
//! so the 52-byte extent contains no literal pool. It reads four RGBA8 bytes
//! in order, retains the upper five bits of R, G, and B, and packs them into
//! RGB555A1 bits 15..11, 10..6, and 5..1. The high alpha bit becomes bit 0.
//! It has no NULL or bounds guard.
//!
//! # Deliberate deviations
//!
//! The ARM ABI returns the 16-bit packed value in `r0`; this port represents
//! that unchanged register value as `u32`. It performs no validation, matching
//! the original pure bitwise leaf.

/// Packs four RGBA8 component bytes into a 16-bit RGB555A1 value.
///
/// # Safety
///
/// `components` must identify four readable bytes in R, G, B, A order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba8_to_rgb555a1(components: *const u8) -> u32 {
    let blue = u32::from(*components.add(2));
    let green = u32::from(*components.add(1));
    let red = u32::from(*components);
    let alpha = u32::from(*components.add(3));

    ((red & 0xf8) << 8)
        | ((green & 0xf8) << 3)
        | ((blue & 0xf8) >> 2)
        | (alpha >> 7)
}

#[cfg(test)]
mod tests {
    use super::rgba8_to_rgb555a1;

    #[test]
    fn packs_full_intensity_primary_colors_and_alpha() {
        assert_eq!(unsafe { rgba8_to_rgb555a1([0xff, 0x00, 0x00, 0x00].as_ptr()) }, 0xf800);
        assert_eq!(unsafe { rgba8_to_rgb555a1([0x00, 0xff, 0x00, 0x00].as_ptr()) }, 0x07c0);
        assert_eq!(unsafe { rgba8_to_rgb555a1([0x00, 0x00, 0xff, 0x00].as_ptr()) }, 0x003e);
        assert_eq!(unsafe { rgba8_to_rgb555a1([0x00, 0x00, 0x00, 0x80].as_ptr()) }, 0x0001);
    }

    #[test]
    fn assigns_each_component_to_its_rgb555a1_field() {
        let components = [0xab, 0xcd, 0xef, 0x92];

        assert_eq!(unsafe { rgba8_to_rgb555a1(components.as_ptr()) }, 0xae7b);
    }

    #[test]
    fn discards_low_rgb_bits_and_low_alpha_bits_from_offset_record() {
        let record = [0xa5, 0x0f, 0xf7, 0x9a, 0x7f, 0x5a];

        assert_eq!(unsafe { rgba8_to_rgb555a1(record.as_ptr().add(1)) }, 0x0fa6);
    }
}
