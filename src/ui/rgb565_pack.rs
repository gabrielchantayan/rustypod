//! `rgb8_to_rgb565` — original: `FUN_082a0074` @ `0x082a0074` (40 bytes;
//! **8 unconditional `bl` call sites**, no predicated or tail-branch callers,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The raw body starts with `ldrb r1,[r0,#2]` and ends with `bx lr` at
//! `0x082a0098`; the distinct RGBA4444 packer begins at `0x082a009c`, so the
//! 40-byte extent contains no literal pool. It reads three RGB8 bytes in
//! R, G, B order, retains the upper 5/6/5 component bits, and packs them into
//! RGB565 bits 15..11, 10..5, and 4..0. It has no NULL or bounds guard.
//!
//! # Deliberate deviations
//!
//! The ARM ABI returns the 16-bit packed value in `r0`; this port represents
//! that unchanged register value as `u32`. It performs no validation, matching
//! the original pure bitwise leaf.

/// Packs three RGB8 component bytes into a 16-bit RGB565 value.
///
/// # Safety
///
/// `components` must identify three readable bytes in R, G, B order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb8_to_rgb565(components: *const u8) -> u32 {
    let blue = u32::from(*components.add(2));
    let green = u32::from(*components.add(1));
    let red = u32::from(*components);

    ((red & 0xf8) << 8) | ((green & 0xfc) << 3) | (blue >> 3)
}

#[cfg(test)]
mod tests {
    use super::rgb8_to_rgb565;

    #[test]
    fn packs_full_intensity_primary_colors() {
        assert_eq!(unsafe { rgb8_to_rgb565([0xff, 0x00, 0x00].as_ptr()) }, 0xf800);
        assert_eq!(unsafe { rgb8_to_rgb565([0x00, 0xff, 0x00].as_ptr()) }, 0x07e0);
        assert_eq!(unsafe { rgb8_to_rgb565([0x00, 0x00, 0xff].as_ptr()) }, 0x001f);
    }

    #[test]
    fn assigns_each_component_to_its_rgb565_field() {
        let components = [0xab, 0xcd, 0xef];

        assert_eq!(unsafe { rgb8_to_rgb565(components.as_ptr()) }, 0xae7d);
    }

    #[test]
    fn discards_low_component_bits_from_an_offset_record() {
        let record = [0xa5, 0x0f, 0xf3, 0x9d, 0x5a];

        assert_eq!(unsafe { rgb8_to_rgb565(record.as_ptr().add(1)) }, 0x0f93);
    }
}
