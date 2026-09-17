//! `rgba8_to_rgba8888` — original: `FUN_082a0100` @ `0x082a0100` (36 bytes;
//! **4 unconditional `bl` call sites**, no predicated `bl` call sites,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The raw body begins with `ldrb r1,[r0]` and ends with `bx lr` at
//! `0x082a0120`; the next separately linked function begins at `0x082a0124`,
//! so the complete extent is nine instructions with no literal pool. It reads
//! four RGBA8 bytes in order and returns them as the u32 `0xRRGGBBAA`. It has
//! no NULL, alignment, or bounds guard.
//!
//! # Deliberate deviations
//!
//! None. The ARM return-register value is represented directly as `u32`.

/// Packs four RGBA8 component bytes into a `0xRRGGBBAA` u32.
///
/// # Safety
///
/// `components` must identify four readable bytes in R, G, B, A order.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rgba8_to_rgba8888")]
#[inline(never)]
pub unsafe extern "C" fn rgba8_to_rgba8888(components: *const u8) -> u32 {
    (u32::from(*components) << 24)
        | (u32::from(*components.add(1)) << 16)
        | (u32::from(*components.add(2)) << 8)
        | u32::from(*components.add(3))
}

#[cfg(test)]
mod tests {
    use super::rgba8_to_rgba8888;

    #[test]
    fn packs_each_component_in_rgba_order() {
        let components = [0x12, 0x34, 0x56, 0x78];

        assert_eq!(unsafe { rgba8_to_rgba8888(components.as_ptr()) }, 0x1234_5678);
    }

    #[test]
    fn reads_exactly_four_bytes_from_an_offset_record() {
        let record = [0xa5, 0x01, 0x23, 0x45, 0x67, 0x5a];

        assert_eq!(unsafe { rgba8_to_rgba8888(record.as_ptr().add(1)) }, 0x0123_4567);
    }

    #[test]
    fn preserves_zero_and_all_set_components() {
        assert_eq!(unsafe { rgba8_to_rgba8888([0; 4].as_ptr()) }, 0);
        assert_eq!(unsafe { rgba8_to_rgba8888([0xff; 4].as_ptr()) }, u32::MAX);
    }
}
