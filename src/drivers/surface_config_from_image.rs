//! `surface_config_from_image` — original: `FUN_08144994` @ `0x08144994`
//! (156 bytes; six direct `bl` call sites, binary-scanned).
//!
//! Builds the mutable portion of a display-layer configuration descriptor from
//! an image record. The source record's format halfword is at `+0x14`; its
//! bounds are the word pairs `{+0x98, +0xa0}` and `{+0x9c, +0xa4}`. RGB565
//! (`0x0565`) selects config format 2, packed 24-bit-alpha (`0x1888`) selects
//! format 3, and every other format selects format 0 with the low byte of the
//! opaque `+0x30` word set to `0x80`. The horizontal and vertical spans are
//! stored in both the size and buffer-size fields.
//!
//! Raw ARM confirms Ghidra's 156-byte extent: the next sibling starts at
//! `0x08144a30`. Its six direct callers are all unconditional `bl` at
//! `0x081444f8`, `0x08145cec`, `0x08146040`, `0x08146274`, `0x08146534`, and
//! `0x0814658c`; no predicated direct call reaches this function. The routine
//! has no calls of its own. It preserves and returns its original `r0`, though
//! every known caller discards that value. Deliberate deviations: none.

/// Initialize a display-layer config from an image's format and bounds.
///
/// `context` is retained solely because the original preserves it in `r0`.
/// Both `image` and `config` must be four-byte aligned, as required by the
/// original `ldrh`/`ldm`/`str` instructions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_config_from_image(
    context: *mut u8,
    image: *const u8,
    config: *mut u8,
) -> *mut u8 {
    let format = (image.add(0x14) as *const u16).read();
    let start_x = (image.add(0x98) as *const u32).read();
    let start_y = (image.add(0x9c) as *const u32).read();
    let end_x = (image.add(0xa0) as *const u32).read();
    let end_y = (image.add(0xa4) as *const u32).read();
    let width = end_x.wrapping_sub(start_x);
    let height = end_y.wrapping_sub(start_y);

    config.add(1).write_volatile(3);
    match format {
        0x0565 => {
            (config.add(0x30) as *mut u16).write_volatile(0);
            config.write_volatile(2);
        }
        0x1888 => {
            (config.add(0x30) as *mut u32).write_volatile(0);
            config.write_volatile(3);
        }
        _ => {
            config.write_volatile(0);
            config.add(0x30).write_volatile(0x80);
        }
    }
    config.add(0x2d).write_volatile(0);
    (config.add(0x18) as *mut u32).write_volatile(width);
    (config.add(0x10) as *mut u32).write_volatile(width);
    (config.add(0x14) as *mut u32).write_volatile(height);
    (config.add(0x0c) as *mut u32).write_volatile(height);
    (config.add(0x28) as *mut u32).write_volatile(0);
    (config.add(0x24) as *mut u32).write_volatile(0);
    (config.add(4) as *mut u32).write_volatile(0);
    (config.add(8) as *mut u32).write_volatile(0);

    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Image([u8; 0xa8]);

    #[repr(align(4))]
    #[derive(Debug, Eq, PartialEq)]
    struct Config([u8; 0x40]);

    fn image(format: u16, start_x: u32, start_y: u32, end_x: u32, end_y: u32) -> Image {
        let mut image = Image([0xa5; 0xa8]);
        image.0[0x14..0x16].copy_from_slice(&format.to_le_bytes());
        image.0[0x98..0x9c].copy_from_slice(&start_x.to_le_bytes());
        image.0[0x9c..0xa0].copy_from_slice(&start_y.to_le_bytes());
        image.0[0xa0..0xa4].copy_from_slice(&end_x.to_le_bytes());
        image.0[0xa4..0xa8].copy_from_slice(&end_y.to_le_bytes());
        image
    }

    fn word_at(config: &Config, offset: usize) -> u32 {
        u32::from_le_bytes(config.0[offset..offset + 4].try_into().unwrap())
    }

    fn configure(image: &Image, context: *mut u8) -> (Config, *mut u8) {
        let mut config = Config([0xa5; 0x40]);
        let returned = unsafe { surface_config_from_image(context, image.0.as_ptr(), config.0.as_mut_ptr()) };
        (config, returned)
    }

    #[test]
    fn rgb565_selects_format_two_and_preserves_the_upper_opaque_halfword() {
        let image = image(0x0565, 10, 20, 330, 260);
        let (config, _) = configure(&image, core::ptr::null_mut());

        assert_eq!(config.0[0], 2);
        assert_eq!(config.0[1], 3);
        assert_eq!(&config.0[0x30..0x34], &[0, 0, 0xa5, 0xa5]);
    }

    #[test]
    fn packed_1888_selects_format_three_and_zeros_the_opaque_word() {
        let image = image(0x1888, 0, 0, 320, 240);
        let (config, _) = configure(&image, core::ptr::null_mut());

        assert_eq!(config.0[0], 3);
        assert_eq!(config.0[1], 3);
        assert_eq!(word_at(&config, 0x30), 0);
    }

    #[test]
    fn unknown_format_sets_the_byte_flag_without_touching_the_opaque_tail() {
        let image = image(0x0102, 0, 0, 1, 1);
        let (config, _) = configure(&image, core::ptr::null_mut());

        assert_eq!(config.0[0], 0);
        assert_eq!(config.0[1], 3);
        assert_eq!(&config.0[0x30..0x34], &[0x80, 0xa5, 0xa5, 0xa5]);
    }

    #[test]
    fn bounds_become_wrapping_size_and_buffer_size_pairs() {
        let image = image(0x0565, 0xffff_fffe, 8, 3, 2);
        let (config, _) = configure(&image, core::ptr::null_mut());

        assert_eq!(word_at(&config, 0x10), 5);
        assert_eq!(word_at(&config, 0x18), 5);
        assert_eq!(word_at(&config, 0x0c), 0xffff_fffa);
        assert_eq!(word_at(&config, 0x14), 0xffff_fffa);
    }

    #[test]
    fn zeroed_fields_and_untouched_defaults_match_the_original_write_set() {
        let image = image(0x0565, 0, 0, 0, 0);
        let context = 0x1234usize as *mut u8;
        let (config, returned) = configure(&image, context);

        assert_eq!(returned, context);
        for offset in [0x04, 0x08, 0x24, 0x28] {
            assert_eq!(word_at(&config, offset), 0, "word +{offset:#x}");
        }
        for offset in [0x1c, 0x20] {
            assert_eq!(word_at(&config, offset), 0xa5a5_a5a5, "word +{offset:#x}");
        }
        assert_eq!(config.0[0x2c], 0xa5);
        assert_eq!(config.0[0x2d], 0);
        assert_eq!(&config.0[0x02..0x04], &[0xa5, 0xa5]);
        assert_eq!(&config.0[0x2e..0x30], &[0xa5, 0xa5]);
        assert_eq!(&config.0[0x34..], &[0xa5; 12]);
    }
}
