//! `rgb555a1_cursor_read_rgba8` — original: `FUN_0825ecdc` @ 0x0825ecdc
//! (20 bytes; **9 unconditional `bl` call sites**, no predicated or tail
//! branches, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The complete raw body is five words: it loads the current `u16` from the
//! cursor in `r2`, advances that cursor by one halfword before reading the
//! pixel, then tail-branches to 0x0824bf18. That leaf expands the packed
//! RGB555A1 value to the `{R, G, B, A}` RGBA8 record at `r0`: bits 15..11,
//! 10..6, and 5..1 become five-bit R/G/B components expanded by repeating
//! their high three bits; bit 0 becomes either transparent zero or opaque
//! `0xff` alpha. The Ghidra `r1` parameter is unused and overwritten by the
//! pixel load.
//!
//! The 20-byte extent is exact: 0x0825ecd8 is the preceding sibling's tail
//! branch, and 0x0825ecf0 begins the next function (`cmn r0,#1`). There is no
//! literal pool.
//!
//! # Deliberate deviations
//!
//! The original tail-calls the leaf ported below. The wrapper advances its
//! cursor before the source halfword read; the leaf retains the RGBA output
//! order and absence of NULL or bounds guards.

/// `u32_cursor_read_be_bytes` — original: `FUN_0825ec18` @ 0x0825ec18
/// (60 bytes; **8 unconditional `bl` call sites**, no predicated or tail
/// branches, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// The complete 15-word body loads the aligned native-endian `u32` through
/// the cursor in `r2`, advances the cursor by four bytes before dereferencing
/// it, then stores the word's most-significant byte through least-significant
/// byte at `r0`. Thus a little-endian source word is materialized as four
/// big-endian bytes. The incoming `r1` is overwritten with `r0` and unused.
/// The 60-byte extent is exact: the preceding sibling ends with `pop {r4,pc}`
/// at 0x0825ec14, and the separately linked RGB565 reader starts with
/// `push {r4,lr}` at 0x0825ec54. There is no literal pool.
///
/// # Deliberate deviations
///
/// The ARM leaves the loaded word in `r0`, but Ghidra declares this a `void`
/// helper and each verified direct caller overwrites or otherwise ignores
/// `r0`. The port therefore models its observable output and cursor effects
/// with a `void` ABI rather than exposing that incidental register residue.
///
/// # Safety
///
/// `source_cursor` must point to a writable aligned pointer to a readable
/// aligned `u32`; `destination` must name four writable bytes. The original
/// has no NULL, alignment, or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_cursor_read_be_bytes(
    destination: *mut u8,
    _unused: u32,
    source_cursor: *mut *const u32,
) {
    let source = source_cursor.read();
    source_cursor.write(source.add(1));
    let value = source.read();

    destination.write_volatile((value >> 24) as u8);
    destination.add(1).write_volatile((value >> 16) as u8);
    destination.add(2).write_volatile((value >> 8) as u8);
    destination.add(3).write_volatile(value as u8);
}

/// `luminance_alpha88_expand_to_rgba8` — original: `FUN_0824bd7c` @ 0x0824bd7c
/// (28 bytes; **8 direct unconditional `bl` call sites**, no predicated `bl`
/// forms or direct plain-`b` tails).
///
/// The complete seven-word leaf starts after the previous sibling's final
/// instruction at 0x0824bd78 and ends with `bx lr` at 0x0824bd94; 0x0824bd98
/// starts the separately linked four-component average helper. There is no
/// literal pool. It expands the packed luminance/alpha value's low byte into
/// R, G, and B, then writes its next byte as A, producing `{L, L, L, A}`.
/// Bits 16..31 do not affect the result. Full-image decoding of aligned ARM
/// B/BL words finds the eight unconditional `bl` sites at 0x08250a84,
/// 0x08250a94, 0x08250ab8, 0x08250ac8, 0x08250f90, 0x08250fa8, 0x08251398,
/// and 0x082513a4; there are no predicated calls or direct tail branches.
///
/// # Deliberate deviations
///
/// None. The four ordered volatile byte stores model the ARM `strb` writes.
///
/// # Safety
///
/// `destination` must name four writable bytes. The original has no NULL,
/// alignment, or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn luminance_alpha88_expand_to_rgba8(
    destination: *mut u8,
    packed_pixel: u32,
) {
    let luminance = packed_pixel as u8;

    destination.write_volatile(luminance);
    destination.add(1).write_volatile(luminance);
    destination.add(2).write_volatile(luminance);
    destination.add(3).write_volatile((packed_pixel >> 8) as u8);
}



/// `rgb565_expand_to_rgba8` — original: `FUN_0824be9c` @ 0x0824be9c
/// (60 bytes; **8 direct unconditional `bl` call sites**, no predicated
/// `bl` forms; one unconditional plain-`b` tail at 0x0825ec84).
///
/// The complete 15-word leaf starts immediately after its predecessor's
/// `bx lr` at 0x0824be98 and ends with `bx lr` at 0x0824bed4; 0x0824bed8
/// begins the separate RGBA4444 expansion leaf, with no literal pool between
/// them. It expands `packed_pixel` bits 15..11, 10..5, and 4..0 into 5/6/5
/// bit R/G/B components by repeating their high bits, then stores
/// `{R, G, B, 0xff}` to `destination`. Full-image decoding finds the eight
/// direct unconditional `bl` sites at 0x08250b58, 0x08250b68, 0x08250b8c,
/// 0x08250b9c, 0x08251024, 0x0825103c, 0x08251424, and 0x08251430; the only
/// direct tail branch is the RGB565 cursor reader at 0x0825ec84.
///
/// # Deliberate deviations
///
/// None. The four ordered volatile byte stores model the ARM `strb` writes.
///
/// # Safety
///
/// `destination` must name four writable bytes. The original has no NULL,
/// alignment, or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb565_expand_to_rgba8(destination: *mut u8, packed_pixel: u32) {
    let red = ((packed_pixel & 0xf800) >> 8) as u8;
    let green = ((packed_pixel & 0x07e0) >> 3) as u8;
    let blue = ((packed_pixel & 0x001f) << 3) as u8;

    destination.write_volatile(red | (red >> 5));
    destination.add(1).write_volatile(green | (green >> 6));
    destination.add(2).write_volatile(blue | (blue >> 5));
    destination.add(3).write_volatile(0xff);
}

/// `rgb565_cursor_read_rgba8` — original: `FUN_0825ec74` @ 0x0825ec74
/// (20 bytes; **8 unconditional `bl` call sites**, no predicated or tail
/// branches, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// The complete raw body is five words: it loads the current `u16` from the
/// cursor in `r2`, advances that cursor by one halfword before reading the
/// pixel, then tail-branches to `rgb565_expand_to_rgba8` at 0x0824be9c. The
/// port preserves that cursor-before-read ordering and calls the dedicated
/// leaf port for the RGBA8 output.
///
/// Reads one packed RGB565 pixel through `source_cursor`, advances the cursor,
/// and writes its expanded `{R, G, B, A}` bytes to `destination`.
///
/// # Safety
///
/// `source_cursor` must point to a writable aligned pointer to a readable
/// aligned `u16`; `destination` must name four writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb565_cursor_read_rgba8(
    destination: *mut u8,
    _unused: u32,
    source_cursor: *mut *const u16,
) {
    let source = source_cursor.read();
    source_cursor.write(source.add(1));
    let pixel = source.read();

    rgb565_expand_to_rgba8(destination, u32::from(pixel));
}

/// `rgb555a1_expand_to_rgba8` — original: `FUN_0824bf18` @ 0x0824bf18
/// (68 bytes; **8 direct unconditional `bl` call sites**, no predicated
/// `bl` forms; one unconditional plain-`b` tail at 0x0825ecec).
///
/// The complete 17-word leaf begins immediately after its predecessor's
/// `bx lr` at 0x0824bf14 and ends at 0x0824bf58; 0x0824bf5c starts the
/// separate four-byte store helper, with no literal pool between them. It
/// expands packed RGB555A1 in `packed_pixel`: bits 15..11, 10..6, and 5..1
/// become five-bit R/G/B components by repeating their high three bits; bit
/// 0 becomes transparent zero or opaque `0xff` alpha. Bits above 15 do not
/// affect the result. Full-image decoding finds the eight `bl` sites at
/// 0x08250c28, 0x08250c38, 0x08250c5c, 0x08250c6c, 0x082510b4, 0x082510cc,
/// 0x082514ac, and 0x082514b8; all are unconditional.
///
/// # Deliberate deviations
///
/// None. The four ordered volatile byte stores model the ARM `strb` writes.
///
/// # Safety
///
/// `destination` must name four writable bytes. The original has no NULL,
/// alignment, or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb555a1_expand_to_rgba8(destination: *mut u8, packed_pixel: u32) {
    let red = ((packed_pixel & 0xf800) >> 8) as u8;
    let green = ((packed_pixel & 0x07c0) >> 3) as u8;
    let blue = ((packed_pixel & 0x003e) << 2) as u8;

    destination.write_volatile(red | (red >> 5));
    destination.add(1).write_volatile(green | (green >> 5));
    destination.add(2).write_volatile(blue | (blue >> 5));
    destination.add(3).write_volatile(if packed_pixel & 1 == 0 { 0 } else { 0xff });
}

/// Reads one packed RGB555A1 pixel through `source_cursor`, advances the
/// cursor, and writes its expanded `{R, G, B, A}` bytes to `destination`.
///
/// # Safety
///
/// `source_cursor` must point to a writable aligned pointer to a readable
/// aligned `u16`; `destination` must name four writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb555a1_cursor_read_rgba8(
    destination: *mut u8,
    _unused: u32,
    source_cursor: *mut *const u16,
) {
    let source = source_cursor.read();
    source_cursor.write(source.add(1));
    let pixel = source.read();

    rgb555a1_expand_to_rgba8(destination, pixel.into());
}

/// `rgba4444_expand_to_rgba8` — original: `FUN_0824bed8` @ 0x0824bed8
/// (64 bytes; **8 direct unconditional `bl` call sites**, no predicated
/// `bl` forms; one unconditional plain-`b` tail at 0x0825ecd8).
///
/// The complete 16-word leaf begins immediately after its predecessor's
/// `bx lr` at 0x0824bed4 and ends with `bx lr` at 0x0824bf14; 0x0824bf18
/// begins the separately linked RGB555A1 expansion leaf, with no literal
/// pool between them. It expands `packed_pixel` bits 15..12, 11..8, 7..4,
/// and 3..0 by copying each nibble into both halves of its output byte,
/// writing `{R, G, B, A}` in that order. Bits above 15 do not affect the
/// result. Full-image decoding finds the eight `bl` sites at 0x08250cf8,
/// 0x08250d08, 0x08250d2c, 0x08250d3c, 0x08251144, 0x0825115c, 0x08251534,
/// and 0x08251540; all are unconditional. The plain tail branch at
/// 0x0825ecd8 is the RGBA4444 cursor reader.
///
/// # Deliberate deviations
///
/// None. The four ordered volatile byte stores model the ARM `strb` writes.
///
/// # Safety
///
/// `destination` must name four writable bytes. The original has no NULL,
/// alignment, or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba4444_expand_to_rgba8(destination: *mut u8, packed_pixel: u32) {
    let red = ((packed_pixel & 0xf000) >> 8) as u8;
    let green = ((packed_pixel & 0x0f00) >> 4) as u8;
    let blue = (packed_pixel & 0x00f0) as u8;
    let alpha = ((packed_pixel & 0x000f) << 4) as u8;

    destination.write_volatile(red | (red >> 4));
    destination.add(1).write_volatile(green | (green >> 4));
    destination.add(2).write_volatile(blue | (blue >> 4));
    destination.add(3).write_volatile(alpha | (alpha >> 4));
}

/// `rgba4444_cursor_read_rgba8` — original: `FUN_0825ecc8` @ 0x0825ecc8
/// (20 bytes; **9 unconditional `bl` call sites**, no predicated or direct-tail
/// callers, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// The complete raw body loads a packed RGBA4444 halfword through the cursor
/// in `r2`, advances that cursor by one halfword before reading the pixel, and
/// tail-branches to the RGBA4444 expansion leaf at 0x0824bed8. The incoming
/// `r1` is overwritten by the pixel load.
///
/// # Deliberate deviations
///
/// The original tail-calls `rgba4444_expand_to_rgba8`; the wrapper makes a
/// Rust call while retaining the cursor-before-halfword-read ordering and the
/// leaf's RGBA output order and absence of guards.
///
/// # Safety
///
/// `source_cursor` must point to a writable aligned pointer to a readable
/// aligned `u16`; `destination` must name four writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba4444_cursor_read_rgba8(
    destination: *mut u8,
    _unused: u32,
    source_cursor: *mut *const u16,
) {
    let source = source_cursor.read();
    source_cursor.write(source.add(1));
    let pixel = source.read();

    rgba4444_expand_to_rgba8(destination, pixel.into());
}


#[cfg(test)]
mod tests {
    use super::{luminance_alpha88_expand_to_rgba8, rgb555a1_cursor_read_rgba8, rgb555a1_expand_to_rgba8, rgb565_cursor_read_rgba8, rgb565_expand_to_rgba8, rgba4444_cursor_read_rgba8, rgba4444_expand_to_rgba8, u32_cursor_read_be_bytes};
    #[test]
    fn expands_every_rgb565_value_and_ignores_upper_input_bits() {
        for pixel in 0..=u16::MAX {
            let mut destination = [0xa5; 6];

            unsafe {
                rgb565_expand_to_rgba8(destination.as_mut_ptr().add(1), u32::from(pixel) | 0xbeef_0000);
            }

            assert_eq!(&destination[1..5], &reference_rgb565(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
        }
    }

    #[test]
    fn expands_every_luminance_alpha88_value_and_ignores_upper_input_bits() {
        for pixel in 0..=u16::MAX {
            let mut destination = [0xa5; 6];

            unsafe {
                luminance_alpha88_expand_to_rgba8(
                    destination.as_mut_ptr().add(1),
                    u32::from(pixel) | 0xbeef_0000,
                );
            }

            assert_eq!(
                &destination[1..5],
                &[pixel as u8, pixel as u8, pixel as u8, (pixel >> 8) as u8],
                "pixel {pixel:#06x}",
            );
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
        }
    }


    fn reference_rgb555a1(pixel: u16) -> [u8; 4] {
        let expand = |component: u8| (component << 3) | (component >> 2);
        [
            expand(((pixel >> 11) & 0x1f) as u8),
            expand(((pixel >> 6) & 0x1f) as u8),
            expand(((pixel >> 1) & 0x1f) as u8),
            if pixel & 1 == 0 { 0 } else { 0xff },
        ]
    }

    fn reference_rgb565(pixel: u16) -> [u8; 4] {
        let red = ((pixel & 0xf800) >> 8) as u8;
        let green = ((pixel & 0x07e0) >> 3) as u8;
        let blue = ((pixel & 0x001f) << 3) as u8;
        [red | (red >> 5), green | (green >> 6), blue | (blue >> 5), 0xff]
    }

    #[test]
    fn writes_u32_as_big_endian_bytes_and_advances_one_word() {
        for value in [0, u32::MAX, 0x1122_3344, 0x80ff_7f00] {
            let source = [value, !value];
            let mut cursor = source.as_ptr();
            let mut destination = [0xa5; 6];

            unsafe {
                u32_cursor_read_be_bytes(destination.as_mut_ptr().add(1), 0xffff_ffff, &mut cursor);
            }

            assert_eq!(&destination[1..5], &value.to_be_bytes(), "word {value:#010x}");
            assert_eq!(destination[0], 0xa5, "word {value:#010x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "word {value:#010x} wrote past destination");
            assert_eq!(cursor, unsafe { source.as_ptr().add(1) }, "word {value:#010x}");
        }
    }

    #[test]
    fn preserves_u32_cursor_progression_across_multiple_words() {
        let source = [0x1122_3344, 0xaabb_ccdd, 0xfeed_face];
        let mut cursor = source.as_ptr();
        let mut first = [0; 4];
        let mut second = [0; 4];

        unsafe {
            u32_cursor_read_be_bytes(first.as_mut_ptr(), 0, &mut cursor);
            u32_cursor_read_be_bytes(second.as_mut_ptr(), 0xffff_ffff, &mut cursor);
        }

        assert_eq!(first, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(second, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(cursor, unsafe { source.as_ptr().add(2) });
    }

    #[test]
    fn expands_every_rgb565_value_and_advances_one_halfword() {
        for pixel in 0..=u16::MAX {
            let source = [pixel, !pixel];
            let mut cursor = source.as_ptr();
            let mut destination = [0xa5; 6];

            unsafe {
                rgb565_cursor_read_rgba8(destination.as_mut_ptr().add(1), 0, &mut cursor);
            }

            assert_eq!(&destination[1..5], &reference_rgb565(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
            assert_eq!(cursor, unsafe { source.as_ptr().add(1) }, "pixel {pixel:#06x}");
        }
    }

    #[test]
    fn expands_every_rgb555a1_value_and_ignores_upper_input_bits() {
        for pixel in 0..=u16::MAX {
            let mut destination = [0xa5; 6];

            unsafe {
                rgb555a1_expand_to_rgba8(destination.as_mut_ptr().add(1), u32::from(pixel) | 0xbeef_0000);
            }

            assert_eq!(&destination[1..5], &reference_rgb555a1(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
        }
    }

    #[test]
    fn preserves_cursor_progression_across_multiple_pixels() {
        let source = [0x0000, 0xffff, 0x10c1];
        let mut cursor = source.as_ptr();
        let mut first = [0; 4];
        let mut second = [0; 4];

        unsafe {
            rgb555a1_cursor_read_rgba8(first.as_mut_ptr(), 0xffff_ffff, &mut cursor);
            rgb555a1_cursor_read_rgba8(second.as_mut_ptr(), 0, &mut cursor);
        }

        assert_eq!(first, [0, 0, 0, 0]);
        assert_eq!(second, [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(cursor, unsafe { source.as_ptr().add(2) });
    }

    fn reference_rgba4444(pixel: u16) -> [u8; 4] {
        let expand = |component: u8| (component << 4) | component;
        [
            expand(((pixel >> 12) & 0xf) as u8),
            expand(((pixel >> 8) & 0xf) as u8),
            expand(((pixel >> 4) & 0xf) as u8),
            expand((pixel & 0xf) as u8),
        ]
    }

    #[test]
    fn expands_every_rgba4444_value_and_ignores_upper_input_bits() {
        for pixel in 0..=u16::MAX {
            let mut destination = [0xa5; 6];

            unsafe {
                rgba4444_expand_to_rgba8(destination.as_mut_ptr().add(1), u32::from(pixel) | 0xfedc_0000);
            }

            assert_eq!(&destination[1..5], &reference_rgba4444(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
        }
    }

    #[test]
    fn expands_every_rgba4444_value_and_advances_one_halfword() {
        for pixel in 0..=u16::MAX {
            let source = [pixel, !pixel];
            let mut cursor = source.as_ptr();
            let mut destination = [0xa5; 6];

            unsafe {
                rgba4444_cursor_read_rgba8(destination.as_mut_ptr().add(1), 0, &mut cursor);
            }

            assert_eq!(&destination[1..5], &reference_rgba4444(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
            assert_eq!(cursor, unsafe { source.as_ptr().add(1) }, "pixel {pixel:#06x}");
        }
    }
}
