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
//! The original tail-calls the unported leaf at 0x0824bf18. This port inlines
//! its fully decoded bit expansion rather than adding a second dispatch seam;
//! the cursor update remains before the source halfword read and output stores
//! remain in R/G/B/A order. Neither pointer has a NULL or bounds guard.

/// `rgb565_cursor_read_rgba8` — original: `FUN_0825ec74` @ 0x0825ec74
/// (20 bytes; **8 unconditional `bl` call sites**, no predicated or tail
/// branches, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// The complete raw body is five words: it loads the current `u16` from the
/// cursor in `r2`, advances that cursor by one halfword before reading the
/// pixel, then tail-branches to 0x0824be9c. That leaf expands the packed
/// RGB565 value to the `{R, G, B, A}` RGBA8 record at `r0`: bits 15..11,
/// 10..5, and 4..0 become 5/6/5-bit R/G/B components expanded by repeating
/// their high bits, and alpha is `0xff`. The Ghidra `r1` parameter is unused
/// and overwritten by the pixel load.
///
/// The 20-byte extent is exact: 0x0825ec70 is the preceding sibling's
/// `pop {r4,pc}`, and 0x0825ec88 starts the next function (`push {r4,lr}`).
/// There is no literal pool.
///
/// # Deliberate deviations
///
/// The original tail-calls the unported leaf at 0x0824be9c. This port inlines
/// its fully decoded bit expansion rather than adding a dispatch seam; it
/// preserves the cursor-before-halfword-read ordering, RGBA output order, and
/// absence of NULL or bounds guards.
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

    let red = ((pixel & 0xf800) >> 8) as u8;
    let green = ((pixel & 0x07e0) >> 3) as u8;
    let blue = ((pixel & 0x001f) << 3) as u8;

    destination.write_volatile(red | (red >> 5));
    destination.add(1).write_volatile(green | (green >> 6));
    destination.add(2).write_volatile(blue | (blue >> 5));
    destination.add(3).write_volatile(0xff);
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

    let red = ((pixel & 0xf800) >> 8) as u8;
    let green = ((pixel & 0x07c0) >> 3) as u8;
    let blue = ((pixel & 0x003e) << 2) as u8;

    destination.write_volatile(red | (red >> 5));
    destination.add(1).write_volatile(green | (green >> 5));
    destination.add(2).write_volatile(blue | (blue >> 5));
    destination.add(3).write_volatile(if pixel & 1 == 0 { 0 } else { 0xff });
}

/// `rgba4444_cursor_read_rgba8` — original: `FUN_0825ecc8` @ 0x0825ecc8
/// (20 bytes; **9 unconditional `bl` call sites**, no predicated or direct-tail
/// callers, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// The complete raw body loads a packed RGBA4444 halfword through the cursor
/// in `r2`, advances that cursor by one halfword before reading the pixel, and
/// tail-branches to 0x0824bed8. That unported leaf expands each four-bit
/// component by copying its nibble into both halves of the corresponding
/// output byte, writing `{R, G, B, A}` to `r0`. The incoming `r1` is
/// overwritten by the pixel load.
///
/// # Deliberate deviations
///
/// The original tail-calls the unported leaf at 0x0824bed8. This port inlines
/// its decoded expansion instead of adding a second dispatch seam; it retains
/// the cursor-before-halfword-load order, RGBA output order, and absence of
/// NULL or bounds guards.
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

    let red = ((pixel & 0xf000) >> 8) as u8;
    let green = ((pixel & 0x0f00) >> 4) as u8;
    let blue = (pixel & 0x00f0) as u8;
    let alpha = ((pixel & 0x000f) << 4) as u8;

    destination.write_volatile(red | (red >> 4));
    destination.add(1).write_volatile(green | (green >> 4));
    destination.add(2).write_volatile(blue | (blue >> 4));
    destination.add(3).write_volatile(alpha | (alpha >> 4));
}


#[cfg(test)]
mod tests {
    use super::{rgb555a1_cursor_read_rgba8, rgb565_cursor_read_rgba8, rgba4444_cursor_read_rgba8};

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
    fn expands_every_packed_value_and_advances_one_halfword() {
        for pixel in 0..=u16::MAX {
            let source = [pixel, !pixel];
            let mut cursor = source.as_ptr();
            let mut destination = [0xa5; 6];

            unsafe {
                rgb555a1_cursor_read_rgba8(destination.as_mut_ptr().add(1), 0, &mut cursor);
            }

            assert_eq!(&destination[1..5], &reference_rgb555a1(pixel), "pixel {pixel:#06x}");
            assert_eq!(destination[0], 0xa5, "pixel {pixel:#06x} wrote before destination");
            assert_eq!(destination[5], 0xa5, "pixel {pixel:#06x} wrote past destination");
            assert_eq!(cursor, unsafe { source.as_ptr().add(1) }, "pixel {pixel:#06x}");
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
