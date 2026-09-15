//! `rgb8_cursor_write_rgb565` — original: `FUN_0825ec54` @ `0x0825ec54`
//! (32 bytes; **5 unconditional `bl` call sites**, no predicated `bl` forms
//! or direct tail branches, binary-scanned by decoding every aligned ARM B/BL
//! word in `osos.dec`).
//!
//! The exact eight-word body starts after the preceding `pop {r4,pc}` at
//! `0x0825ec50` and ends with `pop {r4,pc}` at `0x0825ec70`; the distinct
//! RGB565 cursor reader starts at `0x0825ec74`, with no literal pool. It loads
//! the `u16` destination cursor from `r1`, advances and stores that cursor
//! before converting the RGB8 record at `r2` through `rgb8_to_rgb565`, then
//! stores the packed halfword at the old cursor.
//!
//! # Deliberate deviations
//!
//! The original calls the separately linked packer at `0x082a0074`; this port
//! makes the equivalent Rust call. It preserves the cursor-before-component-read
//! ordering and has no NULL, alignment, or bounds guards.

use crate::ui::rgb565_pack::rgb8_to_rgb565;

/// Converts one RGB8 triplet and writes the RGB565 result through `destination_cursor`.
///
/// # Safety
///
/// `destination_cursor` must identify a writable aligned pointer to one writable
/// `u16`; `components` must identify three readable bytes in R, G, B order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb8_cursor_write_rgb565(
    _unused: u32,
    destination_cursor: *mut *mut u16,
    components: *const u8,
) {
    let destination = destination_cursor.read();
    destination_cursor.write(destination.add(1));
    destination.write(rgb8_to_rgb565(components) as u16);
}

#[cfg(test)]
mod tests {
    use super::rgb8_cursor_write_rgb565;

    #[test]
    fn packs_triplets_advances_cursor_and_preserves_bounds() {
        for (components, packed) in [([0xff, 0x00, 0x00], 0xf800), ([0x12, 0xab, 0xfe], 0x155f)] {
            let mut destination = [0xa5a5, 0x0000, 0x5a5a];
            let mut cursor = destination.as_mut_ptr().wrapping_add(1);

            unsafe { rgb8_cursor_write_rgb565(0xffff_ffff, &mut cursor, components.as_ptr()) };

            assert_eq!(destination, [0xa5a5, packed, 0x5a5a]);
            assert_eq!(cursor, destination.as_mut_ptr().wrapping_add(2));
        }
    }

    #[test]
    fn advances_before_reading_components() {
        let mut storage = [0u16; 3];
        let components = unsafe { storage.as_mut_ptr().cast::<u8>().add(2) };
        unsafe { components.copy_from_nonoverlapping([0x12, 0xab, 0xfe].as_ptr(), 3) };
        let mut cursor = storage.as_mut_ptr();

        unsafe { rgb8_cursor_write_rgb565(0, &mut cursor, components) };

        assert_eq!(storage[0], 0x155f);
        assert_eq!(cursor, unsafe { storage.as_mut_ptr().add(1) });
    }
}
