//! `rgba8_cursor_write_rgba4444` — original: `FUN_0825ec88` @ `0x0825ec88`
//! (32 bytes; **5 unconditional `bl` call sites**, no predicated `bl` forms
//! or direct tail branches, binary-scanned by decoding every ARM B/BL word in
//! `osos.dec`).
//!
//! The complete eight-word body starts with `push {r4,lr}` at `0x0825ec88` and
//! ends with `pop {r4,pc}` at `0x0825eca4`; the distinct RGB555A1 cursor writer
//! starts at `0x0825eca8`, so there is no literal pool. It loads the current
//! destination halfword pointer from `destination_cursor`, advances the cursor
//! before conversion, packs the four RGBA8 bytes at `components` through
//! `rgba8_to_rgba4444`, and stores the returned low halfword.
//!
//! # Deliberate deviations
//!
//! The ARM leaves the packer's `u32` return in `r0` after the `strh`, but every
//! observed caller treats this helper as `void`; this port exposes only its
//! observable store and cursor effects. The volatile halfword store preserves
//! the ARM `strh` side effect.

use crate::ui::rgba4444_pack::rgba8_to_rgba4444;

/// Packs one RGBA8 record through `destination_cursor` as RGBA4444.
///
/// # Safety
///
/// `destination_cursor` must point to a writable aligned pointer to a writable
/// aligned `u16`; `components` must identify four readable RGBA8 bytes. The
/// original has no NULL, alignment, or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba8_cursor_write_rgba4444(
    _unused: u32,
    destination_cursor: *mut *mut u16,
    components: *const u8,
) {
    let destination = destination_cursor.read();
    destination_cursor.write(destination.add(1));
    destination.write_volatile(rgba8_to_rgba4444(components) as u16);
}

#[cfg(test)]
mod tests {
    use super::rgba8_cursor_write_rgba4444;

    fn reference_rgba4444(components: &[u8; 4]) -> u16 {
        ((u16::from(components[0]) & 0xf0) << 8)
            | ((u16::from(components[1]) & 0xf0) << 4)
            | (u16::from(components[2]) & 0xf0)
            | (u16::from(components[3]) >> 4)
    }

    #[test]
    fn advances_cursor_and_writes_only_its_current_halfword() {
        let components = [0xab, 0xcd, 0xef, 0x12];
        let mut pixels = [0xa5a5, 0x5a5a, 0xc3c3];
        let mut cursor = unsafe { pixels.as_mut_ptr().add(1) };

        unsafe { rgba8_cursor_write_rgba4444(0xffff_ffff, &mut cursor, components.as_ptr()) };

        assert_eq!(pixels, [0xa5a5, reference_rgba4444(&components), 0xc3c3]);
        assert_eq!(cursor, unsafe { pixels.as_mut_ptr().add(2) });
    }

    #[test]
    fn truncates_component_low_bits_from_an_offset_record() {
        let record = [0xa5, 0x0f, 0xf7, 0x9a, 0xb3, 0x5a];
        let mut pixels = [0; 2];
        let mut cursor = pixels.as_mut_ptr();
        let components = unsafe { record.as_ptr().add(1) };

        unsafe { rgba8_cursor_write_rgba4444(0, &mut cursor, components) };

        assert_eq!(pixels[0], 0x0f9b);
        assert_eq!(cursor, unsafe { pixels.as_mut_ptr().add(1) });
    }
}
