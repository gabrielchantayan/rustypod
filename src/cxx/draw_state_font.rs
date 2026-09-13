//! `draw_state_set_font` — original: `FUN_0826421c` @ 0x0826421c (44
//! bytes, 0x0826421c..0x08264248; 7 unconditional `bl` call sites, zero
//! predicated forms, and zero tail `b` calls, binary-scanned by decoding
//! every ARM B/BL word in osos.dec).
//!
//! The next distinct function begins at 0x08264248 (`push {r4,r5,r6,r7,lr}`),
//! so Ghidra's 44-byte extent has no swallowed literal pool or sibling.
//! This setter copies an 8-byte font handle into the scoped 0x44-byte
//! draw-state record at +0x20/+0x24, then derives its byte at +0x28 from the
//! handle's first word: zero for a null handle; otherwise byte +0x4c of the
//! low-bit-cleared font object, with bit 2 set when the first handle word is
//! low-bit tagged. The original does not validate either input.
//!
//! Deliberate deviations: named offsets replace the original's raw ARM
//! offsets. The firmware stores target-width words, so this port keeps font
//! handles as `u32` words on every target rather than host pointer-sized
//! fields.

use crate::cxx::draw_state::DRAW_STATE_EMBEDDED_PAIR_OFFSET;

/// Byte offset of the style byte derived from the current font handle.
pub const DRAW_STATE_FONT_STYLE_OFFSET: usize = 0x28;

/// Byte offset in an untagged font object used to derive draw-state style.
const FONT_DRAW_STYLE_OFFSET: usize = 0x4c;

/// `draw_state_set_font` — original: `FUN_0826421c` @ 0x0826421c (44 bytes;
/// 7 unconditional `bl` call sites, zero predicated forms, zero tail `b`,
/// binary-scanned).
///
/// Copies the two target-width words at `font_handle` into the draw-state
/// record at +0x20/+0x24. A zero first word writes style byte zero. Otherwise
/// the first word is a low-bit-tagged pointer to a font object: this function
/// reads its byte +0x4c after clearing that tag, then ORs style bit 2 back in
/// when the tag was set. The pair stores precede that object-byte read, as in
/// the original `ldm`/`stm`/`bics` sequence.
///
/// # Safety
///
/// `record` must be writable for a word-aligned 0x44-byte draw-state record.
/// `font_handle` must be readable for two aligned `u32` words. When its first
/// word is nonzero, clearing bit 0 must produce a readable font object with a
/// byte at +0x4c. The original has no NULL or bounds guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_font(record: *mut u8, font_handle: *const u32) {
    let font_word = unsafe { font_handle.read() };
    let font_metadata = unsafe { font_handle.add(1).read() };

    unsafe {
        (record.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) as *mut u32).write(font_word);
        (record.add(DRAW_STATE_EMBEDDED_PAIR_OFFSET + core::mem::size_of::<u32>()) as *mut u32)
            .write(font_metadata);
    }

    let font_object = font_word & !1;
    let mut style = if font_object == 0 {
        0
    } else {
        unsafe { (font_object as *const u8).add(FONT_DRAW_STYLE_OFFSET).read() }
    };
    if font_word & 1 != 0 {
        style |= 4;
    }
    unsafe { record.add(DRAW_STATE_FONT_STYLE_OFFSET).write(style) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const GUARD: u8 = 0xa5;
    const FONT_OBJECT_BYTES: usize = 0x1000;

    #[test]
    fn null_font_copies_both_words_and_clears_only_style() {
        let mut record = [GUARD; DRAW_STATE_SIZE];
        let expected = record;
        let handle = [0, 0xfeed_cafe];

        unsafe { draw_state_set_font(record.as_mut_ptr(), handle.as_ptr()) };

        assert_eq!(
            unsafe { (record.as_ptr().add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) as *const u32).read() },
            handle[0]
        );
        assert_eq!(
            unsafe {
                (record
                    .as_ptr()
                    .add(DRAW_STATE_EMBEDDED_PAIR_OFFSET + core::mem::size_of::<u32>())
                    as *const u32)
                    .read()
            },
            handle[1]
        );
        assert_eq!(record[DRAW_STATE_FONT_STYLE_OFFSET], 0);
        for (offset, (&actual, &before)) in record.iter().zip(expected.iter()).enumerate() {
            let written = (DRAW_STATE_EMBEDDED_PAIR_OFFSET
                ..DRAW_STATE_EMBEDDED_PAIR_OFFSET + 2 * core::mem::size_of::<u32>())
                .contains(&offset)
                || offset == DRAW_STATE_FONT_STYLE_OFFSET;
            if !written {
                assert_eq!(actual, before, "byte {offset:#x} outside the three stores changed");
            }
        }
    }

    #[test]
    fn font_object_style_preserves_tag_and_handle_words() {
        let Some(font_object) = try_map_u32_slab(hints::DRAW_STATE_FONT, FONT_OBJECT_BYTES) else {
            assert!(note_missing_u32_fixture("cxx/draw_state_font"));
            return;
        };
        unsafe { core::ptr::write_bytes(font_object, GUARD, FONT_OBJECT_BYTES) };
        unsafe { font_object.add(FONT_DRAW_STYLE_OFFSET).write(0x92) };

        for (font_word, expected_style) in [
            (font_object as u32, 0x92),
            ((font_object as u32) | 1, 0x96),
        ] {
            let mut record = [GUARD; DRAW_STATE_SIZE];
            let handle = [font_word, 0x0123_4567];
            unsafe { draw_state_set_font(record.as_mut_ptr(), handle.as_ptr()) };

            assert_eq!(
                unsafe { (record.as_ptr().add(DRAW_STATE_EMBEDDED_PAIR_OFFSET) as *const u32).read() },
                handle[0],
                "first word is copied before style derivation"
            );
            assert_eq!(
                unsafe {
                    (record
                        .as_ptr()
                        .add(DRAW_STATE_EMBEDDED_PAIR_OFFSET + core::mem::size_of::<u32>())
                        as *const u32)
                        .read()
                },
                handle[1],
                "second word is copied verbatim"
            );
            assert_eq!(record[DRAW_STATE_FONT_STYLE_OFFSET], expected_style);
        }
    }
}
