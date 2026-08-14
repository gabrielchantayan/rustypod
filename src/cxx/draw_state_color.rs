//! `draw_state_set_foreground_color` — original: `FUN_0826319c` @
//! 0x0826319c (8 bytes; **68 `bl` call sites, 0 `b`**, binary-scanned by
//! decoding every B/BL word in osos.dec).
//!
//! The foreground-colour setter of the 0x44-byte **draw-state record**
//! documented in [`crate::cxx::draw_state`] — the scoped value object
//! every retailOS drawing call builds on its stack, fills in, and hands
//! to a draw routine. Whole function, decoded from the raw words:
//!
//! ```text
//! 0826319c:  e2800011   add r0, r0, #0x11   ; &this->foreground_color
//! 082631a0:  ea003bd0   b   0x082720e8      ; tail call copy_color(dst, src)
//! ```
//!
//! It is *not* a veneer (no `ldr pc,[pc,#-4]` + target word) and not an
//! empty destructor: it is a two-instruction member function that binds
//! one field offset and tail-branches into a shared copy helper. Its
//! immediate neighbour `FUN_08263194` @ 0x08263194 is the identical
//! shape with `#0x15` (22 `bl` call sites) — the background colour. No
//! DATA word in the image holds either address, so neither is dispatched
//! virtually.
//!
//! # Why offset 0x11, and why a byte-at-a-time copy
//!
//! The record packs a style byte at +0x10 immediately ahead of two
//! 4-byte colours, so both colours are *unaligned*: +0x11..+0x14 and
//! +0x15..+0x18. That is exactly why the shared helper @ 0x082720e8
//! (36 bytes, 46 `bl` + 2 `b` call sites) is four `ldrb`/`strb` pairs
//! rather than a word move:
//!
//! ```text
//! 082720e8:  ldrb r2,[r1]    ; strb r2,[r0]
//!            ldrb r2,[r1,#1] ; strb r2,[r0,#1]
//!            ldrb r2,[r1,#2] ; strb r2,[r0,#2]
//!            ldrb r1,[r1,#3] ; strb r1,[r0,#3]
//!            bx   lr
//! ```
//!
//! # Which colour is which
//!
//! Three independent readings agree that +0x11 is the foreground:
//!
//! - The record's body initializer @ 0x082630f0 writes +0x10..+0x13 = 0
//!   and +0x14..+0x18 = 0xff, i.e. the +0x11 colour defaults to
//!   `{0, 0, 0, 0xff}` (opaque black) and the +0x15 colour to
//!   `{0xff, 0xff, 0xff, 0xff}` (opaque white) — text on paper.
//! - The draw call @ 0x08262bdc hands the engine @ 0x080f1600 both
//!   colours as `add r2, r12, #0x11; add r3, r12, #0x15; strd r2,[sp]`,
//!   so the +0x11 colour is the *first* of the pair.
//! - The list-row draw path @ 0x0819b80c calls this setter with
//!   `&view + 0x22c`, the row's text colour (names.yaml, 0x0819b614's
//!   class), and only when the row's style code says "a colour".
//!
//! # Deviations
//!
//! - The tail-called helper @ 0x082720e8 is ported under its own name as
//!   [`crate::cxx::color_copy::color_copy`], and this setter calls it —
//!   the byte moves, their order and their volatility all live there.
//! - The original returns nothing; `r0` happens to survive the tail call
//!   as `this + 0x11`, but no `bl` site reads it, so the port is `void`.
//! - No NULL guard on either pointer, matching the original.

use crate::cxx::color_copy::{color_copy, COLOR_BYTES};
use crate::cxx::draw_state::DRAW_STATE_SIZE;

/// Bytes in a draw-state colour: the helper @ 0x082720e8 copies four.
pub const DRAW_STATE_COLOR_BYTES: usize = COLOR_BYTES;

/// Byte offset of the foreground colour: `add r0, r0, #0x11`.
/// Unaligned by construction — the style byte at +0x10 precedes it.
pub const DRAW_STATE_FOREGROUND_COLOR_OFFSET: usize = 0x11;

/// Byte offset of the background colour, bound by the sibling setter
/// `FUN_08263194` @ 0x08263194 (`add r0, r0, #0x15`; 22 `bl` call
/// sites). Not ported here; named so this module's tests can prove the
/// foreground setter leaves it alone.
pub const DRAW_STATE_BACKGROUND_COLOR_OFFSET: usize = 0x15;

/// Byte offset of the style byte the two colours sit behind (written by
/// the setter @ 0x08262d70).
pub const DRAW_STATE_STYLE_OFFSET: usize = 0x10;

/// draw_state_set_foreground_color — original: `FUN_0826319c` @
/// 0x0826319c (8 bytes; 68 `bl` call sites, binary-scanned).
///
/// Copies the four colour bytes at `color` into the draw-state record's
/// foreground slot at `record + 0x11`. Touches nothing else — not the
/// style byte at +0x10, not the background colour at +0x15.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_foreground_color(record: *mut u8, color: *const u8) {
    color_copy(record.add(DRAW_STATE_FOREGROUND_COLOR_OFFSET), color);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record filled with a recognisable pattern plus 0x10 guard bytes
    /// past its end.
    fn record() -> [u8; DRAW_STATE_SIZE + 0x10] {
        let mut bytes = [0u8; DRAW_STATE_SIZE + 0x10];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        bytes
    }

    #[test]
    fn writes_exactly_the_four_bytes_at_offset_0x11() {
        let mut bytes = record();
        let expected_untouched = record();
        let color = [0xde, 0xad, 0xbe, 0xefu8];

        unsafe { draw_state_set_foreground_color(bytes.as_mut_ptr(), color.as_ptr()) };

        let start = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
        let end = start + DRAW_STATE_COLOR_BYTES;
        assert_eq!(&bytes[start..end], &color, "the colour lands at +0x11..+0x15");
        assert_eq!(
            &bytes[..start],
            &expected_untouched[..start],
            "everything below +0x11 — including the style byte at +0x10 — is untouched"
        );
        assert_eq!(
            &bytes[end..],
            &expected_untouched[end..],
            "the background colour at +0x15 and the record tail are untouched"
        );
        assert_eq!(end, DRAW_STATE_BACKGROUND_COLOR_OFFSET, "the two colours abut");
        assert_eq!(
            start - 1,
            DRAW_STATE_STYLE_OFFSET,
            "the foreground colour sits immediately behind the style byte"
        );
    }

    #[test]
    fn the_copy_is_alignment_agnostic_on_both_sides() {
        // The destination is unaligned by construction (+0x11); the
        // source is whatever the caller hands over — the list-row path
        // passes `&view + 0x22c`, itself word-aligned, but the helper
        // has 46 other callers and assumes nothing.
        let color = [0x01, 0x23, 0x45, 0x67u8];
        for src_align in 0..4usize {
            for dst_shift in 0..4usize {
                let mut source = [0xa5u8; 4 + 4];
                source[src_align..src_align + 4].copy_from_slice(&color);
                let mut bytes = [0u8; DRAW_STATE_SIZE + 0x10];

                unsafe {
                    draw_state_set_foreground_color(
                        bytes.as_mut_ptr().add(dst_shift),
                        source.as_ptr().add(src_align),
                    )
                };

                let start = dst_shift + DRAW_STATE_FOREGROUND_COLOR_OFFSET;
                assert_eq!(
                    &bytes[start..start + 4],
                    &color,
                    "src_align {src_align}, dst_shift {dst_shift}"
                );
            }
        }
    }

    #[test]
    fn every_byte_value_survives_including_nul_and_0xff() {
        // Colour bytes are opaque data: a NUL is not a terminator and
        // 0xff (the body initializer's default alpha) is not a sentinel.
        for color in [[0, 0, 0, 0u8], [0xff; 4], [0, 0xff, 0, 0xffu8], [0xff, 0, 0xff, 0]] {
            let mut bytes = record();
            unsafe { draw_state_set_foreground_color(bytes.as_mut_ptr(), color.as_ptr()) };
            let start = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
            assert_eq!(&bytes[start..start + 4], &color);
        }
    }

    #[test]
    fn an_overlapping_source_propagates_forward_like_the_original() {
        // The original never buffers: dst = src + 1 replicates src[0]
        // across the field. Locking this in is the whole reason the port
        // keeps the four moves in order.
        let mut bytes = record();
        let src = DRAW_STATE_FOREGROUND_COLOR_OFFSET - 1;
        let seed = bytes[src];

        unsafe {
            let base = bytes.as_mut_ptr();
            draw_state_set_foreground_color(base, base.add(src));
        }

        let start = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
        assert_eq!(
            &bytes[start..start + 4],
            &[seed; 4],
            "forward byte-at-a-time copy smears the overlapped byte"
        );
    }

    #[test]
    fn setting_the_foreground_leaves_a_seeded_background_intact() {
        // The default record body has foreground {0,0,0,0xff} and
        // background {0xff,0xff,0xff,0xff} (body_init @ 0x082630f0);
        // repainting the text colour must not smear into the paper.
        let mut bytes = [0u8; DRAW_STATE_SIZE];
        bytes[DRAW_STATE_STYLE_OFFSET] = 0x21;
        let bg = DRAW_STATE_BACKGROUND_COLOR_OFFSET;
        bytes[bg..bg + 4].copy_from_slice(&[0xff; 4]);
        bytes[DRAW_STATE_FOREGROUND_COLOR_OFFSET + 3] = 0xff;

        let color = [0x10, 0x20, 0x30, 0x80u8];
        unsafe { draw_state_set_foreground_color(bytes.as_mut_ptr(), color.as_ptr()) };

        assert_eq!(bytes[DRAW_STATE_STYLE_OFFSET], 0x21, "style byte preserved");
        let start = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
        assert_eq!(&bytes[start..start + 4], &color);
        assert_eq!(&bytes[bg..bg + 4], &[0xff; 4], "background preserved");
    }
}
