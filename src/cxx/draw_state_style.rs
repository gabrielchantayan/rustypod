//! `draw_state_set_style` — original: `FUN_08262d70` @ 0x08262d70
//! (8 bytes; **36 `bl` + 2 `blne` = 38 call sites, 0 `b`**,
//! binary-scanned by decoding every B/BL word in osos.dec — exactly the
//! 38 Ghidra reports).
//!
//! The style-byte setter of the 0x44-byte **draw-state record**
//! documented in [`crate::cxx::draw_state`] — the scoped value object
//! every retailOS drawing call builds on its stack, fills in, and hands
//! to a draw routine. Whole function, decoded from the raw words
//! (`1010 c0e5 1eff 2fe1`):
//!
//! ```text
//! 08262d70:  e5c01010   strb r1, [r0, #16]   ; this->style = style
//! 08262d74:  e12fff1e   bx   lr
//! ```
//!
//! Not a veneer (no `ldr pc,[pc,#-4]` + target word) and not an empty
//! destructor (a real `strb`, not a lone `bx lr`): a one-instruction
//! member function. Ghidra omits the function from its C listing
//! entirely — only its callers appear — so the raw bytes above are the
//! sole authority. The next function starts at 0x08262d78 (a sibling
//! two-word setter: `str r1,[r0,#8]; str r2,[r0,#12]; bx lr`,
//! unported), confirming the 8-byte extent. No DATA word in the image
//! holds the address, so it is never dispatched virtually.
//!
//! # What the style byte is
//!
//! The record packs one style byte at +0x10 immediately ahead of the
//! two unaligned 4-byte colours at +0x11/+0x15 (see
//! [`crate::cxx::draw_state_color`]). The draw call @ 0x08262bdc passes
//! the byte to the text/layout draw engine @ 0x080f1600 together with
//! both colours and the clip rect. Observed values at call sites:
//!
//! - The list-row draw path @ 0x0819b80c picks the byte from the view's
//!   +0x224/+0x225 fields by bit 3 of the view flag word at +0x48 and
//!   applies it here; a style code of 0x21 means "a colour" (that path
//!   then also calls the foreground setter @ 0x0826319c).
//! - The two predicated `blne` sites @ 0x0826cd10 / 0x0826cd3c guard on
//!   a source byte being != 0xff (`ldrb ...; cmp r0,#0xff; movne r1,
//!   #0x22 / movne r1,r8; blne`) — i.e. 0xff is the caller-side
//!   sentinel for "no style override", and only then is a concrete
//!   code (0x22, or a computed value) stored. The gate lives entirely
//!   in the callers; this callee has no sentinel check of its own and
//!   stores whatever byte it is handed.
//!
//! # Deviations
//!
//! - The original returns nothing and never writes r0 — no caller can
//!   depend on a return value, so the port is `void`.
//! - No NULL guard on `record`, matching the original's unconditional
//!   `strb` (the predicated call sites guard on the *value*, never on
//!   the pointer).

use crate::cxx::draw_state::DRAW_STATE_SIZE;
use crate::cxx::draw_state_color::DRAW_STATE_STYLE_OFFSET;

/// draw_state_set_style — original: `FUN_08262d70` @ 0x08262d70
/// (8 bytes; 36 `bl` + 2 `blne` call sites, binary-scanned).
///
/// Stores `style` into the draw-state record's style byte at
/// `record + 0x10`. Touches nothing else — not the foreground colour at
/// +0x11, not the background colour at +0x15.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_style(record: *mut u8, style: u8) {
    record.add(DRAW_STATE_STYLE_OFFSET).write(style);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::draw_state_color::{
        DRAW_STATE_BACKGROUND_COLOR_OFFSET, DRAW_STATE_FOREGROUND_COLOR_OFFSET,
    };

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
    fn writes_exactly_the_byte_at_offset_0x10() {
        let mut bytes = record();
        let expected_untouched = record();

        unsafe { draw_state_set_style(bytes.as_mut_ptr(), 0x21) };

        assert_eq!(
            bytes[DRAW_STATE_STYLE_OFFSET], 0x21,
            "the style byte lands at +0x10"
        );
        assert_eq!(
            &bytes[..DRAW_STATE_STYLE_OFFSET],
            &expected_untouched[..DRAW_STATE_STYLE_OFFSET],
            "everything below +0x10 is untouched"
        );
        assert_eq!(
            &bytes[DRAW_STATE_STYLE_OFFSET + 1..],
            &expected_untouched[DRAW_STATE_STYLE_OFFSET + 1..],
            "both colours at +0x11/+0x15 and the record tail are untouched"
        );
        assert_eq!(
            DRAW_STATE_STYLE_OFFSET + 1,
            DRAW_STATE_FOREGROUND_COLOR_OFFSET,
            "the style byte sits immediately ahead of the foreground colour"
        );
    }

    #[test]
    fn every_byte_value_survives_including_the_observed_codes() {
        // 0x21 and 0x22 are the style codes observed at call sites; 0x00
        // is the body initializer's default; 0xff is only a sentinel on
        // the caller side — this setter stores it like any other byte.
        for style in [0x00u8, 0x21, 0x22, 0xff] {
            let mut bytes = record();
            unsafe { draw_state_set_style(bytes.as_mut_ptr(), style) };
            assert_eq!(bytes[DRAW_STATE_STYLE_OFFSET], style);
        }
    }

    #[test]
    fn the_store_is_alignment_agnostic() {
        // The record is word-aligned at every observed call site, but
        // the original's `strb` assumes nothing — prove the port doesn't
        // either.
        for shift in 0..4usize {
            let mut bytes = [0xa5u8; DRAW_STATE_SIZE + 0x10];
            unsafe { draw_state_set_style(bytes.as_mut_ptr().add(shift), 0x22) };
            assert_eq!(bytes[shift + DRAW_STATE_STYLE_OFFSET], 0x22, "shift {shift}");
        }
    }

    #[test]
    fn setting_the_style_leaves_a_seeded_record_intact() {
        // The default record body has foreground {0,0,0,0xff} and
        // background {0xff,0xff,0xff,0xff} (body_init @ 0x082630f0);
        // restyling must not smear into either colour.
        let mut bytes = [0u8; DRAW_STATE_SIZE];
        let fg = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
        let bg = DRAW_STATE_BACKGROUND_COLOR_OFFSET;
        bytes[fg + 3] = 0xff;
        bytes[bg..bg + 4].copy_from_slice(&[0xff; 4]);

        unsafe { draw_state_set_style(bytes.as_mut_ptr(), 0x21) };

        assert_eq!(bytes[DRAW_STATE_STYLE_OFFSET], 0x21);
        assert_eq!(&bytes[fg..fg + 4], &[0, 0, 0, 0xff], "foreground preserved");
        assert_eq!(&bytes[bg..bg + 4], &[0xff; 4], "background preserved");
    }
}
