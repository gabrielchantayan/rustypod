//! `draw_state_get_style` — retailOS `FUN_082a1d5c` at `0x082a1d5c`.
//!
//! Raw ARM establishes the true extent as `0x082a1d5c..0x082a1d64`: `ldrb
//! r0,[r0,#0x10]; bx lr`; the separately linked next function begins at
//! `0x082a1d64`. A binary scan of every ARM B/BL-immediate word in osos.dec
//! finds five inbound direct calls, all unconditional plain `bl` and zero
//! predicated forms.
//!
//! Reads the style byte at +0x10 from the 0x44-byte draw-state record. This
//! is the complement of [`super::draw_state_style::draw_state_set_style`]:
//! callers save this byte before temporarily changing rendering style, then
//! restore it. Deliberate deviation: none; Rust returns `u8`, which is the
//! zero-extended value produced by ARM `ldrb`.

use crate::cxx::draw_state_color::DRAW_STATE_STYLE_OFFSET;

/// draw_state_get_style — retailOS `FUN_082a1d5c` at `0x082a1d5c`
/// (8 bytes; five unconditional plain-`bl` call sites, zero predicated).
///
/// Reads the draw-state style byte at `record + 0x10`. The original has no
/// NULL, bounds, or alignment check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_get_style(record: *const u8) -> u8 {
    unsafe { record.add(DRAW_STATE_STYLE_OFFSET).read() }
}

#[cfg(test)]
mod tests {
    use super::draw_state_get_style;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;
    use crate::cxx::draw_state_color::DRAW_STATE_STYLE_OFFSET;

    #[test]
    fn reads_style_byte_without_touching_adjacent_colors() {
        let mut record = [0xa5_u8; DRAW_STATE_SIZE];
        record[DRAW_STATE_STYLE_OFFSET - 1] = 0x11;
        record[DRAW_STATE_STYLE_OFFSET] = 0xff;
        record[DRAW_STATE_STYLE_OFFSET + 1] = 0x22;

        assert_eq!(unsafe { draw_state_get_style(record.as_ptr()) }, 0xff);
        assert_eq!(record[DRAW_STATE_STYLE_OFFSET - 1], 0x11);
        assert_eq!(record[DRAW_STATE_STYLE_OFFSET + 1], 0x22);
    }

    #[test]
    fn zero_extends_every_style_value() {
        let mut record = [0_u8; DRAW_STATE_SIZE];
        for style in [0x00, 0x01, 0x21, 0x22, 0x80, 0xff] {
            record[DRAW_STATE_STYLE_OFFSET] = style;
            assert_eq!(unsafe { draw_state_get_style(record.as_ptr()) }, style);
        }
    }
}
