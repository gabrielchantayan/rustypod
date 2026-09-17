//! `draw_state_get_background_color` — retailOS `FUN_082a1d64` at
//! `0x082a1d64`.
//!
//! Raw ARM establishes the true extent as `0x082a1d64..0x082a1d6c`: `add
//! r1,r1,#0x15; b 0x082720ac`. The separately linked next function begins at
//! `0x082a1d6c`. A binary scan of every ARM B/BL-immediate word finds four
//! inbound direct calls, all unconditional plain `bl` and zero predicated
//! forms.
//!
//! Binds the background-colour field at `record + 0x15` as the source of the
//! four-byte ascending copy at `0x082720ac`. Deliberate deviation: the
//! original tail-branches to `color_copy_unaligned`; Rust calls its direct
//! port, preserving its volatile byte-wise copy order.

use crate::cxx::color_copy::color_copy_unaligned;
use crate::cxx::draw_state_color::DRAW_STATE_BACKGROUND_COLOR_OFFSET;

/// draw_state_get_background_color — retailOS `FUN_082a1d64` at `0x082a1d64`
/// (8 bytes; four unconditional plain-`bl` call sites, zero predicated).
///
/// Copies the four bytes at `record + 0x15` into `dst`. The original has no
/// NULL, bounds, or alignment checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_get_background_color(dst: *mut u8, record: *const u8) {
    unsafe { color_copy_unaligned(dst, record.add(DRAW_STATE_BACKGROUND_COLOR_OFFSET)) };
}

#[cfg(test)]
mod tests {
    use super::draw_state_get_background_color;
    use crate::cxx::color_copy::COLOR_BYTES;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;
    use crate::cxx::draw_state_color::DRAW_STATE_BACKGROUND_COLOR_OFFSET;

    #[test]
    fn copies_background_color_without_touching_neighbors() {
        let mut record = [0xa5_u8; DRAW_STATE_SIZE];
        record[DRAW_STATE_BACKGROUND_COLOR_OFFSET..DRAW_STATE_BACKGROUND_COLOR_OFFSET + COLOR_BYTES]
            .copy_from_slice(&[0x12, 0x00, 0xff, 0x34]);
        let mut destination = [0x5a_u8; COLOR_BYTES + 1];

        unsafe { draw_state_get_background_color(destination.as_mut_ptr(), record.as_ptr()) };

        assert_eq!(&destination[..COLOR_BYTES], &[0x12, 0x00, 0xff, 0x34]);
        assert_eq!(destination[COLOR_BYTES], 0x5a);
        assert_eq!(record[DRAW_STATE_BACKGROUND_COLOR_OFFSET - 1], 0xa5);
        assert_eq!(record[DRAW_STATE_BACKGROUND_COLOR_OFFSET + COLOR_BYTES], 0xa5);
    }

    #[test]
    fn preserves_forward_overlap_behavior() {
        let mut bytes = [0_u8; DRAW_STATE_SIZE + COLOR_BYTES];
        bytes[DRAW_STATE_BACKGROUND_COLOR_OFFSET..DRAW_STATE_BACKGROUND_COLOR_OFFSET + COLOR_BYTES]
            .copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);
        let destination = unsafe { bytes.as_mut_ptr().add(DRAW_STATE_BACKGROUND_COLOR_OFFSET + 1) };

        unsafe { draw_state_get_background_color(destination, bytes.as_ptr()) };

        assert_eq!(
            &bytes[DRAW_STATE_BACKGROUND_COLOR_OFFSET..DRAW_STATE_BACKGROUND_COLOR_OFFSET + COLOR_BYTES + 1],
            &[0x10, 0x10, 0x10, 0x10, 0x10]
        );
    }
}
