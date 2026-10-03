//! `draw_state_set_stroke_parameters` — original: `FUN_08262d78` @
//! 0x08262d78 (12 bytes, ending at the distinct function 0x08262d84).
//! Whole-image ARM decoding finds 2 plain BL callers at 0x0816acbc and
//! 0x0816b508, 0 predicated BL callers; this leaf has no outbound calls.
//!
//! Raw words: e5801008 (`str r1,[r0,#8]`), e580200c
//! (`str r2,[r0,#12]`), e12fff1e (`bx lr`). Sets two words in the
//! scoped 0x44-byte draw-state record, leaving every other field intact.
//! The rectangle-outline adapter 0x08264430 consumes +8 as stroke width.
//! The meaning of +12 is not established; both observed callers set the
//! pair to (1, 1) before drawing rectangle outlines.
//!
//! Deviations: none in memory behavior. The C ABI returns void, matching
//! Ghidra and callers that do not consume r0; the original leaves r0 intact.
//! Uses aligned target-width words, never host-sized pointer fields.

/// Sets stroke width and the still-unidentified auxiliary stroke word.
///
/// # Safety
/// `record` must be word-aligned and writable through byte offset +0x0f.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_stroke_parameters(
    record: *mut u32,
    stroke_width: i32,
    auxiliary: u32,
) {
    record.add(2).write(stroke_width as u32);
    record.add(3).write(auxiliary);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;

    #[test]
    fn replaces_both_words_without_clobbering_neighboring_state() {
        let initial = [0xa5c3_7e19u32; DRAW_STATE_SIZE / 4 + 2];
        let mut record = initial;
        for (width, auxiliary) in [
            (1, 1), (0, 0), (-1, u32::MAX),
            (i32::MIN, 0x1234_5678), (i32::MAX, 0x8000_0000),
        ] {
            unsafe {
                draw_state_set_stroke_parameters(record.as_mut_ptr().add(1), width, auxiliary);
            }
            let mut expected = initial;
            expected[3] = width as u32;
            expected[4] = auxiliary;
            assert_eq!(record, expected);
        }
    }
}
