//! `draw_state_set_surface_and_clip` — original: `FUN_08264550` @
//! 0x08264550 (20 bytes, 0x08264550..0x08264564; **4 unconditional
//! `bl` + 0 predicated `bl` call sites**, independently counted from the
//! raw ARM branch encodings in osos.dec).
//!
//! Stores the caller-selected draw-target surface identity at +0x1c of a
//! 0x44-byte draw-state record, then copies a caller-computed four-word
//! QuickDraw clip rect verbatim to +0x34..+0x40. Raw ARM is:
//!
//! ```text
//! str r1, [r0, #0x1c]!    ; record->surface = surface
//! ldm r2, {r1, r2, r3, ip}; load clip's four words
//! add r0, r0, #0x18       ; record + 0x34
//! stm r0, {r1, r2, r3, ip}; record->clip = clip
//! bx  lr
//! ```
//!
//! Deliberate deviations: the ARM leaves `record + 0x34` in r0 through its
//! final `stm`; sampled callers do not consume it, so this is a `void`
//! Rust function. It uses aligned `u32`/`Rect` accesses: the ARM `str`/`ldm`/
//! `stm` require word-aligned record and clip pointers, and every accessed
//! offset is word-aligned.

use crate::cxx::draw_state::DRAW_STATE_SURFACE_OFFSET;
use crate::cxx::draw_state_surface::DRAW_STATE_CLIP_RECT_OFFSET;
use crate::ui::rect::Rect;

/// draw_state_set_surface_and_clip — original: `FUN_08264550` @ 0x08264550
/// (20 bytes; 4 unconditional `bl` + 0 predicated `bl` call sites).
///
/// Stores the raw 32-bit `surface` identity at `record + 0x1c`, then copies
/// the four-word `clip` rect unchanged into `record + 0x34`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_surface_and_clip(
    record: *mut u8,
    surface: u32,
    clip: *const Rect,
) {
    unsafe {
        record.add(DRAW_STATE_SURFACE_OFFSET).cast::<u32>().write(surface);
        record
            .add(DRAW_STATE_CLIP_RECT_OFFSET)
            .cast::<Rect>()
            .write(clip.read());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;

    #[repr(C, align(4))]
    struct DrawStateFixture([u8; DRAW_STATE_SIZE]);

    #[test]
    fn stores_surface_and_all_distinct_clip_words_verbatim() {
        let mut record = DrawStateFixture([0xa5; DRAW_STATE_SIZE]);
        let clip = Rect {
            top: -0x1020_3040,
            left: 0x1122_3344,
            bottom: -7,
            right: 0x5566_7788,
        };

        unsafe {
            draw_state_set_surface_and_clip(record.0.as_mut_ptr(), 0x89ab_cdef, &clip);
            assert_eq!(
                record.0.as_ptr().add(DRAW_STATE_SURFACE_OFFSET).cast::<u32>().read(),
                0x89ab_cdef
            );
            assert_eq!(
                record.0.as_ptr().add(DRAW_STATE_CLIP_RECT_OFFSET).cast::<Rect>().read(),
                clip
            );
        }
        assert_eq!(record.0[DRAW_STATE_SURFACE_OFFSET - 1], 0xa5);
        assert_eq!(record.0[DRAW_STATE_SURFACE_OFFSET + 4], 0xa5);
        assert_eq!(record.0[DRAW_STATE_CLIP_RECT_OFFSET - 1], 0xa5);
    }

    #[test]
    fn preserves_an_unusual_input_rect_without_mutating_it() {
        let mut record = DrawStateFixture([0; DRAW_STATE_SIZE]);
        let clip = Rect {
            top: i32::MAX,
            left: i32::MIN,
            bottom: i32::MIN + 1,
            right: i32::MAX - 1,
        };
        let original = clip;

        unsafe {
            draw_state_set_surface_and_clip(record.0.as_mut_ptr(), 0, &clip);
            assert_eq!(record.0.as_ptr().add(DRAW_STATE_CLIP_RECT_OFFSET).cast::<Rect>().read(), original);
        }
        assert_eq!(clip, original);
    }
}
