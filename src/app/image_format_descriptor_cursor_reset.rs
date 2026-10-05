//! Reset the image-format descriptor iteration cursor.
//!
//! Original `FUN_081d5fd4` @ `0x081d5fd4`, **12 bytes**
//! (`0x081d5fd4..0x081d5fe0`, exclusive end). Raw words are
//! `e3e01000 e580128c e12fff1e`: mvn r1,#0; str r1,[r0,#0x28c]; bx lr.
//! The next real function starts at `0x081d5fe0` with cmp r1,#0x11.
//! Whole-image A32 decoding verifies two inbound plain BL calls
//! (`0x081f0c2c`, `0x0821b23c`), zero predicated inbound BL calls,
//! and zero outbound plain or predicated BL calls.
//!
//! Store the before-first-slot sentinel in word 163 (+0x28c). The iterator
//! at 0x081d5f54 increments this cursor before scanning up to eighteen
//! descriptor records. Preserve every other word, including the descriptor
//! count at +0x290. No NULL checks or deliberate deviations.

const DESCRIPTOR_CURSOR_WORD: usize = 0xa3;

/// Reset iteration to before the first descriptor slot.
///
/// # Safety
/// `slots` must be non-null, aligned, and writable through word 163.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_cursor_reset(slots: *mut u32) {
    slots.add(DESCRIPTOR_CURSOR_WORD).write(u32::MAX);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_fresh_active_exhausted_and_arbitrary_cursors_only() {
        for cursor in [0, 1, 17, 18, 0x8000_0000, u32::MAX] {
            let mut slots = [0u32; DESCRIPTOR_CURSOR_WORD + 2];
            for (index, word) in slots.iter_mut().enumerate() {
                *word = 0x1234_0000 | index as u32;
            }
            slots[DESCRIPTOR_CURSOR_WORD] = cursor;
            let mut expected = slots;
            expected[DESCRIPTOR_CURSOR_WORD] = u32::MAX;

            unsafe { image_format_descriptor_cursor_reset(slots.as_mut_ptr()) };
            assert_eq!(slots, expected);
            // The iterator's wrapping increment now starts at slot zero.
            assert_eq!(slots[DESCRIPTOR_CURSOR_WORD].wrapping_add(1), 0);
        }
    }
}
