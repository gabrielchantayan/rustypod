//! Advance the image-format descriptor cursor to the next populated slot.
//!
//! Original `FUN_081d5f54` @ `0x081d5f54`, 60 bytes, exclusive end
//! `0x081d5f90` (the next function loads the descriptor count). Whole-image
//! A32 decoding verifies two inbound plain BLs at 0x081f0c74 and 0x0821b24c,
//! zero predicated inbound BLs, and zero outbound plain or predicated BLs.
//! Increment the cursor at +0x28c with wrapping arithmetic, then scan eighteen
//! 36-byte records, skipping those whose sequence word at +0x24 is UINT32_MAX.
//! Store and return the first populated index, or UINT32_MAX on exhaustion.
//! Exhaustion resets to the before-first sentinel, so a subsequent call starts
//! again at slot zero. The count at +0x290 does not constrain the scan.
//! No deliberate deviations; unlike Ghidra's void prototype, raw r0 and both
//! callers establish the returned index.

const CURSOR_WORD: usize = 163;
const FIRST_SEQUENCE_WORD: usize = 9;
const RECORD_WORDS: usize = 9;
const SLOT_COUNT: u32 = 18;

/// # Safety
/// `slots` must be aligned and readable through word 162, with word 163
/// readable and writable. No NULL checks are performed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_cursor_next(slots: *mut u32) -> u32 {
    let mut index = slots.add(CURSOR_WORD).read();
    loop {
        index = index.wrapping_add(1);
        if index >= SLOT_COUNT {
            index = u32::MAX;
            break;
        }
        if slots.add(FIRST_SEQUENCE_WORD + index as usize * RECORD_WORDS).read() != u32::MAX {
            break;
        }
    }
    slots.add(CURSOR_WORD).write(index);
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_scan_matches_reference_and_changes_only_cursor() {
        for mask in [0, 1, 1 << 17, 0x2aaaa, 0x15555, 0x3ffff] {
            for cursor in (0..=19).chain([u32::MAX, u32::MAX - 1, 0x8000_0000]) {
                let mut slots = [0x1234_5678; 165];
                for slot in 0..18 {
                    slots[9 + slot * 9] = if mask & (1 << slot) == 0 { u32::MAX } else { slot as u32 };
                }
                slots[163] = cursor;
                // A deliberately unrelated count must not limit iteration.
                slots[164] = 0;
                let first = cursor.wrapping_add(1);
                let expected_index = (first..18).find(|&slot| mask & (1 << slot) != 0).unwrap_or(u32::MAX);
                let mut expected = slots;
                expected[163] = expected_index;
                assert_eq!(unsafe { image_format_descriptor_cursor_next(slots.as_mut_ptr()) }, expected_index);
                assert_eq!(slots, expected);
            }
        }
    }

    #[test]
    fn exhaustion_restarts_and_only_minus_one_marks_empty() {
        let mut slots = [u32::MAX; 165];
        slots[9] = 0;
        slots[9 + 17 * 9] = 0xffff_fffe;
        slots[164] = u32::MAX;
        for expected in [0, 17, u32::MAX, 0, 17, u32::MAX] {
            assert_eq!(unsafe { image_format_descriptor_cursor_next(slots.as_mut_ptr()) }, expected);
            assert_eq!(slots[163], expected);
        }
    }
}
