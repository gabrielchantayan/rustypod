//! Indexed video-engine four-word setter — `FUN_08252080` @ 0x08252080.
//! True size: 68 bytes (0x08252080..0x082520c4), including the error
//! literal at 0x082520c0. Whole-image A32 scan: two plain inbound BLs
//! (0x08252078, 0x082d1c38), zero predicated BLs. Body: two plain BLs,
//! zero predicated BLs.
//!
//! Accept IDs 0x84c0 and 0x84c1 and copy the four supplied words into
//! engine+0x22c and engine+0x23c respectively. All other IDs latch 0x501
//! without modifying either vector. Values are opaque bit patterns.
//!
//! Deliberate deviations: omit incidental argument-register restoration
//! and expose the void setter ABI used by the public wrapper 0x082d1c04;
//! Ghidra's u64 return is an artifact of restoring the stack staging words.
//! Reuse the existing four-word assignment and first-error latch ports.

use crate::cxx::templates::deque_iter_assign_alias_c774;
use crate::util::error_latch::latch_first_error;

/// # Safety
/// `engine` must be aligned and writable through +0x24b for accepted IDs.
/// For other IDs only the first writable error word is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_set_indexed_vector(
    engine: *mut u32, id: u32, first: u32, second: u32, third: u32, fourth: u32,
) {
    let index = id.wrapping_sub(0x84c0);
    if index >= 2 {
        latch_first_error(engine, 0x501);
        return;
    }
    let vector = [first, second, third, fourth];
    deque_iter_assign_alias_c774(engine.add(0x22c / 4 + index as usize * 4), vector.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_ids_replace_only_the_selected_four_words() {
        for id in [0x84c0, 0x84c1] {
            for values in [[0; 4], [u32::MAX, 0x8000_0000, 0x7fff_ffff, 1],
                           [0x1234_5678, 0x8765_4321, 0xdead_beef, 0xa5a5_5a5a]] {
                let mut engine = [0x1357_2468u32; 0x250 / 4];
                let mut expected = engine;
                let start = 0x22c / 4 + (id - 0x84c0) as usize * 4;
                expected[start..start + 4].copy_from_slice(&values);
                unsafe {
                    video_engine_set_indexed_vector(engine.as_mut_ptr(), id,
                        values[0], values[1], values[2], values[3]);
                }
                assert_eq!(engine, expected);
            }
        }
    }

    #[test]
    fn rejected_ids_preserve_vectors_and_latch_only_the_first_error() {
        for id in [0, 0x84bf, 0x84c2, 0x1_84c0, 0x8000_84c0, u32::MAX] {
            for error in [0, 0x500, u32::MAX] {
                let mut engine = [0x2468_1357u32; 0x250 / 4];
                engine[0] = error;
                let mut expected = engine;
                expected[0] = if error == 0 { 0x501 } else { error };
                unsafe { video_engine_set_indexed_vector(engine.as_mut_ptr(), id, 1, 2, 3, 4); }
                assert_eq!(engine, expected);
            }
        }
    }

    #[test]
    fn rejection_requires_only_the_error_word() {
        let mut error = 0;
        unsafe { video_engine_set_indexed_vector(&mut error, 0x84bf, 1, 2, 3, 4); }
        assert_eq!(error, 0x501);
    }
}
