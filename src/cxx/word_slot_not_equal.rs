//! Inequality predicate for opaque 32-bit C++ value slots.
//!
//! Original: FUN_083d7350 at 0x083d7350, 16 bytes, true extent
//! [0x083d7350, 0x083d7360). Raw words: e52de004 ebfffff7 e2200001
//! e49df004; the independent PUSH at 0x083d7360 begins the next function.
//! One outgoing plain BL to word_slot_equal (0x083d7338), zero predicated
//! BLs. Whole-image aligned A32 decoding finds one incoming plain BL at
//! 0x083d92d4 and zero incoming predicated BLs.
//!
//! Forward both aligned slot pointers to the existing equality predicate,
//! then invert its canonical 0/1 result with XOR 1. Only the first word of
//! each slot participates; following words and pointed-to data are ignored.
//! Deliberate deviations: none. Ghidra's no-argument signature is corrected
//! from the raw register flow and the caller's two stack-local slot pointers.

use super::word_slot_equal::word_slot_equal;

/// # Safety
/// Both pointers must be aligned and readable for one u32. Neither is
/// NULL-checked, matching retailOS. The pointers may alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_slot_not_equal(left: *const u32, right: *const u32) -> u32 {
    (word_slot_equal(left, right) as u32) ^ 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_full_word_with_canonical_result() {
        for left in [0, 1, 0x8000_0000, 0xffff_ffff, 0x1234_5678] {
            for right in [0, 1, 0x8000_0000, 0xffff_ffff, 0x1234_5678] {
                assert_eq!(unsafe { word_slot_not_equal(&left, &right) },
                    if left == right { 0 } else { 1 });
            }
            for bit in 0..32 {
                let right = left ^ (1 << bit);
                assert_eq!(unsafe { word_slot_not_equal(&left, &right) }, 1);
            }
        }
    }

    #[test]
    fn ignores_trailing_words_and_accepts_aliasing() {
        let left = [u32::MAX, 0];
        let right = [u32::MAX, u32::MAX];
        assert_eq!(unsafe { word_slot_not_equal(left.as_ptr(), right.as_ptr()) }, 0);
        assert_eq!(unsafe { word_slot_not_equal(left.as_ptr(), left.as_ptr()) }, 0);
        assert_eq!(left, [u32::MAX, 0]);
        assert_eq!(right, [u32::MAX, u32::MAX]);
    }
}
