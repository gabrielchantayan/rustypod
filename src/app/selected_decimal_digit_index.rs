//! `selected_decimal_digit_index` — original `FUN_0827f1a0` at `0x0827f1a0`.
//! True size: 8 bytes (`0x0827f1a0..0x0827f1a8`); the next function begins
//! at `0x0827f1a8`. Raw words are `e590008c` (LDR r0, [r0, #0x8c]) and
//! `e12fff1e` (BX lr). Whole-image aligned A32 decoding verifies two incoming
//! plain BLs, at `0x0813ff88` and `0x0820e938`, zero predicated incoming BLs,
//! and zero outgoing plain or predicated BLs.
//!
//! Returns the selected decimal digit index word unchanged. Unlock and volume
//! limit callers use zero to detect completion; digit-editing routines use
//! this same field as an index. There is no range check or normalization.
//! Deliberate representation deviation: the opaque owner is addressed in
//! four-byte words, preserving target offsets independently of host pointers.
//! No behavioral deviations.

const SELECTED_DIGIT_WORD: usize = 0x8c / 4;

/// Reads the current selected digit index, preserving all 32 bits.
///
/// # Safety
/// `owner` must be non-NULL, word-aligned, and readable through offset +0x8c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selected_decimal_digit_index(owner: *const u32) -> u32 {
    owner.add(SELECTED_DIGIT_WORD).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_completion_indices_and_out_of_range_words_without_mutation() {
        let mut owner = [0xa5a5_5a5a; SELECTED_DIGIT_WORD + 2];
        for index in [0, 1, 2, 3, 4, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            owner[SELECTED_DIGIT_WORD] = index;
            let before = owner;
            assert_eq!(unsafe { selected_decimal_digit_index(owner.as_ptr()) }, index);
            assert_eq!(owner, before);
        }
    }
}
