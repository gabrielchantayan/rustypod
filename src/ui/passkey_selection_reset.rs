//! `passkey_selection_reset` — original `FUN_0827f11c` at `0x0827f11c`.
//! True size: 16 bytes (`0x0827f11c..0x0827f12c`); the next real function
//! starts at `0x0827f12c`. Raw words: `e3a01000 e58010a0 e580108c e12fff1e`.
//! Whole-image aligned A32 decoding verifies two incoming unconditional BLs
//! (`0x0813f524`, `0x0813f858`), zero incoming predicated BLs, and zero
//! outgoing plain or predicated BLs.
//!
//! Clears the passkey view's string selection mode at +0xa0, then its selected
//! digit index at +0x8c. Callers reset before switching lock/passkey layouts;
//! digit editing selects the alternate embedded string only when mode is one.
//! All other fields and r0 are preserved. Deliberate representation deviation:
//! address opaque fields in four-byte words, independent of host pointer width.
//! No behavioral deviations; volatile stores retain the original store order.

const STRING_SELECTION_MODE_WORD: usize = 0xa0 / 4;
const SELECTED_DIGIT_WORD: usize = 0x8c / 4;

/// Resets passkey selection and preserves the owner pointer in r0.
///
/// # Safety
/// `owner` must be non-NULL, word-aligned, and writable through offset +0xa0.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn passkey_selection_reset(owner: *mut u32) -> *mut u32 {
    owner.add(STRING_SELECTION_MODE_WORD).write_volatile(0);
    owner.add(SELECTED_DIGIT_WORD).write_volatile(0);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_primary_alternate_and_unknown_modes_without_touching_other_fields() {
        for (mode, index) in [(0, 0), (1, 3), (2, 4), (u32::MAX, u32::MAX),
                              (0x8000_0000, 0x7fff_ffff)] {
            let mut owner = [0u32; STRING_SELECTION_MODE_WORD + 2];
            for (word, value) in owner.iter_mut().enumerate() {
                *value = 0xa5a5_0000 | word as u32;
            }
            owner[STRING_SELECTION_MODE_WORD] = mode;
            owner[SELECTED_DIGIT_WORD] = index;
            let mut expected = owner;
            expected[STRING_SELECTION_MODE_WORD] = 0;
            expected[SELECTED_DIGIT_WORD] = 0;
            let pointer = owner.as_mut_ptr();
            assert_eq!(unsafe { passkey_selection_reset(pointer) }, pointer);
            assert_eq!(owner, expected);
            assert_eq!(unsafe { passkey_selection_reset(pointer) }, pointer);
            assert_eq!(owner, expected);
        }
    }
}
