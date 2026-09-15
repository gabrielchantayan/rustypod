//! `two_word_clear_third` — original: `FUN_08280174` @ **0x08280174**
//! (**16 bytes**, `0x08280174..0x08280184`; the next separately linked function
//! begins at `0x08280184`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **five**
//! direct call sites, all unconditional plain `bl` (0x0814d3e4, 0x081c1ad4,
//! 0x081c1f24, 0x081c8000, and 0x081c8db0); there are no predicated calls.
//! The raw body writes zero to two consecutive 32-bit words at `target +
//! 0x00..0x04` and leaves `r0` unchanged. Ghidra declares the function `void`,
//! but the preserved `r0` returns the C++ receiver. No deliberate deviations.

/// Clears two consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for two `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.two_word_clear_third")]
#[inline(never)]
pub unsafe extern "C" fn two_word_clear_third(target: *mut u32) -> *mut u32 {
    unsafe {
        target.write(0);
        target.add(1).write(0);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_an_interior_pair_and_returns_the_receiver() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef];
        let target = words.as_mut_ptr().wrapping_add(1);

        let returned = unsafe { two_word_clear_third(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0xdead_beef]);
    }

    #[test]
    fn clears_the_first_pair_without_writing_the_next_word() {
        let mut words = [u32::MAX, 1, 0x0123_4567];

        unsafe { two_word_clear_third(words.as_mut_ptr()) };

        assert_eq!(words, [0, 0, 0x0123_4567]);
    }
}
