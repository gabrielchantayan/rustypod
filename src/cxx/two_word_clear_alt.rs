//! `two_word_clear_alt` — original: `FUN_083b45ec` @ **0x083b45ec**
//! (**16 bytes**, `0x083b45ec..0x083b45fc`; the next separately linked function
//! begins at `0x083b45fc`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **five**
//! direct call sites, all unconditional plain `bl` (0x080f9b18, 0x080fcbac,
//! 0x080fcd18, 0x080fd378, and 0x081d5e34); there are no predicated calls or
//! plain-`b` tail calls. The raw body writes zero to two consecutive 32-bit
//! words at `target + 0x00..0x04`, then returns with `r0` unchanged. No
//! deliberate deviations: the Rust result preserves that observed ABI even
//! though Ghidra declares the function `void`.

/// Clears two consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for two `u32` values; stock
/// has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.two_word_clear_alt")]
#[inline(never)]
pub unsafe extern "C" fn two_word_clear_alt(target: *mut u32) -> *mut u32 {
    target.write(0);
    target.add(1).write(0);
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exactly_two_target_words_and_returns_target() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef];
        let target = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { two_word_clear_alt(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0xdead_beef]);
    }

    #[test]
    fn overwrites_nonzero_words_without_touching_adjacent_storage() {
        let mut words = [u32::MAX, 0xdead_beef, 0x0123_4567, 0xa5a5_5a5a];
        let target = words.as_mut_ptr();

        unsafe { two_word_clear_alt(target) };

        assert_eq!(words, [0, 0, 0x0123_4567, 0xa5a5_5a5a]);
    }
}
