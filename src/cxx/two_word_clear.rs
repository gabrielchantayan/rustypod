//! `two_word_clear` — original: `FUN_081598a4` @ **0x081598a4**
//! (**16 bytes**, `0x081598a4..0x081598b4`; the next separately linked function
//! begins at `0x081598b4`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **six**
//! direct call sites, all unconditional plain `bl` (0x0826457c, 0x082645b0,
//! 0x082645f4, 0x08264684, 0x08275064, and 0x08275558); there are no predicated
//! calls, tail branches, or aligned data-word references. The raw body writes
//! zero to two consecutive 32-bit words at `target + 0x00..0x04` and leaves
//! `r0` unchanged. Ghidra declares it `void`, but the preserved `r0` gives this
//! C++ constructor its `target` result. No deliberate deviations.

/// Clears two consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for two `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.two_word_clear")]
#[inline(never)]
pub unsafe extern "C" fn two_word_clear(target: *mut u32) -> *mut u32 {
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
    fn clears_exactly_two_target_words_and_returns_target() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef];
        let target = words.as_mut_ptr().wrapping_add(1);

        let returned = unsafe { two_word_clear(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0xdead_beef]);
    }
}
