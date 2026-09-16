//! `three_word_clear_return_alt` — original: `FUN_083e7168` @ **0x083e7168**
//! (**20 bytes**, `0x083e7168..0x083e717c`; the separately linked successor
//! `FUN_083e717c` begins at `0x083e717c`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **four**
//! direct call sites, all unconditional plain `bl` (0x0826a554, 0x0826a58c,
//! 0x082ca9e4, and 0x082caa2c); there are no predicated calls or direct tail
//! branches. The raw body materializes zero in `r1`, stores it to the three
//! consecutive 32-bit words at `target + 0x00..0x08`, and preserves `r0`.
//! Ghidra declares it `void`, but callers 0x082ca9e4 and 0x0826a554 consume
//! the preserved target, so this port returns `target`.
//!
//! In context this is a C++ container default constructor: callers at
//! 0x082ca98c hand the cleared 12-byte head to the reserve-like helper
//! `FUN_083e7048` and the push-back helper `FUN_083e7140`, matching a
//! `{begin, end, end_of_storage}` triple. No deliberate deviations.

/// Clears three consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for three `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_word_clear_return_alt")]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_return_alt(target: *mut u32) -> *mut u32 {
    unsafe {
        target.write(0);
        target.add(1).write(0);
        target.add(2).write(0);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exactly_the_three_target_words() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef, 0xc001_d00d];

        let returned = unsafe { three_word_clear_return_alt(words.as_mut_ptr().add(1)) };

        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
        assert_eq!(returned, unsafe { words.as_mut_ptr().add(1) });
    }

    #[test]
    fn leaves_words_outside_the_triple_untouched() {
        let mut words = [0xffff_ffffu32; 4];

        unsafe { three_word_clear_return_alt(words.as_mut_ptr()) };

        assert_eq!(words, [0, 0, 0, 0xffff_ffff]);
    }
}
