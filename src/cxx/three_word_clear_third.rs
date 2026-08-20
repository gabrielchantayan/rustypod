//! `three_word_clear_third` — original: `FUN_083e143c` @ 0x083e143c (20 bytes).
//!
//! Source: `ipod-decomp/decomp/c/038/083e143c_FUN_083e143c.c`.
//!
//! Leaf clear helper: writes a single zero value to the three consecutive
//! 32-bit words at offsets +0, +4, and +8 from its aligned writable argument.
//! It has no NULL guard, reads no target words, and makes no other stores.
//! A dedicated code section keeps this separately hookable export from being
//! folded into its byte-identical siblings by LLVM.


/// Clears exactly the three consecutive 32-bit words beginning at `target`.
/// `target` must be valid, aligned, and writable for three `u32` values, as
/// required by the original unconditional stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_word_clear_third")]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_third(target: *mut u32) {
    unsafe {
        target.write(0);
        target.add(1).write(0);
        target.add(2).write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exactly_the_three_target_words() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef, 0xc001_d00d];

        unsafe { three_word_clear_third(words.as_mut_ptr().add(1)) };

        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
    }
}
