//! `three_word_clear_ninth` — original: `FUN_083e4dd4` @ 0x083e4dd4 (20 bytes).
//!
//! Source: `ipod-decomp/decomp/c/038/083e4dd4_FUN_083e4dd4.c`.
//!
//! Leaf clear helper: moves zero into a temporary register, then unconditionally
//! writes it to the three consecutive 32-bit words at offsets +0, +4, and +8
//! from its aligned writable argument. It has no NULL guard, reads no target
//! words, and makes no other stores. A dedicated code section keeps this
//! separately hookable export from its byte-identical siblings.

/// Clears exactly the three consecutive 32-bit words beginning at `target`.
/// `target` must be valid, aligned, and writable for three `u32` values, as
/// required by the original unconditional stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_word_clear_ninth")]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_ninth(target: *mut u32) {
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
    fn clears_the_three_target_words_without_touching_surrounding_bytes() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef, 0xc001_d00d];
        let before = words;

        unsafe { three_word_clear_ninth(words.as_mut_ptr().add(1)) };

        assert_eq!(words[0].to_ne_bytes(), before[0].to_ne_bytes(), "bytes before +0");
        assert_eq!(words[1], 0, "+0");
        assert_eq!(words[2], 0, "+4");
        assert_eq!(words[3], 0, "+8");
        assert_eq!(words[4].to_ne_bytes(), before[4].to_ne_bytes(), "bytes after +8");
    }
}
