//! `three_word_clear_return` — original: `FUN_083e5aec` @ **0x083e5aec**
//! (**20 bytes**, `0x083e5aec..0x083e5afc`; the separately linked successor
//! begins at `0x083e5b00`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **five**
//! direct call sites, all unconditional plain `bl` (0x08197a88, 0x082aaf50,
//! 0x082ab00c, 0x082ab028, and 0x083db348); there are no predicated calls or
//! direct tail branches. The raw body materializes zero in `r1`, stores it to
//! the three consecutive 32-bit words at `target + 0x00..0x08`, and preserves
//! `r0`. Ghidra declares it `void`, but callers 0x08197a88 and 0x083db348
//! consume the preserved target, so this port returns `target`. No deliberate
//! deviations.

/// Clears three consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for three `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_word_clear_return")]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_return(target: *mut u32) -> *mut u32 {
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
    fn clears_exactly_three_words_and_returns_the_preserved_target() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef, 0xc001_d00d];
        let target = words.as_mut_ptr().wrapping_add(1);

        let returned = unsafe { three_word_clear_return(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
    }
}
