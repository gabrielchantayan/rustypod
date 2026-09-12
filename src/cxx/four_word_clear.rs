//! `four_word_clear` — original: `FUN_08158cf0` @ **0x08158cf0**
//! (**24 bytes**, `0x08158cf0..0x08158d08`; the next separately linked function
//! begins at `0x08158d08`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **eight**
//! direct call sites, all unconditional plain `bl` (0x0812775c, 0x08140578,
//! 0x0814066c, 0x08284700, 0x0828478c, 0x08284834, 0x082848ac, and
//! 0x0829b3e4); there are no predicated calls or tail branches. The raw body
//! writes zero to four consecutive 32-bit words at `target + 0x00..0x0c` and
//! leaves `r0` unchanged. Ghidra declares it `void`, but caller 0x0814066c
//! consumes the preserved destination, so this port returns `target`. No
//! deliberate deviations.

/// Clears four consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for four `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.four_word_clear")]
#[inline(never)]
pub unsafe extern "C" fn four_word_clear(target: *mut u32) -> *mut u32 {
    unsafe {
        target.write(0);
        target.add(1).write(0);
        target.add(2).write(0);
        target.add(3).write(0);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exactly_four_target_words_and_returns_target() {
        let mut words = [0x1122_3344, 0xa5a5_5a5a, 0x5566_7788, 0xdead_beef, 0xc001_d00d, 0xfeed_face];
        let target = words.as_mut_ptr().wrapping_add(1);

        let returned = unsafe { four_word_clear(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0, 0xfeed_face]);
    }
}
