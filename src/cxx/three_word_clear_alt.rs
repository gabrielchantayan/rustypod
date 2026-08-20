//! `three_word_clear_alt` — original: `FUN_083e0e68` @ 0x083e0e68 (20 bytes).
//!
//! Source: `ipod-decomp/decomp/c/038/083e0e68_FUN_083e0e68.c`.
//!
//! Byte-identical alternate of `three_word_clear`: unconditionally writes zero
//! to the three consecutive 32-bit words at offsets +0, +4, and +8 from its
//! aligned writable argument. It has no NULL guard, reads no target words, and
//! makes no other stores. Decompiled callers at 0x0811f050 and 0x0811f4f4
//! consume the unchanged ARM `r0` destination after returning. Although the
//! standalone C decompile labels it `void`, the Rust signature returns
//! `target` to preserve that observed ABI behavior.

/// Clears exactly the three consecutive 32-bit words beginning at `target`,
/// then returns `target` for the direct callers' expected destination pointer.
/// `target` must be valid, aligned, and writable for three `u32` values, as
/// required by the original unconditional stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_alt(target: *mut u32) -> *mut u32 {
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

        let returned = unsafe { three_word_clear_alt(words.as_mut_ptr().add(1)) };
        assert_eq!(returned, words.as_mut_ptr().wrapping_add(1));

        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
    }
}
