//! `three_word_clear_twelfth` — original: `FUN_083e6e60` @ 0x083e6e60
//! (20 bytes; `0x083e6e60..0x083e6e73`). The separately linked successor
//! `FUN_083e6e74` starts at 0x083e6e74.
//!
//! Raw ARM decoding finds three inbound direct call sites, all unconditional
//! plain `bl`; there are no predicated calls. The body materializes zero in
//! `r1`, stores it at `target + 0x00`, `+0x04`, and `+0x08`, then preserves
//! `r0`. Ghidra declares `void`, but all three callers consume preserved `r0`,
//! so this port returns `target`. No other behavioral deviations.

/// Clears three consecutive 32-bit words beginning at `target` and returns the
/// preserved target pointer.
///
/// `target` must be valid, aligned, and writable for three `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.three_word_clear_twelfth"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_twelfth(target: *mut u32) -> *mut u32 {
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

        let returned = unsafe { three_word_clear_twelfth(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
    }
}
