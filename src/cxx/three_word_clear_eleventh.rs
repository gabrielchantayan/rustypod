//! `three_word_clear_eleventh` — original: `FUN_0824c6c4` @ **0x0824c6c4**
//! (**20 bytes**, `0x0824c6c4..0x0824c6d7`; the independently linked successor
//! begins at `0x0824c6d8`).
//!
//! Decoding every aligned ARM `B`/`BL` immediate in `osos.dec` finds **four**
//! direct call sites, all unconditional plain `bl` (0x0824cca8, 0x08255f34,
//! 0x08255f3c, and 0x08255fcc); there are no predicated calls. The raw body
//! materializes zero in `r1`, stores it to `target + 0x08`, `+0x04`, then
//! `+0x00`, and preserves `r0`. Ghidra declares the function `void`, but all
//! four callers use the preserved target after the call, so this port returns
//! `target`. Rust uses volatile stores to retain the firmware's descending
//! store order; this is the only deliberate deviation.

/// Clears three consecutive 32-bit words beginning at `target`, then returns
/// `target` exactly as the ARM body preserves `r0`.
///
/// `target` must be valid, aligned, and writable for three `u32` values; stock
/// code has no NULL guard and makes no reads from the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_word_clear_eleventh")]
#[inline(never)]
pub unsafe extern "C" fn three_word_clear_eleventh(target: *mut u32) -> *mut u32 {
    unsafe {
        target.add(2).write_volatile(0);
        target.add(1).write_volatile(0);
        target.write_volatile(0);
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

        let returned = unsafe { three_word_clear_eleventh(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0xc001_d00d]);
    }
}
