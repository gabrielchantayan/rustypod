//! Zeroes a three-word record while preserving its address.

/// `zero_three_words` — original: `FUN_081bb794` @ **0x081bb794** (20 bytes
/// exactly, `0x081bb794..0x081bb7a8`; `0x081bb7a8` opens the distinct next
/// function).
///
/// Decoding every aligned ARM B/BL-immediate word in `osos.dec` verifies **5
/// direct inbound `bl` call sites**, all unconditional: 0x0827bcc8,
/// 0x0827bcdc, 0x0828ca04, 0x0828ca18, and 0x082ac1cc. There are no predicated
/// BL forms or direct tail branches. The five-instruction body loads zero into
/// r1, stores it to three consecutive aligned words at `dst`, then returns the
/// unchanged destination in r0. Callers use it to initialize 12-byte fields
/// within larger graphics and UI records.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `dst` must be non-NULL, four-byte aligned, and writable for three `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_three_words")]
#[inline(never)]
pub unsafe extern "C" fn zero_three_words(dst: *mut u32) -> *mut u32 {
    dst.write(0);
    dst.add(1).write(0);
    dst.add(2).write(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::zero_three_words;

    #[test]
    fn zeroes_only_three_adjacent_words_and_returns_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { zero_three_words(dst) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0x1111_1111, 0, 0, 0, 0x5555_5555]);
    }

    #[test]
    fn overwrites_full_width_nonzero_words() {
        let mut words = [u32::MAX, 0x8000_0000, 0x7fff_ffff];

        unsafe { zero_three_words(words.as_mut_ptr()) };

        assert_eq!(words, [0; 3]);
    }
}
