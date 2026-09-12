//! Zeroes a four-word record.

/// `zero_four_words` — original: `FUN_082486ec` @ **0x082486ec** (20 bytes
/// exactly, `0x082486ec..0x08248700`; `0x08248704` opens the distinct next
/// function).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **8 direct inbound
/// `bl` call sites**, all unconditional: 0x0824c658, 0x0824c660, 0x0824c668,
/// 0x0825603c, 0x08256044, 0x08256058, 0x08256d1c, and 0x08256d24. There are
/// no predicated BL forms or direct tail branches. The five-instruction body
/// loads zero into r1, writes it to four consecutive aligned words at `dst`,
/// and returns the unchanged destination in r0. Ghidra's reported 24-byte
/// extent includes the separate following function's first instruction.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `dst` must be non-NULL, four-byte aligned, and writable for four `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_four_words")]
#[inline(never)]
pub unsafe extern "C" fn zero_four_words(dst: *mut u32) -> *mut u32 {
    dst.write(0);
    dst.add(1).write(0);
    dst.add(2).write(0);
    dst.add(3).write(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::zero_four_words;

    #[test]
    fn zeroes_only_four_adjacent_words_and_returns_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555, 0x6666_6666];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { zero_four_words(dst) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0x1111_1111, 0, 0, 0, 0, 0x6666_6666]);
    }

    #[test]
    fn overwrites_full_width_nonzero_words() {
        let mut words = [u32::MAX, 0x8000_0000, 0x7fff_ffff, 1];

        unsafe { zero_four_words(words.as_mut_ptr()) };

        assert_eq!(words, [0; 4]);
    }
}
