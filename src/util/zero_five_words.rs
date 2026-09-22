//! Zeroes a five-word record.
//!
//! `zero_five_words` — original: `FUN_081fd5f4` @ **0x081fd5f4** (28 bytes
//! exactly, `0x081fd5f4..0x081fd60f`; `ldr pc, [pc, #-4]` at `0x081fd610`
//! begins the following veneer). Raw A32 decoding finds **3 direct inbound
//! plain `bl` call sites**, all unconditional: 0x081d612c, 0x081f1adc, and
//! 0x08267c40. There are no predicated `bl` forms. The seven-instruction body
//! loads zero into r2, writes it to five consecutive aligned words at `dst`,
//! and returns the unchanged destination in r0.
//!
//! Deliberate deviations: volatile stores prevent LLVM from replacing the
//! five observed word writes with a bulk memset.
//!
//! # Safety
//!
//! `dst` must be non-NULL, four-byte aligned, and writable for five `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_five_words")]
#[inline(never)]
pub unsafe extern "C" fn zero_five_words(dst: *mut u32) -> *mut u32 {
    dst.write_volatile(0);
    dst.add(1).write_volatile(0);
    dst.add(2).write_volatile(0);
    dst.add(3).write_volatile(0);
    dst.add(4).write_volatile(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::zero_five_words;

    #[test]
    fn zeroes_only_five_adjacent_words_and_returns_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555, 0x6666_6666, 0x7777_7777];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { zero_five_words(dst) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0x1111_1111, 0, 0, 0, 0, 0, 0x7777_7777]);
    }

    #[test]
    fn overwrites_full_width_nonzero_words() {
        let mut words = [u32::MAX, 0x8000_0000, 0x7fff_ffff, 1, 0xdead_beef];

        unsafe { zero_five_words(words.as_mut_ptr()) };

        assert_eq!(words, [0; 5]);
    }
}
