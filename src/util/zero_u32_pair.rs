//! Zeroes a two-word record.

/// `zero_u32_pair` — originals: `FUN_080fffcc` @ **0x080fffcc** and
/// `FUN_081bb6b8` @ **0x081bb6b8** (each 16 bytes; 10 and 4 verified
/// unconditional `bl` call sites respectively, no predicated `bl` forms).
///
/// Both raw ARM bodies are `mov r1, #0; str r1, [r0]; str r1, [r0, #4]; bx
/// lr`. They write zero to two consecutive aligned words and return the
/// unchanged destination in `r0`. Ghidra incorrectly declares the return type
/// `void`; chained calls in `FUN_081f7278` and `FUN_081f72d0` consume the
/// returned pointer. No NULL guard exists; every decoded caller supplies
/// writable storage. Deliberate deviation: the two instruction-identical
/// retail entries intentionally share this Rust implementation.
///
/// # Safety
///
/// `dst` must be non-NULL, four-byte aligned, and writable for two `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_u32_pair")]
#[inline(never)]
pub unsafe extern "C" fn zero_u32_pair(dst: *mut u32) -> *mut u32 {
    dst.write(0);
    dst.add(1).write(0);
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::zero_u32_pair;

    #[test]
    fn zeroes_only_the_adjacent_pair_and_returns_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { zero_u32_pair(dst) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0x1111_1111, 0, 0, 0x4444_4444]);
    }

    #[test]
    fn overwrites_nonzero_full_width_words() {
        let mut words = [u32::MAX, 0x8000_0000];

        unsafe { zero_u32_pair(words.as_mut_ptr()) };

        assert_eq!(words, [0, 0]);
    }

    #[test]
    fn zeroes_a_pair_at_the_end_of_a_larger_record() {
        let mut words = [0xfeed_face, 0x0123_4567, 0x89ab_cdef, u32::MAX];
        let dst = unsafe { words.as_mut_ptr().add(2) };

        unsafe { zero_u32_pair(dst) };

        assert_eq!(words, [0xfeed_face, 0x0123_4567, 0, 0]);
    }
}
