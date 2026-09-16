//! A two-word in-place exchange helper.

/// exchange_u32_words — original: `FUN_083ea774` @ 0x083ea774 (20 bytes;
/// 4 verified unconditional `bl` call sites, no predicated `bl` forms).
///
/// Raw ARM loads the second aligned word, then the first, and writes their
/// values back in the opposite locations. It has no NULL guard. In particular,
/// aliasing `first == second` preserves the word, unlike the XOR-based helper
/// at 0x080e75ac. Deliberate deviation: volatile accesses retain the original
/// load-before-store ordering when the pointers alias.
///
/// # Safety
/// `first` and `second` must each be valid, aligned `u32` pointers. They may
/// alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.exchange_u32_words")]
#[inline(never)]
pub unsafe extern "C" fn exchange_u32_words(first: *mut u32, second: *mut u32) {
    let second_value = second.read_volatile();
    let first_value = first.read_volatile();
    first.write_volatile(second_value);
    second.write_volatile(first_value);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::exchange_u32_words;

    #[test]
    fn exchanges_adjacent_words_without_touching_neighbours() {
        let mut words = [0xfeed_face, 0x0123_4567, 0x89ab_cdef, 0xcafe_babe];

        unsafe { exchange_u32_words(words.as_mut_ptr().add(1), words.as_mut_ptr().add(2)) };

        assert_eq!(words, [0xfeed_face, 0x89ab_cdef, 0x0123_4567, 0xcafe_babe]);
    }

    #[test]
    fn preserves_a_word_when_the_pointers_alias() {
        let mut word = 0xdead_beef;
        let ptr = core::ptr::addr_of_mut!(word);

        unsafe { exchange_u32_words(ptr, ptr) };

        assert_eq!(word, 0xdead_beef);
    }
}
