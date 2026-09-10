//! A two-word in-place exchange helper.

/// swap_u32_words — original: `FUN_080e75ac` @ 0x080e75ac (44 bytes;
/// 12 verified unconditional `bl` call sites, no predicated `bl` forms).
///
/// Raw ARM exchanges the aligned words through three XOR stores: read both
/// words, store their XOR through `first`, reread `second`, then finish both
/// stores. There is no NULL guard. In particular, aliasing `first == second`
/// deliberately clears that word, unlike a conventional swap. Deviations:
/// none.
///
/// # Safety
/// `first` and `second` must each be valid, aligned `u32` pointers. They may
/// alias, in which case the original's XOR sequence writes zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.swap_u32_words")]
#[inline(never)]
pub unsafe extern "C" fn swap_u32_words(first: *mut u32, second: *mut u32) {
    let xor = first.read() ^ second.read();
    first.write(xor);
    let moved = second.read() ^ xor;
    second.write(moved);
    first.write(first.read() ^ moved);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::swap_u32_words;

    #[test]
    fn exchanges_full_width_words_without_touching_neighbours() {
        let mut words = [0xfeed_face, 0, u32::MAX, 0xcafe_babe];

        unsafe { swap_u32_words(words.as_mut_ptr().add(1), words.as_mut_ptr().add(2)) };

        assert_eq!(words, [0xfeed_face, u32::MAX, 0, 0xcafe_babe]);
    }

    #[test]
    fn preserves_word_order_for_non_adjacent_locations() {
        let mut words = [0x0123_4567, 0xaaaa_aaaa, 0x89ab_cdef];

        unsafe { swap_u32_words(words.as_mut_ptr(), words.as_mut_ptr().add(2)) };

        assert_eq!(words, [0x89ab_cdef, 0xaaaa_aaaa, 0x0123_4567]);
    }

    #[test]
    fn same_address_follows_the_xor_sequence_and_clears_the_word() {
        let mut word = 0xdead_beef;
        let ptr = core::ptr::addr_of_mut!(word);

        unsafe { swap_u32_words(ptr, ptr) };

        assert_eq!(word, 0);
    }
}
