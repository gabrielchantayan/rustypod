//! A two-word record initialization helper.

/// store_u32_pair — originals: `FUN_081b4e24` @ 0x081b4e24 and
/// `FUN_081bb69c` @ 0x081bb69c (8 bytes each).
///
/// Raw ARM gives both bodies as `stm r0, {r1, r2}; bx lr`. The 0x081bb69c
/// body ends at the next real function boundary, 0x081bb6a4. A full-image
/// aligned A32 decode finds three inbound unconditional `bl` sites
/// (0x080e28b4, 0x081ee2d4, and 0x081fa9a4), no predicated `bl` forms, and
/// no outbound calls. It stores `first` and `second` as consecutive aligned
/// words at `dst`, then returns the unchanged `dst` in `r0`. Ghidra declares
/// the assigned function `void`; the retained r0 value is deliberate ABI
/// behavior. No NULL guard exists; callers must provide a valid, aligned
/// two-word destination. Deliberate deviation: the identical 0x081b4e24 and
/// 0x081bb69c leaves share this one Rust implementation.
///
/// # Safety
/// `dst` must be valid for two aligned `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_u32_pair")]
#[inline(never)]
pub unsafe extern "C" fn store_u32_pair(dst: *mut u32, first: u32, second: u32) -> *mut u32 {
    dst.write(first);
    dst.add(1).write(second);
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::store_u32_pair;

    #[test]
    fn stores_full_width_values_and_returns_destination() {
        let mut words = [0xdead_beef, 0xcafe_babe, 0xfeed_face];
        let dst = words.as_mut_ptr();

        let returned = unsafe { store_u32_pair(dst, 0, u32::MAX) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0, u32::MAX, 0xfeed_face]);
    }

    #[test]
    fn stores_exactly_a_two_word_destination() {
        let mut pair = [u32::MAX, 0];
        let dst = pair.as_mut_ptr();

        let returned = unsafe { store_u32_pair(dst, 0x1357_9bdf, 0x2468_ace0) };

        assert_eq!(returned, dst);
        assert_eq!(pair, [0x1357_9bdf, 0x2468_ace0]);
    }

    #[test]
    fn stores_adjacent_words_at_an_interior_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            store_u32_pair(dst, 0x0123_4567, 0x89ab_cdef);
        }

        assert_eq!(words, [0x1111_1111, 0x0123_4567, 0x89ab_cdef, 0x4444_4444]);
    }
}
