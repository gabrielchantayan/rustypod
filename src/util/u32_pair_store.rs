//! A two-word record initialization helper.

/// store_u32_pair — original: `FUN_081b4e24` @ 0x081b4e24 (8 bytes;
/// 20 verified unconditional `bl` call sites, no predicated `bl` forms).
///
/// Raw ARM is `stm r0, {r1, r2}; bx lr`: stores `first` and `second` as
/// consecutive aligned words at `dst`, then returns the unchanged `dst` in
/// `r0`. Ghidra incorrectly declares the return type `void`; callers at
/// 0x081281a8, 0x0816de24, 0x081dcf7c, 0x081dd024, and 0x081fadc4 consume the
/// returned pointer. No NULL guard exists; callers must provide a valid,
/// aligned two-word destination. Deviations: none.
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
    fn stores_adjacent_words_at_an_interior_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            store_u32_pair(dst, 0x0123_4567, 0x89ab_cdef);
        }

        assert_eq!(words, [0x1111_1111, 0x0123_4567, 0x89ab_cdef, 0x4444_4444]);
    }
}
