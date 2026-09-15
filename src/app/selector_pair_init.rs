//! `selector_pair_init` — original: `FUN_081d9698` @ `0x081d9698`.
//!
//! The verified 8-byte body (`0x081d9698..0x081d96a0`) is `stm r0, {r1,
//! r2}; bx lr`. It writes the two selector words to consecutive aligned
//! destination words and preserves the destination in `r0`.
//!
//! **5 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `osos.dec`: 0x081c84d4,
//! 0x081c855c, 0x081c85dc, 0x081c8798, and 0x081c8800. The next real function
//! begins at 0x081d96a0. Deliberate deviation: Ghidra declares `void`, but the
//! raw `stm` and `bx lr` preserve `r0`, so this port exposes the returned
//! destination pointer.

/// Initializes a two-word selector pair and returns its destination.
///
/// # Safety
///
/// `selector` must be valid and aligned for two `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_pair_init(
    selector: *mut u32,
    first: u32,
    second: u32,
) -> *mut u32 {
    selector.write(first);
    selector.add(1).write(second);
    selector
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::selector_pair_init;

    #[test]
    fn stores_full_width_selector_words_and_returns_destination() {
        let mut words = [0xdead_beef, 0xcafe_babe, 0xfeed_face];
        let selector = words.as_mut_ptr();

        let returned = unsafe { selector_pair_init(selector, 0, u32::MAX) };

        assert_eq!(returned, selector);
        assert_eq!(words, [0, u32::MAX, 0xfeed_face]);
    }

    #[test]
    fn stores_only_the_adjacent_words_at_an_interior_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let selector = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            selector_pair_init(selector, 0x0123_4567, 0x89ab_cdef);
        }

        assert_eq!(words, [0x1111_1111, 0x0123_4567, 0x89ab_cdef, 0x4444_4444]);
    }
}
