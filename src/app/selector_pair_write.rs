//! `selector_pair_write` — original: `FUN_081d9690` @ `0x081d9690`.
//!
//! Raw words `0xe8800006` and `0xe12fff1e` establish the verified 8-byte body
//! (`0x081d9690..0x081d9698`): `stmia r0, {r1, r2}; bx lr`. It writes the two
//! incoming selector words to consecutive aligned destination words and preserves
//! the destination in `r0`.
//!
//! **3 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `osos.dec`: `0x081af5bc`,
//! `0x081af614`, and `0x081c86cc`. The next real function begins at
//! `0x081d9698`. Deliberate deviation: Ghidra declares `void`, but the raw
//! `stmia` and `bx lr` preserve `r0`, so this port exposes the returned
//! destination pointer.

/// Writes a two-word selector pair and returns its destination.
///
/// # Safety
///
/// `selector` must be valid and aligned for two `u32` writes.
#[cfg_attr(target_os = "none", link_section = ".text.selector_pair_write")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_pair_write(
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

    use super::selector_pair_write;

    #[test]
    fn stores_full_width_words_and_returns_destination() {
        let mut words = [0xdead_beef, 0xcafe_babe, 0xfeed_face];
        let selector = words.as_mut_ptr();

        let returned = unsafe { selector_pair_write(selector, 0, u32::MAX) };

        assert_eq!(returned, selector);
        assert_eq!(words, [0, u32::MAX, 0xfeed_face]);
    }

    #[test]
    fn writes_only_the_adjacent_words_at_an_interior_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let selector = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            selector_pair_write(selector, 0x0123_4567, 0x89ab_cdef);
        }

        assert_eq!(words, [0x1111_1111, 0x0123_4567, 0x89ab_cdef, 0x4444_4444]);
    }
}
