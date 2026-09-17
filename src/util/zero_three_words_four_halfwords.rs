//! Zeroes a packed twenty-byte record.

/// `zero_three_words_four_halfwords` — original: `FUN_0827213c` @
/// **0x0827213c** (36 bytes exactly, `0x0827213c..0x08272160`; the `cmp r1,
/// #5` at `0x08272160` opens the distinct next function).
///
/// Decoding the raw ARM words verifies four direct inbound `bl` call sites,
/// all unconditional (0x0807463c, 0x08080f30, 0x0810ef38, and 0x0810f728),
/// and no predicated BL forms. The body clears three aligned words followed by
/// four aligned halfwords at offsets 0x0, 0x4, 0x8, 0xc, 0xe, 0x10, and 0x12,
/// returning the unchanged destination in r0.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `dst` must be non-NULL, four-byte aligned, and writable for 20 bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_three_words_four_halfwords")]
#[inline(never)]
pub unsafe extern "C" fn zero_three_words_four_halfwords(dst: *mut u32) -> *mut u32 {
    core::ptr::write_volatile(dst, 0);
    core::ptr::write_volatile(dst.add(1), 0);
    core::ptr::write_volatile(dst.add(2), 0);
    let halfwords = dst.cast::<u16>();
    core::ptr::write_volatile(halfwords.add(6), 0);
    core::ptr::write_volatile(halfwords.add(7), 0);
    core::ptr::write_volatile(halfwords.add(8), 0);
    core::ptr::write_volatile(halfwords.add(9), 0);
    dst
}

#[cfg(test)]
mod tests {
    use super::zero_three_words_four_halfwords;

    #[test]
    fn zeroes_the_packed_record_and_returns_destination() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555, 0x6666_6666, 0x7777_7777];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { zero_three_words_four_halfwords(dst) };

        assert_eq!(returned, dst);
        assert_eq!(words, [0x1111_1111, 0, 0, 0, 0, 0, 0x7777_7777]);
    }

    #[test]
    fn overwrites_each_halfword_of_nonzero_tail() {
        let mut words = [u32::MAX, 0x8000_0001, 0x7fff_ffff, 0x1234_abcd, 0xabcd_1234];

        unsafe { zero_three_words_four_halfwords(words.as_mut_ptr()) };

        assert_eq!(words, [0; 5]);
    }
}
