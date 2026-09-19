//! Reverses each word in a four-word record in place.

/// `bswap_four_u32s_inplace` — original: `FUN_080ac17c` @ **0x080ac17c**
/// (132 bytes exactly, `0x080ac17c..0x080ac200`; the separately linked next
/// function begins at `0x080ac200`).
///
/// Raw `osos.dec` words decode as four repeated aligned `ldr`, shift/mask/OR,
/// and `str` sequences, followed by `bx lr`. Decoding all ARM branch words
/// finds four direct inbound `blne` call sites (0x0809499c, 0x08094f90,
/// 0x080950ec, and 0x08095b5c), no plain `bl` call sites, and no direct calls
/// in this leaf body. The function reverses the bytes of each of four
/// consecutive aligned u32s and returns the unchanged input pointer in r0;
/// Ghidra's `void` signature loses that return value. Deliberate deviations:
/// none.
///
/// # Safety
///
/// `record` must be non-NULL, four-byte aligned, and writable for four `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bswap_four_u32s_inplace")]
#[inline(never)]
pub unsafe extern "C" fn bswap_four_u32s_inplace(record: *mut u32) -> *mut u32 {
    record.write_volatile(record.read_volatile().swap_bytes());
    record.add(1).write_volatile(record.add(1).read_volatile().swap_bytes());
    record.add(2).write_volatile(record.add(2).read_volatile().swap_bytes());
    record.add(3).write_volatile(record.add(3).read_volatile().swap_bytes());
    record
}

#[cfg(test)]
mod tests {
    use super::bswap_four_u32s_inplace;

    #[test]
    fn reverses_four_full_width_words_and_returns_record() {
        let mut words = [0x0123_4567, 0x80fe_7fa5, 0, u32::MAX];
        let record = words.as_mut_ptr();

        let returned = unsafe { bswap_four_u32s_inplace(record) };

        assert_eq!(returned, record);
        assert_eq!(words, [0x6745_2301, 0xa57f_fe80, 0, u32::MAX]);
    }

    #[test]
    fn changes_only_the_four_word_record_at_an_interior_pointer() {
        let mut words = [0x1111_1111, 0x0123_4567, 0x89ab_cdef, 0x1020_3040, 0xa5b6_c7d8, 0x2222_2222];
        let record = unsafe { words.as_mut_ptr().add(1) };

        unsafe { bswap_four_u32s_inplace(record) };

        assert_eq!(words, [0x1111_1111, 0x6745_2301, 0xefcd_ab89, 0x4030_2010, 0xd8c7_b6a5, 0x2222_2222]);
    }
}
