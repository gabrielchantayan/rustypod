//! `selector_record_first_word` — original: `FUN_081d5fe0` @ `0x081d5fe0`.
//!
//! **24 bytes** (`0x081d5fe0..0x081d5ff7`); `str r1,[r0]` at `0x081d5ff8`
//! begins the next real function. Raw A32 has no outbound plain or predicated
//! `bl`. Decoding every A32 B/BL-immediate word finds three inbound plain `bl`
//! calls at `0x0811f080`, `0x0811f27c`, and `0x0811f2a4`, zero predicated
//! `bl` calls, and one conditional tail branch at `0x08208668`.
//!
//! # Algorithm
//!
//! Return the first word in the 36-byte record selected by `selector` from the
//! record array at `table + 0x24`. Selectors 0 through 17 are valid; every
//! other `u32` selector returns `u32::MAX` without dereferencing `table`.
//!
//! Deliberate deviations: none. The retail unsigned `cmp r1,#0x11` is retained
//! as an unsigned Rust comparison, and the word read retains the retail aligned
//! load requirement.

/// Return the first word of a selector record, or `u32::MAX` for an invalid selector.
///
/// # Safety
///
/// When `selector < 18`, `table + 0x24 + selector * 0x24` must identify a
/// readable, four-byte-aligned `u32`. RetailOS does not check `table` for null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_record_first_word(table: *const u8, selector: u32) -> u32 {
    if selector < 18 {
        unsafe { table.add(0x24 + selector as usize * 0x24).cast::<u32>().read() }
    } else {
        u32::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_WORDS: usize = 9;
    const RECORD_WORDS: usize = 9;

    fn table() -> [u32; HEADER_WORDS + 18 * RECORD_WORDS] {
        let mut words = [0xdead_beefu32; HEADER_WORDS + 18 * RECORD_WORDS];
        for selector in 0..18 {
            words[HEADER_WORDS + selector * RECORD_WORDS] = 0x1000_0000 + selector as u32;
        }
        words
    }

    #[test]
    fn returns_the_first_word_of_each_boundary_record() {
        let words = table();
        let table = words.as_ptr().cast::<u8>();

        assert_eq!(unsafe { selector_record_first_word(table, 0) }, 0x1000_0000);
        assert_eq!(unsafe { selector_record_first_word(table, 17) }, 0x1000_0011);
    }

    #[test]
    fn rejects_the_first_out_of_range_and_wrapping_selectors_without_a_read() {
        assert_eq!(unsafe { selector_record_first_word(core::ptr::null(), 18) }, u32::MAX);
        assert_eq!(unsafe { selector_record_first_word(core::ptr::null(), u32::MAX) }, u32::MAX);
    }
}
