//! `four_word_sentinel_init` — original: `FUN_08287278` @ **0x08287278**
//! (28 bytes exactly, `0x08287278..0x08287294`; the distinct next function
//! starts at `0x08287294`).
//!
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds 12 direct call sites:
//! all are unconditional `bl`, with no predicated calls or tail branches. The
//! first caller allocates 16 bytes in r0, then consumes the unchanged r0 after
//! this initializer, proving the otherwise undocumented receiver return.
//!
//! # Algorithm
//!
//! Writes zero to the first three aligned `u32` words of the opaque record and
//! `u32::MAX` to its fourth word. It performs no reads or NULL check, and
//! returns the original receiver pointer in r0. No deliberate deviations.

/// Initializes an opaque four-word record whose final word is the invalid
/// sentinel, returning `target` unchanged.
///
/// # Safety
///
/// `target` must be non-NULL, four-byte aligned, and writable for four `u32`
/// words. The retail routine unconditionally performs those stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.four_word_sentinel_init")]
#[inline(never)]
pub unsafe extern "C" fn four_word_sentinel_init(target: *mut u32) -> *mut u32 {
    target.write(0);
    target.add(1).write(0);
    target.add(2).write(0);
    target.add(3).write(u32::MAX);
    target
}

#[cfg(test)]
mod tests {
    use super::four_word_sentinel_init;

    #[test]
    fn initializes_all_four_words_and_returns_the_receiver() {
        let mut words = [0x1357_9bdf, 0x2468_ace0, 0xfeed_face, 0x0102_0304];
        let target = words.as_mut_ptr();

        let returned = unsafe { four_word_sentinel_init(target) };

        assert_eq!(returned, target);
        assert_eq!(words, [0, 0, 0, u32::MAX]);
    }

    #[test]
    fn writes_exactly_four_words_at_an_interior_record() {
        let mut words = [
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
        ];

        unsafe { four_word_sentinel_init(words.as_mut_ptr().add(1)) };

        assert_eq!(words, [0x1111_1111, 0, 0, 0, u32::MAX, 0x6666_6666]);
    }
}
