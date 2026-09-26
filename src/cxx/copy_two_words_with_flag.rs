//! copy_two_words_with_flag — original: `FUN_083dd9c8` @ 0x083dd9c8 (28 bytes).
//!
//! Raw `osos.dec` establishes the exact seven-instruction extent
//! 0x083dd9c8..0x083dd9e3: two ordered aligned word load/store pairs, then an
//! ordered byte load/store pair and `bx lr`. The next independently linked
//! function begins at 0x083dd9e4. The body has zero plain and predicated `bl`
//! instructions. Full-image A32 decoding finds two inbound plain direct `bl`
//! sites (0x083d2ee8 and 0x083d301c) and zero predicated inbound `bl` sites.
//!
//! Algorithm: copy two aligned 32-bit fields from `source_words` to
//! `destination`, then copy the byte selected by `flag` to offset eight.
//! Deliberate deviation: none; ordered reads and writes preserve the stock
//! behavior for overlapping source and destination ranges.

/// Copy a two-word record and its trailing flag byte.
///
/// # Safety
///
/// `destination` and `source_words` must be valid and four-byte aligned for
/// two words; `flag` must be valid for one byte. The ranges may overlap, with
/// accesses performed in the stock instruction order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_two_words_with_flag(
    destination: *mut u32,
    source_words: *const u32,
    flag: *const u8,
) -> *mut u32 {
    unsafe {
        *destination = *source_words;
        *destination.add(1) = *source_words.add(1);
        *(destination.cast::<u8>().add(8)) = *flag;
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_two_words_with_flag;

    #[test]
    fn copies_words_and_flag_and_returns_destination() {
        let source = [0x1122_3344u32, 0x5566_7788];
        let flag = 0xa5u8;
        let mut destination = [0u32; 3];

        let result = unsafe {
            copy_two_words_with_flag(destination.as_mut_ptr(), source.as_ptr(), &flag)
        };

        assert_eq!(result, destination.as_mut_ptr());
        assert_eq!(destination[0], source[0]);
        assert_eq!(destination[1], source[1]);
        assert_eq!(unsafe { *(destination.as_ptr().cast::<u8>().add(8)) }, flag);
    }

    #[test]
    fn preserves_ordered_word_access_for_overlapping_ranges() {
        let mut words = [0x1111_1111u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let flag = 0x7eu8;

        let base = words.as_mut_ptr();
        unsafe {
            copy_two_words_with_flag(base.add(1), base, &flag);
            assert_eq!(core::ptr::read_volatile(base), 0x1111_1111);
            assert_eq!(core::ptr::read_volatile(base.add(1)), 0x1111_1111);
            assert_eq!(core::ptr::read_volatile(base.add(2)), 0x1111_1111);
            assert_eq!(core::ptr::read_volatile(base.add(3)), 0x4444_447e);
            assert_eq!(*base.cast::<u8>().add(12), flag);
        }
    }
}
