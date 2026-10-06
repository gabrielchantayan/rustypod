//! UTF-8 iterator step — `FUN_081862cc` @ 0x081862cc.
//! Raw extent: 44 bytes, ending at the next push prologue @ 0x081862f8.
//! Verified calls: two inbound plain BLs, zero inbound predicated BLs;
//! one outbound plain BL to utf8_next_codepoint @ 0x08276214, zero
//! outbound predicated BLs. Check the literal current byte for NUL; if
//! nonzero, decode and advance the iterator's first pointer field, store
//! the low 16 bits, and return one. NUL returns zero without any writes.
//! No deliberate deviations; the existing decoder is called directly.

use super::string_object::utf8_next_codepoint;

/// Read the next retail UTF-8 codepoint into `output`.
///
/// # Safety
/// `cursor` must point to a writable, initialized cursor field. Its current
/// byte must be readable, and a non-NUL sequence must satisfy the decoder's
/// readable-byte preconditions. For non-NUL input, `output` must be writable
/// and aligned for u16. Other iterator fields are not accessed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_iterator_next(
    cursor: *mut *const u8, output: *mut u16,
) -> u32 {
    if **cursor == 0 {
        return 0;
    }
    *output = utf8_next_codepoint(cursor) as u16;
    1
}

#[cfg(test)]
mod tests {
    use super::utf8_iterator_next;

    #[test]
    fn literal_nul_preserves_cursor_and_output() {
        let text = [0u8];
        let mut cursor = text.as_ptr();
        let mut output = 0xdead;
        unsafe {
            assert_eq!(utf8_iterator_next(&mut cursor, &mut output), 0);
            assert_eq!(utf8_iterator_next(&mut cursor, core::ptr::null_mut()), 0);
        }
        assert_eq!(cursor, text.as_ptr());
        assert_eq!(output, 0xdead);
    }

    #[test]
    fn sequence_consumption_and_permissive_decode() {
        // Expected results derived from retail lead masks, not Unicode validation.
        let cases: &[(&[u8], u16, usize)] = &[
            (b"A\0", 0x41, 1),
            (&[0xc2, 0xa2, 0], 0xa2, 2),
            (&[0xe2, 0x82, 0xac, 0], 0x20ac, 3),
            (&[0xed, 0xa0, 0x80, 0], 0xd800, 3),
            (&[0xc0, 0x80, 0], 0, 2),
            (&[0xc2, 0, 0], 0x80, 2),
            (&[0xe1, 0xff, 0xff, 0], 0x1fff, 3),
            (&[0xf0, 0x9f, 0x92, 0], 0, 3),
            (&[0x80, 0x41, 0x42, 0], 0, 3),
        ];
        for &(text, expected, consumed) in cases {
            let mut cursor = text.as_ptr();
            let mut output = 0xbeef;
            unsafe {
                assert_eq!(utf8_iterator_next(&mut cursor, &mut output), 1);
                assert_eq!(output, expected);
                assert_eq!(cursor, text.as_ptr().add(consumed));
                // A decoded zero was still a successful step; only raw NUL stops.
                output = 0xdead;
                assert_eq!(utf8_iterator_next(&mut cursor, &mut output), 0);
                assert_eq!(cursor, text.as_ptr().add(consumed));
                assert_eq!(output, 0xdead);
            }
        }
    }
}
