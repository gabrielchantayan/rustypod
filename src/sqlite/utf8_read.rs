//! Bounded UTF-8 scalar decoding for SQLite text conversion.
//!
//! `sqlite_utf8_read` — original: `FUN_083863d4` @ **0x083863d4**
//! (120 bytes of code, followed by its 8-byte literal pool at
//! 0x0838644c..0x08386454; the next function starts at 0x08386454).
//! A complete raw-ARM B/BL scan finds **17 direct call sites**, all plain
//! `bl` instructions and none predicated or tail branches. This is SQLite
//! 3.5.9's `sqlite3Utf8Read` from `utf.c`.
//!
//! The routine consumes the first byte unconditionally. ASCII and an orphaned
//! continuation byte are returned unchanged. For a lead byte at least `0xc0`,
//! it seeds an accumulator from SQLite's 64-byte `sqlite3UtfTrans1` table,
//! then consumes consecutive continuation bytes while `cursor != terminator`.
//! It replaces overlong ASCII, UTF-16 surrogates, and U+FFFE/U+FFFF with
//! U+FFFD. It deliberately permits non-standard encodings of other values,
//! including sequences longer than modern UTF-8 allows, exactly as SQLite 3.5.9
//! does.
//!
//! The raw literal points to 0x088faa4b; as documented in `sqlite::mod`, the
//! immutable table is stored at image address 0x08905923 due to the +0xaed8
//! image/runtime skew. Its recovered bytes match SQLite's source table. No
//! deviations.

const UTF8_TRANS1: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
];

/// `sqlite3Utf8Read`: decode one bounded, SQLite-permissive UTF-8 sequence.
///
/// `text` must point to at least one readable byte and `next` must be writable.
/// `terminator` is one-past the readable range; a null terminator pointer is
/// permitted and lets the continuation-byte predicate stop the scan instead.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_utf8_read(
    text: *const u8,
    terminator: *const u8,
    next: *mut *const u8,
) -> u32 {
    let mut cursor = text.add(1);
    let mut codepoint = text.read() as u32;

    if codepoint >= 0xc0 {
        codepoint = UTF8_TRANS1[(codepoint - 0xc0) as usize] as u32;
        while cursor != terminator && cursor.read() & 0xc0 == 0x80 {
            codepoint = (codepoint << 6) + (cursor.read() & 0x3f) as u32;
            cursor = cursor.add(1);
        }
        if codepoint < 0x80
            || codepoint & 0xffff_f800 == 0xd800
            || codepoint & 0xffff_fffe == 0xfffe
        {
            codepoint = 0xfffd;
        }
    }

    next.write(cursor);
    codepoint
}

#[cfg(test)]
mod tests {
    use super::sqlite_utf8_read;

    unsafe fn decode(bytes: &[u8], terminator_index: usize) -> (u32, usize) {
        let mut next = core::ptr::null();
        let value = sqlite_utf8_read(
            bytes.as_ptr(),
            bytes.as_ptr().add(terminator_index),
            &mut next,
        );
        (value, next.offset_from(bytes.as_ptr()) as usize)
    }

    #[test]
    fn decodes_ascii_and_orphaned_continuation_as_single_bytes() {
        unsafe {
            assert_eq!(decode(b"A", 1), (u32::from(b'A'), 1));
            assert_eq!(decode(&[0x80], 1), (0x80, 1));
        }
    }

    #[test]
    fn decodes_two_three_and_four_byte_sequences() {
        unsafe {
            assert_eq!(decode(&[0xc2, 0xa2], 2), (0x00a2, 2));
            assert_eq!(decode(&[0xe2, 0x82, 0xac], 3), (0x20ac, 3));
            assert_eq!(decode(&[0xf0, 0x9f, 0x98, 0x80], 4), (0x1f600, 4));
        }
    }

    #[test]
    fn stops_at_bound_or_noncontinuation_without_consuming_it() {
        unsafe {
            assert_eq!(decode(&[0xe2, 0x82, 0xac], 2), (0x82, 2));
            assert_eq!(decode(&[0xc2, b'A'], 2), (0xfffd, 1));
        }
    }

    #[test]
    fn replaces_overlong_surrogate_and_noncharacter_sequences() {
        unsafe {
            assert_eq!(decode(&[0xc0, 0x80], 2), (0xfffd, 2));
            assert_eq!(decode(&[0xed, 0xa0, 0x80], 3), (0xfffd, 3));
            assert_eq!(decode(&[0xef, 0xbf, 0xbe], 3), (0xfffd, 3));
            assert_eq!(decode(&[0xef, 0xbf, 0xbf], 3), (0xfffd, 3));
        }
    }

    #[test]
    fn retains_permissive_nonstandard_long_sequences() {
        unsafe {
            assert_eq!(decode(&[0xf8, 0x88, 0x80, 0x80, 0x80], 5), (0x20_0000, 5));
        }
    }
}
