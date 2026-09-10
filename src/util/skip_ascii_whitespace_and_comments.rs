//! `skip_ascii_whitespace_and_comments` — original: `FUN_080789a8` @
//! `0x080789a8` (100 bytes, `0x080789a8..0x08078a0b`; extent verified
//! against the following function at `0x08078a0c`).
//!
//! Advances a caller-owned byte cursor across ASCII space, carriage return,
//! line feed, tab, form feed, and NUL bytes. A percent byte begins a comment:
//! the complete line through its CR or LF terminator is discarded, after which
//! scanning resumes. An unterminated percent comment advances the saved cursor
//! one byte beyond `end`: the stock inner loop reaches `end`, then the outer
//! loop's unconditional increment still executes. There are 12 verified static
//! `bl` call sites, all unconditional; decoding every ARM branch word in
//! `osos.dec` found no predicated calls. Deliberate deviations: none.

/// Advance `*cursor` across ignored bytes and percent comment lines.
///
/// The original dereferences `cursor` without a NULL guard and compares raw
/// addresses as unsigned words. `cursor` and `end` must delimit readable
/// bytes in the same address range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn skip_ascii_whitespace_and_comments(
    cursor: *mut *mut u8,
    end: *const u8,
) {
    let mut current = unsafe { cursor.read() };

    while current.cast_const() < end {
        let byte = unsafe { current.read() };
        if byte != b' '
            && byte != b'\r'
            && byte != b'\n'
            && byte != b'\t'
            && byte != 0x0c
            && byte != 0
        {
            if byte != b'%' {
                break;
            }

            while current.cast_const() < end {
                let comment_byte = unsafe { current.read() };
                if comment_byte == b'\r' || comment_byte == b'\n' {
                    break;
                }
                current = current.wrapping_add(1);
            }
        }
        current = current.wrapping_add(1);
    }

    unsafe { cursor.write(current) };
}

#[cfg(test)]
mod tests {
    use super::skip_ascii_whitespace_and_comments;

    unsafe fn skip(bytes: &mut [u8], start: usize) -> usize {
        let mut cursor = unsafe { bytes.as_mut_ptr().add(start) };
        let end = unsafe { bytes.as_ptr().add(bytes.len()) };
        unsafe { skip_ascii_whitespace_and_comments(&mut cursor, end) };
        cursor as usize - bytes.as_ptr() as usize
    }

    #[test]
    fn skips_the_exact_whitespace_set_including_nul() {
        let mut bytes = [b' ', b'\r', b'\n', b'\t', 0x0c, 0, b'X'];
        assert_eq!(unsafe { skip(&mut bytes, 0) }, 6);

        let mut vertical_tab = [0x0b, b'X'];
        assert_eq!(unsafe { skip(&mut vertical_tab, 0) }, 0);
    }

    #[test]
    fn skips_percent_comment_and_its_line_terminator() {
        let mut bytes = [b'%', b'n', b'o', b't', b'e', b'\r', b'\n', b' ', b'X'];
        assert_eq!(unsafe { skip(&mut bytes, 0) }, 8);

        let mut consecutive = [b'%', b'a', b'\n', b'%', b'b', b'\r', b'X'];
        assert_eq!(unsafe { skip(&mut consecutive, 0) }, 6);
    }

    #[test]
    fn advances_past_end_after_unterminated_comment() {
        let mut bytes = [b'%', b'n', b'o', b't', b'e'];
        assert_eq!(unsafe { skip(&mut bytes, 0) }, bytes.len() + 1);
    }

    #[test]
    fn leaves_nonignored_payload_unchanged() {
        let mut payload = [b'X', b' ', b'%'];
        assert_eq!(unsafe { skip(&mut payload, 0) }, 0);
    }
}
