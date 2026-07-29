//! SQLite's identifier dequoting helper.
//!
//! - `dequote` — original: `FUN_083753d0` @ 0x083753d0 (148 bytes;
//!   3 `bl` call sites, binary-scanned). SQLite's `sqlite3Dequote`.
//!
//! `dequote` algorithm: NULL in, nothing happens. Otherwise the first
//! byte decides the quote character: `'` and `"` quote themselves, `[`
//! quotes with `]` (MS SQL Server compatibility) and `` ` `` quotes
//! itself (MySQL compatibility); any other leading byte returns the
//! string untouched. With a quote established, the body is compacted
//! in place from index 1 down to index 0 (original: `r2` is the read
//! cursor starting at 1, `r1` the write cursor starting at 0): an
//! ordinary byte is copied down; a quote byte followed by the same
//! quote is an escaped quote — one copy of it is emitted and the read
//! cursor skips both (original: `strbeq lr, [r0, r12]`); a quote byte
//! followed by anything else is the terminator — a NUL is stored at
//! the write cursor and the function returns. A NUL byte with no
//! closing quote simply ends the loop *without* storing a terminator
//! at the write cursor — the partially compacted prefix and the
//! original NUL further out are left as they are.
//!
//! Deviations: none. Pure in-place byte shuffling; no heap, no flags.

/// dequote — original: `FUN_083753d0` @ 0x083753d0 (148 bytes;
/// 3 `bl` call sites).
///
/// `sqlite3Dequote`: strip the quoting off a SQL identifier in place.
/// Handles `'...'`, `"..."`, `` `...` `` and `[...]` (with the quote
/// doubled as its own escape); anything not starting with a quote
/// character is returned unchanged. A NULL pointer is a no-op.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dequote(z: *mut u8) {
    if z.is_null() {
        return;
    }
    let mut quote = z.read();
    if quote != b'"' && quote != b'\'' {
        if quote == b'[' {
            quote = b']';
        } else if quote != b'`' {
            return;
        }
    }
    let mut read = 1usize;
    let mut write = 0usize;
    loop {
        let c = z.add(read).read();
        if c == 0 {
            return;
        }
        if c == quote {
            if z.add(read + 1).read() == quote {
                // Escaped quote: emit one, skip both.
                z.add(write).write(quote);
                read += 1;
            } else {
                // Closing quote: terminate at the write cursor.
                z.add(write).write(0);
                return;
            }
        } else {
            z.add(write).write(c);
        }
        write += 1;
        read += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Copy `bytes` into a padded buffer at `align` offset; returns
    /// (buffer, offset). The padding canaries catch out-of-range writes.
    fn make_buffer(bytes: &[u8], align: usize) -> (Vec<u8>, usize) {
        let mut buf = std::vec![0xEE; align];
        buf.extend_from_slice(bytes);
        buf.resize(buf.len() + 8, 0xEE);
        (buf, align)
    }

    fn as_str(buf: &[u8]) -> &[u8] {
        let end = buf.iter().position(|&b| b == 0).unwrap();
        &buf[..end]
    }

    #[test]
    fn null_pointer_is_a_no_op() {
        unsafe { dequote(core::ptr::null_mut()) };
    }

    #[test]
    fn unquoted_strings_are_untouched() {
        for case in [&b"abc\0"[..], &b"\0"[..], &b"a'b\0"[..]] {
            let (mut buf, off) = make_buffer(case, 1);
            unsafe { dequote(buf.as_mut_ptr().add(off)) };
            assert_eq!(&buf[off..off + case.len()], case, "{case:?} unchanged");
            assert!(buf[..off].iter().all(|&b| b == 0xEE));
            assert!(buf[off + case.len()..].iter().all(|&b| b == 0xEE));
        }
    }

    #[test]
    fn empty_string_is_untouched() {
        let (mut buf, off) = make_buffer(b"\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(buf[off], 0);
    }

    #[test]
    fn double_quotes_are_stripped() {
        let (mut buf, off) = make_buffer(b"\"main\"\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"main");
    }

    #[test]
    fn single_quotes_with_doubled_escape_collapse() {
        // 'it''s' -> it's
        let (mut buf, off) = make_buffer(b"'it''s'\0", 2);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"it's");
    }

    #[test]
    fn backticks_are_stripped() {
        let (mut buf, off) = make_buffer(b"`tbl`\0", 3);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"tbl");
    }

    #[test]
    fn brackets_quote_with_close_bracket() {
        // [a]b] -> a  (the first ']' closes the quote; the rest is
        // past the terminator and left alone)
        let (mut buf, off) = make_buffer(b"[a]b]\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"a");
    }

    #[test]
    fn bracket_escape_is_doubled_close_bracket() {
        // [a]]b] -> a]b
        let (mut buf, off) = make_buffer(b"[a]]b]\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"a]b");
    }

    #[test]
    fn trailing_quote_escape_then_closer() {
        // 'a''' -> a'
        let (mut buf, off) = make_buffer(b"'a'''\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(as_str(&buf[off..]), b"a'");
    }

    #[test]
    fn unterminated_quote_compacts_without_extra_nul() {
        // "abc + NUL: the body shifts down by one and the loop stops at
        // the original NUL — no terminator is written at the write
        // cursor, so the stale trailing 'c' stays visible. Garbage in,
        // garbage out, exactly like the original.
        let (mut buf, off) = make_buffer(b"\"abc\0", 0);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(&buf[off..off + 5], b"abcc\0");
        assert_eq!(buf[off + 5], 0xEE, "nothing written past the NUL");
    }

    #[test]
    fn empty_quoted_name() {
        // "" -> empty
        let (mut buf, off) = make_buffer(b"\"\"\0", 1);
        unsafe { dequote(buf.as_mut_ptr().add(off)) };
        assert_eq!(buf[off], 0);
    }
}
