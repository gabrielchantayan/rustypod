//! Quoted C-string escaped length — `FUN_082d4b00` @ 0x082d4b00 (44 bytes;
//! 2 inbound plain `bl` call sites, no predicated inbound calls).
//!
//! Raw osos.dec establishes the exact extent 0x082d4b00..0x082d4b2c: the
//! following `push {r4-r8,lr}` at 0x082d4b2c starts a separate function. The
//! leaf body has no `bl` instructions. It scans an unguarded NUL-terminated
//! byte string, counts every byte and one extra byte for every double quote,
//! then adds two enclosing quotes. This is the output length used by the
//! adjacent command-string emitter, which doubles embedded quotes.
//!
//! Deliberate deviation: volatile byte reads prevent LLVM from replacing the
//! scan with an unavailable libc `strlen`; they do not change observable
//! retailOS behavior.

/// Returns the bytes required to quote `text` and double each embedded quote.
///
/// # Safety
///
/// `text` must point to a readable NUL-terminated C string. As in retailOS,
/// this function has no NULL guard and reads until the first NUL byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn quoted_cstr_escaped_len(text: *const u8) -> usize {
    let mut length = 0;
    let mut cursor = text;

    loop {
        let byte = cursor.read_volatile();
        if byte == 0 {
            return length + 2;
        }
        if byte == b'"' {
            length += 1;
        }
        length += 1;
        cursor = cursor.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(text: &[u8]) -> usize {
        2 + text.len() + text.iter().filter(|&&byte| byte == b'"').count()
    }


    #[test]
    fn accounts_for_enclosing_quotes_on_empty_string() {
        assert_eq!(unsafe { quoted_cstr_escaped_len(b"\0".as_ptr()) }, 2);
    }

    #[test]
    fn doubles_each_embedded_quote() {
        for (nul_terminated, expected) in [
            (b"plain\0".as_slice(), b"plain".as_slice()),
            (b"\"\0".as_slice(), b"\"".as_slice()),
            (b"a\"b\"c\0".as_slice(), b"a\"b\"c".as_slice()),
        ] {
            assert_eq!(unsafe { quoted_cstr_escaped_len(nul_terminated.as_ptr()) }, reference(expected));
        }
    }

    #[test]
    fn stops_at_first_nul() {
        let text = b"a\"\0ignored\"";
        assert_eq!(unsafe { quoted_cstr_escaped_len(text.as_ptr()) }, reference(b"a\""));
    }
}
