//! `ps_skip_literal_string` — original `FUN_080b19dc` @ `0x080b19dc`.
//! True extent: 76 bytes, `[0x080b19dc, 0x080b1a28)`; the next function
//! begins with an independent literal load. Whole-image raw A32 decoding
//! finds two incoming plain BLs (0x080a9548, 0x080cdaf8), no predicated
//! incoming BLs, and no outgoing BLs of either kind.
//!
//! Starting at the opening parenthesis, scan a PostScript literal string.
//! Track nesting with wrapping 32-bit depth; backslash skips the next byte
//! without interpreting it. Store the cursor after the balancing close or
//! at exhaustion. A final backslash advances one byte beyond the limit.
//! Callers are the FreeType PostScript token scanner and token extractor.
//! Deliberate deviations: none semantically; native pointer width on hosts,
//! target pointer width on ARM. Wrapping pointer arithmetic preserves the
//! exhausted-escape cursor without forming an out-of-bounds Rust reference.

/// `cursor` must address a writable pointer; bytes from its initial value
/// up to `limit` must be readable whenever the initial value is below it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ps_skip_literal_string(cursor: *mut *const u8, limit: *const u8) {
    let mut current = cursor.read();
    let mut depth = 0u32;
    while (current as usize) < (limit as usize) {
        let byte = current.read();
        if byte == b'\\' {
            current = current.wrapping_add(1);
        } else if byte == b'(' {
            depth = depth.wrapping_add(1);
        } else if byte == b')' {
            depth = depth.wrapping_sub(1);
            if depth == 0 {
                current = current.wrapping_add(1);
                break;
            }
        }
        current = current.wrapping_add(1);
    }
    cursor.write(current);
}

#[cfg(test)]
mod tests {
    use super::ps_skip_literal_string;

    fn check(bytes: &[u8], start: usize, limit: usize, expected: usize) {
        let base = bytes.as_ptr();
        let mut cursor = base.wrapping_add(start);
        unsafe { ps_skip_literal_string(&mut cursor, base.wrapping_add(limit)); }
        assert_eq!(cursor, base.wrapping_add(expected), "{bytes:?}, {start}..{limit}");
    }

    #[test]
    fn nesting_escapes_and_truncation() {
        for (bytes, expected) in [
            (&b"()tail"[..], 2),
            (&b"(a(b)c)tail"[..], 7),
            (&b"(a\\)b)tail"[..], 6),
            (&b"(\\(x)tail"[..], 5),
            (&b"(\\\\)tail"[..], 4),
            (&b"(unterminated"[..], 13),
            (&b"(\0)tail"[..], 3),
            (&b"(\\"[..], 3),
            (&b")()"[..], 3),
        ] {
            check(bytes, 0, bytes.len(), expected);
        }
        check(b"()tail", 0, 1, 1);
        check(b"(\\)tail", 0, 2, 3);
        check(b"()", 2, 2, 2);
        check(b"()", 2, 1, 2);
    }

    #[test]
    fn all_short_inputs_and_limits_match_word_scanner() {
        let alphabet = [b'(', b')', b'\\', 0, b'x'];
        for encoding in 0..3125usize {
            let mut bytes = [0u8; 5];
            let mut digits = encoding;
            for byte in &mut bytes {
                *byte = alphabet[digits % alphabet.len()];
                digits /= alphabet.len();
            }
            for limit in 0..=bytes.len() {
                let mut position = 0;
                let mut nesting = 0u32;
                while position < limit {
                    match bytes[position] {
                        b'\\' => position += 1,
                        b'(' => nesting = nesting.wrapping_add(1),
                        b')' => {
                            nesting = nesting.wrapping_sub(1);
                            if nesting == 0 {
                                position += 1;
                                break;
                            }
                        }
                        _ => {},
                    }
                    position += 1;
                }
                check(&bytes, 0, limit, position);
            }
        }
    }
}
