//! strstr — original: `FUN_08031264` @ 0x08031264 (60 bytes).
//!
//! Byte-at-a-time brute-force search: for each candidate position in the
//! haystack, walk both strings forward while the bytes are equal and the
//! haystack byte is nonzero (the original encodes this as
//! `cmp hc, #1; cmpcs hc, nc; beq` — an unsigned `hc >= 1 && hc == nc`).
//! Running off the end of the needle returns the candidate; running off the
//! end of the haystack returns null. An empty needle therefore returns the
//! haystack unchanged.

/// strstr — find the first occurrence of NUL-terminated `needle` in
/// NUL-terminated `haystack`, or null if there is none.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *const u8 {
    let mut candidate = haystack;
    loop {
        let mut h = candidate;
        let mut n = needle;
        let mut hc;
        let mut nc;
        loop {
            hc = *h;
            nc = *n;
            h = h.add(1);
            n = n.add(1);
            if hc == 0 || hc != nc {
                break;
            }
        }
        if nc == 0 {
            // Needle exhausted: full match starting at `candidate`
            // (empty needle matches immediately).
            return candidate;
        }
        if hc == 0 {
            // Haystack exhausted before the needle matched.
            return core::ptr::null();
        }
        candidate = candidate.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Reference strstr over NUL-terminated C strings in a byte buffer.
    fn reference(buf: &[u8], hay_off: usize, needle_off: usize) -> Option<usize> {
        let hay_len = buf[hay_off..].iter().position(|&b| b == 0).unwrap();
        let needle_len = buf[needle_off..].iter().position(|&b| b == 0).unwrap();
        let hay = &buf[hay_off..hay_off + hay_len];
        let needle = &buf[needle_off..needle_off + needle_len];
        if needle.is_empty() {
            return Some(hay_off);
        }
        if needle.len() > hay.len() {
            return None;
        }
        (0..=hay.len() - needle.len())
            .find(|&i| &hay[i..i + needle.len()] == needle)
            .map(|i| hay_off + i)
    }

    fn run(buf: &[u8], hay_off: usize, needle_off: usize) -> Option<usize> {
        let base = buf.as_ptr();
        let result = unsafe { strstr(base.add(hay_off), base.add(needle_off)) };
        if result.is_null() {
            None
        } else {
            Some(result as usize - base as usize)
        }
    }

    /// Deterministic non-zero pattern byte.
    fn pat(i: usize, seed: u8) -> u8 {
        ((i as u16 * seed as u16 + 7) % 254 + 1) as u8
    }

    /// One buffer holding "haystack\0needle\0"; compare against reference
    /// across haystack lengths 0..64, needle lengths 0..hay+2, and start
    /// alignments 0..3. Needle content is a copy of the haystack prefix so
    /// matches, near-matches and mismatches all occur.
    #[test]
    fn matches_reference_all_lengths_and_alignments() {
        for align in 0..4usize {
            for hay_len in 0..64usize {
                // Worst case: hay_len + align + 1 (NUL) + needle up to
                // hay_len + 2 bytes + 1 (NUL).
                let mut buf = Vec::with_capacity(align + 2 * hay_len + 8);
                buf.resize(align, 0);
                let hay_off = buf.len();
                for i in 0..hay_len {
                    buf.push(pat(i, 37));
                }
                buf.push(0);
                for needle_len in 0..=(hay_len + 2) {
                    let needle_off = buf.len();
                    // Copy haystack prefix; flip the last byte for the
                    // mismatch cases (needle longer than haystack or the
                    // trailing variant).
                    for i in 0..needle_len {
                        let b = if i < hay_len { buf[hay_off + i] } else { 0xAB };
                        buf.push(b);
                    }
                    buf.push(0);

                    let expected = reference(&buf, hay_off, needle_off);
                    let got = run(&buf, hay_off, needle_off);
                    assert_eq!(
                        got, expected,
                        "align={align} hay_len={hay_len} needle_len={needle_len}"
                    );

                    // Also test a mutated last needle byte (forces the
                    // "advance candidate" path to exhaust the haystack).
                    if needle_len > 0 {
                        let mut buf2 = buf.clone();
                        buf2[needle_off + needle_len - 1] ^= 0xFF;
                        if buf2[needle_off + needle_len - 1] == 0 {
                            buf2[needle_off + needle_len - 1] = 1;
                        }
                        let expected = reference(&buf2, hay_off, needle_off);
                        let got = run(&buf2, hay_off, needle_off);
                        assert_eq!(
                            got, expected,
                            "mutated: align={align} hay_len={hay_len} needle_len={needle_len}"
                        );
                    }

                    buf.truncate(needle_off);
                }
            }
        }
    }

    /// Match must be the *first* occurrence, not just any.
    #[test]
    fn returns_first_occurrence() {
        // "aabaaab\0" with needle "aab\0": match at index 0 and 4, expect 0.
        let buf = *b"aabaaab\0aab\0";
        assert_eq!(run(&buf, 0, 8), Some(0));
    }

    #[test]
    fn empty_needle_returns_haystack() {
        let buf = *b"hello\0\0";
        assert_eq!(run(&buf, 0, 6), Some(0));
        // Even for an empty haystack, empty needle returns the haystack ptr.
        let buf2 = *b"\0\0";
        assert_eq!(run(&buf2, 0, 1), Some(0));
    }

    #[test]
    fn no_match_returns_null() {
        let buf = *b"hello world\0xyz\0";
        assert_eq!(run(&buf, 0, 12), None);
        // Needle is a proper prefix extension of the haystack end.
        let buf2 = *b"abc\0abcd\0";
        assert_eq!(run(&buf2, 0, 4), None);
    }

    /// Bytes >= 0x80 compare as unsigned in the original (`cmpcs`), not as
    /// signed chars; make sure high bytes match correctly.
    #[test]
    fn high_bytes_match_unsigned() {
        let buf = [0x80u8, 0xFF, 0x41, 0, 0xFF, 0x41, 0];
        assert_eq!(run(&buf, 0, 4), Some(1));
        // Mutate so it can't match.
        let buf2 = [0x80u8, 0xFE, 0x41, 0, 0xFF, 0x41, 0];
        assert_eq!(run(&buf2, 0, 4), None);
    }
}
