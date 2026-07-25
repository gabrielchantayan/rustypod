//! strchr / strrchr — originals: `FUN_080311dc` @ 0x080311dc (36 bytes) and
//! `FUN_08031240` @ 0x08031240 (36 bytes).
//!
//! Both are plain byte-at-a-time scans (no word tricks in the originals):
//! `strchr` walks forward comparing `(c as u8)` against each byte, exiting on
//! a match or on NUL; `strrchr` scans the whole string, remembering the most
//! recent match. C semantics apply: the terminating NUL is part of the
//! string, so searching for `'\0'` returns a pointer to it (strchr finds it
//! because the match test runs before the NUL test; strrchr records the
//! terminator as its last "match").

/// strchr — original: `FUN_080311dc` @ 0x080311dc (36 bytes).
///
/// Returns a pointer to the first occurrence of `(c as u8)` in `s`, or null
/// if not found. Searching for `'\0'` returns a pointer to the terminator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *const u8 {
    let target = c as u8;
    let mut p = s;
    loop {
        let byte = *p;
        if byte == target {
            return p;
        }
        if byte == 0 {
            return core::ptr::null();
        }
        p = p.add(1);
    }
}

/// strrchr — original: `FUN_08031240` @ 0x08031240 (36 bytes).
///
/// Returns a pointer to the last occurrence of `(c as u8)` in `s`, or null
/// if not found. Searching for `'\0'` returns a pointer to the terminator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *const u8 {
    let target = c as u8;
    let mut last: *const u8 = core::ptr::null();
    let mut p = s;
    loop {
        let byte = *p;
        if byte == target {
            last = p;
        }
        if byte == 0 {
            return last;
        }
        p = p.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Safe reference implementations with the same C semantics.
    fn ref_strchr(s: &[u8], c: i32) -> Option<usize> {
        let target = c as u8;
        for (i, &b) in s.iter().enumerate() {
            if b == target {
                return Some(i);
            }
            if b == 0 {
                return None;
            }
        }
        None // unreachable for NUL-terminated input
    }

    fn ref_strrchr(s: &[u8], c: i32) -> Option<usize> {
        let target = c as u8;
        let mut last = None;
        for (i, &b) in s.iter().enumerate() {
            if b == target {
                last = Some(i);
            }
            if b == 0 {
                return last;
            }
        }
        None // unreachable for NUL-terminated input
    }

    /// Build a NUL-terminated string of `len` payload bytes at `align`
    /// offset inside a padded buffer; the payload contains no interior NULs.
    fn make_buf(len: usize, align: usize, needle: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(align + len + 1 + 8);
        v.resize(align, 0xAA);
        for i in 0..len {
            // Deterministic non-NUL payload, sprinkled with `needle`.
            let b = if i % 5 == 2 { needle.max(1) } else { ((i * 37 + 11) % 254 + 1) as u8 };
            v.push(b);
        }
        v.push(0);
        v.resize(align + len + 1 + 8, 0xAA);
        v
    }

    fn check(buf: &[u8], align: usize, c: i32) {
        let base = unsafe { buf.as_ptr().add(align) };
        let expected = ref_strchr(&buf[align..], c);
        let got = unsafe { strchr(base, c) };
        match expected {
            Some(off) => assert_eq!(got, unsafe { base.add(off) }, "strchr c={c:#x} align={align}"),
            None => assert!(got.is_null(), "strchr c={c:#x} align={align}"),
        }
        let expected = ref_strrchr(&buf[align..], c);
        let got = unsafe { strrchr(base, c) };
        match expected {
            Some(off) => assert_eq!(got, unsafe { base.add(off) }, "strrchr c={c:#x} align={align}"),
            None => assert!(got.is_null(), "strrchr c={c:#x} align={align}"),
        }
    }

    #[test]
    fn matches_reference_lengths_and_alignments() {
        for len in 0..64usize {
            for align in 0..4usize {
                let buf = make_buf(len, align, b'x');
                // Hit, miss, and terminator search.
                check(&buf, align, b'x' as i32);
                check(&buf, align, 0xFE);
                check(&buf, align, 0);
            }
        }
    }

    #[test]
    fn needle_is_payload_byte_at_every_position() {
        // Exactly one occurrence, swept across the string.
        for len in 1..32usize {
            for pos in 0..len {
                for align in 0..4usize {
                    let mut v: Vec<u8> = std::iter::repeat(0xAA).take(align).collect();
                    for i in 0..len {
                        v.push(if i == pos { b'q' } else { b'w' });
                    }
                    v.push(0);
                    check(&v, align, b'q' as i32);
                }
            }
        }
    }

    #[test]
    fn c_is_truncated_to_u8() {
        let mut v: Vec<u8> = b"abc".to_vec();
        v.push(0);
        // 0x141 truncates to b'A' (absent), 0x161 truncates to b'a' (present).
        assert!(unsafe { strchr(v.as_ptr(), 0x141) }.is_null());
        assert_eq!(unsafe { strchr(v.as_ptr(), 0x161) }, v.as_ptr());
        assert!(unsafe { strrchr(v.as_ptr(), 0x141) }.is_null());
        assert_eq!(unsafe { strrchr(v.as_ptr(), 0x161) }, v.as_ptr());
    }

    #[test]
    fn search_for_nul_returns_terminator() {
        let mut v: Vec<u8> = b"hello".to_vec();
        v.push(0);
        let term = unsafe { v.as_ptr().add(5) };
        assert_eq!(unsafe { strchr(v.as_ptr(), 0) }, term);
        assert_eq!(unsafe { strrchr(v.as_ptr(), 0) }, term);
        // Empty string: terminator is the first byte.
        let e: Vec<u8> = std::vec![0];
        assert_eq!(unsafe { strchr(e.as_ptr(), 0) }, e.as_ptr());
        assert_eq!(unsafe { strrchr(e.as_ptr(), 0) }, e.as_ptr());
        assert!(unsafe { strchr(e.as_ptr(), b'a' as i32) }.is_null());
        assert!(unsafe { strrchr(e.as_ptr(), b'a' as i32) }.is_null());
    }

    #[test]
    fn strrchr_picks_last_occurrence() {
        let mut v: Vec<u8> = b"abacada".to_vec();
        v.push(0);
        let expected = unsafe { v.as_ptr().add(6) };
        assert_eq!(unsafe { strrchr(v.as_ptr(), b'a' as i32) }, expected);
        assert_eq!(unsafe { strchr(v.as_ptr(), b'a' as i32) }, v.as_ptr());
    }
}
