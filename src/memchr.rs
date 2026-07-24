//! memchr — original: `FUN_08031180` @ 0x08031180 (52 bytes).
//!
//! Plain byte-at-a-time scan: the original is a post-increment `ldrb` loop
//! that walks `len` bytes comparing against `c as u8`, returning a pointer to
//! the first match or null. Unlike the ADS memmove/memcpy, there are no
//! word-at-a-time tricks here — the port is a direct transcription.
//!
//! Behavioral verification: host-side `cargo test` compares against a simple
//! reference implementation across lengths, alignments and match positions;
//! `tools/match.py` (ipod-decomp) reports the mnemonic-level diff against
//! the original machine code.

/// Scan the first `len` bytes at `s` for `c as u8`; return a pointer to the
/// first matching byte, or null if none matches (or `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, len: usize) -> *const u8 {
    let needle = c as u8;
    let end = s.add(len);
    let mut cur = s;
    // The original is a do-while that loads first and checks the end pointer
    // before the byte, so it always touches s[0] when len != 0; the result is
    // the same as an ordinary bounded scan.
    while cur != end {
        let byte = *cur;
        cur = cur.add(1);
        if byte == needle {
            return cur.sub(1);
        }
    }
    core::ptr::null()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple reference implementation.
    fn ref_memchr(s: &[u8], c: i32, len: usize) -> *const u8 {
        let needle = c as u8;
        for i in 0..len {
            if s[i] == needle {
                return unsafe { s.as_ptr().add(i) };
            }
        }
        core::ptr::null()
    }

    /// 8-byte aligned backing buffer so `base.add(off)` covers alignments 0..3.
    fn aligned_buf(size: usize, fill: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(size + 8);
        v.resize(size + 8, fill);
        assert_eq!(v.as_ptr() as usize & 7, 0);
        v
    }

    /// Every length 0..64 x alignment 0..3 x match position (first, last,
    /// middle, none), compared against the reference.
    #[test]
    fn matches_reference_all_lengths_and_alignments() {
        for len in 0..64usize {
            for off in 0..4usize {
                for pos in [None, Some(0), Some(len / 2), len.checked_sub(1)] {
                    let mut buf = aligned_buf(off + len, 0x41);
                    let s = unsafe { buf.as_ptr().add(off) };
                    if let Some(p) = pos {
                        if p < len {
                            buf[off + p] = 0x42;
                        } else {
                            continue;
                        }
                    }
                    let got = unsafe { memchr(s, 0x42, len) };
                    let want = ref_memchr(&buf[off..off + len.max(1)], 0x42, len);
                    assert_eq!(got, want, "len={len} off={off} pos={pos:?}");
                }
            }
        }
    }

    /// c is taken mod 256: high bits of the i32 argument are ignored.
    #[test]
    fn c_is_truncated_to_u8() {
        let buf = aligned_buf(16, 0x05);
        let s = buf.as_ptr();
        for c in [0x05i32, 0x105, -0xfb /* ...ff05 */, 0x7f05] {
            assert_eq!(unsafe { memchr(s, c, 16) }, s, "c={c:#x}");
        }
        for c in [0x06i32, 0x106, 0x7f06] {
            assert_eq!(unsafe { memchr(s, c, 16) }, core::ptr::null(), "c={c:#x}");
        }
    }

    /// Searching for NUL: matches like any other byte, and bytes past a NUL
    /// are still scanned (memchr is not NUL-terminated).
    #[test]
    fn nul_search_and_scan_past_nul() {
        let mut buf = aligned_buf(8, 0x41);
        buf[2] = 0;
        buf[5] = 0x58;
        let s = buf.as_ptr();
        unsafe {
            assert_eq!(memchr(s, 0, 8), s.add(2));
            assert_eq!(memchr(s, 0x58, 8), s.add(5)); // past the NUL at [2]
            assert_eq!(memchr(s, 0, 2), core::ptr::null()); // NUL out of range
        }
    }

    /// len == 0 returns null without touching the buffer.
    #[test]
    fn zero_length_returns_null() {
        let buf = aligned_buf(1, 0x42);
        assert_eq!(unsafe { memchr(buf.as_ptr(), 0x42, 0) }, core::ptr::null());
    }
}
