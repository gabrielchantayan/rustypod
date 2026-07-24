//! Ports of the string catenation routines from osos.
//!
//! Both originals are plain byte loops (no word optimization), so the Rust
//! ports are one-to-one:
//!
//! - `strcat` — original: `FUN_080311b4` @ 0x080311b4 (40 bytes).
//!   Scans `dst` forward to its NUL, then copies `src` byte-by-byte
//!   *including* the terminating NUL (load, test, store, loop while
//!   nonzero). Returns `dst`.
//! - `strncat` — original: `FUN_08031200` @ 0x08031200 (64 bytes).
//!   Scans `dst` to its NUL, then copies up to `len` bytes of `src`. The
//!   original tests `len == 0` *before* reading `src`, so `len == 0` never
//!   touches `src` at all; it stores each byte, returns early if that byte
//!   was NUL, and otherwise writes a NUL after the `len`th byte. Returns
//!   `dst`.
//!
//! Behavioral verification: host-side `cargo test` compares against a simple
//! reference implementation over lengths, alignments, and NUL positions;
//! `tools/match.py` (ipod-decomp) reports the mnemonic-level diff against
//! the original machine code.

/// Find the NUL terminator of `dst`, returning a pointer to it.
///
/// `read_volatile` keeps LLVM from rewriting the scan into a `strlen` call
/// (the crate exports no `strlen` symbol); the generated code is the same
/// ldrb/cmp/bne byte loop as the original.
#[inline(always)]
unsafe fn find_nul(dst: *mut u8) -> *mut u8 {
    let mut end = dst;
    while end.read_volatile() != 0 {
        end = end.add(1);
    }
    end
}

/// strcat — append `src` at `dst`'s NUL, NUL-terminate, return `dst`.
#[no_mangle]
pub unsafe extern "C" fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    let mut end = find_nul(dst);
    let mut src = src;
    loop {
        let byte = *src;
        src = src.add(1);
        *end = byte;
        end = end.add(1);
        if byte == 0 {
            break;
        }
    }
    dst
}

/// strncat — append at most `len` chars of `src` at `dst`'s NUL, always
/// NUL-terminate, return `dst`.
#[no_mangle]
pub unsafe extern "C" fn strncat(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    let mut end = find_nul(dst);
    let mut src = src;
    let mut remaining = len;
    while remaining != 0 {
        let byte = *src;
        src = src.add(1);
        *end = byte;
        end = end.add(1);
        if byte == 0 {
            return dst;
        }
        remaining -= 1;
    }
    *end = 0;
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple reference implementations written straight from the C standard.
    fn ref_strcat(dst: &mut [u8], src: &[u8]) {
        let end = dst.iter().position(|&b| b == 0).unwrap();
        let n = src.iter().position(|&b| b == 0).unwrap();
        dst[end..end + n + 1].copy_from_slice(&src[..n + 1]);
    }

    fn ref_strncat(dst: &mut [u8], src: &[u8], len: usize) {
        let end = dst.iter().position(|&b| b == 0).unwrap();
        let src_len = src.iter().position(|&b| b == 0).unwrap();
        let n = src_len.min(len);
        dst[end..end + n].copy_from_slice(&src[..n]);
        dst[end + n] = 0;
    }

    /// Build a NUL-terminated string of `n` nonzero bytes inside a padded
    /// buffer at the given alignment offset, with `extra` spare bytes after
    /// the NUL (room for catenation); returns (buffer, offset).
    fn make_string(n: usize, align: usize, seed: u8, extra: usize) -> (Vec<u8>, usize) {
        let mut buf = Vec::with_capacity(align + n + 8 + extra);
        buf.resize(align, 0xEE);
        for i in 0..n {
            buf.push((i as u16 * seed as u16 % 251) as u8 | 1); // never NUL
        }
        buf.push(0);
        buf.resize(buf.len() + 7 + extra, 0xEE);
        (buf, align)
    }

    #[test]
    fn strcat_matches_reference() {
        for dst_len in 0..64usize {
            for src_len in 0..64usize {
                for dst_align in 0..4usize {
                    for src_align in 0..4usize {
                        let (mut dst, doff) = make_string(dst_len, dst_align, 37, src_len);
                        let (src, soff) = make_string(src_len, src_align, 91, 0);
                        let mut reference = dst.clone();
                        ref_strcat(&mut reference[doff..], &src[soff..]);
                        unsafe {
                            let ret = strcat(
                                dst.as_mut_ptr().add(doff),
                                src.as_ptr().add(soff),
                            );
                            assert_eq!(ret, dst.as_mut_ptr().add(doff));
                        }
                        assert_eq!(
                            dst, reference,
                            "strcat mismatch: dst_len={dst_len} src_len={src_len} \
                             dst_align={dst_align} src_align={src_align}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn strncat_matches_reference() {
        for dst_len in [0usize, 1, 5, 33] {
            for src_len in [0usize, 1, 5, 33] {
                // len below, equal to, and above the source length.
                for len in [0usize, 1, src_len, src_len + 1, 64] {
                    for dst_align in 0..4usize {
                        for src_align in 0..4usize {
                            let (mut dst, doff) = make_string(dst_len, dst_align, 37, len);
                            let (src, soff) = make_string(src_len, src_align, 91, 0);
                            let mut reference = dst.clone();
                            ref_strncat(&mut reference[doff..], &src[soff..], len);
                            unsafe {
                                let ret = strncat(
                                    dst.as_mut_ptr().add(doff),
                                    src.as_ptr().add(soff),
                                    len,
                                );
                                assert_eq!(ret, dst.as_mut_ptr().add(doff));
                            }
                            assert_eq!(
                                dst, reference,
                                "strncat mismatch: dst_len={dst_len} src_len={src_len} \
                                 len={len} dst_align={dst_align} src_align={src_align}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// len == 0 must not read `src` at all (the original checks the count
    /// before loading) and must only write the terminating NUL.
    #[test]
    fn strncat_zero_len_only_nul_terminates() {
        let (mut dst, doff) = make_string(5, 0, 37, 0);
        let before = dst.clone();
        unsafe {
            // src points at unmapped-adjacent poison; a read would still
            // succeed here, so instead verify via the reference that no
            // bytes are appended.
            strncat(dst.as_mut_ptr().add(doff), b"abc".as_ptr(), 0);
        }
        let mut reference = before.clone();
        ref_strncat(&mut reference[doff..], b"abc\0", 0);
        assert_eq!(dst, reference);
    }
}
