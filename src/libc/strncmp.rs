//! strncmp — original: `FUN_0803105c` @ 0x0803105c (116 bytes).
//!
//! Bounded string compare. When both pointers are word-aligned, compares a
//! word at a time, detecting an in-word NUL terminator with the classic
//! `0x01010101` idiom: `(w - 0x01010101) & !w & 0x80808080` is nonzero iff
//! `w` contains a zero byte. On a word mismatch or in-word NUL (and whenever
//! either pointer is misaligned) it drops to the ADS byte-tail idiom
//! `cmp byte,#1; cmpcs byte1,byte2` — i.e. continue while the byte from `a`
//! is nonzero and equal to the byte from `b`. Returns `(u8)a[i] - (u8)b[i]`
//! at the first mismatching/terminating position, or 0 when `len` bytes
//! compared equal.

/// NUL-detection constant; `WORD_ONES << 7` is the high-bit mask 0x80808080.
const WORD_ONES: u32 = 0x0101_0101;

/// strncmp — original @ 0x0803105c.
#[no_mangle]
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    let mut a = a;
    let mut b = b;
    let mut len = len;

    if (a as usize | b as usize) & 3 == 0 {
        // Both word-aligned: compare whole words while none differs and
        // none contains a NUL byte.
        while len >= 4 {
            let word_a = (a as *const u32).read();
            let word_b = (b as *const u32).read();
            if word_a != word_b || word_a.wrapping_sub(WORD_ONES) & !word_a & (WORD_ONES << 7) != 0 {
                break;
            }
            a = a.add(4);
            b = b.add(4);
            len -= 4;
        }
    }

    // Byte tail (also the whole loop when either pointer is misaligned):
    // the original's `cmp byte,#1; cmpcs byte1,byte2` continues only while
    // byte_a != 0 and byte_a == byte_b.
    loop {
        if len == 0 {
            return 0;
        }
        let byte_a = *a;
        let byte_b = *b;
        a = a.add(1);
        b = b.add(1);
        if byte_a == 0 || byte_a != byte_b {
            return byte_a as i32 - byte_b as i32;
        }
        len -= 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple byte-at-a-time reference with the C strncmp contract:
    /// stop at the first mismatch or NUL, else after `len` equal bytes.
    fn reference(a: &[u8], b: &[u8], len: usize) -> i32 {
        for i in 0..len {
            let (x, y) = (a[i], b[i]);
            if x == 0 || x != y {
                return x as i32 - y as i32;
            }
        }
        0
    }

    /// Worst case the word path reads whole aligned words inside the
    /// `len` window only — 8 bytes of slack per side is plenty.
    const PAD: usize = 8;

    /// Compare `a[..len]` against `b[..len]` with both impls at the given
    /// offsets into padded buffers.
    fn check(a: &[u8], b: &[u8], len: usize, off_a: usize, off_b: usize) {
        let mut buf_a = std::vec![0u8; a.len() + off_a + PAD];
        let mut buf_b = std::vec![0u8; b.len() + off_b + PAD];
        buf_a[off_a..off_a + a.len()].copy_from_slice(a);
        buf_b[off_b..off_b + b.len()].copy_from_slice(b);
        let got = unsafe { strncmp(buf_a.as_ptr().add(off_a), buf_b.as_ptr().add(off_b), len) };
        let want = reference(a, b, len);
        assert_eq!(
            got, want,
            "mismatch: a={a:?} b={b:?} len={len} off_a={off_a} off_b={off_b}"
        );
    }

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        // Nonzero bytes only; NULs are placed explicitly by the tests.
        (0..size).map(|i| ((i as u16 * seed as u16) % 251 + 1) as u8).collect()
    }

    #[test]
    fn all_lengths_and_alignments_no_nul() {
        for size in [8usize, 32, 64] {
            let base = pattern(size, 37);
            for off_a in 0..4 {
                for off_b in 0..4 {
                    for len in 0..=64usize.min(size) {
                        // Equal prefixes.
                        check(&base, &base, len, off_a, off_b);
                        // Mismatch at the last compared byte.
                        if len > 0 {
                            let mut diff = base.clone();
                            diff[len - 1] = diff[len - 1].wrapping_add(1).max(1);
                            check(&base, &diff, len, off_a, off_b);
                            check(&diff, &base, len, off_a, off_b);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mismatch_at_every_position() {
        let size = 64usize;
        let a = pattern(size, 91);
        for pos in 0..size {
            let mut b = a.clone();
            b[pos] = if a[pos] == 200 { 1 } else { 200 };
            for off in 0..4 {
                check(&a, &b, size, off, off);
                check(&a, &b, size, off, 0);
                check(&a, &b, size, 0, off);
            }
        }
    }

    #[test]
    fn nul_at_every_position() {
        let size = 64usize;
        for pos in 0..size {
            // NUL in both strings at the same spot: compare stops there.
            let mut a = pattern(size, 53);
            let mut b = a.clone();
            a[pos] = 0;
            b[pos] = 0;
            // Differ after the NUL — must not be observed.
            if pos + 1 < size {
                b[pos + 1] = b[pos + 1].wrapping_add(7).max(1);
            }
            for off in 0..4 {
                check(&a, &b, size, off, off);
            }

            // NUL only in `a`: returns 0 - b[pos] (negative).
            let a2 = pattern(size, 53);
            let mut b2 = a2.clone();
            let mut a2 = a2;
            a2[pos] = 0;
            check(&a2, &b2, size, 0, 0);
            check(&a2, &b2, size, 3, 1);

            // NUL only in `b`: returns a[pos] - 0 (positive).
            check(&b2, &a2, size, 0, 0);
            check(&b2, &a2, size, 1, 3);
        }
    }

    #[test]
    fn len_zero_and_edge_cases() {
        check(&[0], &[0], 0, 0, 0);
        check(&[b'x'], &[b'y'], 0, 1, 2);
        check(&[0], &[0], 1, 0, 0);
        check(&[0], &[b'a'], 1, 0, 0);
        check(&[b'a'], &[0], 1, 0, 0);
        // Count exhausted exactly at a word boundary after equal words.
        check(b"abcd", b"abcd", 4, 0, 0);
        check(b"abcdefg", b"abcdefg", 7, 0, 0);
        check(b"abcdefgh", b"abcdefgX", 7, 0, 0);
    }
}
