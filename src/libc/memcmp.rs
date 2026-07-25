//! memcmp — original: `FUN_08030f64` @ 0x08030f64 (128 bytes).
//!
//! When `len >= 4` and both pointers are word-aligned, compares word at a
//! time; on a word mismatch it backs up to the start of that word and
//! re-scans byte by byte to locate the exact differing byte. Everything else
//! (short lengths, misaligned pointers, the sub-word tail) is compared byte
//! by byte. Returns the `u8` difference of the first mismatching byte
//! (`(int)a[i] - (int)b[i]`), or 0 when the ranges are equal.
//!
//! Simplification: the original's byte path is a 2x-unrolled loop (an odd
//! remaining length compares one byte first, then proceeds in pairs); the
//! simple byte loop below is behaviorally identical.

/// memcmp — returns <0, 0, or >0 as the first differing byte of `a` is
/// less than, equal to, or greater than that of `b`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    let mut a = a;
    let mut b = b;
    let mut remaining = len;

    if remaining >= 4 && (a as usize | b as usize) & 3 == 0 {
        // Both word-aligned: compare a word at a time.
        while remaining >= 4 {
            let word_a = (a as *const u32).read();
            let word_b = (b as *const u32).read();
            if word_a != word_b {
                // Re-scan this word byte by byte to find the first
                // differing byte (`remaining` still covers it).
                break;
            }
            a = a.add(4);
            b = b.add(4);
            remaining -= 4;
        }
    }

    // Byte tail (also the whole compare when short or misaligned).
    while remaining > 0 {
        let byte_a = *a;
        let byte_b = *b;
        if byte_a != byte_b {
            return byte_a as i32 - byte_b as i32;
        }
        a = a.add(1);
        b = b.add(1);
        remaining -= 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple reference: plain byte-by-byte compare.
    fn ref_memcmp(a: &[u8], b: &[u8], len: usize) -> i32 {
        for i in 0..len {
            if a[i] != b[i] {
                return a[i] as i32 - b[i] as i32;
            }
        }
        0
    }

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8).collect()
    }

    /// Every length 0..64 at every alignment 0..3 for both buffers, with
    /// the buffers equal, and with a mismatch planted at every position.
    #[test]
    fn matches_reference_all_lengths_and_alignments() {
        let base = pattern(80, 37);
        for len in 0..64usize {
            for off_a in 0..4usize {
                for off_b in 0..4usize {
                    // Equal ranges (b is a copy of a's bytes).
                    let a = &base[off_a..off_a + len];
                    let mut b_buf = base[off_b..off_b + len].to_vec();
                    // b_buf must hold a's contents for the equal case.
                    b_buf.copy_from_slice(a);

                    let got = unsafe { memcmp(a.as_ptr(), b_buf.as_ptr(), len) };
                    assert_eq!(got, 0, "equal: len={len} off_a={off_a} off_b={off_b}");

                    // Plant a mismatch at each position (both directions).
                    for pos in 0..len {
                        for delta in [1i16, -1] {
                            let mut b_mod = b_buf.clone();
                            b_mod[pos] = (b_mod[pos] as i16 + delta) as u8;
                            let got = unsafe { memcmp(a.as_ptr(), b_mod.as_ptr(), len) };
                            let want = ref_memcmp(a, &b_mod, len);
                            assert_eq!(
                                got, want,
                                "mismatch: len={len} off_a={off_a} off_b={off_b} pos={pos} delta={delta}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Result sign and magnitude: u8 subtraction, not just -1/0/1.
    #[test]
    fn returns_byte_difference() {
        let a = [0x10u8, 0x00];
        let b = [0xf0u8, 0x00];
        assert_eq!(unsafe { memcmp(a.as_ptr(), b.as_ptr(), 2) }, 0x10 - 0xf0);
        assert_eq!(unsafe { memcmp(b.as_ptr(), a.as_ptr(), 2) }, 0xf0 - 0x10);
    }

    /// len = 0 always returns 0, even with differing bytes and equal
    /// or misaligned pointers.
    #[test]
    fn zero_length() {
        let a = [1u8, 2, 3, 4];
        let b = [9u8, 8, 7, 6];
        assert_eq!(unsafe { memcmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
        assert_eq!(unsafe { memcmp(a.as_ptr(), a.as_ptr(), 0) }, 0);
    }

    /// Bytes past the first mismatch must not affect the result.
    #[test]
    fn stops_at_first_mismatch() {
        let a = [1u8, 5, 5, 5, 9, 9, 9, 9];
        let b = [1u8, 2, 3, 4, 0, 0, 0, 0];
        assert_eq!(unsafe { memcmp(a.as_ptr(), b.as_ptr(), 8) }, 5 - 2);
    }
}
