//! __rt_memcpy — original: entry thunk @ 0x08000020 (180 bytes, up to the
//! memmove entry at 0x080000d4).
//!
//! The general memcpy entry of the ADS runtime — the hottest function in the
//! OS (~620 call sites via its veneer). `len <= 3` goes straight to the byte
//! tail. Otherwise a byte prologue word-aligns `dst` (1-3 bytes), then:
//! - if `src` is now word-aligned, the original tail-branches to the shared
//!   aligned body @ 0x08000188 (32-byte blocks, then 16/8/4 leftovers);
//! - else it merges adjacent source words with a funnel shift (the original
//!   has three specialized loops for the 8/16/24-bit shifts).
//! Both paths finish with a 0-3 byte tail (shared code @ 0x080001d4).
//!
//! Deviations from the original (behavior-preserving):
//! - The aligned body is duplicated inline instead of tail-branched to, to
//!   keep this port self-contained (no coupling to `memcpy.rs`).
//! - The prologue's conditionally-unrolled byte stores become a simple loop,
//!   and the three shift-specialized funnel loops become one loop with a
//!   parameterized shift (same simplification as memmove's forward path).
//! - The original clobbers r0 and effectively returns the advanced pointer;
//!   this port keeps the C memcpy contract and returns the original `dst`.
//! - Like the original, the funnel path may read up to a word past the end
//!   of the copied source range (never writes outside `dst..dst+len`).
//!   Overlapping ranges are not supported (memcpy, not memmove).

/// # Safety
/// `dst` and `src` must be valid for `len` bytes and must not overlap.
#[no_mangle]
pub unsafe extern "C" fn __rt_memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    let mut d = dst;
    let mut s = src;
    let mut remaining = len;

    if remaining > 3 {
        // Prologue: single bytes until dst is word-aligned.
        let dst_misalign = d as usize & 3;
        if dst_misalign != 0 {
            let head = 4 - dst_misalign;
            for _ in 0..head {
                *d = *s;
                d = d.add(1);
                s = s.add(1);
            }
            remaining -= head;
        }

        let src_misalign = s as usize & 3;
        if src_misalign == 0 {
            // Both aligned: the shared body the original tail-branches to —
            // 32-byte blocks (two ldm/stm pairs of 4 words), then 16/8/4
            // leftovers via bit tests on the remaining length.
            let mut d32 = d as *mut u32;
            let mut s32 = s as *const u32;
            while remaining >= 32 {
                let (w0, w1, w2, w3) =
                    (s32.read(), s32.add(1).read(), s32.add(2).read(), s32.add(3).read());
                let (w4, w5, w6, w7) = (
                    s32.add(4).read(),
                    s32.add(5).read(),
                    s32.add(6).read(),
                    s32.add(7).read(),
                );
                d32.write(w0);
                d32.add(1).write(w1);
                d32.add(2).write(w2);
                d32.add(3).write(w3);
                d32.add(4).write(w4);
                d32.add(5).write(w5);
                d32.add(6).write(w6);
                d32.add(7).write(w7);
                d32 = d32.add(8);
                s32 = s32.add(8);
                remaining -= 32;
            }
            if remaining & 16 != 0 {
                let (w0, w1, w2, w3) =
                    (s32.read(), s32.add(1).read(), s32.add(2).read(), s32.add(3).read());
                d32.write(w0);
                d32.add(1).write(w1);
                d32.add(2).write(w2);
                d32.add(3).write(w3);
                d32 = d32.add(4);
                s32 = s32.add(4);
            }
            if remaining & 8 != 0 {
                let (w0, w1) = (s32.read(), s32.add(1).read());
                d32.write(w0);
                d32.add(1).write(w1);
                d32 = d32.add(2);
                s32 = s32.add(2);
            }
            if remaining & 4 != 0 {
                d32.write(s32.read());
                d32 = d32.add(1);
                s32 = s32.add(1);
            }
            d = d32 as *mut u8;
            s = s32 as *const u8;
            remaining &= 3;
        } else if remaining >= 4 {
            // Source misaligned by `src_misalign` bytes: funnel-merge words.
            let shift = src_misalign * 8;
            let mut aligned_src = (s as usize & !3) as *const u8;
            let mut prev_word = read_word(aligned_src);
            let mut d32 = d as *mut u32;
            while remaining >= 4 {
                let next_word = read_word(aligned_src.add(4));
                d32.write((prev_word >> shift) | (next_word << (32 - shift)));
                prev_word = next_word;
                aligned_src = aligned_src.add(4);
                d32 = d32.add(1);
                remaining -= 4;
            }
            d = d32 as *mut u8;
            s = aligned_src.add(src_misalign);
        }
        // (remaining < 4 with misaligned src falls through to the byte tail.)
    }

    // Byte tail: 0-3 leftover bytes, or the whole copy when len <= 3.
    while remaining > 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
        remaining -= 1;
    }
    dst
}

#[inline(always)]
unsafe fn read_word(aligned: *const u8) -> u32 {
    (aligned as *const u32).read()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Simple byte-at-a-time reference implementation (non-overlapping).
    fn ref_memcpy(dst: &mut [u8], dst_off: usize, src: &[u8], src_off: usize, len: usize) {
        for i in 0..len {
            dst[dst_off + i] = src[src_off + i];
        }
    }

    /// Distinct, non-trivial byte pattern.
    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8).collect()
    }

    /// The funnel-shift path reads whole words and may touch up to 3 bytes
    /// past the copied source range — the original does the same. Padding
    /// keeps those reads in-bounds; the copied range itself is what we check.
    const PAD: usize = 16;

    /// Offset into `buf` at which the pointer has the requested misalignment.
    fn off_for_align(base: usize, misalign: usize) -> usize {
        (4 - (base & 3)) % 4 + misalign
    }

    /// All dst/src alignments 0..3 x lengths 0..=64, plus 32-byte-block
    /// sizes, against the byte-wise reference. Separate non-overlapping
    /// buffers (memcpy contract, not memmove).
    #[test]
    fn matches_reference_all_alignments_and_lengths() {
        const SIZE: usize = 160 + PAD;
        let lengths: Vec<usize> = (0..=64usize).chain([96, 128, 156, 160]).collect();
        for dst_mis in 0..4usize {
            for src_mis in 0..4usize {
                for &len in &lengths {
                    let src = pattern(SIZE, 37);
                    let mut dst = vec![0xAAu8; SIZE];
                    let mut reference = dst.clone();
                    let dst_off = off_for_align(dst.as_ptr() as usize, dst_mis);
                    let src_off = off_for_align(src.as_ptr() as usize, src_mis);
                    unsafe {
                        let ret = __rt_memcpy(
                            dst.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                        assert_eq!(ret, dst.as_mut_ptr().add(dst_off), "return value");
                    }
                    ref_memcpy(&mut reference, dst_off, &src, src_off, len);
                    assert_eq!(
                        dst, reference,
                        "mismatch: dst_mis={dst_mis} src_mis={src_mis} len={len}"
                    );
                }
            }
        }
    }

    /// Bytes outside the copied range must be untouched.
    #[test]
    fn leaves_surrounding_bytes_intact() {
        const SIZE: usize = 128 + PAD;
        for dst_mis in 0..4usize {
            for src_mis in 0..4usize {
                for len in [0usize, 1, 3, 4, 5, 31, 32, 33, 64, 100] {
                    let src = pattern(SIZE, 91);
                    let mut dst = pattern(SIZE, 13);
                    let before = dst.clone();
                    let dst_off = off_for_align(dst.as_ptr() as usize, dst_mis);
                    let src_off = off_for_align(src.as_ptr() as usize, src_mis);
                    unsafe {
                        __rt_memcpy(
                            dst.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                    }
                    assert_eq!(&dst[..dst_off], &before[..dst_off], "head clobbered");
                    assert_eq!(
                        &dst[dst_off + len..],
                        &before[dst_off + len..],
                        "tail clobbered: dst_mis={dst_mis} src_mis={src_mis} len={len}"
                    );
                }
            }
        }
    }

    /// len == 0 must copy nothing and return dst.
    #[test]
    fn zero_length() {
        let src = pattern(16, 5);
        let mut dst = pattern(16, 9);
        let before = dst.clone();
        unsafe {
            let ret = __rt_memcpy(dst.as_mut_ptr(), src.as_ptr(), 0);
            assert_eq!(ret, dst.as_mut_ptr());
        }
        assert_eq!(dst, before);
    }
}
