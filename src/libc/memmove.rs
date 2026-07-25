//! Ports of the ARM ADS 1.0.1 runtime memory/string routines found at the
//! start of osos. Each function keeps the original's algorithm
//! (word-optimized copies, funnel shifts for misalignment) with names that
//! say what things do.
//!
//! Behavioral verification: host-side `cargo test` compares against std on
//! randomized overlapping buffers; `tools/match.py` (ipod-decomp) reports
//! the mnemonic-level diff against the original machine code.

/// memmove — original: `FUN_080000d4` @ 0x080000d4 (452 bytes).
///
/// Word-optimized overlapping copy. Copies backward when `dst` overlaps the
/// end of the source range, forward otherwise. Both paths word-align the
/// destination, stream 32-byte blocks down to single bytes, and merge
/// adjacent words with a funnel shift when the source is misaligned.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    if len == 0 || dst == src as *mut u8 {
        return dst;
    }
    if (dst as usize) > (src as usize) && (dst as usize) - (src as usize) < len {
        copy_backward(dst, src, len);
    } else {
        copy_forward(dst, src, len);
    }
    dst
}

#[inline(always)]
unsafe fn read_word(aligned: *const u8) -> u32 {
    (aligned as *const u32).read()
}

#[inline(always)]
unsafe fn write_word(aligned: *mut u8, value: u32) {
    (aligned as *mut u32).write(value);
}

/// Forward copy, `dst` may not be word-aligned on entry.
unsafe fn copy_forward(mut dst: *mut u8, mut src: *const u8, mut len: usize) {
    if len >= 4 {
        // Prologue: single bytes until dst is word-aligned.
        let dst_misalign = dst as usize & 3;
        if dst_misalign != 0 {
            let head = 4 - dst_misalign;
            for _ in 0..head {
                *dst = *src;
                dst = dst.add(1);
                src = src.add(1);
            }
            len -= head;
        }

        let src_shift = (src as usize & 3) * 8;
        if src_shift == 0 {
            // Both aligned: 32-byte blocks, then 16/8/4-byte leftovers.
            let mut d32 = dst as *mut u32;
            let mut s32 = src as *const u32;
            while len >= 32 {
                let (w0, w1, w2, w3) = (s32.read(), s32.add(1).read(), s32.add(2).read(), s32.add(3).read());
                let (w4, w5, w6, w7) = (s32.add(4).read(), s32.add(5).read(), s32.add(6).read(), s32.add(7).read());
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
                len -= 32;
            }
            if len & 16 != 0 {
                let (w0, w1, w2, w3) = (s32.read(), s32.add(1).read(), s32.add(2).read(), s32.add(3).read());
                d32.write(w0);
                d32.add(1).write(w1);
                d32.add(2).write(w2);
                d32.add(3).write(w3);
                d32 = d32.add(4);
                s32 = s32.add(4);
            }
            if len & 8 != 0 {
                let (w0, w1) = (s32.read(), s32.add(1).read());
                d32.write(w0);
                d32.add(1).write(w1);
                d32 = d32.add(2);
                s32 = s32.add(2);
            }
            if len & 4 != 0 {
                d32.write(s32.read());
                d32 = d32.add(1);
                s32 = s32.add(1);
            }
            dst = d32 as *mut u8;
            src = s32 as *const u8;
            len &= 3;
        } else {
            // Source misaligned by `src_shift` bits: funnel-merge words.
            let mut aligned_src = (src as usize & !3) as *const u8;
            let mut prev_word = read_word(aligned_src);
            let mut d32 = dst as *mut u32;
            while len >= 4 {
                let next_word = read_word(aligned_src.add(4));
                d32.write((prev_word >> src_shift) | (next_word << (32 - src_shift)));
                prev_word = next_word;
                aligned_src = aligned_src.add(4);
                d32 = d32.add(1);
                len -= 4;
            }
            dst = d32 as *mut u8;
            src = aligned_src.add(src_shift / 8);
        }
    }
    // Tail bytes.
    while len > 0 {
        *dst = *src;
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }
}

/// Backward copy for `src < dst < src + len` (overlap from above).
unsafe fn copy_backward(dst: *mut u8, src: *const u8, len: usize) {
    let mut dst_end = dst.add(len);
    let mut src_end = src.add(len);
    let mut remaining = len;

    if remaining >= 4 {
        // Prologue: single bytes until dst_end is word-aligned.
        let dst_misalign = dst_end as usize & 3;
        if dst_misalign != 0 {
            for _ in 0..dst_misalign {
                dst_end = dst_end.sub(1);
                src_end = src_end.sub(1);
                *dst_end = *src_end;
            }
            remaining -= dst_misalign;
        }

        let src_shift = (src_end as usize & 3) * 8;
        if src_shift == 0 {
            // Both aligned: 16-byte blocks, then 8/4-byte leftovers.
            let mut d32 = dst_end as *mut u32;
            let mut s32 = src_end as *const u32;
            while remaining >= 16 {
                let (w0, w1, w2, w3) = (
                    s32.sub(1).read(),
                    s32.sub(2).read(),
                    s32.sub(3).read(),
                    s32.sub(4).read(),
                );
                d32.sub(1).write(w0);
                d32.sub(2).write(w1);
                d32.sub(3).write(w2);
                d32.sub(4).write(w3);
                d32 = d32.sub(4);
                s32 = s32.sub(4);
                remaining -= 16;
            }
            if remaining & 8 != 0 {
                let (w0, w1) = (s32.sub(1).read(), s32.sub(2).read());
                d32.sub(1).write(w0);
                d32.sub(2).write(w1);
                d32 = d32.sub(2);
                s32 = s32.sub(2);
            }
            if remaining & 4 != 0 {
                d32.sub(1).write(s32.sub(1).read());
                d32 = d32.sub(1);
                s32 = s32.sub(1);
            }
            dst_end = d32 as *mut u8;
            src_end = s32 as *const u8;
            remaining &= 3;
        } else {
            // Source end misaligned by `src_shift` bits: funnel-merge.
            let mut aligned_src = (src_end as usize & !3) as *const u8;
            let mut next_word = read_word(aligned_src);
            let mut d32 = dst_end as *mut u32;
            while remaining >= 4 {
                let prev_word = read_word(aligned_src.sub(4));
                d32.sub(1).write((prev_word >> src_shift) | (next_word << (32 - src_shift)));
                next_word = prev_word;
                aligned_src = aligned_src.sub(4);
                d32 = d32.sub(1);
                remaining -= 4;
            }
            dst_end = d32 as *mut u8;
            src_end = aligned_src.add(src_shift / 8);
        }
    }
    // Head bytes (at the start of the range), copied backward for overlap.
    while remaining > 0 {
        dst_end = dst_end.sub(1);
        src_end = src_end.sub(1);
        *dst_end = *src_end;
        remaining -= 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn std_memmove(dst: &mut [u8], dst_off: usize, src: &[u8], src_off: usize, len: usize) {
        // safe reference via slices
        let tmp: Vec<u8> = src[src_off..src_off + len].to_vec();
        dst[dst_off..dst_off + len].copy_from_slice(&tmp);
    }

    /// Exhaustive-ish: single backing buffer, every small offset/len combo.
    /// Buffers are padded: like the original ARM code, the funnel-shift
    /// paths may read up to a word past the copied range.
    const PAD: usize = 16;

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size + PAD)
            .map(|i| ((i as u16 * seed as u16) % 251) as u8)
            .collect()
    }

    #[test]
    fn matches_std_small_buffers() {
        for size in [8usize, 16, 64] {
            for src_off in 0..size {
                for dst_off in 0..size {
                    for len in 0..=(size - src_off.max(dst_off)) {
                        let mut orig = pattern(size, 37);
                        let mut reference = orig.clone();
                        unsafe {
                            let base = orig.as_mut_ptr();
                            memmove(base.add(dst_off), base.add(src_off), len);
                        }
                        let tmp: Vec<u8> = reference[src_off..src_off + len].to_vec();
                        reference[dst_off..dst_off + len].copy_from_slice(&tmp);
                        assert_eq!(
                            orig, reference,
                            "mismatch: size={size} src={src_off} dst={dst_off} len={len}"
                        );
                    }
                }
            }
        }
    }

    /// Larger buffers including 32-byte block paths.
    #[test]
    fn matches_std_large_buffers() {
        for size in [128usize, 256, 517] {
            for (src_off, dst_off) in [(0, 1), (1, 0), (3, 7), (7, 3), (0, 13), (13, 0), (5, 5)] {
                for len in [0usize, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 100] {
                    if src_off + len > size || dst_off + len > size {
                        continue;
                    }
                    let mut orig = pattern(size, 91);
                    let mut reference = orig.clone();
                    unsafe {
                        let base = orig.as_mut_ptr();
                        memmove(base.add(dst_off), base.add(src_off), len);
                    }
                    let tmp: Vec<u8> = reference[src_off..src_off + len].to_vec();
                    reference[dst_off..dst_off + len].copy_from_slice(&tmp);
                    assert_eq!(
                        orig, reference,
                        "mismatch: size={size} src={src_off} dst={dst_off} len={len}"
                    );
                }
            }
        }
    }
}
