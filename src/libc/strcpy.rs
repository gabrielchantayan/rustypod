//! strcpy — original: `__strcpy_arm` (FUN_08030ff4) @ 0x08030ff4 (100 bytes).
//!
//! ARM ADS 1.0.1 runtime. When `(dst | src) & 3 == 0`, copies a word at a
//! time using the classic zero-byte-detection idiom:
//! `(w - 0x01010101) & !w & 0x80808080 != 0` signals a NUL somewhere in the
//! word (in the original: `sub lr, r3, ip; bic lr, lr, r3; tst lr, ip, lsl #7`
//! with `ip = 0x01010101`). Once a NUL-bearing word is found, its remaining
//! bytes are stored one at a time until the NUL itself is written. When
//! either pointer is misaligned, the original uses a 2x-unrolled byte loop;
//! we keep that unroll. Returns `dst`.
//!
//! Note: like the original, the aligned path reads a full word from `src`
//! even near the terminator, so it may touch up to 3 bytes past the NUL.

/// strcpy — copy the NUL-terminated string at `src` to `dst` (inclusive),
/// returning `dst`. No bounds checking; buffers must not overlap.
#[no_mangle]
pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    let mut d = dst;
    let mut s = src;

    if (d as usize | s as usize) & 3 == 0 {
        // Word-at-a-time path (both pointers word-aligned).
        const ONES: u32 = 0x01010101;
        const HIGHS: u32 = 0x80808080; // ONES << 7
        let mut d32 = d as *mut u32;
        let mut s32 = s as *const u32;
        // Reads until the word containing the NUL; stores only full
        // NUL-free words, then finishes byte-by-byte.
        let mut word = loop {
            let word = s32.read();
            if word.wrapping_sub(ONES) & !word & HIGHS != 0 {
                break word;
            }
            d32.write(word);
            d32 = d32.add(1);
            s32 = s32.add(1);
        };
        // Store the NUL-bearing word's bytes up to and including the NUL.
        d = d32 as *mut u8;
        loop {
            let byte = word as u8;
            *d = byte;
            d = d.add(1);
            if byte == 0 {
                return dst;
            }
            word >>= 8;
        }
    } else {
        // Misaligned path: 2x-unrolled byte copy, as in the original.
        loop {
            let b0 = *s;
            *d = b0;
            s = s.add(1);
            d = d.add(1);
            if b0 == 0 {
                break;
            }
            let b1 = *s;
            *d = b1;
            s = s.add(1);
            d = d.add(1);
            if b1 == 0 {
                break;
            }
        }
        dst
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple byte-at-a-time reference strcpy.
    unsafe fn ref_strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
        let mut i = 0;
        loop {
            let b = *src.add(i);
            *dst.add(i) = b;
            if b == 0 {
                return dst;
            }
            i += 1;
        }
    }

    // The aligned word path may read up to 3 bytes past the NUL; pad the
    // backing buffer so those reads stay in-bounds.
    const PAD: usize = 8;

    /// Build a source buffer: `len` nonzero bytes, then a NUL, then padding.
    fn source(len: usize) -> Vec<u8> {
        let mut v: Vec<u8> = (0..len).map(|i| (i as u8 % 200) + 1).collect();
        v.push(0);
        v.extend(std::iter::repeat(0xAA).take(PAD));
        v
    }

    #[test]
    fn matches_reference_all_alignments_and_lengths() {
        for len in 0..64usize {
            let src_buf = source(len);
            for dst_align in 0..4usize {
                // Backing buffer with room for the alignment offset + copy.
                let mut dst_buf = std::vec![0xCCu8; dst_align + len + 1 + PAD];
                let mut ref_buf = dst_buf.clone();
                let ret;
                unsafe {
                    let s = src_buf.as_ptr();
                    ret = strcpy(dst_buf.as_mut_ptr().add(dst_align), s);
                    let ref_ret = ref_strcpy(ref_buf.as_mut_ptr().add(dst_align), s);
                    assert_eq!(ref_ret, ref_buf.as_mut_ptr().add(dst_align));
                }
                assert_eq!(ret, unsafe { dst_buf.as_mut_ptr().add(dst_align) });
                assert_eq!(
                    dst_buf, ref_buf,
                    "mismatch: len={len} dst_align={dst_align}"
                );
            }
        }
    }

    #[test]
    fn matches_reference_src_alignments() {
        // dst stays word-aligned; vary src alignment via an offset prefix.
        for len in 0..64usize {
            for src_off in 0..4usize {
                let mut src_buf = std::vec![0x55u8; src_off];
                src_buf.extend(source(len));
                let mut dst_buf = std::vec![0xCCu8; len + 1 + PAD];
                let mut ref_buf = dst_buf.clone();
                unsafe {
                    let s = src_buf.as_ptr().add(src_off);
                    strcpy(dst_buf.as_mut_ptr(), s);
                    ref_strcpy(ref_buf.as_mut_ptr(), s);
                }
                assert_eq!(dst_buf, ref_buf, "mismatch: len={len} src_off={src_off}");
            }
        }
    }

    #[test]
    fn returns_dst_and_writes_nul() {
        let src = source(5);
        let mut dst_buf = std::vec![0xCCu8; 16];
        let ret = unsafe { strcpy(dst_buf.as_mut_ptr().add(1), src.as_ptr()) };
        assert_eq!(ret, unsafe { dst_buf.as_mut_ptr().add(1) });
        assert_eq!(&dst_buf[1..7], &src[..6]); // 5 bytes + NUL
        assert_eq!(dst_buf[0], 0xCC); // untouched prefix
        assert_eq!(dst_buf[7], 0xCC); // untouched after NUL
    }
}
