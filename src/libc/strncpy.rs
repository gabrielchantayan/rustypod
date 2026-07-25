//! strncpy — original: `FUN_080310d4` @ 0x080310d4 (104 bytes).
//!
//! Classic strncpy semantics: copies from `src` to `dst` until a NUL is
//! copied or `len` bytes have been written, then zero-pads the remainder of
//! the `len`-byte destination region. Returns the original `dst`.
//!
//! When both pointers are word-aligned the original copies a word at a time,
//! testing each word for a NUL byte with the 0x01010101 idiom
//! (`(w - 0x01010101) & !w & 0x80808080`); on finding one it backs up and
//! finishes byte-by-byte. Otherwise (or for the tail) it copies single
//! bytes. The zero-padding tail was a call to an external zero-fill helper
//! (thunk @ 0x08037dc8 -> 0x220002d4); here it is an inline `write_bytes`.

/// True if `word` contains a zero byte (0x01010101 idiom, as in the original).
#[inline(always)]
fn word_has_nul(word: u32) -> bool {
    (word.wrapping_sub(0x0101_0101) & !word & 0x8080_8080) != 0
}

#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    let orig_dst = dst;
    let mut dst = dst;
    let mut src = src;
    let mut remaining = len;

    if (dst as usize | src as usize) & 3 == 0 {
        // Both aligned: copy whole words that contain no NUL byte.
        while remaining >= 4 {
            let word = (src as *const u32).read();
            if word_has_nul(word) {
                break;
            }
            (dst as *mut u32).write(word);
            dst = dst.add(4);
            src = src.add(4);
            remaining -= 4;
        }
    }

    // Byte loop: copy until NUL or the count runs out.
    while remaining > 0 {
        let byte = *src;
        *dst = byte;
        dst = dst.add(1);
        src = src.add(1);
        remaining -= 1;
        if byte == 0 {
            // Pad the rest of the len-byte region with zeros.
            dst.write_bytes(0, remaining);
            break;
        }
    }

    orig_dst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Byte-at-a-time reference with C strncpy semantics.
    fn ref_strncpy(dst: *mut u8, src: *const u8, len: usize) {
        unsafe {
            let mut d = dst;
            let mut s = src;
            let mut n = len;
            while n > 0 {
                let b = *s;
                *d = b;
                d = d.add(1);
                n -= 1;
                if b == 0 {
                    d.write_bytes(0, n);
                    return;
                }
                s = s.add(1);
            }
        }
    }

    const MAX_LEN: usize = 64;
    // Room for 3 bytes of misalignment plus a word of over-read (the
    // original's word loop may read up to 3 bytes past the NUL).
    const BUF: usize = MAX_LEN + 8;

    /// Non-zero fill pattern for source bytes before the (optional) NUL.
    fn fill_src(buf: &mut [u8], nul_pos: Option<usize>, up_to: usize) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i as u32 * 37 + 11) % 251 + 1) as u8; // never 0
        }
        if let Some(p) = nul_pos {
            if p < up_to {
                buf[p] = 0;
            }
        }
    }

    fn run_case(dst_off: usize, src_off: usize, len: usize, nul_pos: Option<usize>) {
        let mut src_buf = std::vec![0u8; BUF];
        fill_src(&mut src_buf, nul_pos, len);

        let mut got = std::vec![0xAAu8; BUF];
        let mut want = got.clone();

        let ret = unsafe { strncpy(got.as_mut_ptr().add(dst_off), src_buf.as_ptr().add(src_off), len) };
        unsafe {
            ref_strncpy(want.as_mut_ptr().add(dst_off), src_buf.as_ptr().add(src_off), len);
        }

        assert_eq!(
            ret,
            unsafe { got.as_mut_ptr().add(dst_off) },
            "must return original dst (dst_off={dst_off} src_off={src_off} len={len} nul={nul_pos:?})"
        );
        assert_eq!(
            got, want,
            "mismatch: dst_off={dst_off} src_off={src_off} len={len} nul={nul_pos:?}"
        );
    }

    #[test]
    fn matches_reference_no_nul() {
        for dst_off in 0..4 {
            for src_off in 0..4 {
                for len in 0..=MAX_LEN {
                    run_case(dst_off, src_off, len, None);
                }
            }
        }
    }

    #[test]
    fn matches_reference_nul_at_every_position() {
        for dst_off in 0..4 {
            for src_off in 0..4 {
                for len in 1..=MAX_LEN {
                    for nul_pos in 0..len {
                        run_case(dst_off, src_off, len, Some(nul_pos));
                    }
                }
            }
        }
    }

    #[test]
    fn len_zero_touches_nothing() {
        let mut buf = std::vec![0xAAu8; BUF];
        let src = std::vec![0x55u8; BUF];
        let before = buf.clone();
        let ret = unsafe { strncpy(buf.as_mut_ptr(), src.as_ptr(), 0) };
        assert_eq!(ret, buf.as_mut_ptr());
        assert_eq!(buf, before);
    }
}
