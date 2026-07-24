//! memcpy — original: `FUN_08000188` @ 0x08000188 (108 bytes).
//!
//! The aligned fast path of the ADS runtime copy, broken out as its own
//! entry point: both pointers are assumed word-aligned on entry (memmove
//! reaches this code once it has aligned the destination and found the
//! source aligned too). Streams 32-byte blocks (two 16-byte ldm/stm pairs),
//! then handles 16/8/4-byte leftovers via flag tricks on the remaining
//! length, then 0-3 tail bytes.
//!
//! Deviation from the original: the ARM routine clobbers r0/r1 as it goes
//! and returns the *advanced* pointers; this port keeps the C memcpy
//! contract and returns the original `dst`. Overlapping ranges are not
//! supported (same as the original).

/// # Safety
/// `dst` and `src` must both be word-aligned and valid for `len` bytes,
/// and the ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    let mut d32 = dst as *mut u32;
    let mut s32 = src as *const u32;
    let mut remaining = len;

    // 32-byte blocks (the original uses two ldm/stm pairs of 4 words).
    while remaining >= 32 {
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
        remaining -= 32;
    }
    // 16/8/4-byte leftovers (bit tests on the remaining length).
    if remaining & 16 != 0 {
        let (w0, w1, w2, w3) = (s32.read(), s32.add(1).read(), s32.add(2).read(), s32.add(3).read());
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
    // 0-3 tail bytes.
    let mut d = d32 as *mut u8;
    let mut s = s32 as *const u8;
    for _ in 0..(remaining & 3) {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Simple byte-at-a-time reference implementation.
    fn ref_memcpy(dst: &mut [u8], dst_off: usize, src: &[u8], src_off: usize, len: usize) {
        for i in 0..len {
            dst[dst_off + i] = src[src_off + i];
        }
    }

    /// Distinct, non-trivial byte pattern.
    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8).collect()
    }

    /// The original contract requires word-aligned pointers, so offsets are
    /// multiples of 4. Lengths 0..=64 cover the 32-byte block loop plus all
    /// 16/8/4/2/1 leftover combinations.
    #[test]
    fn matches_reference_all_lengths_and_word_offsets() {
        const SIZE: usize = 96;
        for dst_off in (0..16).step_by(4) {
            for src_off in (0..16).step_by(4) {
                for len in 0..=64usize {
                    let src = pattern(SIZE, 37);
                    let mut dst = vec![0xAAu8; SIZE];
                    let mut reference = dst.clone();
                    unsafe {
                        let ret = memcpy(
                            dst.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                        assert_eq!(ret, dst.as_mut_ptr().add(dst_off), "return value");
                    }
                    ref_memcpy(&mut reference, dst_off, &src, src_off, len);
                    assert_eq!(
                        dst, reference,
                        "mismatch: dst_off={dst_off} src_off={src_off} len={len}"
                    );
                }
            }
        }
    }

    /// Bytes outside the copied range must be untouched.
    #[test]
    fn leaves_surrounding_bytes_intact() {
        const SIZE: usize = 64;
        for len in 0..=32usize {
            let src = pattern(SIZE, 91);
            let mut dst = pattern(SIZE, 13);
            let before = dst.clone();
            unsafe {
                memcpy(dst.as_mut_ptr().add(8), src.as_ptr().add(4), len);
            }
            assert_eq!(&dst[..8], &before[..8], "head clobbered, len={len}");
            assert_eq!(&dst[8 + len..], &before[8 + len..], "tail clobbered, len={len}");
        }
    }

    /// len == 0 must copy nothing and return dst.
    #[test]
    fn zero_length() {
        let src = pattern(16, 5);
        let mut dst = pattern(16, 9);
        let before = dst.clone();
        unsafe {
            let ret = memcpy(dst.as_mut_ptr(), src.as_ptr(), 0);
            assert_eq!(ret, dst.as_mut_ptr());
        }
        assert_eq!(dst, before);
    }
}
