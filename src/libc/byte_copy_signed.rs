//! byte_copy_signed — original: `FUN_080e7ebc` @ 0x080e7ebc (24 bytes).
//!
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/008/080e7ebc_FUN_080e7ebc.c`.
//! Call count verified by decoding every BL word in osos.dec: 15 sites, all
//! plain `bl` (no predicated forms), e.g. the "Finder"/"System"/"Desktop DB"
//! record writers near 0x080aab00 and 0x080b4550.
//!
//! The six-instruction ARM leaf is a forward, byte-at-a-time copy whose
//! argument order is (src, dst, len) — reversed relative to the libc
//! convention — and whose loop guard is SIGNED:
//!
//! ```text
//! loop: subs    r3, r2, #0      @ test len as signed
//!       ldrbgt  r3, [r0], #1    @ byte = *src++
//!       sub     r2, r2, #1      @ len-- (unconditional, flags preserved)
//!       strbgt  r3, [r1], #1    @ *dst++ = byte
//!       bgt     loop
//!       bx      lr
//! ```
//!
//! While `len > 0` (signed) it copies one byte per iteration; a zero or
//! negative `len` touches neither pointer (the unconditional decrement of the
//! caller-saved r2 is unobservable). Return is void; the advanced src/dst in
//! r0/r1 are not a defined result. Overlap is not repaired: the original's
//! forward-copy behavior is retained rather than becoming memmove.
//!
//! Deviation: volatile byte accesses prevent LLVM from replacing the loop
//! with an unavailable freestanding memcpy intrinsic; for valid, nonvolatile
//! buffers this preserves the original reads and writes. Unlike the adjacent
//! `byte_copy` (0x080005fc, `(dst, src, u32)` with a `len != 0` guard), this
//! one takes `(src, dst, i32)` and treats any negative length as a no-op.

/// Copies `len` bytes from `src` to `dst` in ascending address order.
///
/// The copy runs only while `len > 0` as a signed value; `len <= 0` performs
/// no reads or writes.
///
/// # Safety
/// For a positive `len`, both ranges must be valid for `len` bytes. The
/// source and destination may overlap, with the original's forward-copy
/// semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_copy_signed(mut src: *const u8, mut dst: *mut u8, mut len: i32) {
    while len > 0 {
        dst.write_volatile(src.read_volatile());
        src = src.add(1);
        dst = dst.add(1);
        len -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slice model of the ARM leaf, deliberately separate from the
    /// raw-pointer loop: signed guard, forward order.
    fn reference(src: &[u8], dst: &mut [u8], len: i32) {
        let mut i = 0usize;
        let mut remaining = len;
        while remaining > 0 {
            dst[i] = src[i];
            i += 1;
            remaining -= 1;
        }
    }

    #[test]
    fn copies_all_lengths_without_touching_guards() {
        const LEN: usize = 64;
        let mut src = [0u8; LEN + 16];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for len in 0..=LEN {
            let mut dst = [0xa5u8; LEN + 16];
            unsafe { byte_copy_signed(src.as_ptr().add(8), dst.as_mut_ptr().add(4), len as i32) };
            assert_eq!(&dst[..4], &[0xa5; 4], "head guard, len={len}");
            assert_eq!(
                &dst[4..4 + len],
                &src[8..8 + len],
                "copied bytes, len={len}"
            );
            assert!(
                dst[4 + len..].iter().all(|&byte| byte == 0xa5),
                "tail guard, len={len}"
            );

            let mut model_dst = [0xa5u8; LEN + 16];
            reference(&src[8..8 + len], &mut model_dst[4..4 + len], len as i32);
            assert_eq!(&dst[..], &model_dst[..], "reference model, len={len}");
        }
    }

    #[test]
    fn nonpositive_length_dereferences_neither_pointer() {
        unsafe {
            byte_copy_signed(core::ptr::null(), core::ptr::null_mut(), 0);
            byte_copy_signed(core::ptr::null(), core::ptr::null_mut(), -1);
            byte_copy_signed(core::ptr::null(), core::ptr::null_mut(), i32::MIN);
        }
    }

    #[test]
    fn overlap_retains_forward_copy_behavior() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        unsafe { byte_copy_signed(bytes.as_ptr(), bytes.as_mut_ptr().add(2), 5) };
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }
}
