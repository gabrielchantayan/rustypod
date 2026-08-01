//! byte_copy — original: `FUN_080005fc` @ 0x080005fc (24 bytes).
//!
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/000/080005fc_FUN_080005fc.c`.
//! The six-instruction ARM leaf decrements `len`, tests it against -1, then
//! post-increments a byte load and store while the count remains nonzero. It
//! is therefore a forward, byte-at-a-time copy with a `void` return; zero
//! length performs no reads or writes. Overlap is deliberately not repaired:
//! it retains the original forward-copy behavior rather than becoming
//! `memmove`.
//!
//! Deviation: volatile byte accesses prevent LLVM from replacing the loop with
//! an unavailable freestanding memcpy intrinsic; for valid, nonvolatile
//! buffers this preserves the original reads and writes.

/// Copies `len` bytes from `src` to `dst` in ascending address order.
///
/// # Safety
/// For a nonzero `len`, both ranges must be valid for `len` bytes. The source
/// and destination may overlap, with the original's forward-copy semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_copy(mut dst: *mut u8, mut src: *const u8, mut len: u32) {
    while len != 0 {
        dst.write_volatile(src.read_volatile());
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_lengths_without_touching_guards() {
        const LEN: usize = 64;
        let mut src = [0u8; LEN + 16];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for len in 0..=LEN {
            let mut dst = [0xa5u8; LEN + 16];
            unsafe { byte_copy(dst.as_mut_ptr().add(4), src.as_ptr().add(8), len as u32) };
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
        }
    }

    #[test]
    fn overlap_retains_forward_copy_behavior() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        unsafe { byte_copy(bytes.as_mut_ptr().add(2), bytes.as_ptr(), 5) };
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }

    #[test]
    fn zero_length_dereferences_neither_pointer() {
        unsafe { byte_copy(core::ptr::null_mut(), core::ptr::null(), 0) };
    }
}
