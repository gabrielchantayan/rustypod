//! forward_byte_copy — original: `FUN_082c4f38` @ 0x082c4f38 (24 bytes).
//!
//! Raw extent verified from `osos.dec`: this six-instruction leaf ends at
//! 0x082c4f4c (`bx lr`); the independently linked next function opens at
//! 0x082c4f50. Decoding every ARM B/BL word in the image finds 13 direct call
//! sites, all plain unconditional `bl` instructions (none predicated).
//!
//! The ARM loop subtracts one from `len`, uses `cmn r2,#1` as its zero test,
//! then post-increments one byte from `src` to `dst` while `len` remains
//! nonzero. It is therefore a forward byte-at-a-time copy with a void return:
//! zero length does not dereference either pointer. Overlap deliberately keeps
//! the load-then-store forward propagation rather than becoming `memmove`.
//!
//! Deviation: volatile byte accesses stop LLVM's loop-idiom pass replacing the
//! retail loop with a freestanding memcpy intrinsic. The target-only unique
//! section keeps this separately linked exported leaf distinct from the
//! byte-identical `byte_copy` port at 0x080005fc.

/// Copies `len` bytes from `src` to `dst` in ascending address order.
///
/// # Safety
/// For nonzero `len`, both ranges must be valid for `len` bytes. The ranges
/// may overlap, with the original's forward-copy semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.forward_byte_copy_082c4f38")]
#[inline(never)]
pub unsafe extern "C" fn forward_byte_copy(mut dst: *mut u8, mut src: *const u8, mut len: u32) {
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
    fn copies_every_length_without_touching_guards() {
        const LEN: usize = 64;
        let mut src = [0u8; LEN + 16];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for len in 0..=LEN {
            let mut dst = [0xa5u8; LEN + 16];
            unsafe { forward_byte_copy(dst.as_mut_ptr().add(4), src.as_ptr().add(8), len as u32) };
            assert_eq!(&dst[..4], &[0xa5; 4], "head guard, len={len}");
            assert_eq!(&dst[4..4 + len], &src[8..8 + len], "copied bytes, len={len}");
            assert!(
                dst[4 + len..].iter().all(|&byte| byte == 0xa5),
                "tail guard, len={len}"
            );
        }
    }

    #[test]
    fn overlap_retains_forward_copy_behavior() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        unsafe { forward_byte_copy(bytes.as_mut_ptr().add(2), bytes.as_ptr(), 5) };
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }

    #[test]
    fn zero_length_dereferences_neither_pointer() {
        unsafe { forward_byte_copy(core::ptr::null_mut(), core::ptr::null(), 0) };
    }
}
