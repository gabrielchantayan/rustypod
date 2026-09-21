//! null_guarded_forward_byte_copy — original: `FUN_08369bc0` @ 0x08369bc0
//! (44 bytes; 3 inbound call sites, binary-scanned aligned ARM B/BL words:
//! 3 plain `bl` at 0x0808c5f8, 0x08098f50, and 0x080b5220; 0 predicated
//! `bl`).
//!
//! Raw osos.dec establishes the body from `cmp r0,#0` at 0x08369bc0 through
//! `bx lr` at 0x08369be8; the next independently linked function begins with
//! `ldr r0,[pc,#20]` at 0x08369bec. The function first returns status 9 when
//! either destination or source is NULL. Otherwise it decrements the unsigned
//! byte count, copying one byte from source to destination and advancing both
//! pointers while the decremented count is not `u32::MAX`; it returns status 0.
//! This gives forward-copy overlap behavior and makes zero length a no-op.
//!
//! Deliberate deviation: volatile byte accesses prevent LLVM from replacing
//! the loop with an unavailable freestanding memcpy intrinsic. The raw loop's
//! unsigned wrapping counter semantics and observable byte order are retained.

/// Copies `len` bytes from `src` to `dst` in ascending address order.
///
/// Returns 9 if either pointer is NULL; otherwise returns 0, including for a
/// zero-length copy.
///
/// # Safety
/// When `len` is nonzero and neither pointer is NULL, both ranges must be
/// valid for `len` bytes. Overlap retains the original forward-copy behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn null_guarded_forward_byte_copy(
    mut dst: *mut u8,
    mut src: *const u8,
    mut len: u32,
) -> u32 {
    if dst.is_null() || src.is_null() {
        return 9;
    }

    while len != 0 {
        dst.write_volatile(src.read_volatile());
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn copies_nonzero_range_and_returns_success() {
        let src = [0x10u8, 0x20, 0x30, 0x40];
        let mut dst = [0u8; 4];

        assert_eq!(unsafe { null_guarded_forward_byte_copy(dst.as_mut_ptr(), src.as_ptr(), 4) }, 0);
        assert_eq!(dst, src);
    }

    #[test]
    fn zero_length_leaves_valid_buffers_untouched() {
        let src = [0x10u8];
        let mut dst = [0xa5u8];

        assert_eq!(unsafe { null_guarded_forward_byte_copy(dst.as_mut_ptr(), src.as_ptr(), 0) }, 0);
        assert_eq!(dst, [0xa5]);
    }

    #[test]
    fn null_pointers_fail_before_any_copy() {
        let src = [0x10u8];
        let mut dst = [0xa5u8];

        assert_eq!(unsafe { null_guarded_forward_byte_copy(core::ptr::null_mut(), src.as_ptr(), 1) }, 9);
        assert_eq!(unsafe { null_guarded_forward_byte_copy(dst.as_mut_ptr(), core::ptr::null(), 1) }, 9);
        assert_eq!(dst, [0xa5]);
    }

    #[test]
    fn overlap_copies_forward_like_the_retail_loop() {
        let mut bytes = [1u8, 2, 3, 4, 5];

        assert_eq!(unsafe { null_guarded_forward_byte_copy(bytes.as_mut_ptr().add(1), bytes.as_ptr(), 4) }, 0);
        assert_eq!(bytes, [1, 1, 1, 1, 1]);
    }
}
