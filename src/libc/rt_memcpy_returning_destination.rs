//! rt_memcpy_returning_destination — original: `FUN_082a789c` @ 0x082a789c (20 bytes).
//!
//! Raw `osos.dec` words establish the complete five-instruction A32 body from
//! 0x082a789c through 0x082a78ac; `push {r4, lr}` at 0x082a78b0 begins the
//! next independently entered function. Whole-image A32 decoding finds three
//! inbound unconditional `BL` instructions (0x08134b6c, 0x081de8a8, and
//! 0x081e8b74), no predicated `BL` instructions, and one outbound
//! unconditional `BL` at 0x082a78a4 to the 0x08037db0 IRAM veneer for
//! `__rt_memcpy`.
//!
//! The wrapper preserves its destination in `r4`, invokes `__rt_memcpy` with
//! the original three arguments, and returns the saved destination regardless
//! of the callee's `r0` result. Deliberate deviation: the existing Rust
//! `__rt_memcpy` implementation is called directly instead of through the
//! retailOS IRAM veneer; this preserves the wrapper's copy and return contract.

/// Copies `len` bytes using the retailOS `__rt_memcpy` runtime and returns `dst`.
///
/// # Safety
/// `dst` and `src` must be valid for `len` bytes and must not overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rt_memcpy_returning_destination_082a789c")]
#[inline(never)]
pub unsafe extern "C" fn rt_memcpy_returning_destination(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> *mut u8 {
    let returned_dst = core::ptr::read_volatile(core::ptr::addr_of!(dst));
    crate::libc::rt_memcpy::__rt_memcpy(dst, src, len);
    core::ptr::read_volatile(core::ptr::addr_of!(returned_dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_real_edge_lengths_and_returns_destination() {
        for len in [0, 1, 3, 4, 31, 32, 33, 64] {
            let mut source = [0u8; 72];
            let mut destination = [0xa5u8; 72];
            for (index, byte) in source.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
            }

            let dst = unsafe { destination.as_mut_ptr().add(4) };
            let src = unsafe { source.as_ptr().add(4) };
            let returned = unsafe { rt_memcpy_returning_destination(dst, src, len) };

            assert_eq!(returned, dst, "len={len}");
            assert_eq!(&destination[4..4 + len], &source[4..4 + len], "len={len}");
            assert!(destination[..4].iter().all(|&byte| byte == 0xa5), "prefix, len={len}");
            assert!(destination[4 + len..].iter().all(|&byte| byte == 0xa5), "suffix, len={len}");
        }
    }

    #[test]
    fn zero_length_forwards_without_dereferencing_pointers() {
        let returned = unsafe {
            rt_memcpy_returning_destination(core::ptr::null_mut(), core::ptr::null(), 0)
        };
        assert!(returned.is_null());
    }
}
