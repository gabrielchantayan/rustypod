//! Zero an unwritten buffer suffix — original: `FUN_080a63e4` @ 0x080a63e4
//! (20 bytes; 11 plain `bl` call sites, binary-scanned B/BL words).
//!
//! The function accepts a buffer, its total capacity, and the number of bytes
//! already initialized. If `initialized < total`, it reaches the
//! already-ported [`super::bzero::bzero`] for the remaining range; otherwise
//! it returns without reading or writing memory. Its unsigned comparison means
//! an initialized length greater than capacity is also a no-op. A suffix whose
//! unsigned length has bit 31 set reaches bzero as a negative `i32`, where its
//! signed-length guard likewise makes it a no-op.
//!
//! Deliberate deviation: the volatile function-pointer load prevents LLVM from
//! inlining bzero, preserving this function as a distinct device hook target
//! rather than its stock direct tail branch. Observable writes and no-op cases
//! are unchanged.

// Volatile indirection preserves the bzero call boundary on device builds.
static BZERO: unsafe extern "C" fn(*mut u8, i32) = super::bzero::bzero;

/// Zero the portion of `dst[..total]` beginning at `initialized`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn zero_unwritten_suffix(dst: *mut u8, total: u32, initialized: u32) {
    if initialized < total {
        let bzero = core::ptr::read_volatile(core::ptr::addr_of!(BZERO));
        bzero(
            dst.add(initialized as usize),
            total.wrapping_sub(initialized) as i32,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn zeroes_only_the_unwritten_suffix() {
        let mut bytes = [0xa5u8; 10];
        bytes[1..4].copy_from_slice(&[0x11, 0x22, 0x33]);

        unsafe { zero_unwritten_suffix(bytes.as_mut_ptr().add(1), 7, 3) };

        assert_eq!(bytes, [0xa5, 0x11, 0x22, 0x33, 0, 0, 0, 0, 0xa5, 0xa5]);
    }

    #[test]
    fn initialized_length_at_or_past_capacity_is_a_noop() {
        let mut bytes = [0xa5u8; 8];

        unsafe { zero_unwritten_suffix(bytes.as_mut_ptr(), 5, 5) };
        unsafe { zero_unwritten_suffix(bytes.as_mut_ptr(), 5, 7) };

        assert_eq!(bytes, [0xa5; 8]);
    }

    #[test]
    fn signed_overflow_length_keeps_bzero_noop_behavior() {
        let mut bytes = [0xa5u8; 4];

        unsafe { zero_unwritten_suffix(bytes.as_mut_ptr(), u32::MAX, 0) };

        assert_eq!(bytes, [0xa5; 4]);
    }
}
