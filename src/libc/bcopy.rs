//! bcopy — original: `FUN_08042cbc` @ 0x08042cbc (16 bytes; 47 call
//! sites, binary-scanned b/bl words).
//!
//! `mov r3,r0; mov r0,r1; mov r1,r3; b 0x08037e00` — swaps the first two
//! arguments and tail-branches the thunk at 0x08037e00 onto ROM memmove
//! @ 0x220000d4. The classic BSD `bcopy(src, dst, len)` argument-order
//! adapter over memmove.
//!
//! Deviation (house precedent, see libc/rom_string.rs's
//! `rom_memmove_keep_dst`): ROM 0x220000d4 mirrors the ported osos
//! memmove @ 0x080000d4, so the port calls the Rust [`memmove`] directly
//! instead of dispatching through the ROM thunk.

use crate::libc::memmove::memmove;

/// bcopy — original: `FUN_08042cbc` @ 0x08042cbc (16 bytes).
///
/// Overlap-safe copy of `len` bytes from `src` to `dst` — memmove with
/// the BSD `(src, dst)` argument order.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bcopy(src: *const u8, dst: *mut u8, len: usize) {
    memmove(dst, src, len);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn copies_with_src_dst_order() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        unsafe { bcopy(src.as_ptr(), dst.as_mut_ptr(), 5) };
        assert_eq!(dst, src);
    }

    #[test]
    fn overlapping_forward_copy_is_memmove_safe() {
        // Shift right within one buffer: dst overlaps src from above.
        let mut buf = vec![1u8, 2, 3, 4, 5, 0, 0];
        unsafe { bcopy(buf.as_ptr(), buf.as_mut_ptr().add(2), 5) };
        assert_eq!(buf, [1, 2, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn zero_length_copies_nothing() {
        let src = [9u8];
        let mut dst = [7u8];
        unsafe { bcopy(src.as_ptr(), dst.as_mut_ptr(), 0) };
        assert_eq!(dst, [7]);
    }
}
