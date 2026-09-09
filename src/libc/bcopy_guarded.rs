//! bcopy_guarded — original: `FUN_0805d0f4` @ 0x0805d0f4 (24 bytes; 15
//! call sites, binary-scanned b/bl words: 14 plain `bl` + 1 `blne` @
//! 0x0808d3ac, so one caller additionally gates the call on a NE
//! condition; the length guard below is unconditional inside the
//! callee).
//!
//! ```text
//! mov   r3, r0          ; save src
//! cmp   r2, #0          ; signed length check
//! mov   r0, r1          ; dst -> arg0
//! movge r1, r3          ; src -> arg1
//! bge   0x08037e00      ; tail: rom_memmove(dst, src, len)
//! bx    lr              ; len < 0: no-op
//! ```
//!
//! A BSD-argument-order memmove adapter (same swap as [`bcopy`]) with a
//! signed-length guard: when `len` is negative the function returns
//! without touching memory. 0x08037e00 is a `ldr pc,[pc,#-4]` veneer
//! onto ROM memmove @ 0x220000d4 (IRAM mirror of the ported osos
//! memmove @ 0x080000d4).
//!
//! Deviation (house precedent, see libc/rom_string.rs's
//! `rom_memmove_keep_dst` and libc/bcopy.rs): the port calls the Rust
//! [`memmove`] directly instead of dispatching through the ROM veneer.

use crate::libc::memmove::memmove;

/// bcopy_guarded — original: `FUN_0805d0f4` @ 0x0805d0f4 (24 bytes).
///
/// Overlap-safe copy of `len` bytes from `src` to `dst` — bcopy with a
/// signed length: negative `len` is a no-op.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bcopy_guarded(src: *const u8, dst: *mut u8, len: i32) {
    if len < 0 {
        return;
    }
    memmove(dst, src, len as usize);
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
        unsafe { bcopy_guarded(src.as_ptr(), dst.as_mut_ptr(), 5) };
        assert_eq!(dst, src);
    }

    #[test]
    fn overlapping_copy_is_memmove_safe() {
        // Shift right within one buffer: dst overlaps src from above.
        let mut buf = vec![1u8, 2, 3, 4, 5, 0, 0];
        unsafe { bcopy_guarded(buf.as_ptr(), buf.as_mut_ptr().add(2), 5) };
        assert_eq!(buf, [1, 2, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn zero_length_copies_nothing() {
        let src = [9u8];
        let mut dst = [7u8];
        unsafe { bcopy_guarded(src.as_ptr(), dst.as_mut_ptr(), 0) };
        assert_eq!(dst, [7]);
    }

    #[test]
    fn negative_length_is_a_noop() {
        // The guard is the whole point of this function: cmp r2,#0 /
        // bxlt lr — a negative length must not copy and must not
        // dereference either pointer.
        let src = [1u8, 2, 3];
        let mut dst = [7u8, 7, 7];
        unsafe {
            bcopy_guarded(src.as_ptr(), dst.as_mut_ptr(), -1);
            bcopy_guarded(src.as_ptr(), dst.as_mut_ptr(), i32::MIN);
        }
        assert_eq!(dst, [7, 7, 7]);
    }

    #[test]
    fn negative_length_tolerates_null_pointers() {
        // Guard fires before any memory access.
        unsafe { bcopy_guarded(core::ptr::null(), core::ptr::null_mut(), -42) };
    }
}
