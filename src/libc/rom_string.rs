//! Ports of the three tiny ROM-string veneers of the ADS library region —
//! the wrappers osos uses to reach the mask ROM's copies of memcpy/memmove
//! while preserving the C return-value contract:
//!
//! - `rom_memcpy_keep_dst` — original @ 0x0803357c (12 bytes):
//!   `stmdb sp!, {r0, lr}; bl 0x08037dd0; ldmia sp!, {r0, pc}`. The thunk
//!   @ 0x08037dd0 (`ldr pc, [pc, #-4]; .word 0x22000020`) jumps to the
//!   ROM `__rt_memcpy` @ 0x22000020, which advances r0 past the copied
//!   bytes; the push/pop restores and returns the original `dst`.
//! - `rom_memmove_keep_dst` — original @ 0x08035680 (12 bytes, unlisted
//!   in functions.csv — folded into the preceding raise range): the same
//!   push/pop shape around the thunk @ 0x08037dd8 (`.word 0x220000d4`,
//!   the ROM memmove).
//! - `memmove_u16` — original @ 0x08033588 (8 bytes):
//!   `mov r2, r2, lsl #1; b 0x08035680` — scales a u16 element count to
//!   bytes and tail-branches into `rom_memmove_keep_dst`; i.e. a
//!   wide-char (u16) element memmove returning `dst`. Caller in osos:
//!   the wide-string helper @ 0x083d9a2c.
//!
//! ROM boundary: the mask ROM at 0x22000000 is the link-order mirror of
//! the start of osos (ROM 0x22000XXX == osos 0x08000XXX, verified in
//! kernel/thunks.rs / task_lock.rs), so the ROM routines these veneers
//! reach ARE the already-ported osos copies: ROM `__rt_memcpy`
//! @ 0x22000020 == osos 0x08000020 (`libc::rt_memcpy::__rt_memcpy`) and
//! ROM memmove @ 0x220000d4 == osos 0x080000d4 (`libc::memmove::memmove`).
//! The port therefore calls the Rust ports directly — no dispatch-table
//! hook is needed at this ROM boundary because the ROM code is not
//! missing, it is byte-identical mirrored code that is already ported and
//! host-testable (deviation from the literal thunk jump, same machine
//! behavior).
//!
//! Deviation: the Rust `__rt_memcpy`/`memmove` ports already return the
//! original `dst` (the ROM copies clobber r0), so the veneers' push/pop
//! dance reduces to returning the callee's result.

use crate::libc::memmove::memmove;
use crate::libc::rt_memcpy::__rt_memcpy;

/// rom_memcpy_keep_dst — original @ 0x0803357c (12 bytes).
///
/// memcpy via the ROM `__rt_memcpy` @ 0x22000020 (== ported osos
/// 0x08000020), returning the original `dst` (the ROM routine advances
/// r0; the original veneer restores it from the stack).
///
/// # Safety
/// `dst` and `src` must be valid for `len` bytes and must not overlap
/// (memcpy contract; the funnel path may also read up to a word past the
/// source range, like the original).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rom_memcpy_keep_dst(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    __rt_memcpy(dst, src, len)
}

/// rom_memmove_keep_dst — original @ 0x08035680 (12 bytes; unlisted in
/// functions.csv).
///
/// memmove via the ROM memmove @ 0x220000d4 (== ported osos 0x080000d4),
/// returning the original `dst`.
///
/// # Safety
/// `dst` and `src` must be valid for `len` bytes (overlap allowed).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rom_memmove_keep_dst(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    memmove(dst, src, len)
}

/// memmove_u16 — original @ 0x08033588 (8 bytes).
///
/// Overlapping move of `count` u16 elements: scales the element count to
/// bytes (`mov r2, r2, lsl #1` — wrapping, like the 32-bit shift) and
/// tail-branches into `rom_memmove_keep_dst`. Returns `dst`.
///
/// # Safety
/// `dst` and `src` must be valid for `count` u16 elements (overlap
/// allowed).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memmove_u16(dst: *mut u16, src: *const u16, count: usize) -> *mut u16 {
    rom_memmove_keep_dst(dst as *mut u8, src as *const u8, count.wrapping_shl(1)) as *mut u16
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Padding so the memcpy funnel path's word-overread stays in bounds
    /// (see PORTING.md rule 3).
    const PAD: usize = 4;

    #[test]
    fn rom_memcpy_copies_and_returns_dst() {
        for misalign in 0..4usize {
            for len in 0..48usize {
                let src: Vec<u8> = (0..len as u8 + PAD as u8).collect();
                let mut dst = std::vec![0xAAu8; len + misalign + PAD];
                let d = unsafe { dst.as_mut_ptr().add(misalign) };
                let ret = unsafe { rom_memcpy_keep_dst(d, src.as_ptr(), len) };
                assert_eq!(ret, d, "must return the original dst");
                assert_eq!(&dst[misalign..misalign + len], &src[..len]);
                assert!(dst[..misalign].iter().all(|&b| b == 0xAA));
            }
        }
    }

    #[test]
    fn rom_memmove_handles_overlap_and_returns_dst() {
        // Forward overlap (dst inside src range) forces the backward path.
        let mut buf: Vec<u8> = (0..32).collect();
        let expect: Vec<u8> = buf.clone();
        let ret = unsafe { rom_memmove_keep_dst(buf.as_mut_ptr().add(4), buf.as_ptr(), 20) };
        assert_eq!(ret, unsafe { buf.as_mut_ptr().add(4) });
        assert_eq!(&buf[4..24], &expect[..20]);
    }

    #[test]
    fn memmove_u16_scales_element_count_to_bytes() {
        let src: [u16; 6] = [0x1122, 0x3344, 0x5566, 0x7788, 0x99aa, 0xbbcc];
        let mut dst = [0u16; 6];
        let ret = unsafe { memmove_u16(dst.as_mut_ptr(), src.as_ptr(), 6) };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst, src);
        // Zero elements: nothing written.
        let mut untouched = [0xDEADu16; 2];
        unsafe { memmove_u16(untouched.as_mut_ptr(), src.as_ptr(), 0) };
        assert_eq!(untouched, [0xDEAD, 0xDEAD]);
    }

    #[test]
    fn memmove_u16_overlapping_shift_by_one_element() {
        // Classic overlapped shift: matches a reference copy via std.
        let mut buf: [u16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let expect: [u16; 8] = [1, 1, 2, 3, 4, 5, 6, 8];
        unsafe { memmove_u16(buf.as_mut_ptr().add(1), buf.as_ptr(), 6) };
        assert_eq!(buf, expect);
    }
}
