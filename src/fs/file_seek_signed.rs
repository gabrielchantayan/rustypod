//! Signed absolute file seek — `FUN_08161a80` @ `0x08161a80`.
//! True extent: 36 bytes (`0x08161a80..0x08161aa4`); the next function
//! starts with a handle load and tail branch. Raw A32 decoding verifies two
//! inbound plain BLs (0x08236a4c, 0x08236bd4), zero predicated inbound BLs,
//! and one outbound plain BL to the ported file seek at 0x082787b8.
//!
//! Loads the outer handle's first pointer, sign-extends the i32 offset into
//! the callee's low/high words, supplies absolute origin zero, and returns
//! the seek status unchanged. The unused r1 ABI word receives the sign word.
//! No deliberate algorithm deviations. Native host pointers expand the
//! outer pointer field; the target field remains one aligned 32-bit word.
//! Ghidra's void return is corrected: ARM preserves r0 and callers test it.

use core::ffi::c_void;

/// # Safety
/// `handle` must point to a readable file pointer accepted by
/// [`crate::ft::system::ft_platform_file_seek`]. Neither pointer is null-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn file_seek_signed_absolute(
    handle: *const *mut c_void,
    offset: i32,
) -> i32 {
    let sign = (offset >> 31) as u32;
    crate::ft::system::ft_platform_file_seek(handle.read(), sign, offset as u32, sign, 0)
}
