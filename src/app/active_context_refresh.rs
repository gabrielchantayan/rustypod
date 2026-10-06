//! Active-context refresh — `FUN_0817ddd0` @ `0x0817ddd0`.
//!
//! Raw extent is [0x0817ddd0, 0x0817de08), 56 bytes; the next function
//! starts with an independently entered byte load. Two incoming plain BLs
//! (0x0817dcd0, 0x0817e038), no predicated incoming BLs. Four outgoing plain
//! BLs, no predicated outgoing BLs, followed by a tail B to 0x0817de8c.
//! Gate on state byte 3/4, then dispatch status, mapped code, scalar value,
//! and scaled level in that order. Preserve the original pointer across all
//! calls: downstream routines independently recheck state and may mutate it.
//! No target behavioral deviations. Unported scalar and scaled-level updates
//! remain calls to verified retail addresses; host execution of those updates
//! is deliberately unsupported rather than silently dropping side effects.

use crate::app::context_dispatch_mapped_code::context_dispatch_mapped_code;
use crate::app::state_status_dispatch::state_status_dispatch;
use crate::util::value_predicate::byte_is_three_or_four;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn refresh_scalar(context: *mut u8) {
    let update: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0817_dfacusize);
    update(context);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn refresh_scaled_level(context: *mut u8) {
    let update: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0817_de8cusize);
    update(context);
}

#[cfg(not(target_os = "none"))]
unsafe fn refresh_scalar(_context: *mut u8) {
    panic!("retail scalar update at 0x0817dfac is unavailable on host");
}

#[cfg(not(target_os = "none"))]
unsafe fn refresh_scaled_level(_context: *mut u8) {
    panic!("retail scaled-level update at 0x0817de8c is unavailable on host");
}

/// Requires a live retail context for active states; inactive states need only
/// one readable byte. NULL is not accepted, matching the original byte load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_context_refresh(context: *mut u8) {
    if byte_is_three_or_four(context) == 0 { return; }
    state_status_dispatch(context);
    context_dispatch_mapped_code(context.cast());
    refresh_scalar(context);
    refresh_scaled_level(context);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_inactive_state_needs_only_one_byte_and_is_unchanged() {
        for state in 0..=u8::MAX {
            if state == 3 || state == 4 { continue; }
            let mut byte = state;
            unsafe { active_context_refresh(&mut byte); }
            assert_eq!(byte, state);
        }
    }

    #[test]
    fn inactive_unaligned_context_preserves_neighbors() {
        for offset in 0..4 {
            let mut bytes = [0xa5; 7];
            bytes[offset] = 2;
            let expected = bytes;
            unsafe { active_context_refresh(bytes.as_mut_ptr().add(offset)); }
            assert_eq!(bytes, expected);
        }
    }
}
