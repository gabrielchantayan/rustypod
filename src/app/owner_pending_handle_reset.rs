//! Resets an owner's pending shared-cell handle.
//!
//! `owner_pending_handle_reset` — retailOS `FUN_0820840c` @ `0x0820840c`
//! (56 bytes; two incoming plain `bl` call sites at 0x08208258 and 0x08208378,
//! zero predicated `bl` forms). Raw instructions span 0x0820840c..0x08208440;
//! the next distinct `push` prologue begins at 0x08208444. The body has four
//! unconditional outbound `bl` instructions: `owner_state_reset`, then
//! `shared_cell_construct`, `shared_cell_assign`, and `shared_cell_release`.
//!
//! Algorithm: reset the related owner state, clear word +0x2c0, construct an
//! empty temporary shared-cell handle, assign it to the +0x2c4 slot, then
//! release the temporary.
//!
//! Deliberate deviation: on hosts the target's four-byte +0x2c4 handle slot
//! cannot safely hold a native-width `SharedCell` pointer at that offset. The
//! empty construction/assignment/release sequence is therefore represented by
//! its observed result (a zero u32 slot); target builds call the ported helpers.

#[cfg(test)]
extern crate std;

#[cfg(target_os = "none")]
use crate::cxx::shared_cell::{shared_cell_assign, shared_cell_construct, shared_cell_release, SharedCell};

use crate::app::owner_state_reset::owner_state_reset;

/// Resets the owner's pending shared-cell handle.
///
/// # Safety
/// `state` must name writable owner storage through offset 0x2c7. Firmware
/// callers additionally require the embedded +0x2c4 slot to be a valid
/// shared-cell slot for the ported helper calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_pending_handle_reset(state: *mut u8) {
    unsafe { owner_state_reset(state) };
    unsafe { (state.add(0x2c0) as *mut u32).write(0) };

    #[cfg(target_os = "none")]
    {
        let mut empty: *mut SharedCell = core::ptr::null_mut();
        unsafe { shared_cell_construct(&mut empty, core::ptr::null_mut()) };
        unsafe { shared_cell_assign(state.add(0x2c4).cast(), &mut empty) };
        unsafe { shared_cell_release(&mut empty) };
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        (state.add(0x2c4) as *mut u32).write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_state_and_clears_the_target_width_pending_words() {
        let mut state = [0xa5a5_a5a5u32; 0x2c8 / 4];
        state[0x2b0 / 4] = 0;
        unsafe { owner_pending_handle_reset(state.as_mut_ptr().cast()); }

        assert_eq!(state[0x2b0 / 4], 0);
        assert_eq!(state[0x2b4 / 4], u32::MAX);
        assert_eq!(state[0x2b8 / 4], 0);
        assert_eq!(state[0x2c0 / 4], 0);
        assert_eq!(state[0x2c4 / 4], 0);
        assert_eq!(state[0x2bc / 4], 0xa5a5_a5a5);
    }
}
