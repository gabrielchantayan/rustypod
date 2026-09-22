//! Resets an owner's pending shared-cell handle.
//!
//! `owner_pending_handle_reset` — retailOS `FUN_0820840c` @ `0x0820840c`
//! (56 bytes; two incoming plain `bl` call sites at 0x08208258 and 0x08208378,
//! zero predicated `bl` forms). Raw instructions span 0x0820840c..0x08208440;
//! the next distinct `push` prologue begins at 0x08208444. The body has four
//! unconditional outbound `bl` instructions: the still-unidentified reset at
//! 0x081fcae4, then `shared_cell_construct`, `shared_cell_assign`, and
//! `shared_cell_release`.
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

#[cfg(target_os = "none")]
use core::mem;
#[cfg(not(target_os = "none"))]
use core::ptr;

type OwnerStateReset = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
const OWNER_STATE_RESET_ADDRESS: usize = 0x081f_cae4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_state_reset(state: *mut u8) {
    let reset: OwnerStateReset = unsafe { mem::transmute(OWNER_STATE_RESET_ADDRESS) };
    unsafe { reset(state) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_owner_state_reset(_state: *mut u8) {}

/// Host replacement for the unported state-reset callee at 0x081fcae4.
#[cfg(not(target_os = "none"))]
static mut HOST_OWNER_STATE_RESET: OwnerStateReset = unavailable_owner_state_reset;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn owner_state_reset(state: *mut u8) {
    let reset = unsafe { ptr::read_volatile(ptr::addr_of!(HOST_OWNER_STATE_RESET)) };
    unsafe { reset(state) };
}

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

    static HOST_OWNER_STATE_RESET_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OBSERVED_STATE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_owner_state_reset(state: *mut u8) {
        unsafe {
            OBSERVED_STATE = state;
            (state.add(0x10) as *mut u32).write(0x1234_5678);
        }
    }

    #[test]
    fn resets_state_and_clears_the_target_width_pending_words() {
        let _lock = HOST_OWNER_STATE_RESET_LOCK.lock();
        let mut state = [0xa5a5_a5a5u32; 0x2c8 / 4];
        unsafe {
            let previous = HOST_OWNER_STATE_RESET;
            HOST_OWNER_STATE_RESET = recording_owner_state_reset;
            OBSERVED_STATE = core::ptr::null_mut();
            owner_pending_handle_reset(state.as_mut_ptr().cast());
            HOST_OWNER_STATE_RESET = previous;
        }

        assert_eq!(unsafe { OBSERVED_STATE }, state.as_mut_ptr().cast());
        assert_eq!(state[0x10 / 4], 0x1234_5678);
        assert_eq!(state[0x2c0 / 4], 0);
        assert_eq!(state[0x2c4 / 4], 0);
        assert_eq!(state[0x2bc / 4], 0xa5a5_a5a5);
    }
}
