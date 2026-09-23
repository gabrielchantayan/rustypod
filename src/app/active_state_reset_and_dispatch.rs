//! Clears an active state and dispatches its completion action.
//!
//! `active_state_reset_and_dispatch` — original: `FUN_0815de58` @
//! `0x0815de58` (76 bytes, `0x0815de58..0x0815deac`). Raw ARM decoding finds
//! the next function's `push` at `0x0815deac`; the final eight bytes of this
//! extent are the `0x56d1` and `0x2a2a2a2a` literal-pool words. There are three
//! direct callers: one unconditional `bl` and two predicated `blne` calls.
//! The function itself has one predicated `blne` to `0x081d0fc4`.
//!
//! If the active byte at `+0x4c` is set, it clears the optional pending-state
//! object at `+0x48`, clears that byte, sets the completion byte at `+0x7c` to
//! three, then tail-dispatches vtable slot `+0x58` with `(self, 0x2a2a2a2a,
//! 0x56d1)`. Deliberate deviations: the ARM tail dispatch is an ordinary final
//! call in Rust, because its return value is unobserved; host builds use seams
//! for the unported direct call and target-width virtual function pointer.

#[cfg(target_os = "none")]
use core::mem;

const CLEAR_PENDING_STATE_ADDRESS: usize = 0x081d_0fc4;
const COMPLETION_ACTION: u32 = 0x2a2a_2a2a;
const COMPLETION_KIND: u32 = 0x56d1;
const COMPLETION_SLOT_WORD: usize = 0x58 / 4;

type ClearPendingState = unsafe extern "C" fn(*mut u8) -> u32;
type CompletionDispatch = unsafe extern "C" fn(*mut ActiveState, u32, u32);

/// Target-width prefix through the state completion byte.
///
/// Pointer fields remain `u32` so their offsets match ARM on 64-bit host tests.
#[repr(C)]
pub struct ActiveState {
    vtable: u32,
    _unknown_04_47: [u32; 17],
    pending_state: u32,
    active: u8,
    _unknown_4d_7b: [u8; 0x2f],
    completion_state: u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clear_pending_state(_state: *mut u8) -> u32 {
    panic!("install active-state reset host pending-state seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_completion_dispatch(_state: *mut ActiveState, _action: u32, _kind: u32) {
    panic!("install active-state reset host completion-dispatch seam")
}

#[cfg(not(target_os = "none"))]
pub static mut ACTIVE_STATE_RESET_CLEAR_PENDING: ClearPendingState = missing_clear_pending_state;
#[cfg(not(target_os = "none"))]
pub static mut ACTIVE_STATE_RESET_DISPATCH: CompletionDispatch = missing_completion_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_pending_state(state: *mut u8) {
    let clear: ClearPendingState = unsafe { mem::transmute(CLEAR_PENDING_STATE_ADDRESS) };
    unsafe { clear(state); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn clear_pending_state(state: *mut u8) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_STATE_RESET_CLEAR_PENDING))(state); }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_completion(state: *mut ActiveState) {
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).vtable)) };
    let address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(COMPLETION_SLOT_WORD)) };
    let dispatch: CompletionDispatch = unsafe { mem::transmute(address as usize) };
    unsafe { dispatch(state, COMPLETION_ACTION, COMPLETION_KIND); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_completion(state: *mut ActiveState) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_STATE_RESET_DISPATCH))(state, COMPLETION_ACTION, COMPLETION_KIND); }
}

/// # Safety
/// `state`, its optional pending-state pointer, and its vtable completion slot
/// must satisfy the unchecked retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_state_reset_and_dispatch(state: *mut ActiveState) {
    unsafe {
        if (*state).active == 0 {
            return;
        }
        if (*state).pending_state != 0 {
            clear_pending_state((*state).pending_state as *mut u8);
        }
        (*state).active = 0;
        (*state).completion_state = 3;
        dispatch_completion(state);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CLEAR_ARGUMENT: usize = 0;
    static mut DISPATCH_ARGUMENTS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn clear_fixture(state: *mut u8) -> u32 {
        unsafe { CLEAR_ARGUMENT = state as usize; }
        1
    }

    unsafe extern "C" fn dispatch_fixture(state: *mut ActiveState, action: u32, kind: u32) {
        unsafe { DISPATCH_ARGUMENTS = (state as usize, action, kind); }
    }

    fn fixture(active: u8, pending_state: u32) -> ActiveState {
        ActiveState { vtable: 0, _unknown_04_47: [0; 17], pending_state, active, _unknown_4d_7b: [0; 0x2f], completion_state: 0 }
    }

    #[test]
    fn inactive_state_is_unchanged_and_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        let mut state = fixture(0, 0x1234_5678);
        state.completion_state = 0xa5;
        unsafe {
            ACTIVE_STATE_RESET_CLEAR_PENDING = missing_clear_pending_state;
            ACTIVE_STATE_RESET_DISPATCH = missing_completion_dispatch;
            active_state_reset_and_dispatch(&mut state);
        }
        assert_eq!(state.active, 0);
        assert_eq!(state.pending_state, 0x1234_5678);
        assert_eq!(state.completion_state, 0xa5);
    }

    #[test]
    fn active_state_clears_pending_then_dispatches_completion() {
        let _guard = TEST_LOCK.lock();
        let mut state = fixture(1, 0x1234_5678);
        unsafe {
            CLEAR_ARGUMENT = 0;
            DISPATCH_ARGUMENTS = (0, 0, 0);
            ACTIVE_STATE_RESET_CLEAR_PENDING = clear_fixture;
            ACTIVE_STATE_RESET_DISPATCH = dispatch_fixture;
            active_state_reset_and_dispatch(&mut state);
            ACTIVE_STATE_RESET_CLEAR_PENDING = missing_clear_pending_state;
            ACTIVE_STATE_RESET_DISPATCH = missing_completion_dispatch;
            assert_eq!(CLEAR_ARGUMENT, 0x1234_5678);
            assert_eq!(DISPATCH_ARGUMENTS, (core::ptr::addr_of_mut!(state) as usize, COMPLETION_ACTION, COMPLETION_KIND));
        }
        assert_eq!(state.active, 0);
        assert_eq!(state.completion_state, 3);
    }

    #[test]
    fn active_state_without_pending_state_skips_clear_seam() {
        let _guard = TEST_LOCK.lock();
        let mut state = fixture(1, 0);
        unsafe {
            DISPATCH_ARGUMENTS = (0, 0, 0);
            ACTIVE_STATE_RESET_CLEAR_PENDING = missing_clear_pending_state;
            ACTIVE_STATE_RESET_DISPATCH = dispatch_fixture;
            active_state_reset_and_dispatch(&mut state);
            ACTIVE_STATE_RESET_DISPATCH = missing_completion_dispatch;
        }
        assert_eq!(state.active, 0);
        assert_eq!(state.completion_state, 3);
    }
}
