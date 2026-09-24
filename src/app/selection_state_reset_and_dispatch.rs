//! Resets selection state and emits its completion dispatch.
//!
//! `selection_state_reset_and_dispatch` — original: `FUN_08114378` @
//! `0x08114378` (60 bytes, `0x08114378..0x081143b4`). Raw ARM decoding finds
//! the next function's `push` at `0x081143b4`; the final eight bytes of this
//! extent are the `0x000063d6` and `0x564d6178` literal-pool words. There are
//! three unconditional direct `bl` callers and no predicated direct `bl`
//! callers. The function itself has one unconditional direct `bl` to the
//! unported `FUN_08113a18` and no predicated direct `bl` calls.
//!
//! It writes -1 to the selection-state word at `+0x444`, invokes the retail
//! selection-state refresh helper, then tail-dispatches vtable slot `+0x58`
//! with `(self, 0x564d6178, 0x63d6)`. Deliberate deviations: Rust performs an
//! ordinary final call because the dispatch result is unobserved; host builds
//! use seams for the unported helper and target-width virtual function pointer.

#[cfg(target_os = "none")]
use core::mem;

const REFRESH_SELECTION_STATE_ADDRESS: usize = 0x0811_3a18;
const COMPLETION_ACTION: u32 = 0x564d_6178;
const COMPLETION_KIND: u32 = 0x0000_63d6;
const COMPLETION_SLOT_WORD: usize = 0x58 / 4;

type RefreshSelectionState = unsafe extern "C" fn(*mut u8);
type CompletionDispatch = unsafe extern "C" fn(*mut SelectionState, u32, u32);

/// Target-width prefix through the selection-state word.
///
/// The vtable is a `u32` so its offset remains the ARM target layout on hosts.
#[repr(C)]
pub struct SelectionState {
    vtable: u32,
    _unknown_04_443: [u8; 0x440],
    selection_state: i32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh_selection_state(_state: *mut u8) {
    panic!("install selection-state reset host refresh seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_completion_dispatch(_state: *mut SelectionState, _action: u32, _kind: u32) {
    panic!("install selection-state reset host completion-dispatch seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_RESET_REFRESH: RefreshSelectionState = missing_refresh_selection_state;
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_RESET_DISPATCH: CompletionDispatch = missing_completion_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn refresh_selection_state(state: *mut u8) {
    let refresh: RefreshSelectionState = unsafe { mem::transmute(REFRESH_SELECTION_STATE_ADDRESS) };
    unsafe { refresh(state); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn refresh_selection_state(state: *mut u8) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STATE_RESET_REFRESH))(state); }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_completion(state: *mut SelectionState) {
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).vtable)) };
    let address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(COMPLETION_SLOT_WORD)) };
    let dispatch: CompletionDispatch = unsafe { mem::transmute(address as usize) };
    unsafe { dispatch(state, COMPLETION_ACTION, COMPLETION_KIND); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_completion(state: *mut SelectionState) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STATE_RESET_DISPATCH))(state, COMPLETION_ACTION, COMPLETION_KIND); }
}

/// # Safety
/// `state`, the unported refresh helper, and its vtable completion slot must
/// satisfy the unchecked retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_reset_and_dispatch(state: *mut SelectionState) {
    unsafe {
        (*state).selection_state = -1;
        refresh_selection_state(state.cast());
        dispatch_completion(state);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut SELECTION_STATE_DURING_REFRESH: i32 = 0;
    static mut REFRESH_ARGUMENT: usize = 0;
    static mut DISPATCH_ARGUMENTS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn refresh_fixture(state: *mut u8) {
        unsafe {
            EVENTS[0] = 1;
            REFRESH_ARGUMENT = state as usize;
            SELECTION_STATE_DURING_REFRESH = (*(state as *mut SelectionState)).selection_state;
        }
    }

    unsafe extern "C" fn dispatch_fixture(state: *mut SelectionState, action: u32, kind: u32) {
        unsafe {
            EVENTS[1] = 2;
            DISPATCH_ARGUMENTS = (state as usize, action, kind);
        }
    }

    #[test]
    fn reset_precedes_refresh_and_completion_dispatch() {
        let _guard = TEST_LOCK.lock();
        let mut state = SelectionState { vtable: 0, _unknown_04_443: [0; 0x440], selection_state: 73 };
        unsafe {
            EVENTS = [0; 2];
            SELECTION_STATE_DURING_REFRESH = 0;
            REFRESH_ARGUMENT = 0;
            DISPATCH_ARGUMENTS = (0, 0, 0);
            SELECTION_STATE_RESET_REFRESH = refresh_fixture;
            SELECTION_STATE_RESET_DISPATCH = dispatch_fixture;
            selection_state_reset_and_dispatch(&mut state);
            SELECTION_STATE_RESET_REFRESH = missing_refresh_selection_state;
            SELECTION_STATE_RESET_DISPATCH = missing_completion_dispatch;
            assert_eq!(EVENTS, [1, 2]);
            assert_eq!(SELECTION_STATE_DURING_REFRESH, -1);
            assert_eq!(REFRESH_ARGUMENT, core::ptr::addr_of_mut!(state) as usize);
            assert_eq!(DISPATCH_ARGUMENTS, (core::ptr::addr_of_mut!(state) as usize, COMPLETION_ACTION, COMPLETION_KIND));
        }
        assert_eq!(state.selection_state, -1);
    }
}
