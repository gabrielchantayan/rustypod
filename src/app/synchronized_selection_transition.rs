//! `synchronized_selection_transition` — original: `FUN_08161000` @
//! 0x08161000 (52 bytes).
//!
//! Raw `osos.dec` establishes the exact 52-byte extent, 0x08161000 through
//! 0x08161030; 0x08161034 starts the next separately linked function. The
//! body has three plain direct `bl` instructions: mutex_lock @ 0x0807f5c4,
//! the unresolved transition worker @ 0x08161190, and mutex_unlock @
//! 0x0807f6a0. Raw ARM branch decoding finds four inbound direct calls: three
//! plain `bl` and one predicated `blne` (@ 0x0825aa18).
//!
//! Algorithm: lock the state mutex at +0x10, run the requested transition,
//! unlock, then return the worker result. Deliberate deviation: the worker's
//! semantic identity is not recovered, so it is a role-based host seam and a
//! verified direct call on target; the target layout uses 32-bit words while
//! the host widens the mutex cell pointer.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex as KernelMutex};

const RETAIL_SELECTION_TRANSITION: usize = 0x0816_1190;

#[repr(C)]
pub struct SelectionTransitionState {
    pub unresolved_00_to_0c: [u32; 4],
    pub mutex: KernelMutex,
}

pub type SelectionTransitionWorker = unsafe extern "C" fn(*mut SelectionTransitionState, u32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct SelectionTransitionOps {
    pub transition: SelectionTransitionWorker,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_transition(_state: *mut SelectionTransitionState, _requested: u32) -> u32 {
    panic!("install selection-transition host operations before dispatching")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_TRANSITION_OPS: SelectionTransitionOps = SelectionTransitionOps {
    transition: missing_selection_transition,
};

#[inline(always)]
unsafe fn transition(state: *mut SelectionTransitionState, requested: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let worker: SelectionTransitionWorker = unsafe { core::mem::transmute(RETAIL_SELECTION_TRANSITION) };
        unsafe { worker(state, requested) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let worker = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_TRANSITION_OPS.transition)) };
        unsafe { worker(state, requested) }
    }
}

/// Runs a requested state transition while holding the state-owned mutex.
///
/// # Safety
///
/// `state` must point to the target-layout state object and remain valid for
/// the lock, transition worker, and unlock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn synchronized_selection_transition(state: *mut SelectionTransitionState, requested: u32) -> u32 {
    unsafe {
        mutex_lock(core::ptr::addr_of_mut!((*state).mutex));
        let result = transition(state, requested);
        mutex_unlock(core::ptr::addr_of_mut!((*state).mutex));
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_STATE: *mut SelectionTransitionState = core::ptr::null_mut();
    static mut SEEN_REQUEST: u32 = 0;

    unsafe extern "C" fn record_transition(state: *mut SelectionTransitionState, requested: u32) -> u32 {
        unsafe {
            SEEN_STATE = state;
            SEEN_REQUEST = requested;
        }
        requested ^ 0xa5a5_5a5a
    }

    #[test]
    fn locks_dispatches_and_returns_worker_result_for_all_request_values() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            SELECTION_TRANSITION_OPS = SelectionTransitionOps { transition: record_transition };
        }
        let mut state = SelectionTransitionState {
            unresolved_00_to_0c: [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444],
            mutex: KernelMutex { sem_cell: core::ptr::null_mut(), unused: 0xfeed_face },
        };
        for requested in [0, 1, 2, u32::MAX] {
            unsafe {
                SEEN_STATE = core::ptr::null_mut();
                SEEN_REQUEST = 0;
                assert_eq!(synchronized_selection_transition(&mut state, requested), requested ^ 0xa5a5_5a5a);
                assert_eq!(SEEN_STATE, core::ptr::addr_of_mut!(state));
                assert_eq!(SEEN_REQUEST, requested);
            }
        }
        assert_eq!(state.unresolved_00_to_0c, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);
        assert_eq!(state.mutex.unused, 0xfeed_face);
    }
}
