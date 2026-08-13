//! Final state dispatch — `FUN_08005320` @ 0x08005320 (40 bytes).
//!
//! The routine reads a state record's active-state byte at +0x20. When that
//! state is 2, it first restores the byte at +0x21 through the already ported
//! state-transition helper. It then reloads the active state and terminally
//! dispatches it through the retailOS thunk at 0x082aad24. The target thunk is
//! modeled as diverging: control never returns to this helper after dispatch.

use super::state_transition::set_state_and_notify;

/// Record offset holding the active state byte.
const CURRENT_STATE: usize = 0x20;
/// Record offset holding the state supplied to the transition helper.
const DEFERRED_STATE: usize = 0x21;
/// State requiring the deferred-state transition before terminal dispatch.
const DEFERRED_STATE_PENDING: u8 = 2;
/// Terminal thunk reached by the original dispatch path.
const ROM_TERMINAL_STATE_CALLBACK: usize = 0x082a_ad24;

/// ABI of the original terminal state callback on the firmware target.
#[cfg(not(test))]
pub type TerminalStateCallback = unsafe fn(state: u8) -> !;

/// Host-test callback ABI. The target callback is terminal; returning test
/// recorders let host tests inspect the completed dispatch safely.
#[cfg(test)]
pub type TerminalStateCallback = unsafe fn(state: u8);

/// Runtime integration seam for the terminal state callback.
#[derive(Clone, Copy)]
pub struct StateFinalizeOps {
    pub terminal_state_callback: TerminalStateCallback,
}

#[cfg(not(test))]
unsafe fn rom_terminal_state_callback(state: u8) -> ! {
    let callback: unsafe extern "C" fn(u8) -> ! = core::mem::transmute(ROM_TERMINAL_STATE_CALLBACK);
    callback(state)
}

#[cfg(test)]
unsafe fn unavailable_terminal_state_callback(_state: u8) {
    unreachable!("host tests must install a terminal state callback")
}

/// Direct-ROM default; host tests replace this callback before calling the port.
pub static mut STATE_FINALIZE_OPS: StateFinalizeOps = StateFinalizeOps {
    #[cfg(not(test))]
    terminal_state_callback: rom_terminal_state_callback,
    #[cfg(test)]
    terminal_state_callback: unavailable_terminal_state_callback,
};

#[inline(always)]
unsafe fn state_finalize_ops() -> StateFinalizeOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STATE_FINALIZE_OPS))
}

/// finalize_state_and_dispatch — original: `FUN_08005320` @ 0x08005320
/// (40 bytes). Reference: `decomp/c/000/08005320_FUN_08005320.c`.
///
/// If `record`'s active state is 2, call [`set_state_and_notify`] with the
/// deferred state byte at +0x21. Reload the active state after that call and
/// terminally invoke the 0x082aad24 thunk with it. The original performs no
/// null or bounds checks. The direct target call is represented by
/// [`STATE_FINALIZE_OPS`] so host tests do not branch into unmapped firmware;
/// the ROM default preserves its diverging control-flow contract.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn finalize_state_and_dispatch(record: *mut u8) -> ! {
    if record.add(CURRENT_STATE).read_volatile() == DEFERRED_STATE_PENDING {
        set_state_and_notify(record, record.add(DEFERRED_STATE).read_volatile());
    }
    (state_finalize_ops().terminal_state_callback)(record.add(CURRENT_STATE).read_volatile())
}

/// Host-test counterpart of [`finalize_state_and_dispatch`].
///
/// The firmware entry's callback is terminal. This host-only version permits
/// its recorder to return after observing the same terminal dispatch edge.
#[cfg(test)]
pub unsafe fn finalize_state_and_dispatch(record: *mut u8) {
    if record.add(CURRENT_STATE).read_volatile() == DEFERRED_STATE_PENDING {
        set_state_and_notify(record, record.add(DEFERRED_STATE).read_volatile());
    }
    (state_finalize_ops().terminal_state_callback)(record.add(CURRENT_STATE).read_volatile());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::state_transition::{StateNotificationFn, StateTransitionOps, STATE_TRANSITION_OPS};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TRANSITION_CALLS: usize = 0;
    static mut TRANSITION_STATE: u8 = 0;
    static mut TERMINAL_CALLS: usize = 0;
    static mut TERMINAL_STATE: u8 = 0;

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved_finalize_ops: StateFinalizeOps,
        saved_transition_ops: StateTransitionOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe {
                STATE_FINALIZE_OPS = self.saved_finalize_ops;
                STATE_TRANSITION_OPS = self.saved_transition_ops;
            }
        }
    }

    fn install_recorders() -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved_finalize_ops = core::ptr::read_volatile(core::ptr::addr_of!(STATE_FINALIZE_OPS));
            let saved_transition_ops = core::ptr::read_volatile(core::ptr::addr_of!(STATE_TRANSITION_OPS));
            STATE_FINALIZE_OPS = StateFinalizeOps {
                terminal_state_callback: record_terminal_state,
            };
            STATE_TRANSITION_OPS = StateTransitionOps {
                notify_state_change: record_transition as StateNotificationFn,
            };
            core::ptr::addr_of_mut!(TRANSITION_CALLS).write(0);
            core::ptr::addr_of_mut!(TRANSITION_STATE).write(0);
            core::ptr::addr_of_mut!(TERMINAL_CALLS).write(0);
            core::ptr::addr_of_mut!(TERMINAL_STATE).write(0);
            TestOps {
                _lock: lock,
                saved_finalize_ops,
                saved_transition_ops,
            }
        }
    }

    unsafe extern "C" fn record_transition(_context: u32) {
        let calls = core::ptr::addr_of!(TRANSITION_CALLS).read();
        core::ptr::addr_of_mut!(TRANSITION_CALLS).write(calls + 1);
    }

    unsafe fn record_terminal_state(state: u8) {
        let calls = core::ptr::addr_of!(TERMINAL_CALLS).read();
        core::ptr::addr_of_mut!(TERMINAL_CALLS).write(calls + 1);
        core::ptr::addr_of_mut!(TERMINAL_STATE).write(state);
    }

    #[repr(align(4))]
    struct StateRecord {
        bytes: [u8; DEFERRED_STATE + 1],
    }

    impl StateRecord {
        fn new(current: u8, deferred: u8) -> Self {
            let mut record = Self {
                bytes: [0xa5; DEFERRED_STATE + 1],
            };
            record.bytes[CURRENT_STATE] = current;
            record.bytes[DEFERRED_STATE] = deferred;
            record
        }

        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
    }

    #[test]
    fn deferred_state_transitions_then_terminally_forwards_reloaded_state() {
        let _ops = install_recorders();
        let mut record = StateRecord::new(DEFERRED_STATE_PENDING, 0x47);

        unsafe { finalize_state_and_dispatch(record.as_mut_ptr()) };
        assert_eq!(record.bytes[CURRENT_STATE], 0x47);
        unsafe {
            assert_eq!(TRANSITION_CALLS, 1);
            assert_eq!(TERMINAL_CALLS, 1);
            assert_eq!(TERMINAL_STATE, 0x47);
        }
    }

    #[test]
    fn other_states_skip_transition_and_dispatch_the_original_state() {
        let _ops = install_recorders();
        let mut record = StateRecord::new(0x83, 0x47);

        unsafe { finalize_state_and_dispatch(record.as_mut_ptr()) };
        assert_eq!(record.bytes[CURRENT_STATE], 0x83);
        unsafe {
            assert_eq!(TRANSITION_CALLS, 0);
            assert_eq!(TERMINAL_CALLS, 1);
            assert_eq!(TERMINAL_STATE, 0x83);
        }
    }
}
