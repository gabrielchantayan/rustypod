//! `queue_complete` — original: `FUN_0822b5e0` @ `0x0822b5e0` (**140 bytes**,
//! `0x0822b5e0..0x0822b66c`; the separately linked next function begins at
//! `0x0822b66c`).
//!
//! Raw ARM has five inbound `blne` call sites (and no unconditional inbound
//! `bl`): `0x081b6fd8`, `0x081cc958`, `0x081cca8c`, `0x081cce88`, and
//! `0x081cd000`. Its body contains five unconditional `bl` instructions and
//! one predicated `bleq`. It first requires a non-NULL request interface and
//! request-flags bit 0, then checks the interface's completion gate. On a
//! passed gate it reads the selected position, retries that read only when it
//! is not `u32::MAX`, forwards `(state, 1, position)` to the selected position
//! setter, and runs the queue operation. A successful operation whose release
//! check is clear releases the request interface. It returns one only when the
//! completion gate rejects the request; all other paths return zero.
//!
//! Deliberate deviation: the three unported fixed-address callees use
//! replaceable host operations. Target builds retain their observed addresses;
//! the already ported position getter, setter, and cursor release are called
//! directly.

use core::ptr::addr_of;

const REQUEST_INTERFACE_OFFSET: usize = 0x14;
const REQUEST_FLAGS_OFFSET: usize = 0x24;
const RETAIL_COMPLETION_GATE: usize = 0x0822_ab50;
const RETAIL_QUEUE_OPERATION: usize = 0x0822_b020;
const RETAIL_RELEASE_CHECK: usize = 0x0821_43e8;

pub type QueueCompleteGate = unsafe extern "C" fn(*mut u8) -> u32;
pub type QueueCompleteOperation = unsafe extern "C" fn(*mut u8) -> u32;
pub type QueueCompleteReleaseCheck = unsafe extern "C" fn(*mut u8) -> u32;
pub type QueueCompleteRelease = unsafe extern "C" fn(*mut u8);
pub type QueueCompleteSetPosition = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[derive(Clone, Copy)]
pub struct QueueCompleteOps {
    pub completion_gate: QueueCompleteGate,
    pub queue_operation: QueueCompleteOperation,
    pub release_check: QueueCompleteReleaseCheck,
    pub release: QueueCompleteRelease,
    pub set_position: QueueCompleteSetPosition,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_completion_gate(state: *mut u8) -> u32 {
    let gate: QueueCompleteGate = core::mem::transmute(RETAIL_COMPLETION_GATE);
    gate(state)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_queue_operation(state: *mut u8) -> u32 {
    let operation: QueueCompleteOperation = core::mem::transmute(RETAIL_QUEUE_OPERATION);
    operation(state)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_release_check(state: *mut u8) -> u32 {
    let check: QueueCompleteReleaseCheck = core::mem::transmute(RETAIL_RELEASE_CHECK);
    check(state)
}

unsafe extern "C" fn retail_release(request_interface: *mut u8) {
    crate::cxx::list_cursor_release::list_cursor_release(
        request_interface.cast::<crate::cxx::list_cursor_release::ListCursorReleaseState>(),
    );
}

unsafe extern "C" fn retail_set_position(state: *mut u8, mode: u32, position: u32) -> u32 {
    crate::app::mode_selected_position_set::mode_selected_position_set(state, mode, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_gate(_state: *mut u8) -> u32 {
    panic!("install queue-complete host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operation(_state: *mut u8) -> u32 {
    panic!("install queue-complete host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_check(_state: *mut u8) -> u32 {
    panic!("install queue-complete host operations")
}

#[cfg(target_os = "none")]
pub const DEFAULT_QUEUE_COMPLETE_OPS: QueueCompleteOps = QueueCompleteOps {
    completion_gate: retail_completion_gate,
    queue_operation: retail_queue_operation,
    release_check: retail_release_check,
    release: retail_release,
    set_position: retail_set_position,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_QUEUE_COMPLETE_OPS: QueueCompleteOps = QueueCompleteOps {
    completion_gate: missing_gate,
    queue_operation: missing_operation,
    release_check: missing_release_check,
    release: retail_release,
    set_position: retail_set_position,
};

pub static mut QUEUE_COMPLETE_OPS: QueueCompleteOps = DEFAULT_QUEUE_COMPLETE_OPS;

#[inline(always)]
fn ops() -> QueueCompleteOps {
    unsafe { core::ptr::read_volatile(addr_of!(QUEUE_COMPLETE_OPS)) }
}

/// Completes the selected queue request when its completion gate permits it.
///
/// # Safety
///
/// `state` must be non-NULL and readable at `+0x14`, `+0x24`, `+0x2ec`,
/// `+0x5e4`, and `+0x5f8`. A nonzero request-interface word and every callee
/// must satisfy their unchecked retailOS pointer preconditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queue_complete(state: *mut u8) -> u32 {
    let request_interface = state.add(REQUEST_INTERFACE_OFFSET).cast::<u32>().read();
    if request_interface == 0 || state.add(REQUEST_FLAGS_OFFSET).read() & 1 == 0 {
        return 0;
    }

    let operations = ops();
    if (operations.completion_gate)(state) == 0 {
        return 1;
    }

    let position = crate::app::mode_selected_position::mode_selected_position(state);
    let position = if position == u32::MAX {
        0
    } else {
        crate::app::mode_selected_position::mode_selected_position(state)
    };
    (operations.set_position)(state, 1, position);

    if (operations.queue_operation)(state) != 0 && (operations.release_check)(state) == 0 {
        (operations.release)(request_interface as usize as *mut u8);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::mode_selected_position_set::MODE_SELECTED_POSITION_SET_TEST_LOCK;
    use std::sync::atomic::{AtomicU32, Ordering};

    const MODE_POSITION_OFFSET: usize = 0x2ec;
    const DEFAULT_POSITION_OFFSET: usize = 0x5e4;
    const MODE_FLAGS_OFFSET: usize = 0x5f8;
    const STATE_BYTES: usize = MODE_FLAGS_OFFSET + 1;
    static GATE_RESULT: AtomicU32 = AtomicU32::new(0);
    static OPERATION_RESULT: AtomicU32 = AtomicU32::new(0);
    static RELEASE_CHECK_RESULT: AtomicU32 = AtomicU32::new(0);
    static RELEASED: AtomicU32 = AtomicU32::new(0);
    static SET_MODE: AtomicU32 = AtomicU32::new(0);
    static SET_POSITION: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn gate(_state: *mut u8) -> u32 { GATE_RESULT.load(Ordering::Relaxed) }
    unsafe extern "C" fn operation(_state: *mut u8) -> u32 { OPERATION_RESULT.load(Ordering::Relaxed) }
    unsafe extern "C" fn release_check(_state: *mut u8) -> u32 { RELEASE_CHECK_RESULT.load(Ordering::Relaxed) }
    unsafe extern "C" fn release(_request: *mut u8) { RELEASED.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn set_position(_state: *mut u8, mode: u32, position: u32) -> u32 {
        SET_MODE.store(mode, Ordering::Relaxed);
        SET_POSITION.store(position, Ordering::Relaxed);
        0
    }

    fn install_ops() -> QueueCompleteOps {
        QueueCompleteOps { completion_gate: gate, queue_operation: operation, release_check, release, set_position }
    }

    fn state(request: u32, request_flags: u8, mode_flags: u8, mode_position: u32, default_position: u32) -> [u8; STATE_BYTES] {
        let mut state = [0; STATE_BYTES];
        unsafe {
            state.as_mut_ptr().add(REQUEST_INTERFACE_OFFSET).cast::<u32>().write(request);
            state.as_mut_ptr().add(MODE_POSITION_OFFSET).cast::<u32>().write(mode_position);
            state.as_mut_ptr().add(DEFAULT_POSITION_OFFSET).cast::<u32>().write(default_position);
        }
        state[REQUEST_FLAGS_OFFSET] = request_flags;
        state[MODE_FLAGS_OFFSET] = mode_flags;
        state
    }

    #[test]
    fn rejects_missing_or_unflagged_requests_without_dispatch() {
        let _set_lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        unsafe { QUEUE_COMPLETE_OPS = install_ops(); }
        for (request, flags) in [(0, 1), (0x1234, 0), (0x1234, 2)] {
            GATE_RESULT.store(1, Ordering::Relaxed);
            let mut state = state(request, flags, 0, 3, 7);
            assert_eq!(unsafe { queue_complete(state.as_mut_ptr()) }, 0);
        }
    }

    #[test]
    fn gate_rejection_is_the_only_nonzero_result() {
        let _set_lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        unsafe { QUEUE_COMPLETE_OPS = install_ops(); }
        GATE_RESULT.store(0, Ordering::Relaxed);
        let mut state = state(0x1234, 1, 0, 3, 7);
        assert_eq!(unsafe { queue_complete(state.as_mut_ptr()) }, 1);
    }

    #[test]
    fn completes_with_selected_position_and_releases_only_when_clear() {
        let _set_lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        unsafe { QUEUE_COMPLETE_OPS = install_ops(); }
        GATE_RESULT.store(1, Ordering::Relaxed);
        OPERATION_RESULT.store(1, Ordering::Relaxed);
        RELEASE_CHECK_RESULT.store(0, Ordering::Relaxed);
        RELEASED.store(0, Ordering::Relaxed);
        let mut state = state(0x1234, 1, 1, 0x1122_3344, 0x5566_7788);
        assert_eq!(unsafe { queue_complete(state.as_mut_ptr()) }, 0);
        assert_eq!(SET_MODE.load(Ordering::Relaxed), 1);
        assert_eq!(SET_POSITION.load(Ordering::Relaxed), 0x1122_3344);
        assert_eq!(RELEASED.load(Ordering::Relaxed), 1);

        RELEASE_CHECK_RESULT.store(1, Ordering::Relaxed);
        assert_eq!(unsafe { queue_complete(state.as_mut_ptr()) }, 0);
        assert_eq!(RELEASED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sentinel_position_is_replaced_with_zero() {
        let _set_lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        unsafe { QUEUE_COMPLETE_OPS = install_ops(); }
        GATE_RESULT.store(1, Ordering::Relaxed);
        OPERATION_RESULT.store(0, Ordering::Relaxed);
        let mut state = state(0x1234, 1, 0, 3, u32::MAX);
        assert_eq!(unsafe { queue_complete(state.as_mut_ptr()) }, 0);
        assert_eq!(SET_POSITION.load(Ordering::Relaxed), 0);
    }
}
