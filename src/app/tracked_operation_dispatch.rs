//! Dispatches operation types 3, 4, and 5 after synchronizing tracked state.

/// Host/target seam for the state synchronizer at `0x082419b0`.
pub type OperationStateSync = unsafe extern "C" fn(*mut u8);
/// Host/target seam for the operation dispatcher at `0x08243778`.
pub type OperationDispatch = unsafe extern "C" fn(*mut u8, u32, *mut u8, *mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_operation_state_sync(_state: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_operation_dispatch(
    _operation_list: *mut u8,
    _operation_type: u32,
    _configuration: *mut u8,
    _payload: *mut u8,
) {
}

/// Host-only replacement for the retail state synchronizer.
#[cfg(not(target_arch = "arm"))]
pub static mut OPERATION_STATE_SYNC: OperationStateSync = missing_operation_state_sync;
/// Host-only replacement for the retail operation dispatcher.
#[cfg(not(target_arch = "arm"))]
pub static mut OPERATION_DISPATCH: OperationDispatch = missing_operation_dispatch;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_operation_state_sync(state: *mut u8);
    fn retail_operation_dispatch(
        operation_list: *mut u8,
        operation_type: u32,
        configuration: *mut u8,
        payload: *mut u8,
    );
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_operation_state_sync(state: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(OPERATION_STATE_SYNC))(state);
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_operation_dispatch(
    operation_list: *mut u8,
    operation_type: u32,
    configuration: *mut u8,
    payload: *mut u8,
) {
    core::ptr::read_volatile(core::ptr::addr_of!(OPERATION_DISPATCH))(
        operation_list,
        operation_type,
        configuration,
        payload,
    );
}

// The stock PC-relative BL transfers cannot reach from the Rust payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_operation_state_sync
    .type retail_operation_state_sync, %function
retail_operation_state_sync:
    ldr     pc, [pc, #-4]
    .word   0x082419b0
    .size retail_operation_state_sync, . - retail_operation_state_sync

    .globl retail_operation_dispatch
    .type retail_operation_dispatch, %function
retail_operation_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x08243778
    .size retail_operation_dispatch, . - retail_operation_dispatch
"#
);

/// tracked_operation_dispatch — original: `FUN_08242694` @ **0x08242694**
/// (76 bytes, `0x08242694..0x082426dc`; the next separately linked function
/// starts at `0x082426e0`). Raw decoding finds **five inbound direct `bl` call
/// sites**, all unconditional; there are no predicated forms.
///
/// Synchronizes the tracked operation state, then dispatches operation types
/// 3, 4, and 5 in that order. Every dispatch receives the list at `state+0x44`,
/// configuration at `state+0x40`, and payload at `state+0x6c`.
///
/// Deliberate deviations: none in behavior. ARM builds use literal veneers for
/// the two stock callees because the payload cannot use the stock PC-relative
/// branch ranges; the stock tail branch to the type-5 dispatch becomes a call.
///
/// # Safety
///
/// `state` must identify a retail state object with valid fields at `+0x40`,
/// `+0x44`, and `+0x6c`; the two retail callees impose the remaining validity
/// requirements.
#[cfg_attr(target_os = "none", link_section = ".text.tracked_operation_dispatch")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tracked_operation_dispatch(state: *mut u8) {
    retail_operation_state_sync(state);

    retail_operation_dispatch(
        core::ptr::read_volatile(state.add(0x44) as *const u32) as usize as *mut u8,
        3,
        core::ptr::read_volatile(state.add(0x40) as *const u32) as usize as *mut u8,
        state.add(0x6c),
    );
    retail_operation_dispatch(
        core::ptr::read_volatile(state.add(0x44) as *const u32) as usize as *mut u8,
        4,
        core::ptr::read_volatile(state.add(0x40) as *const u32) as usize as *mut u8,
        state.add(0x6c),
    );
    retail_operation_dispatch(
        core::ptr::read_volatile(state.add(0x44) as *const u32) as usize as *mut u8,
        5,
        core::ptr::read_volatile(state.add(0x40) as *const u32) as usize as *mut u8,
        state.add(0x6c),
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(u32, usize, usize, usize)> = Vec::new();
    static mut CALL_ORDER: Vec<u32> = Vec::new();
    static mut STATE: *mut u8 = core::ptr::null_mut();
    static mut SYNC_STATE: usize = 0;

    unsafe extern "C" fn record_sync(state: *mut u8) {
        SYNC_STATE = state as usize;
        CALL_ORDER.push(0);
    }

    unsafe extern "C" fn record_dispatch(
        operation_list: *mut u8,
        operation_type: u32,
        configuration: *mut u8,
        payload: *mut u8,
    ) {
        CALLS.push((operation_type, operation_list as usize, configuration as usize, payload as usize));
        CALL_ORDER.push(operation_type);
        if operation_type == 3 {
            (STATE.add(0x44) as *mut u32).write(0x1111_2222);
            (STATE.add(0x40) as *mut u32).write(0x3333_4444);
        }
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                OPERATION_STATE_SYNC = missing_operation_state_sync;
                OPERATION_DISPATCH = missing_operation_dispatch;
                CALLS = Vec::new();
                CALL_ORDER = Vec::new();
                STATE = core::ptr::null_mut();
                SYNC_STATE = 0;
            }
        }
    }

    fn arrange() -> (MutexGuard<'static, ()>, Reset) {
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            OPERATION_STATE_SYNC = record_sync;
            OPERATION_DISPATCH = record_dispatch;
            CALLS = Vec::new();
            CALL_ORDER = Vec::new();
            STATE = core::ptr::null_mut();
            SYNC_STATE = 0;
        }
        (guard, Reset)
    }

    #[test]
    fn synchronizes_then_dispatches_all_three_operation_types() {
        let (_guard, _reset) = arrange();
        let mut state = [0u32; 28];
        let operation_list = 0x1234_5678u32;
        let configuration = 0x8765_4321u32;
        let state_bytes = state.as_mut_ptr().cast::<u8>();
        unsafe {
            (state_bytes.add(0x44) as *mut u32).write(operation_list);
            (state_bytes.add(0x40) as *mut u32).write(configuration);
            STATE = state_bytes;
            tracked_operation_dispatch(state_bytes);

            assert_eq!(SYNC_STATE, state_bytes as usize);
            assert_eq!(CALL_ORDER, [0, 3, 4, 5]);
            assert_eq!(CALLS, [
                (3, operation_list as usize, configuration as usize, state_bytes.add(0x6c) as usize),
                (4, 0x1111_2222, 0x3333_4444, state_bytes.add(0x6c) as usize),
                (5, 0x1111_2222, 0x3333_4444, state_bytes.add(0x6c) as usize),
            ]);
        }
    }
}
