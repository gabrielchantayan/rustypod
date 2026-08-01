//! Pending UI cleanup dispatch.
//!
//! `ui_dispatch_pending_cleanup` — original: `FUN_08005d28` @ `0x08005d28`
//! (52 bytes). Reference: `decomp/c/000/08005d28_FUN_08005d28.c`; the ARM
//! sequence loads the byte at +0x06, calls `FUN_08005ef0` then the
//! `FUN_080035e0` veneer with `0x2200_8cb8`, clears that byte, and returns 0.
//!
//! On the 32-bit target the cleanup slot has a decoder pointer at +0x00 and
//! an active-cleanup byte at +0x06. `FUN_08005ef0` dereferences that pointer
//! and tail-dispatches its vtable entry at +0x0c. The second target is outside
//! the ported UI surface, so both foreign calls are represented by the local
//! seam below. They deliberately receive the wrapper's original ARM ABI
//! arguments: the slot, then the fixed UI notification context.

/// Byte that marks a cleanup slot as requiring its paired shutdown dispatch.
pub const PENDING_CLEANUP_OFFSET: usize = 0x06;

/// Fixed context passed to the second foreign call by the retailOS wrapper.
const UI_NOTIFICATION_CONTEXT: *mut u8 = 0x2200_8cb8 as *mut u8;

/// Unported calls made by [`ui_dispatch_pending_cleanup`].
///
/// `dispatch_cleanup` is `FUN_08005ef0`; it receives the cleanup slot and
/// dispatches the slot's decoder through vtable offset +0x0c. `notify_cleanup`
/// is the `FUN_080035e0` veneer and receives `0x2200_8cb8` in `r0`.
#[derive(Clone, Copy)]
pub struct UiPendingCleanupOps {
    pub dispatch_cleanup: unsafe extern "C" fn(cleanup_slot: *mut u8),
    pub notify_cleanup: unsafe extern "C" fn(notification_context: *mut u8),
}

unsafe extern "C" fn missing_dispatch_cleanup(_cleanup_slot: *mut u8) {}

unsafe extern "C" fn missing_notify_cleanup(_notification_context: *mut u8) {}

/// Default unwired seam. It keeps the wrapper callable until the two retailOS
/// targets are bridged by the UI subsystem.
pub const DEFAULT_UI_PENDING_CLEANUP_OPS: UiPendingCleanupOps = UiPendingCleanupOps {
    dispatch_cleanup: missing_dispatch_cleanup,
    notify_cleanup: missing_notify_cleanup,
};

/// Active UI cleanup-call seam. Target integration may replace it with bridges
/// to the two retailOS calls; host tests install recorders.
pub static mut UI_PENDING_CLEANUP_OPS: UiPendingCleanupOps = DEFAULT_UI_PENDING_CLEANUP_OPS;

#[inline(always)]
fn pending_cleanup_ops() -> UiPendingCleanupOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_PENDING_CLEANUP_OPS)) }
}

/// ui_dispatch_pending_cleanup — original: `FUN_08005d28` @ `0x08005d28` (52 bytes).
///
/// If the cleanup slot's byte at +0x06 is clear, returns zero without a call or
/// store. Otherwise it dispatches the slot's pending cleanup, notifies the
/// fixed UI context, clears that byte, and returns zero. The calls and clear
/// occur strictly in that order.
///
/// # Deviations
///
/// The two firmware callees are not ported. [`UI_PENDING_CLEANUP_OPS`] keeps
/// their observed ARM ABI and ordering explicit rather than inventing their
/// internals. The default seam is no-op only when integration has not wired
/// those callees; it does not alter the wrapper's clear-path behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_dispatch_pending_cleanup(cleanup_slot: *mut u8) -> i32 {
    let ops = pending_cleanup_ops();
    if unsafe { cleanup_slot.add(PENDING_CLEANUP_OFFSET).read_volatile() } == 0 {
        return 0;
    }

    unsafe {
        (ops.dispatch_cleanup)(cleanup_slot);
        (ops.notify_cleanup)(UI_NOTIFICATION_CONTEXT);
        cleanup_slot
            .add(PENDING_CLEANUP_OFFSET)
            .write_volatile(0);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Copy)]
    struct Mock {
        state: usize,
        call_count: usize,
        calls: [(u8, usize); 2],
        dispatch_flag: u8,
        notify_flag: u8,
    }

    impl Mock {
        const EMPTY: Self = Self {
            state: 0,
            call_count: 0,
            calls: [(0, 0); 2],
            dispatch_flag: 0xff,
            notify_flag: 0xff,
        };
    }

    static TEST_LOCK: AtomicBool = AtomicBool::new(false);
    static mut MOCK: Mock = Mock::EMPTY;

    unsafe extern "C" fn mock_dispatch_cleanup(cleanup_slot: *mut u8) {
        unsafe {
            let mock = &mut *core::ptr::addr_of_mut!(MOCK);
            let call_index = mock.call_count;
            mock.calls[call_index] = (1, cleanup_slot as usize);
            mock.call_count = call_index + 1;
            mock.dispatch_flag = cleanup_slot.add(PENDING_CLEANUP_OFFSET).read_volatile();
        }
    }

    unsafe extern "C" fn mock_notify_cleanup(notification_context: *mut u8) {
        unsafe {
            let mock = &mut *core::ptr::addr_of_mut!(MOCK);
            let call_index = mock.call_count;
            mock.calls[call_index] = (2, notification_context as usize);
            mock.call_count = call_index + 1;
            mock.notify_flag = (mock.state as *const u8)
                .add(PENDING_CLEANUP_OFFSET)
                .read_volatile();
        }
    }

    struct Bench {
        previous: UiPendingCleanupOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { UI_PENDING_CLEANUP_OPS = self.previous };
            TEST_LOCK.store(false, Ordering::Release);
        }
    }

    fn bench(state: &mut [u8; 8]) -> Bench {
        while TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        let previous = unsafe { UI_PENDING_CLEANUP_OPS };
        unsafe {
            *core::ptr::addr_of_mut!(MOCK) = Mock {
                state: state.as_mut_ptr() as usize,
                ..Mock::EMPTY
            };
            UI_PENDING_CLEANUP_OPS = UiPendingCleanupOps {
                dispatch_cleanup: mock_dispatch_cleanup,
                notify_cleanup: mock_notify_cleanup,
            };
        }
        Bench { previous }
    }

    #[test]
    fn clear_flag_returns_zero_without_calls_or_stores() {
        let mut state = [0xa5; 8];
        state[PENDING_CLEANUP_OFFSET] = 0;
        let before = state;
        let _bench = bench(&mut state);

        assert_eq!(unsafe { ui_dispatch_pending_cleanup(state.as_mut_ptr()) }, 0);
        assert_eq!(state, before, "clear flag is a true no-op");
        assert_eq!(unsafe { (*core::ptr::addr_of!(MOCK)).call_count }, 0);
    }

    #[test]
    fn set_flag_calls_foreign_helpers_in_order_then_clears_and_returns_zero() {
        let mut state = [0xa5; 8];
        state[PENDING_CLEANUP_OFFSET] = 1;
        let state_ptr = state.as_mut_ptr();
        let _bench = bench(&mut state);

        assert_eq!(unsafe { ui_dispatch_pending_cleanup(state_ptr) }, 0);

        let mock = unsafe { *core::ptr::addr_of!(MOCK) };
        assert_eq!(mock.call_count, 2);
        assert_eq!(mock.calls, [(1, state_ptr as usize), (2, UI_NOTIFICATION_CONTEXT as usize)]);
        assert_eq!(mock.dispatch_flag, 1, "dispatch precedes the flag clear");
        assert_eq!(mock.notify_flag, 1, "notification precedes the flag clear");
        assert_eq!(state[PENDING_CLEANUP_OFFSET], 0, "both calls precede clearing");
        for (offset, byte) in state.iter().enumerate() {
            if offset != PENDING_CLEANUP_OFFSET {
                assert_eq!(*byte, 0xa5, "unrelated state byte +{offset:#x}");
            }
        }
    }
}
