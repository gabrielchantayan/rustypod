//! `event_handler_callback_cancel` — `FUN_081b0c90` @ `0x081b0c90`.
//! True extent: 44 bytes (40 instruction bytes plus the global-state literal);
//! next function: `0x081b0cbc`. One outgoing plain BL, zero predicated BLs,
//! and one tail B. Whole-image decoding finds two plain inbound BLs and one B.
//!
//! If global state byte +2 is zero, do nothing. Otherwise clear it before
//! obtaining the event-handler source and dispatching callback-target vtable
//! slot +0x0c through `0x08038148` -> `0x22007fcc` (osos mirror `0x08007fcc`).
//! Clearing first makes repeated or reentrant cancellation a no-op.
//!
//! Deliberate deviations: reuse the ported source veneer; LLVM chooses the
//! frame and tail-call form. The unported virtual-dispatch wrapper remains an
//! exact-address target seam, not a guessed framework operation. Host entry
//! fails explicitly because the state and callback belong to retailOS; tests
//! exercise the same transition with isolated state and a synchronous callback.

#[inline(always)]
unsafe fn cancel_if_pending(flag: *mut u8, notify: impl FnOnce()) {
    if core::ptr::read_volatile(flag) == 0 { return; }
    core::ptr::write_volatile(flag, 0);
    notify();
}

/// Cancels the pending global event-handler callback once.
///
/// # Safety
/// Requires initialized retailOS global state, IRAM relocation, and a valid
/// callback target supporting vtable slot +0x0c. Not thread-safe, like stock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_callback_cancel() {
    #[cfg(target_os = "none")]
    cancel_if_pending(0x089c_b232 as *mut u8, || {
        let source = crate::kernel::thunks::iram_event_handler_source_veneer();
        // Raw 0x08007fcc ignores incoming r0, gets the callback target through
        // 0x08003910, then dispatches its first-word vtable's fourth slot.
        let dispatch: unsafe extern "C" fn(*mut u8) =
            core::mem::transmute(0x2200_7fccusize);
        dispatch(source);
    });
    #[cfg(not(target_os = "none"))]
    panic!("event_handler_callback_cancel requires retailOS global state");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_state_does_not_notify_or_touch_neighbors() {
        let mut state = [0xa5, 0x5a, 0, 0xff];
        unsafe { cancel_if_pending(state.as_mut_ptr().add(2), || panic!("inactive notification")); }
        assert_eq!(state, [0xa5, 0x5a, 0, 0xff]);
    }

    #[test]
    fn every_nonzero_flag_clears_before_reentrant_and_repeated_cancellation() {
        for pending in 1..=255u8 {
            let mut state = [0xa5, 0x5a, pending, 0xff];
            let flag = unsafe { state.as_mut_ptr().add(2) };
            let mut notifications = 0;
            unsafe {
                cancel_if_pending(flag, || {
                    assert_eq!(flag.read_volatile(), 0);
                    notifications += 1;
                    cancel_if_pending(flag, || panic!("reentrant notification"));
                });
                cancel_if_pending(flag, || panic!("repeated notification"));
            }
            assert_eq!(notifications, 1);
            assert_eq!(state, [0xa5, 0x5a, 0, 0xff]);
        }
    }
}
