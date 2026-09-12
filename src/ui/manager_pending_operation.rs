//! Shared UI-manager pending-operation completion.
//!
//! `ui_manager_finish_pending_operation` — original:
//! `thunk_EXT_FUN_2200509c` @ `0x08038130` (8-byte literal veneer, target
//! `FUN_0800509c` @ `0x0800509c`, 88 bytes including its literal word).
//!
//! Raw bytes establish that the veneer reaches the relocator mirror at
//! `0x2200509c`. The body clears the byte at `0x22008c94`, conditionally sets
//! stream-buffer request flags `0x18` and enters the nonstandard entry
//! `0x081b09b4`, then conditionally tail-dispatches the cleanup slot at
//! `manager + 0x10`. Decoding every ARM `B`/`BL` in `osos.dec` found eight
//! unconditional `bl` callers and one unconditional tail `b` caller; no call
//! is predicated. The caller supplies the active manager as `r0`, an enable
//! gate as `r1`, and a cleanup-request value as `r2`.
//!
//! The `0x081b09b4` target is a mid-function entry, not a normal ABI function:
//! it consumes manager and cleanup-request from callee-saved `r4`/`r5`, while
//! the wrapper also supplies `manager + 0x28` in `r0`. The ARM bridge below
//! establishes that exact register frame and forces the `popeq` at the entry
//! to its stock false path (the preceding `stream_buffer_request_flags_update`
//! does this with `cmp r5, #0` for its constant enable argument). Its class
//! identity remains unrecovered, so the host seam describes the observed
//! pending-operation completion rather than inventing a callee name.

use crate::app::buffer_refill_request::stream_buffer_request_flags_update;
use crate::ui::pending_cleanup::ui_dispatch_pending_cleanup;

/// Offset of the manager's byte which gates the delegated completion.
pub const UI_MANAGER_ACTIVE_OFFSET: usize = 0x00;
/// Offset of the manager-owned pending-cleanup slot.
pub const UI_MANAGER_PENDING_CLEANUP_OFFSET: usize = 0x10;
/// Request-controller mask set before delegated completion.
pub const UI_MANAGER_COMPLETION_REQUEST_MASK: u32 = 0x18;

#[cfg(target_os = "none")]
const UI_MANAGER_OPERATION_MARKER: *mut u8 = 0x2200_8c94 as *mut u8;

/// Host model for the operation marker byte at target address `0x22008c94`.
#[cfg(not(target_os = "none"))]
pub static mut UI_MANAGER_OPERATION_MARKER: u8 = 0;

#[inline(always)]
fn ui_manager_operation_marker() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        UI_MANAGER_OPERATION_MARKER
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(UI_MANAGER_OPERATION_MARKER)
    }
}

/// Host replacement for the nonstandard `0x081b09b4` completion entry.
///
/// The target bridge receives `manager` in `r4`, `cleanup_requested` in `r5`,
/// and derives the original `r0 = manager + 0x28` itself.
#[cfg(not(target_os = "none"))]
pub type UiManagerPendingOperationComplete = unsafe extern "C" fn(*mut u8, u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pending_operation_complete(_manager: *mut u8, _cleanup_requested: u32) -> i32 {
    -1
}

/// Host seam for the unported mid-function completion entry at `0x081b09b4`.
/// Target builds use [`retail_ui_manager_pending_operation_complete`] instead.
#[cfg(not(target_os = "none"))]
pub static mut UI_MANAGER_PENDING_OPERATION_COMPLETE: UiManagerPendingOperationComplete =
    missing_pending_operation_complete;

#[cfg(target_os = "none")]
extern "C" {
    fn retail_ui_manager_pending_operation_complete(manager: *mut u8, cleanup_requested: u32) -> i32;
}

#[inline(always)]
unsafe fn complete_pending_operation(manager: *mut u8, cleanup_requested: u32) -> i32 {
    #[cfg(target_os = "none")]
    {
        unsafe { retail_ui_manager_pending_operation_complete(manager, cleanup_requested) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let completion = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(UI_MANAGER_PENDING_OPERATION_COMPLETE))
        };
        unsafe { completion(manager, cleanup_requested) }
    }
}

/// ui_manager_finish_pending_operation — original: `thunk_EXT_FUN_2200509c`
/// @ `0x08038130` (8 bytes), mirror body `FUN_0800509c` @ `0x0800509c`
/// (88 bytes).
///
/// Clears the operation marker before every return. If `manager[0]` and
/// `completion_enabled` are nonzero, sets request-controller mask `0x18` and
/// enters the manager's pending-operation completion. When `cleanup_requested`
/// is nonzero, it then tail-dispatches the manager cleanup slot at `+0x10`; its
/// zero result replaces any delegated-completion result. Otherwise the result
/// is `-1` on the skipped path or exactly the delegated-completion result.
///
/// # Deliberate deviations
///
/// The `0x081b09b4` entry cannot be expressed as an ordinary Rust ABI call.
/// ARM builds reach it through a register-preserving assembly bridge. Host
/// builds use [`UI_MANAGER_PENDING_OPERATION_COMPLETE`] to expose that foreign
/// boundary without assigning an unsupported identity to the target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.ui_manager_finish_pending_operation"
)]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_finish_pending_operation(
    manager: *mut u8,
    completion_enabled: u32,
    cleanup_requested: u32,
) -> i32 {
    unsafe { ui_manager_operation_marker().write_volatile(0) };

    let mut result = -1;
    if unsafe { manager.add(UI_MANAGER_ACTIVE_OFFSET).read_volatile() } != 0 && completion_enabled != 0 {
        unsafe { stream_buffer_request_flags_update(1, UI_MANAGER_COMPLETION_REQUEST_MASK) };
        result = unsafe { complete_pending_operation(manager, cleanup_requested) };
    }

    if cleanup_requested != 0 {
        unsafe { ui_dispatch_pending_cleanup(manager.add(UI_MANAGER_PENDING_CLEANUP_OFFSET)) }
    } else {
        result
    }
}

// The target is a mid-function entry whose return instruction restores the
// frame established here. `cmp r12, #0` recreates the preceding helper's
// nonzero-enable flags, so `popeq` at 0x081b09b4 does not take its early exit.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ui_manager_pending_operation_complete
    .type retail_ui_manager_pending_operation_complete, %function
retail_ui_manager_pending_operation_complete:
    push    {{r4, r5, r6, lr}}
    mov     r4, r0
    mov     r5, r1
    add     r0, r4, #0x28
    mov     r12, #1
    cmp     r12, #0
    ldr     pc, [pc, #-4]
    .word   0x081b09b4
    .size retail_ui_manager_pending_operation_complete, . - retail_ui_manager_pending_operation_complete
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::buffer_refill_request::{
        STREAM_BUFFER_REQUEST_FLAGS,
        STREAM_BUFFER_REQUEST_TEST_LOCK,
    };
    use crate::ui::pending_cleanup::UI_PENDING_CLEANUP_TEST_LOCK;
    use core::sync::atomic::Ordering;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COMPLETION_CALLS: u32 = 0;
    static mut COMPLETION_MANAGER: usize = 0;
    static mut COMPLETION_CLEANUP_REQUESTED: u32 = 0;
    static mut COMPLETION_RESULT: i32 = 0;

    unsafe extern "C" fn recording_completion(manager: *mut u8, cleanup_requested: u32) -> i32 {
        unsafe {
            COMPLETION_CALLS += 1;
            COMPLETION_MANAGER = manager as usize;
            COMPLETION_CLEANUP_REQUESTED = cleanup_requested;
            COMPLETION_RESULT
        }
    }

    struct Reset {
        previous_completion: UiManagerPendingOperationComplete,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                UI_MANAGER_PENDING_OPERATION_COMPLETE = self.previous_completion;
                UI_MANAGER_OPERATION_MARKER = 0;
                COMPLETION_CALLS = 0;
                COMPLETION_MANAGER = 0;
                COMPLETION_CLEANUP_REQUESTED = 0;
                COMPLETION_RESULT = 0;
            }
        }
    }

    struct RequestFlagsReset;

    impl Drop for RequestFlagsReset {
        fn drop(&mut self) {
            unsafe { STREAM_BUFFER_REQUEST_FLAGS = 0 };
        }
    }

    struct PendingCleanupGuard;

    impl Drop for PendingCleanupGuard {
        fn drop(&mut self) {
            UI_PENDING_CLEANUP_TEST_LOCK.store(false, Ordering::Release);
        }
    }

    fn lock_pending_cleanup() -> PendingCleanupGuard {
        while UI_PENDING_CLEANUP_TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        PendingCleanupGuard
    }


    fn arrange(result: i32) -> (MutexGuard<'static, ()>, Reset) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_completion = unsafe { UI_MANAGER_PENDING_OPERATION_COMPLETE };
        unsafe {
            UI_MANAGER_OPERATION_MARKER = 0xa5;
            COMPLETION_CALLS = 0;
            COMPLETION_MANAGER = 0;
            COMPLETION_CLEANUP_REQUESTED = 0;
            COMPLETION_RESULT = result;
            UI_MANAGER_PENDING_OPERATION_COMPLETE = recording_completion;
        }
        (guard, Reset { previous_completion })
    }

    #[test]
    fn disabled_manager_skips_request_and_completion_but_clears_marker() {
        let (_guard, _reset) = arrange(0x1357);
        let _request_guard = STREAM_BUFFER_REQUEST_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _request_flags_reset = RequestFlagsReset;
        let _cleanup_guard = lock_pending_cleanup();
        let mut manager = [0xa5; 0x18];
        manager[UI_MANAGER_ACTIVE_OFFSET] = 0;
        unsafe { STREAM_BUFFER_REQUEST_FLAGS = 0x40 };

        assert_eq!(unsafe { ui_manager_finish_pending_operation(manager.as_mut_ptr(), 1, 0) }, -1);
        assert_eq!(unsafe { UI_MANAGER_OPERATION_MARKER }, 0);
        assert_eq!(unsafe { COMPLETION_CALLS }, 0);
        assert_eq!(unsafe { STREAM_BUFFER_REQUEST_FLAGS }, 0x40);
    }

    #[test]
    fn enabled_manager_sets_request_mask_and_preserves_completion_result() {
        let (_guard, _reset) = arrange(-0x2468);
        let _request_guard = STREAM_BUFFER_REQUEST_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _request_flags_reset = RequestFlagsReset;
        let _cleanup_guard = lock_pending_cleanup();
        let mut manager = [0xa5; 0x18];
        manager[UI_MANAGER_ACTIVE_OFFSET] = 1;
        let manager_ptr = manager.as_mut_ptr();
        unsafe { STREAM_BUFFER_REQUEST_FLAGS = 0x40 };

        assert_eq!(unsafe { ui_manager_finish_pending_operation(manager_ptr, 7, 0) }, -0x2468);
        assert_eq!(unsafe { UI_MANAGER_OPERATION_MARKER }, 0);
        assert_eq!(unsafe { COMPLETION_CALLS }, 1);
        assert_eq!(unsafe { COMPLETION_MANAGER }, manager_ptr as usize);
        assert_eq!(unsafe { COMPLETION_CLEANUP_REQUESTED }, 0);
        assert_eq!(unsafe { STREAM_BUFFER_REQUEST_FLAGS }, 0x58);
    }

    #[test]
    fn requested_cleanup_replaces_completion_result_and_clears_slot_flag() {
        let (_guard, _reset) = arrange(0x1234_5678);
        let _request_guard = STREAM_BUFFER_REQUEST_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _request_flags_reset = RequestFlagsReset;
        let _cleanup_guard = lock_pending_cleanup();
        let mut manager = [0xa5; 0x18];
        manager[UI_MANAGER_ACTIVE_OFFSET] = 1;
        manager[UI_MANAGER_PENDING_CLEANUP_OFFSET + 0x06] = 1;
        let manager_ptr = manager.as_mut_ptr();
        unsafe { STREAM_BUFFER_REQUEST_FLAGS = 0 };

        assert_eq!(unsafe { ui_manager_finish_pending_operation(manager_ptr, 1, 9) }, 0);
        assert_eq!(unsafe { COMPLETION_CALLS }, 1);
        assert_eq!(unsafe { COMPLETION_MANAGER }, manager_ptr as usize);
        assert_eq!(unsafe { COMPLETION_CLEANUP_REQUESTED }, 9);
        assert_eq!(manager[UI_MANAGER_PENDING_CLEANUP_OFFSET + 0x06], 0);
        assert_eq!(unsafe { STREAM_BUFFER_REQUEST_FLAGS }, UI_MANAGER_COMPLETION_REQUEST_MASK);
    }
}
