//! Lazy service-context initialization — FUN_0820c2c0 @ 0x0820c2c0.
//! True size: 68 bytes to 0x0820c304 (56 code + 12 literal bytes).
//! Raw A32 verification: two outgoing plain BLs, zero predicated BLs;
//! two inbound BLs: plain at 0x08114c74 and EQ at 0x0820c320.
//! If state+0xc is nonzero, return without touching the root or services.
//! Otherwise cache root+0x30, initialize the condition variable, then store
//! kernel_running() at state+0. A zero context does not latch initialization:
//! subsequent calls repeat both services. No locking or NULL-root guard.
//! Deviations: target globals retain their literal addresses; host globals
//! model the state/condition variable and reuse the shared APP_ROOT_OBJECT.
//! The two calls reuse the existing Rust ports; LLVM may inline kernel_running.

use crate::kernel::condvar::{condvar_init, CondVar};
use crate::kernel::sync_mutex::kernel_running;

#[repr(C)]
pub struct ServiceContextState {
    pub task_id: i32,
    pub reserved: [u32; 2],
    pub service_context: u32,
}

#[cfg(not(target_os = "none"))]
pub static mut SERVICE_CONTEXT_STATE: ServiceContextState = ServiceContextState {
    task_id: 0, reserved: [0; 2], service_context: 0,
};
#[cfg(not(target_os = "none"))]
static mut SERVICE_CONTEXT_CONDVAR: core::mem::MaybeUninit<CondVar> = core::mem::MaybeUninit::uninit();

#[inline(always)]
unsafe fn initialize(
    state: *mut ServiceContextState,
    root_context: impl FnOnce() -> u32,
    initialize_condition: impl FnOnce(),
    current_task: impl FnOnce() -> i32,
) {
    if unsafe { (*state).service_context } != 0 {
        return;
    }
    unsafe { (*state).service_context = root_context() };
    initialize_condition();
    unsafe { (*state).task_id = current_task() };
}

/// # Safety
/// The root must be readable through word +0x30 on the initialization path.
/// The globals and kernel services must be initialized and externally serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn service_context_initialize() {
    #[cfg(target_os = "none")]
    let (state, condition) = (0x089cc374 as *mut ServiceContextState, 0x08a78f8c as *mut CondVar);
    #[cfg(not(target_os = "none"))]
    let (state, condition) = (
        core::ptr::addr_of_mut!(SERVICE_CONTEXT_STATE),
        core::ptr::addr_of_mut!(SERVICE_CONTEXT_CONDVAR).cast::<CondVar>(),
    );
    unsafe {
        initialize(state, || {
            #[cfg(target_os = "none")]
            let root = (0x089ca674 as *const *const u32).read();
            #[cfg(not(target_os = "none"))]
            let root = crate::app::context_scope::app_root_object().cast::<u32>();
            root.add(0x30 / 4).read()
        }, || condvar_init(condition), || kernel_running());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn cached_context_skips_even_invalid_root_and_preserves_every_word() {
        let mut state = ServiceContextState { task_id: -7, reserved: [11, 22], service_context: 0x12345678 };
        unsafe { initialize(&mut state, || panic!("root read"), || panic!("condition initialized"), || panic!("task queried")) };
        assert_eq!((state.task_id, state.reserved, state.service_context), (-7, [11, 22], 0x12345678));
    }

    #[test]
    fn context_is_published_before_services_and_task_after_condition() {
        for context in [0, 0x08001234, u32::MAX] {
            let mut state = ServiceContextState { task_id: -9, reserved: [31, 47], service_context: 0 };
            let state_ptr = &mut state as *mut ServiceContextState;
            let stage = Cell::new(0);
            unsafe {
                initialize(state_ptr, || { stage.set(1); context }, || {
                    assert_eq!(stage.get(), 1);
                    assert_eq!((*state_ptr).service_context, context);
                    assert_eq!((*state_ptr).task_id, -9);
                    stage.set(2);
                }, || { assert_eq!(stage.get(), 2); stage.set(3); -123 });
            }
            assert_eq!(stage.get(), 3);
            assert_eq!((state.task_id, state.reserved, state.service_context), (-123, [31, 47], context));
            let calls = Cell::new(0);
            unsafe { initialize(&mut state, || context, || calls.set(calls.get() + 1), || 42) };
            assert_eq!(calls.get(), if context == 0 { 1 } else { 0 });
            assert_eq!(state.task_id, if context == 0 { 42 } else { -123 });
        }
    }
}
