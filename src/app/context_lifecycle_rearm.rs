//! Releases a context's lifecycle guard, notifies the framework root, then reacquires it.
//!
//! `context_lifecycle_rearm` — original: `FUN_081f0888` @ **0x081f0888**
//! (**40 bytes exactly**, `0x081f0888..0x081f08b0`; the `push {r3,lr}` at
//! `0x081f08b0` starts the next real function). Whole-image A32 decoding finds
//! three inbound direct `bl` calls, all predicated `blne` at `0x081f0650`,
//! `0x081f12b4`, and `0x081f13ac`; no plain inbound form occurs. The body has
//! three outgoing plain `bl` instructions (`mutex_unlock` @ `0x0807f6a0`,
//! `framework_root_get` @ `0x0814b460`, and the unported framework-root
//! operation @ `0x0814b4b4`), no predicated outbound BL instructions, and a
//! tail `b` to `mutex_lock` @ `0x0807f5c4`.
//!
//! Algorithm: unlock the lifecycle guard at context `+0x50`, call the
//! framework-root operation with the current root and context, then lock that
//! same guard again. The root is passed through unchanged, including NULL.
//!
//! Deliberate deviation: `0x0814b4b4` is not yet ported, so target builds call
//! its verified address and host builds use a narrow callback seam. Its name
//! here describes only its observed framework-root/context role.

use crate::app::framework_root::framework_root_get;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const LIFECYCLE_GUARD_OFFSET: usize = 0x50;

pub type FrameworkRootContextOperation = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_framework_root_context_operation(_root: *mut u8, _context: *mut u8) {}

/// Host seam for the unported framework-root operation at `0x0814b4b4`.
#[cfg(not(target_os = "none"))]
pub static mut FRAMEWORK_ROOT_CONTEXT_OPERATION: FrameworkRootContextOperation = missing_framework_root_context_operation;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn framework_root_context_operation() -> FrameworkRootContextOperation {
    core::mem::transmute(0x0814_b4b4usize)
}

/// Rearms a context's lifecycle guard after notifying the framework root.
///
/// `context` must be valid through its `Mutex` at `+0x50`; retailOS performs
/// no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_lifecycle_rearm")]
pub unsafe extern "C" fn context_lifecycle_rearm(context: *mut u8) {
    let guard = unsafe { context.add(LIFECYCLE_GUARD_OFFSET).cast::<Mutex>() };
    unsafe { mutex_unlock(guard) };

    let root = unsafe { framework_root_get() };
    #[cfg(target_os = "none")]
    unsafe { framework_root_context_operation()(root, context) };
    #[cfg(not(target_os = "none"))]
    unsafe { FRAMEWORK_ROOT_CONTEXT_OPERATION(root, context) };

    unsafe { mutex_lock(guard) };
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::framework_root::FRAMEWORK_ROOT;
    use core::ptr;
    use std::sync::Mutex as StdMutex;

    #[repr(C)]
    struct Context {
        prefix: [u8; LIFECYCLE_GUARD_OFFSET],
        guard: Mutex,
    }

    static TEST_LOCK: StdMutex<()> = StdMutex::new(());
    static mut OPERATION_ARGS: (usize, usize) = (0, 0);

    unsafe extern "C" fn record_operation(root: *mut u8, context: *mut u8) {
        unsafe { OPERATION_ARGS = (root as usize, context as usize); }
    }

    #[test]
    fn passes_initialized_root_and_original_context_to_framework_operation() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut context = Context {
            prefix: [0; LIFECYCLE_GUARD_OFFSET],
            guard: Mutex { sem_cell: ptr::null_mut(), unused: 0 },
        };
        let root = 0x1234_5678usize as *mut u8;
        unsafe {
            FRAMEWORK_ROOT = root;
            OPERATION_ARGS = (0, 0);
            FRAMEWORK_ROOT_CONTEXT_OPERATION = record_operation;
            context_lifecycle_rearm((&mut context as *mut Context).cast());
            assert_eq!(OPERATION_ARGS, (root as usize, (&context as *const Context) as usize));
            FRAMEWORK_ROOT = ptr::null_mut();
        }
    }

    #[test]
    fn passes_null_root_without_a_guard() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut context = Context {
            prefix: [0; LIFECYCLE_GUARD_OFFSET],
            guard: Mutex { sem_cell: ptr::null_mut(), unused: 0 },
        };
        unsafe {
            FRAMEWORK_ROOT = ptr::null_mut();
            OPERATION_ARGS = (usize::MAX, 0);
            FRAMEWORK_ROOT_CONTEXT_OPERATION = record_operation;
            context_lifecycle_rearm((&mut context as *mut Context).cast());
            assert_eq!(OPERATION_ARGS, (0, (&context as *const Context) as usize));
        }
    }
}
