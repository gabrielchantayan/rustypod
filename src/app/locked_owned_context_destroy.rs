//! Releases the controller's owned context under its mutex.
//!
/// `locked_owned_context_destroy` — original: `FUN_0817bfe8` @
/// **0x0817bfe8** (92 bytes, `0x0817bfe8..0x0817c044`; the next separately
/// linked function begins at `0x0817c044`). Raw ARM has **four plain,
/// unconditional `bl` instructions** and no predicated `bl` forms: lock
/// veneer `0x082621a8`, owned-context destroy `0x0817e0fc`, empty scoped-context
/// destroy `0x08270414`, and `operator_delete` @ `0x082aad24`; it tail-branches
/// to unlock veneer `0x082621ac`.
///
/// Locks the embedded POSIX mutex at `+0xa4c`. If the controller's owned context
/// word at `+0x58` is nonzero, it destroys that context with mode zero, reloads
/// the word, destroys its scoped subobject at `+4`, deletes the enclosing
/// allocation, and clears the ownership word. It then unlocks on every path.
///
/// Deliberate deviations: the direct, unported context destroy @ `0x0817e0fc`
/// is a target-address call with a host operation seam. Rust calls the ported
/// mutex endpoints and `operator_delete` normally instead of preserving the
/// original final tail branch to the unlock veneer.

use crate::heap::veneers::operator_delete;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use crate::app::scoped_context::{scoped_context_destroy, ScopedContext};

const OWNED_CONTEXT_OFFSET: usize = 0x58;
const MUTEX_OFFSET: usize = 0xa4c;
const OWNED_CONTEXT_DESTROY_ADDRESS: usize = 0x0817_e0fc;

type OwnedContextDestroy = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_owned_context(context: *mut u8) {
    let destroy: OwnedContextDestroy = core::mem::transmute(OWNED_CONTEXT_DESTROY_ADDRESS);
    destroy(context, 0);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owned_context_destroy(_context: *mut u8, _mode: u32) {
    panic!("locked_owned_context_destroy requires destroy helper 0x0817e0fc")
}

/// Host replacement for the direct, unported owned-context destroy.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ControllerOwnedContextDestroyOps {
    pub destroy: OwnedContextDestroy,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTROLLER_OWNED_CONTEXT_DESTROY_OPS: ControllerOwnedContextDestroyOps =
    ControllerOwnedContextDestroyOps { destroy: missing_owned_context_destroy };

/// Target builds always call `0x0817e0fc`; host tests install this seam.
#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_OWNED_CONTEXT_DESTROY_OPS: ControllerOwnedContextDestroyOps =
    DEFAULT_CONTROLLER_OWNED_CONTEXT_DESTROY_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_owned_context(context: *mut u8) {
    let destroy = core::ptr::read_volatile(core::ptr::addr_of!(
        CONTROLLER_OWNED_CONTEXT_DESTROY_OPS.destroy
    ));
    destroy(context, 0);
}

/// # Safety
///
/// `controller` must point to a writable retailOS controller object containing
/// a [`PosixMutex`] at `+0xa4c`. A nonzero `+0x58` word must be an owned context
/// allocation whose `+4` subobject is a valid [`ScopedContext`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locked_owned_context_destroy(controller: *mut u8) {
    let mutex = controller.add(MUTEX_OFFSET).cast::<PosixMutex>();
    posix_mutex_lock(mutex);

    if (controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>()).read() != 0 {
        let context = (controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>()).read() as usize as *mut u8;
        destroy_owned_context(context);
        let context = (controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>()).read() as usize as *mut u8;
        scoped_context_destroy(context.add(4).cast::<ScopedContext>());
        operator_delete(context);
        (controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>()).write(0);
    }

    posix_mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x2000;
    const CONTEXT_OFFSET: usize = 0x100;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LOCKED_OWNED_CONTEXT_DESTROY, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static mut DESTROYED_CONTEXT: *mut u8 = ptr::null_mut();
    static mut DESTROY_MODE: u32 = u32::MAX;

    unsafe extern "C" fn record_destroy(context: *mut u8, mode: u32) {
        DESTROYED_CONTEXT = context;
        DESTROY_MODE = mode;
    }

    fn fixture() -> Option<*mut u8> {
        (*FIXTURE).map(|pointer| {
            let base = pointer as *mut u8;
            unsafe { base.write_bytes(0, FIXTURE_LEN) };
            base
        })
    }

    #[test]
    fn destroys_owned_context_with_zero_mode_then_deletes_and_clears_slot() {
        let _guard = TEST_LOCK.lock();
        let Some(controller) = fixture() else {
            assert!(note_missing_u32_fixture("app/locked_owned_context_destroy"));
            return;
        };
        let _heap = mock_heap();
        let original_ops = unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS };
        unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS.destroy = record_destroy };
        unsafe { DESTROYED_CONTEXT = ptr::null_mut(); DESTROY_MODE = u32::MAX; }
        let context = unsafe { controller.add(CONTEXT_OFFSET) };
        unsafe { controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>().write(context as usize as u32) };

        unsafe { locked_owned_context_destroy(controller) };

        assert_eq!(unsafe { DESTROYED_CONTEXT }, context);
        assert_eq!(unsafe { DESTROY_MODE }, 0);
        assert_eq!(free_log(), (1, context, 2));
        assert_eq!(unsafe { controller.add(OWNED_CONTEXT_OFFSET).cast::<u32>().read() }, 0);
        unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS = original_ops };
    }

    #[test]
    fn leaves_null_owned_context_without_destroying_or_deleting() {
        let _guard = TEST_LOCK.lock();
        let Some(controller) = fixture() else {
            assert!(note_missing_u32_fixture("app/locked_owned_context_destroy"));
            return;
        };
        let _heap = mock_heap();
        let original_ops = unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS };
        unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS.destroy = record_destroy };
        unsafe { DESTROYED_CONTEXT = ptr::null_mut(); }

        unsafe { locked_owned_context_destroy(controller) };

        assert!(unsafe { DESTROYED_CONTEXT }.is_null());
        assert_eq!(free_log().0, 0);
        unsafe { CONTROLLER_OWNED_CONTEXT_DESTROY_OPS = original_ops };
    }
}
