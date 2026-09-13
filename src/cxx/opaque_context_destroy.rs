//! `destroy_opaque_context` — original: `FUN_08262944` @ 0x08262944
//! (20 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` establishes the complete body between separately linked
//! functions at 0x08262944 and 0x08262958, with no literal pool:
//!
//! ```text
//! 08262944  push {r4, lr}
//! 08262948  mov  r4, r0
//! 0826294c  bl   0x082e7dd0
//! 08262950  mov  r0, r4
//! 08262954  pop  {r4, pc}
//! ```
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly seven
//! call sites, at 0x0818a2cc, 0x081d69c8, 0x081d7d6c, 0x08261c38,
//! 0x08261ccc, 0x082628dc, and 0x08262a8c. All seven are unconditional `bl`;
//! there are no predicated calls or tail `b` calls. No aligned data word in the
//! image equals 0x08262944, so it is not a vtable-dispatched destructor.
//!
//! # Algorithm
//!
//! Saves the opaque context pointer, passes it to `FUN_082e7dd0`, discards that
//! callee's status, and returns the original pointer. The target callee first
//! validates a context-specific magic word before it releases anything, but
//! the concrete object type and callee identity remain unrecovered.
//!
//! # Deliberate deviation
//!
//! `FUN_082e7dd0` is not ported. Target builds call its fixed retailOS address
//! indirectly; host tests use an injectable seam. This replaces the direct
//! `bl` with an indirect call while preserving its argument, unconditional
//! execution, ignored result, and the `r4`-restored return value.

use core::ffi::c_void;
#[cfg(not(target_os = "none"))]
use core::ptr;

/// Fixed retailOS address of the unported opaque-context teardown,
/// `FUN_082e7dd0`.
const RETAIL_OPAQUE_CONTEXT_DESTROY: usize = 0x082e_7dd0;

/// Host boundary for the unported opaque-context teardown.
#[derive(Clone, Copy)]
pub struct OpaqueContextDestroyOps {
    pub destroy: unsafe extern "C" fn(context: *mut c_void) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_destroy(_context: *mut c_void) -> u32 {
    0
}

/// Host seam for `FUN_082e7dd0`. Tests replace this with a recorder; target
/// builds instead call the original retailOS address directly.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_DESTROY_OPS: OpaqueContextDestroyOps = OpaqueContextDestroyOps {
    destroy: missing_opaque_context_destroy,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_context_destroy(context: *mut c_void) -> u32 {
    let destroy: unsafe extern "C" fn(*mut c_void) -> u32 =
        core::mem::transmute(RETAIL_OPAQUE_CONTEXT_DESTROY);
    destroy(context)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_context_destroy(context: *mut c_void) -> u32 {
    let destroy = ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_DESTROY_OPS.destroy));
    destroy(context)
}

/// `destroy_opaque_context` — original: `FUN_08262944` @ **0x08262944**
/// (20 bytes; 7 unconditional direct `bl` call sites, no predicated forms).
///
/// Calls the opaque-context teardown unconditionally, ignores its status, and
/// returns the original `context` pointer. It has no NULL guard or local
/// memory access; any validation and side effects belong to the callee.
///
/// # Safety
///
/// `context` must meet the unported teardown's opaque-object contract. The
/// wrapper itself only preserves and forwards the pointer, including NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_opaque_context(context: *mut c_void) -> *mut c_void {
    opaque_context_destroy(context);
    context
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                OPAQUE_CONTEXT_DESTROY_OPS = OpaqueContextDestroyOps {
                    destroy: missing_opaque_context_destroy,
                };
            }
        }
    }

    static mut CALL_COUNT: usize = 0;
    static mut SEEN_CONTEXT: *mut c_void = ptr::null_mut();
    static mut RETURN_STATUS: u32 = 0;

    unsafe extern "C" fn recording_destroy(context: *mut c_void) -> u32 {
        unsafe {
            CALL_COUNT += 1;
            SEEN_CONTEXT = context;
            RETURN_STATUS
        }
    }

    fn install_recorder(return_status: u32) -> (parking_lot::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            SEEN_CONTEXT = ptr::null_mut();
            RETURN_STATUS = return_status;
            OPAQUE_CONTEXT_DESTROY_OPS = OpaqueContextDestroyOps {
                destroy: recording_destroy,
            };
        }
        (guard, OpsRestore)
    }

    #[test]
    fn forwards_context_once_and_discards_teardown_status() {
        let (_guard, _restore) = install_recorder(0x1a);
        let mut context = [0xa5a5_a5a5u32; 7];

        let returned = unsafe { destroy_opaque_context(context.as_mut_ptr().cast()) };

        assert_eq!(unsafe { CALL_COUNT }, 1, "one unconditional bl");
        assert_eq!(unsafe { SEEN_CONTEXT }, context.as_mut_ptr().cast());
        assert_eq!(returned, context.as_mut_ptr().cast(), "mov r0, r4");
        assert_eq!(context, [0xa5a5_a5a5; 7], "the wrapper has no local stores");
    }

    #[test]
    fn forwards_null_without_a_wrapper_guard() {
        let (_guard, _restore) = install_recorder(0);

        let returned = unsafe { destroy_opaque_context(ptr::null_mut()) };

        assert_eq!(unsafe { CALL_COUNT }, 1, "NULL reaches the callee");
        assert_eq!(unsafe { SEEN_CONTEXT }, ptr::null_mut());
        assert_eq!(returned, ptr::null_mut());
    }
}
