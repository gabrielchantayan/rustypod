//! `destroy_opaque_context_and_mutex` — original: `FUN_08262a84` @ 0x08262a84
//! (24 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` establishes the complete body from 0x08262a84 through the
//! tail branch at 0x08262a98; the separately linked `push {r4, lr}` at
//! 0x08262a9c is the next function, and there is no literal pool:
//!
//! ```text
//! 08262a84  push {r4, lr}
//! 08262a88  add  r0, r0, #0x1c
//! 08262a8c  bl   0x08262944
//! 08262a90  pop  {r4, lr}
//! 08262a94  sub  r0, r0, #0x1c
//! 08262a98  b    0x08261e54
//! ```
//!
//! Whole-image ARM branch decoding finds five direct unconditional `bl`
//! callers (0x081533b4, 0x081d6a8c, 0x081d7e30, 0x081d81e0, 0x081e6c1c), no
//! predicated `bl` callers, and no direct tail-branch callers.
//!
//! # Algorithm
//!
//! Destroys the opaque context embedded at `this + 0x1c`, converts its
//! returned pointer back to `this`, then tail-calls the C++ mutex wrapper on
//! that pointer. The wrapper returns `this`; pthread mutex-destroy status is
//! deliberately discarded.
//!
//! # Deliberate deviation
//!
//! The opaque-context retail callee is represented by its existing Rust port
//! and host seam. The C++ mutex wrapper is likewise called through its Rust
//! port, preserving unguarded calls, pointer adjustment, call order, and the
//! original-pointer return while the ultimate pthread callee remains unhooked.

use core::ffi::c_void;

use super::opaque_context_destroy::destroy_opaque_context;

/// `destroy_opaque_context_and_mutex` — original: `FUN_08262a84` @
/// **0x08262a84** (24 bytes; five unconditional direct `bl` call sites, no
/// predicated forms).
///
/// Tears down the opaque context at byte offset 0x1c, then returns `this`
/// through the C++ mutex wrapper. There is no NULL guard; the original pointer
/// arithmetic and both callees receive their natural ARM values.
///
/// # Safety
///
/// `this` must satisfy both embedded-context and mutex-destroy contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_opaque_context_and_mutex(this: *mut u8) -> *mut u8 {
    let context = destroy_opaque_context(this.wrapping_add(0x1c).cast::<c_void>());
    super::mutex_destroy::cxx_mutex_destroy(context.cast::<u8>().wrapping_sub(0x1c))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::mutex_destroy::{CxxMutexDestroyOps, DEFAULT_CXX_MUTEX_DESTROY_OPS, CXX_MUTEX_DESTROY_OPS};
    use crate::cxx::opaque_context_destroy::{OpaqueContextDestroyOps, OPAQUE_CONTEXT_DESTROY_OPS};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT_ARGUMENT: *mut c_void = core::ptr::null_mut();
    static mut MUTEX_ARGUMENT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_context(context: *mut c_void) -> u32 {
        CONTEXT_ARGUMENT = context;
        0x1a
    }

    unsafe extern "C" fn missing_context(_context: *mut c_void) -> u32 { 0 }

    unsafe extern "C" fn record_mutex(mutex: *mut u8) -> u32 {
        MUTEX_ARGUMENT = mutex;
        0x14
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                OPAQUE_CONTEXT_DESTROY_OPS = OpaqueContextDestroyOps { destroy: missing_context };
                CXX_MUTEX_DESTROY_OPS = DEFAULT_CXX_MUTEX_DESTROY_OPS;
            }
        }
    }

    fn install_recorders() -> RestoreOps {
        unsafe {
            CONTEXT_ARGUMENT = core::ptr::null_mut();
            MUTEX_ARGUMENT = core::ptr::null_mut();
            OPAQUE_CONTEXT_DESTROY_OPS = OpaqueContextDestroyOps { destroy: record_context };
            CXX_MUTEX_DESTROY_OPS = CxxMutexDestroyOps { mutex_destroy: record_mutex };
        }
        RestoreOps
    }

    #[test]
    fn destroys_embedded_context_then_returns_this_through_mutex_wrapper() {
        let _lock = OPS_LOCK.lock();
        let _restore = install_recorders();
        let mut object = [0xa5u8; 0x40];
        let this = object.as_mut_ptr();

        let returned = unsafe { destroy_opaque_context_and_mutex(this) };

        assert_eq!(unsafe { CONTEXT_ARGUMENT }, unsafe { this.add(0x1c).cast() });
        assert_eq!(unsafe { MUTEX_ARGUMENT }, this);
        assert_eq!(returned, this, "the tail-called C++ mutex wrapper returns this");
        assert_eq!(object, [0xa5; 0x40], "the wrapper has no local stores");
    }

    #[test]
    fn forwards_null_through_the_unchecked_pointer_adjustment() {
        let _lock = OPS_LOCK.lock();
        let _restore = install_recorders();

        let returned = unsafe { destroy_opaque_context_and_mutex(core::ptr::null_mut()) };

        assert_eq!(unsafe { CONTEXT_ARGUMENT as usize }, 0x1c);
        assert!(unsafe { MUTEX_ARGUMENT.is_null() });
        assert!(returned.is_null());
    }
}
