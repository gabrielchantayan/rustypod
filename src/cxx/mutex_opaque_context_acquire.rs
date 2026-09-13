//! `cxx_mutex_opaque_context_acquire` — original: `FUN_08262974` @
//! **0x08262974** (80 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` establishes the complete extent: the 20 instructions from
//! `push {r4,r5,r6,lr}` at 0x08262974 through `pop {r4,r5,r6,pc}` at
//! 0x082629c0. The following `push {r4,r5,r6,lr}` at 0x082629c4 starts the
//! separately linked sibling; there is no literal pool:
//!
//! ```text
//! 08262974  push {r4,r5,r6,lr}
//! 08262978  mov  r4,r0
//! 0826297c  bl   0x08261e20  ; posix_mutex_lock(this)
//! 08262980  ldr  r1,[r4,#0x38]
//! 08262984  mov  r0,#0
//! 08262988  add  r2,r1,#1
//! 0826298c  cmp  r1,#0
//! 08262990  str  r2,[r4,#0x38]
//! 08262994  bge  0x082629b0
//! 08262998  add  r0,r4,#0x1c
//! 0826299c  bl   0x08262914  ; thunk to 0x082e7f78
//! 082629a0  cmp  r0,#0
//! 082629a4  ldrne r1,[r4,#0x38]
//! 082629a8  subne r1,r1,#1
//! 082629ac  strne r1,[r4,#0x38]
//! 082629b0  mov  r5,r0
//! 082629b4  mov  r0,r4
//! 082629b8  bl   0x08261e24  ; posix_mutex_unlock(this)
//! 082629bc  mov  r0,r5
//! 082629c0  pop  {r4,r5,r6,pc}
//! ```
//!
//! Whole-image ARM B/BL-immediate decoding finds six direct `bl` callers:
//! five unconditional (0x0818aa84, 0x081d7080, 0x081d7f00, 0x081d80f4, and
//! 0x081e6aa4) and one `bleq` (0x08153338). There are no tail `b` callers and
//! no aligned data words equal to 0x08262974.
//!
//! # Algorithm
//!
//! Under the embedded mutex, increment the signed activity count at +0x38.
//! A prior negative count activates the adjacent opaque context at +0x1c. If
//! that activation fails, decrement the *reloaded* count and return its status;
//! otherwise return zero. Both mutex statuses are deliberately ignored.
//!
//! # Deliberate deviation
//!
//! The activation routine at 0x082e7f78 remains unported, so target builds
//! call its retail address indirectly and host tests install a seam. This
//! changes that direct `bl` into `blx` while preserving the context argument,
//! activation condition, status return, and failure rollback.

use core::ptr;

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

use super::mutex_opaque_context_construct::CxxMutexOpaqueContext;

/// Fixed retailOS address of the unported opaque-context activation routine,
/// `FUN_082e7f78`.
const RETAIL_OPAQUE_CONTEXT_ACTIVATE: usize = 0x082e_7f78;

/// Host boundary for the unported opaque-context activation routine.
#[derive(Clone, Copy)]
pub struct OpaqueContextActivateOps {
    pub activate: unsafe extern "C" fn(context: *mut u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_activate(_context: *mut u32) -> u32 {
    0
}

/// Host seam for `FUN_082e7f78`. Tests replace this with a recorder; target
/// builds instead call the original retailOS address directly.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_ACTIVATE_OPS: OpaqueContextActivateOps = OpaqueContextActivateOps {
    activate: missing_opaque_context_activate,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_context_activate(context: *mut u32) -> u32 {
    let activate: unsafe extern "C" fn(*mut u32) -> u32 =
        core::mem::transmute(RETAIL_OPAQUE_CONTEXT_ACTIVATE);
    activate(context)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_context_activate(context: *mut u32) -> u32 {
    let activate = ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ACTIVATE_OPS.activate));
    activate(context)
}

/// `cxx_mutex_opaque_context_acquire` — original: `FUN_08262974` @
/// **0x08262974** (80 bytes; 6 direct `bl` callers: 5 unconditional and 1
/// `bleq`, no tail calls or data dispatch).
///
/// Increments `this.active_context_count` while holding the embedded mutex.
/// When its prior signed value was negative, activates `this.opaque_context`.
/// An activation failure rolls the count back by one and becomes the result;
/// otherwise the function returns zero. Lock and unlock statuses are ignored,
/// and there is no NULL guard, matching retailOS.
///
/// # Safety
///
/// `this` must address a writable, properly aligned `CxxMutexOpaqueContext`.
/// Its mutex and opaque child must satisfy their respective retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_opaque_context_acquire(
    this: *mut CxxMutexOpaqueContext,
) -> u32 {
    posix_mutex_lock(this.cast::<PosixMutex>());

    let prior_count = (*this).active_context_count;
    (*this).active_context_count = prior_count.wrapping_add(1);

    let mut status = 0;
    if (prior_count as i32) < 0 {
        status = opaque_context_activate(ptr::addr_of_mut!((*this).opaque_context).cast());
        if status != 0 {
            (*this).active_context_count = (*this).active_context_count.wrapping_sub(1);
        }
    }

    posix_mutex_unlock(this.cast::<PosixMutex>());
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVATION_CALLS: usize = 0;
    static mut ACTIVATION_CONTEXT: *mut u32 = ptr::null_mut();
    static mut ACTIVATION_STATUS: u32 = 0;

    struct OpsRestore(OpaqueContextActivateOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { OPAQUE_CONTEXT_ACTIVATE_OPS = self.0; }
        }
    }

    unsafe extern "C" fn recording_activate(context: *mut u32) -> u32 {
        ACTIVATION_CALLS += 1;
        ACTIVATION_CONTEXT = context;
        ACTIVATION_STATUS
    }

    fn install_recorder(status: u32) -> (parking_lot::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            let restore = OpsRestore(OPAQUE_CONTEXT_ACTIVATE_OPS);
            ACTIVATION_CALLS = 0;
            ACTIVATION_CONTEXT = ptr::null_mut();
            ACTIVATION_STATUS = status;
            OPAQUE_CONTEXT_ACTIVATE_OPS = OpaqueContextActivateOps {
                activate: recording_activate,
            };
            (guard, restore)
        }
    }

    fn object_with_count(active_context_count: u32) -> CxxMutexOpaqueContext {
        CxxMutexOpaqueContext {
            mutex_wrapper: [0; 7],
            opaque_context: [0x5a5a_5a5a; 7],
            active_context_count,
        }
    }

    #[test]
    fn nonnegative_count_increments_without_activation() {
        let (_guard, _restore) = install_recorder(0x71);
        let mut object = object_with_count(0);

        let status = unsafe { cxx_mutex_opaque_context_acquire(&mut object) };

        assert_eq!(status, 0);
        assert_eq!(object.active_context_count, 1);
        assert_eq!(unsafe { ACTIVATION_CALLS }, 0);
        assert_eq!(object.opaque_context, [0x5a5a_5a5a; 7]);
    }

    #[test]
    fn negative_count_activates_and_keeps_increment_on_success() {
        let (_guard, _restore) = install_recorder(0);
        let mut object = object_with_count(u32::MAX - 1);
        let expected_context = object.opaque_context.as_mut_ptr();

        let status = unsafe { cxx_mutex_opaque_context_acquire(&mut object) };

        assert_eq!(status, 0);
        assert_eq!(object.active_context_count, u32::MAX);
        assert_eq!(unsafe { ACTIVATION_CALLS }, 1);
        assert_eq!(unsafe { ACTIVATION_CONTEXT }, expected_context);
    }

    #[test]
    fn activation_failure_restores_count_and_returns_status() {
        let (_guard, _restore) = install_recorder(0x42);
        let mut object = object_with_count(u32::MAX);

        let status = unsafe { cxx_mutex_opaque_context_acquire(&mut object) };

        assert_eq!(status, 0x42);
        assert_eq!(object.active_context_count, u32::MAX);
        assert_eq!(unsafe { ACTIVATION_CALLS }, 1);
    }
}
