//! `cxx_mutex_opaque_context_construct` — original: `FUN_08262a64` @
//! **0x08262a64** (32 bytes; 7 unconditional `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` establishes the complete extent: eight instructions from
//! 0x08262a64 through the `pop {r4, pc}` at 0x08262a80. The following `push`
//! at 0x08262a84 starts the next separately linked function; there is no
//! literal pool:
//!
//! ```text
//! 08262a64  push {r4,lr}
//! 08262a68  bl   0x08261e28  ; cxx_mutex_construct(this, r1, r2, r3)
//! 08262a6c  add  r0,r0,#0x1c
//! 08262a70  bl   0x0826291c  ; initialize_opaque_context(this + 0x1c)
//! 08262a74  sub  r0,r0,#0x1c
//! 08262a78  mov  r1,#0
//! 08262a7c  str  r1,[r0,#0x38]
//! 08262a80  pop  {r4,pc}
//! ```
//!
//! The constructor first builds the 0x1c-byte C++ mutex wrapper, then the
//! adjacent 0x1c-byte opaque context, and finally clears the outer object's
//! word at +0x38. It returns the original object through the two child
//! constructors' documented pointer-return contracts. Whole-image ARM
//! B/BL-immediate decoding finds exactly seven callers — 0x0815335c,
//! 0x08165100, 0x08196ee8, 0x081d6910, 0x081d7cb4, 0x081d8198, and
//! 0x081e6b60 — all unconditional `bl`; no predicated or tail-`b` calls.
//!
//! Source: `ipod-decomp/decomp/c/025/08262a64_FUN_08262a64.c`.
//!
//! No deliberate deviation: both direct callees are ported and invoked in
//! their retailOS order. The representation uses only `u32` words, so its
//! 0x3c-byte target layout remains 0x3c bytes on host builds.

use core::ptr;

use super::mutex::cxx_mutex_construct;
use super::opaque_context_initialize::initialize_opaque_context;

/// Number of u32 words in the 0x1c-byte mutex-wrapper child.
const CXX_MUTEX_WORDS: usize = 7;

/// C++ object built by [`cxx_mutex_opaque_context_construct`].
///
/// The child internals remain opaque here; only their fixed word-sized layout
/// and construction order are established by the raw ARM.
#[repr(C)]
pub struct CxxMutexOpaqueContext {
    mutex_wrapper: [u32; CXX_MUTEX_WORDS],
    opaque_context: [u32; CXX_MUTEX_WORDS],
    initialization_status: u32,
}

/// `cxx_mutex_opaque_context_construct` — original: `FUN_08262a64` @
/// **0x08262a64** (32 bytes; 7 unconditional direct `bl` call sites).
///
/// Constructs the mutex wrapper then the adjacent opaque context, clears the
/// final status word, and returns `this`. `mutex_param_2`, `scope_word0`, and
/// `scope_word1` preserve the incoming r1/r2/r3 register shape passed through
/// to `cxx_mutex_construct`; the parent function itself does not inspect them.
/// There is no NULL guard, matching retailOS.
///
/// # Safety
///
/// `this` must address a writable, properly aligned `CxxMutexOpaqueContext`.
/// The two child constructors impose their own safety contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_opaque_context_construct(
    this: *mut CxxMutexOpaqueContext,
    mutex_param_2: usize,
    scope_word0: usize,
    scope_word1: usize,
) -> *mut CxxMutexOpaqueContext {
    let mutex = cxx_mutex_construct(this.cast(), mutex_param_2, scope_word0, scope_word1)
        .cast::<CxxMutexOpaqueContext>();
    let context = ptr::addr_of_mut!((*mutex).opaque_context).cast::<u32>();
    let context = initialize_opaque_context(context);
    let owner = context.sub(CXX_MUTEX_WORDS).cast::<CxxMutexOpaqueContext>();
    ptr::addr_of_mut!((*owner).initialization_status).write(0);
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::mutex::{CxxMutexConstructOps, CXX_MUTEX_CONSTRUCT_OPS};
    use crate::cxx::opaque_context_initialize::{
        OpaqueContextInitializeOps, OPAQUE_CONTEXT_INITIALIZE_OPS,
    };
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct OpsRestore {
        mutex: CxxMutexConstructOps,
        opaque: OpaqueContextInitializeOps,
    }

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                CXX_MUTEX_CONSTRUCT_OPS = self.mutex;
                OPAQUE_CONTEXT_INITIALIZE_OPS = self.opaque;
            }
        }
    }

    static mut CALLS: [usize; 3] = [0; 3];
    static mut ATTR_SCOPE: [usize; 2] = [0; 2];
    static mut MUTEX_SCOPE: [usize; 2] = [0; 2];
    static mut DESTROY_SCOPE: [usize; 2] = [0; 2];
    static mut OPAQUE_CALLS: usize = 0;
    static mut OPAQUE_STATUS_AT_CALL: u32 = u32::MAX;
    static mut OPAQUE_SELECTOR: *const u32 = ptr::null();
    static mut OPAQUE_RETURN_STATUS: u32 = 0;

    unsafe extern "C" fn recording_attr_init(scope: *mut usize) {
        CALLS[0] += 1;
        ATTR_SCOPE = [scope.read(), scope.add(1).read()];
        scope.write(0x4d54_5841);
    }

    unsafe extern "C" fn recording_mutex_init(_this: *mut u8, scope: *mut usize) {
        CALLS[1] += 1;
        MUTEX_SCOPE = [scope.read(), scope.add(1).read()];
    }

    unsafe extern "C" fn recording_attr_destroy(scope: *mut usize) {
        CALLS[2] += 1;
        DESTROY_SCOPE = [scope.read(), scope.add(1).read()];
    }

    unsafe extern "C" fn recording_opaque_initialize(
        context: *mut u32,
        selector: *const u32,
    ) -> u32 {
        OPAQUE_CALLS += 1;
        OPAQUE_STATUS_AT_CALL = context.add(6).read();
        OPAQUE_SELECTOR = selector;
        // A write after the context proves the outer clear happens after the
        // entire opaque-context constructor returns.
        context.add(CXX_MUTEX_WORDS).write(0xffff_ffff);
        OPAQUE_RETURN_STATUS
    }

    fn install_recorders(return_status: u32) -> (parking_lot::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            let restore = OpsRestore {
                mutex: CXX_MUTEX_CONSTRUCT_OPS,
                opaque: OPAQUE_CONTEXT_INITIALIZE_OPS,
            };
            CALLS = [0; 3];
            ATTR_SCOPE = [0; 2];
            MUTEX_SCOPE = [0; 2];
            DESTROY_SCOPE = [0; 2];
            OPAQUE_CALLS = 0;
            OPAQUE_STATUS_AT_CALL = u32::MAX;
            OPAQUE_SELECTOR = ptr::null();
            OPAQUE_RETURN_STATUS = return_status;
            CXX_MUTEX_CONSTRUCT_OPS = CxxMutexConstructOps {
                attr_init: recording_attr_init,
                mutex_init: recording_mutex_init,
                attr_destroy: recording_attr_destroy,
            };
            OPAQUE_CONTEXT_INITIALIZE_OPS = OpaqueContextInitializeOps {
                initialize: recording_opaque_initialize,
            };
            (guard, restore)
        }
    }

    #[test]
    fn constructs_children_in_order_and_clears_outer_status_last() {
        let (_guard, _restore) = install_recorders(0x2a);
        let mut object = CxxMutexOpaqueContext {
            mutex_wrapper: [0xa5a5_a5a5; CXX_MUTEX_WORDS],
            opaque_context: [0xa5a5_a5a5; CXX_MUTEX_WORDS],
            initialization_status: 0xa5a5_a5a5,
        };

        let returned = unsafe {
            cxx_mutex_opaque_context_construct(&mut object, 0xdead_beef, 0x1111_2222, 0x3333_4444)
        };

        assert_eq!(returned, &mut object as *mut _, "r0 survives both child returns");
        assert_eq!(unsafe { CALLS }, [1, 1, 1], "one mutex child construction");
        assert_eq!(unsafe { ATTR_SCOPE }, [0x1111_2222, 0x3333_4444]);
        assert_eq!(unsafe { MUTEX_SCOPE }, [0x4d54_5841, 0x3333_4444]);
        assert_eq!(unsafe { DESTROY_SCOPE }, [0x4d54_5841, 0x3333_4444]);
        assert_eq!(unsafe { OPAQUE_CALLS }, 1, "one opaque child construction");
        assert_eq!(unsafe { OPAQUE_STATUS_AT_CALL }, 0, "child clears +0x18 first");
        assert_eq!(unsafe { OPAQUE_SELECTOR }, ptr::null(), "child passes NULL selector");
        assert_eq!(object.opaque_context[6], 0x2a, "child stores its returned status");
        assert_eq!(object.initialization_status, 0, "outer +0x38 clear is last");
        assert_eq!(core::mem::size_of::<CxxMutexOpaqueContext>(), 0x3c);
    }

    #[test]
    fn overwrites_prior_child_and_outer_error_statuses_without_a_branch() {
        let (_guard, _restore) = install_recorders(0);
        let mut object = CxxMutexOpaqueContext {
            mutex_wrapper: [0; CXX_MUTEX_WORDS],
            opaque_context: [0; CXX_MUTEX_WORDS],
            initialization_status: 0xfeed_face,
        };
        object.opaque_context[6] = 0xffff_ffff;

        let returned = unsafe { cxx_mutex_opaque_context_construct(&mut object, 0, 0, 0) };

        assert_eq!(returned, &mut object as *mut _);
        assert_eq!(unsafe { OPAQUE_STATUS_AT_CALL }, 0, "old child error is cleared before call");
        assert_eq!(object.opaque_context[6], 0, "zero status is retained");
        assert_eq!(object.initialization_status, 0, "old outer error is overwritten");
    }
}
