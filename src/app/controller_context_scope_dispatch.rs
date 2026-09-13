//! `controller_context_scope_dispatch` — original: `FUN_0821995c` @
//! **0x0821995c** (**80 bytes exactly**, 0x0821995c..0x082199ac).
//!
//! Raw ARM starts with `push {lr}` at 0x0821995c and its final `pop {pc}` is
//! at 0x082199a8; the next independently linked function starts at
//! 0x082199ac. Decoding every aligned ARM `B`/`BL` word in `osos.dec` finds
//! exactly six direct inbound `bl` call sites, all unconditional:
//! 0x0821948c, 0x0821961c, 0x082268dc, 0x082324e0, 0x08238ab8, and
//! 0x08238c3c. There are no predicated or direct tail-branch callers.
//!
//! ## Algorithm
//!
//! Acquires the refcounted body held at controller +0xb4, obtains its
//! implementation pointer through the NULL-guarded handle accessor, and calls
//! virtual slot 143 (+0x23c) with a stack-local 20-byte context-scope record.
//! It then releases the body, passes the record to the unported
//! `FUN_08284034` (which sets byte +0x618 of its +0x04 subject), and finally
//! runs the context-scope's empty destructor.
//!
//! ## Deliberate deviation
//!
//! The acquire, handle access, release, and empty destructor are already
//! ported and called directly. `FUN_08284034` is not ported; its explicit
//! volatile seam reaches the firmware address on target builds and lets host
//! tests install the raw observed byte-store behavior. Its wider semantic
//! identity is deliberately not inferred.

use core::ptr::{addr_of, addr_of_mut};
use crate::app::context_scope::context_scope_drop;

use crate::cxx::handle::{
    handle_deref_or_null, refcounted_body_acquire_from_controller, refcounted_body_release,
    BodyBearingController, RefcountedBody,
};

/// Firmware address of the unported post-dispatch scope-subject marker.
pub const CONTEXT_SCOPE_SUBJECT_MARK_ADDRESS: usize = 0x0828_4034;

const CONTEXT_SCOPE_WORDS: usize = 5;
const CONTEXT_SCOPE_SUBJECT_WORD: usize = 1;
const CONTEXT_SCOPE_DISPATCH_SLOT: usize = 0x23c / 4;

/// Dispatch table for the unported post-dispatch scope-subject marker.
#[derive(Clone, Copy)]
struct ControllerContextScopeDispatchOps {
    mark_scope_subject: unsafe extern "C" fn(scope: *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_mark_scope_subject(scope: *mut u8) {
    let mark: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(CONTEXT_SCOPE_SUBJECT_MARK_ADDRESS) };
    unsafe { mark(scope) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mark_scope_subject(_scope: *mut u8) {
    panic!("controller_context_scope_dispatch requires firmware callee 0x08284034")
}

#[cfg(target_os = "none")]
static mut CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS: ControllerContextScopeDispatchOps =
    ControllerContextScopeDispatchOps {
        mark_scope_subject: firmware_mark_scope_subject,
    };

#[cfg(not(target_os = "none"))]
static mut CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS: ControllerContextScopeDispatchOps =
    ControllerContextScopeDispatchOps {
        mark_scope_subject: missing_mark_scope_subject,
    };

#[inline(always)]
fn controller_context_scope_dispatch_ops() -> ControllerContextScopeDispatchOps {
    unsafe { addr_of!(CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS).read_volatile() }
}

/// `controller_context_scope_dispatch` — original: `FUN_0821995c` @
/// 0x0821995c (80 bytes; 6 direct unconditional `bl` call sites).
///
/// Acquires the controller's body, dispatches its implementation's vtable
/// slot 143 with an uninitialized 20-byte context scope, releases the body,
/// then marks the scope's subject through `FUN_08284034`. Neither the
/// controller/body/implementation nor the virtual dispatch result is
/// NULL-checked by retailOS.
///
/// # Safety
///
/// `controller` must be readable through its body field. Its non-NULL body,
/// implementation, vtable slot 143, and callback-produced context scope must
/// satisfy the requirements encoded by the retailOS call sequence.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_context_scope_dispatch(
    controller: *const BodyBearingController,
) {
    type ContextScopeDispatch = unsafe extern "C" fn(*mut u8, *mut u8);

    let mut body: *mut RefcountedBody = core::ptr::null_mut();
    unsafe { refcounted_body_acquire_from_controller(addr_of_mut!(body), controller) };

    let implementation = unsafe {
        handle_deref_or_null(addr_of!(body).cast::<*const *mut u8>())
    };
    let vtable = unsafe { implementation.cast::<usize>().read() as *const usize };
    let dispatch: ContextScopeDispatch = unsafe {
        core::mem::transmute(vtable.add(CONTEXT_SCOPE_DISPATCH_SLOT).read())
    };
    let mut scope = core::mem::MaybeUninit::<[u32; CONTEXT_SCOPE_WORDS]>::uninit();
    unsafe { dispatch(implementation, scope.as_mut_ptr().cast()) };

    unsafe { refcounted_body_release(addr_of_mut!(body)) };
    let mark_scope_subject = controller_context_scope_dispatch_ops().mark_scope_subject;
    unsafe { mark_scope_subject(scope.as_mut_ptr().cast()) };
    let _ = unsafe { context_scope_drop(scope.as_mut_ptr().cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SUBJECT_FLAG_OFFSET: usize = 0x618;
    const SLAB_LEN: usize = 0x1000;
    const SUBJECT_OFFSET: usize = 0x100;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTROLLER_CONTEXT_SCOPE_DISPATCH, SLAB_LEN)
            .map(|pointer| pointer as usize)
    });
    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<&'static str>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn populate_scope(implementation: *mut u8, scope: *mut u8) {
        assert!(!implementation.is_null());
        EVENTS.lock().push("dispatch");
        unsafe {
            scope
                .cast::<u32>()
                .add(CONTEXT_SCOPE_SUBJECT_WORD)
                .write((*SLAB).expect("fixture present") as u32 + SUBJECT_OFFSET as u32);
        }
    }

    unsafe extern "C" fn record_and_mark_scope_subject(scope: *mut u8) {
        EVENTS.lock().push("mark");
        let subject = unsafe {
            scope
                .cast::<u32>()
                .add(CONTEXT_SCOPE_SUBJECT_WORD)
                .read() as usize as *mut u8
        };
        unsafe { subject.add(SUBJECT_FLAG_OFFSET).write(1) };
    }

    struct OpsRestore(ControllerContextScopeDispatchOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS).write_volatile(self.0)
            };
        }
    }

    #[test]
    fn dispatches_scope_then_releases_body_then_marks_scope_subject() {
        let _ops_lock = OPS_TEST_LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("app::controller_context_scope_dispatch"));
            return;
        };
        unsafe { (slab as *mut u8).write_bytes(0, SLAB_LEN) };
        EVENTS.lock().clear();

        let old_ops = unsafe { addr_of!(CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS).read_volatile() };
        let _ops_restore = OpsRestore(old_ops);
        unsafe {
            addr_of_mut!(CONTROLLER_CONTEXT_SCOPE_DISPATCH_OPS).write_volatile(
                ControllerContextScopeDispatchOps {
                    mark_scope_subject: record_and_mark_scope_subject,
                },
            );
        }

        let mut vtable = [0usize; CONTEXT_SCOPE_DISPATCH_SLOT + 1];
        vtable[CONTEXT_SCOPE_DISPATCH_SLOT] = populate_scope as usize;
        let mut implementation = [vtable.as_mut_ptr() as usize];
        let implementation_ptr = implementation.as_mut_ptr().cast::<u8>();
        let mut body = RefcountedBody {
            opaque0: implementation_ptr as usize,
            refcount: 2,
            mutex: core::ptr::null_mut(),
        };
        let mut controller = BodyBearingController {
            opaque_prefix: [0; 45],
            body: &mut body,
        };

        unsafe { controller_context_scope_dispatch(&mut controller) };

        assert_eq!(body.refcount, 2, "the acquired reference is released after dispatch");
        assert_eq!(unsafe { (slab as *const u8).add(SUBJECT_OFFSET + SUBJECT_FLAG_OFFSET).read() }, 1);
        assert_eq!(
            EVENTS.lock().as_slice(),
            ["dispatch", "mark"],
            "the subject marker runs only after virtual dispatch"
        );
    }
}
