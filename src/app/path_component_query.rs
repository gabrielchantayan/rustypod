//! Scoped path-component query wrapper.
//!
//! Port: [`path_component_query`] — original: `FUN_0809b678` @
//! **0x0809b678** (48 bytes; **12 plain `bl` call sites, 0 predicated
//! `bl`, 0 `b`**, binary-scanned by decoding every ARM branch in
//! `osos.dec`).
//!
//! ## Algorithm
//!
//! Builds a two-word derived [`StringObject`] path object in its r2/r3
//! stack spill slots, calls the component-query helper at 0x0809b6a8,
//! destroys the storage through `string_object_destroy_veneer`, then
//! returns the helper status unchanged. Raw ARM:
//!
//! ```text
//! 0809b678  stmdb sp!, {r2,r3,r4,lr}
//! 0809b67c  mov   r4,r1
//! 0809b680  mov   r1,r0
//! 0809b684  mov   r0,sp
//! 0809b688  bl    0x08279284  @ path_object_construct
//! 0809b68c  mov   r1,r4
//! 0809b690  bl    0x0809b6a8  @ component-query helper
//! 0809b694  mov   r4,r0
//! 0809b698  mov   r0,sp
//! 0809b69c  bl    0x082792fc  @ string_object_destroy_veneer
//! 0809b6a0  mov   r0,r4
//! 0809b6a4  ldmia sp!, {r2,r3,r4,pc}
//! ```
//!
//! All twelve callers pass a path C string and zero as the second word;
//! callers branch on its status, with several distinguishing 0 and 13 for
//! setup/error paths. The name
//! intentionally does not claim a particular filesystem operation: the
//! 0x0809b6a8 helper invokes the still-unported 0x08149e38, whose exact
//! facade-slot semantics are not established.
//!
//! ## Faithful details and deviations
//!
//! The path object passed to the helper is the constructor's return; the
//! destructor always receives the original stack storage. `r4` forwards
//! arg2 to 0x0809b6a8, but that helper overwrites its saved r4 from r0 and
//! never reads r1, so arg2 is dead in the complete stock composition.
//! `path_object_construct` and `string_object_destroy_veneer` are already
//! ported and called directly. The unresolved helper remains a dispatch
//! boundary: device builds call its fixed retailOS address; host builds
//! fail closed with status 0. No identity is invented for it.

use core::mem::MaybeUninit;

use crate::app::path_object_construct::path_object_construct;
use crate::cxx::string_object::{string_object_destroy_veneer, StringObject};

/// The 0x0809b6a8 helper's ABI. Its second word is received from this
/// wrapper but is dead inside the helper's decoded body.
pub type PathComponentQueryWorker =
    unsafe extern "C" fn(path_object: *mut StringObject, unused: u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_path_component_query(
    path_object: *mut StringObject,
    unused: u32,
) -> u32 {
    let worker: PathComponentQueryWorker = core::mem::transmute(0x0809_b6a8usize);
    worker(path_object, unused)
}

/// Host boundary for the unresolved helper. Zero is the stock status used
/// by callers to enter their setup path, so this is deliberately fail-closed.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_path_component_query(
    _path_object: *mut StringObject,
    _unused: u32,
) -> u32 {
    0
}

/// Active component-query helper. This exists solely at the unported
/// 0x0809b6a8 boundary: target builds call retailOS while host tests install
/// a recording implementation.
pub static mut PATH_COMPONENT_QUERY_WORKER: PathComponentQueryWorker =
    firmware_path_component_query;

/// `path_component_query` — original: `FUN_0809b678` @ **0x0809b678**
/// (48 bytes; **12 plain `bl` call sites, 0 predicated, 0 tail branches**).
///
/// Constructs a derived path object from `path`, queries its unresolved
/// component helper with `unused`, destroys the stack storage, and returns
/// the helper's status verbatim. The complete stock helper discards
/// `unused`; it remains in the ABI because this wrapper forwards it exactly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_component_query(path: *const u8, unused: u32) -> u32 {
    let mut guard = MaybeUninit::<StringObject>::uninit();
    let guard = guard.as_mut_ptr();
    let path_object = path_object_construct(guard, path);
    let worker = core::ptr::addr_of!(PATH_COMPONENT_QUERY_WORKER).read_volatile();
    let status = worker(path_object, unused);
    string_object_destroy_veneer(guard);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::cxx::string_object::{StringObjectOps, STRING_OBJECT_OPS, STRING_OBJECT_VTABLE};
    use std::sync::Mutex;

    static PATH_COMPONENT_QUERY_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;
    static mut WORKER_PATH_OBJECT: *mut StringObject = core::ptr::null_mut();
    static mut WORKER_UNUSED: u32 = 0;
    static mut WORKER_VTABLE: usize = 0;
    static mut WORKER_STATUS: u32 = 0;
    static mut DESTROYED_STORAGE: *mut StringObject = core::ptr::null_mut();

    unsafe extern "C" fn recording_worker(
        path_object: *mut StringObject,
        unused: u32,
    ) -> u32 {
        EVENTS[EVENT_COUNT] = 1;
        EVENT_COUNT += 1;
        WORKER_PATH_OBJECT = path_object;
        WORKER_UNUSED = unused;
        WORKER_VTABLE = (*path_object).vtable as usize;
        WORKER_STATUS
    }

    unsafe extern "C" fn recording_release(this: *mut StringObject) {
        EVENTS[EVENT_COUNT] = 2;
        EVENT_COUNT += 1;
        DESTROYED_STORAGE = this;
    }

    struct SeamGuard {
        saved_ops: StringObjectOps,
    }

    impl SeamGuard {
        unsafe fn new() -> Self {
            SeamGuard {
                saved_ops: core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile(),
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_COMPONENT_QUERY_WORKER)
                    .write_volatile(firmware_path_component_query);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.saved_ops);
            }
        }
    }

    unsafe fn install_recording() {
        EVENTS = [0; 2];
        EVENT_COUNT = 0;
        WORKER_PATH_OBJECT = core::ptr::null_mut();
        WORKER_UNUSED = 0;
        WORKER_VTABLE = 0;
        DESTROYED_STORAGE = core::ptr::null_mut();
        core::ptr::addr_of_mut!(PATH_COMPONENT_QUERY_WORKER).write_volatile(recording_worker);
        let mut ops = core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile();
        ops.release_payload = recording_release;
        core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(ops);
    }

    #[test]
    fn constructs_queries_and_destroys_for_all_abi_words() {
        let _query_lock = PATH_COMPONENT_QUERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = unsafe { SeamGuard::new() };
        const PATH: &[u8] = b"iPod_Control/Device\0";

        unsafe {
            for (unused, status) in [(0, 0), (1, 13), (0x5a5a_f00d, 53)] {
                install_recording();
                WORKER_STATUS = status;
                assert_eq!(
                    path_component_query(PATH.as_ptr(), unused),
                    status,
                    "the helper status survives the destructor"
                );
                assert_eq!(EVENTS, [1, 2], "construct -> query -> destroy scope");
                assert!(!WORKER_PATH_OBJECT.is_null(), "the path object was constructed");
                assert_eq!(WORKER_UNUSED, unused, "r4 forwards arg2 into the helper");
                assert_eq!(
                    WORKER_VTABLE,
                    crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS,
                    "the worker sees the derived path-class vtable"
                );
                assert_eq!(
                    DESTROYED_STORAGE,
                    WORKER_PATH_OBJECT,
                    "the ported constructor returns its storage, which the destructor receives"
                );
                assert_eq!(
                    (*DESTROYED_STORAGE).vtable as usize,
                    &STRING_OBJECT_VTABLE as *const _ as usize,
                    "the destructor restores the base vtable before releasing"
                );
            }
        }
    }

    #[test]
    fn host_default_fails_closed() {
        let _query_lock = PATH_COMPONENT_QUERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = unsafe { SeamGuard::new() };
        const PATH: &[u8] = b"Calendars\0";

        unsafe {
            let default = core::ptr::addr_of!(PATH_COMPONENT_QUERY_WORKER).read_volatile();
            assert_eq!(
                default as usize,
                firmware_path_component_query as usize,
                "the only unresolved boundary is the 0x0809b6a8 helper"
            );
            assert_eq!(path_component_query(PATH.as_ptr(), 0), 0);
        }
    }
}
