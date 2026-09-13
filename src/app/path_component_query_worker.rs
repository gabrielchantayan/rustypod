//! Scoped facade path-component query worker.
//!
//! Port: [`path_component_query_worker`] — original: `FUN_0809b6a8` @
//! **0x0809b6a8** (60 bytes; **7 plain `bl` call sites, 0 predicated `bl`,
//! 0 tail `b`**, verified by decoding every ARM `B`/`BL` immediate in
//! `osos.dec`: 0x0809b690, 0x0813ac64, 0x0815e880, 0x081a29bc,
//! 0x081ee7f0, 0x0825878c, and 0x08285774).
//!
//! ## Algorithm
//!
//! Uses its r0-r3 spill slots as a 16-byte [`InterfaceGuard`], preserving
//! `path_object` in r4. It constructs the guard with the live r1 base hint,
//! fetches facade selector 1, invokes the fixed facade query at 0x08149e38
//! with `(facade, path_object)`, destroys the guard, then returns that query
//! status verbatim. The resolved facade operation's semantic identity is not
//! established; its arguments and status propagation are the only claims this
//! port makes.
//!
//! ## Deliberate deviations
//!
//! Guard construction, facade selection, and destruction reuse their existing
//! ported/boundary seams from `path_probe`. The separately linked 0x08149e38
//! callee remains a read-volatile dispatch boundary: device builds call its
//! fixed retailOS address; host builds fail closed with status 0 and tests
//! install a recorder. No callee identity is invented.

use core::mem::MaybeUninit;

use crate::app::path_probe::{
    FacadeFetch, FacadeObject, GuardConstruct, GuardDestroy, InterfaceGuard,
    FACADE_SELECTOR, PATH_PROBE_FACADE_FETCH, PATH_PROBE_GUARD_CTOR,
    PATH_PROBE_GUARD_DTOR,
};
use crate::cxx::string_object::StringObject;

/// Firmware load address of the unresolved facade query called at
/// 0x0809b6c8. Its body consumes `(facade, path_object)` but its concrete
/// operation remains unidentified.
pub const PATH_COMPONENT_FACADE_QUERY_ADDRESS: usize = 0x0814_9e38;

/// ABI of the unresolved facade query at [`PATH_COMPONENT_FACADE_QUERY_ADDRESS`].
pub type PathComponentFacadeQuery =
    unsafe extern "C" fn(facade: *mut FacadeObject, path_object: *mut StringObject) -> u32;

unsafe extern "C" fn firmware_path_component_facade_query(
    facade: *mut FacadeObject,
    path_object: *mut StringObject,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let query: PathComponentFacadeQuery =
            core::mem::transmute(PATH_COMPONENT_FACADE_QUERY_ADDRESS);
        query(facade, path_object)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = facade;
        let _ = path_object;
        0
    }
}

/// The active 0x08149e38 facade-query boundary. Device builds call its fixed
/// retailOS entry; host tests replace it with a recording implementation.
pub static mut PATH_COMPONENT_FACADE_QUERY: PathComponentFacadeQuery =
    firmware_path_component_facade_query;

#[inline(always)]
unsafe fn guard_ctor_fn() -> GuardConstruct {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_PROBE_GUARD_CTOR))
}

#[inline(always)]
unsafe fn facade_fetch_fn() -> FacadeFetch {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_PROBE_FACADE_FETCH))
}

#[inline(always)]
unsafe fn guard_dtor_fn() -> GuardDestroy {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_PROBE_GUARD_DTOR))
}

#[inline(always)]
unsafe fn facade_query_fn() -> PathComponentFacadeQuery {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_COMPONENT_FACADE_QUERY))
}

/// `path_component_query_worker` — original: `FUN_0809b6a8` @
/// **0x0809b6a8** (60 bytes; **7 plain `bl` call sites, 0 predicated, 0 tail
/// branches**).
///
/// Constructs a scoped interface guard with `base_hint`, fetches facade
/// selector 1, calls the unresolved facade query with the fetched facade and
/// `path_object`, destroys the same guard frame, and returns the query status
/// unchanged. The raw body has no NULL guard; each dereference/call occurs in
/// the decoded order.
///
/// Deliberate deviation: 0x08149e38 is not yet ported, so its device call is
/// retained as [`PATH_COMPONENT_FACADE_QUERY`] and the host default returns 0.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_component_query_worker(
    path_object: *mut StringObject,
    base_hint: u32,
) -> u32 {
    let mut guard = MaybeUninit::<InterfaceGuard>::uninit();
    let guard = guard.as_mut_ptr();
    guard_ctor_fn()(guard, base_hint);
    let facade = facade_fetch_fn()(guard, FACADE_SELECTOR);
    let status = facade_query_fn()(facade, path_object);
    guard_dtor_fn()(guard);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_component_query::path_component_query;
    use crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS;
    use crate::app::path_probe::{FacadeObject, InterfaceGuard, FACADE_SELECTOR};
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::cxx::string_object::{StringObjectOps, STRING_OBJECT_OPS, STRING_OBJECT_VTABLE};
    use std::sync::Mutex;

    static PATH_COMPONENT_QUERY_WORKER_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 5] = [0; 5];
    static mut EVENT_COUNT: usize = 0;
    static mut CTOR_GUARD: *mut InterfaceGuard = core::ptr::null_mut();
    static mut CTOR_HINT: u32 = 0;
    static mut FETCH_GUARD: *mut InterfaceGuard = core::ptr::null_mut();
    static mut FETCH_SELECTOR: u32 = 0;
    static mut QUERY_FACADE: *mut FacadeObject = core::ptr::null_mut();
    static mut QUERY_PATH: *mut StringObject = core::ptr::null_mut();
    static mut QUERY_VTABLE: usize = 0;
    static mut QUERY_STATUS: u32 = 0;
    static mut DESTROY_GUARD: *mut InterfaceGuard = core::ptr::null_mut();
    static mut RELEASED_STORAGE: *mut StringObject = core::ptr::null_mut();
    static mut RELEASED_VTABLE: usize = 0;
    static mut MOCK_FACADE: FacadeObject = FacadeObject {
        vtable: core::ptr::null(),
    };
    static mut PATH_OBJECT: StringObject = StringObject {
        vtable: core::ptr::null(),
        payload: core::ptr::null_mut(),
    };

    struct SeamGuard {
        saved_string_ops: StringObjectOps,
    }

    impl SeamGuard {
        unsafe fn new() -> Self {
            SeamGuard {
                saved_string_ops: core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile(),
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                crate::app::path_probe::tests::restore_firmware_seams();
                core::ptr::addr_of_mut!(PATH_COMPONENT_FACADE_QUERY)
                    .write_volatile(firmware_path_component_facade_query);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.saved_string_ops);
            }
        }
    }

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn recording_guard_ctor(
        guard: *mut InterfaceGuard,
        base_hint: u32,
    ) -> *mut InterfaceGuard {
        record(1);
        CTOR_GUARD = guard;
        CTOR_HINT = base_hint;
        guard
    }

    unsafe extern "C" fn recording_facade_fetch(
        guard: *mut InterfaceGuard,
        selector: u32,
    ) -> *mut FacadeObject {
        record(2);
        FETCH_GUARD = guard;
        FETCH_SELECTOR = selector;
        core::ptr::addr_of_mut!(MOCK_FACADE)
    }

    unsafe extern "C" fn recording_facade_query(
        facade: *mut FacadeObject,
        path_object: *mut StringObject,
    ) -> u32 {
        record(3);
        QUERY_FACADE = facade;
        QUERY_PATH = path_object;
        QUERY_VTABLE = (*path_object).vtable as usize;
        QUERY_STATUS
    }

    unsafe extern "C" fn recording_guard_destroy(
        guard: *mut InterfaceGuard,
    ) -> *mut InterfaceGuard {
        record(4);
        DESTROY_GUARD = guard;
        guard
    }

    unsafe extern "C" fn recording_release(storage: *mut StringObject) {
        record(5);
        RELEASED_STORAGE = storage;
        RELEASED_VTABLE = (*storage).vtable as usize;
    }

    unsafe fn install_recording() {
        EVENTS = [0; 5];
        EVENT_COUNT = 0;
        CTOR_GUARD = core::ptr::null_mut();
        CTOR_HINT = 0;
        FETCH_GUARD = core::ptr::null_mut();
        FETCH_SELECTOR = 0;
        QUERY_FACADE = core::ptr::null_mut();
        QUERY_PATH = core::ptr::null_mut();
        QUERY_VTABLE = 0;
        DESTROY_GUARD = core::ptr::null_mut();
        RELEASED_STORAGE = core::ptr::null_mut();
        RELEASED_VTABLE = 0;
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_CTOR).write_volatile(recording_guard_ctor);
        core::ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH).write_volatile(recording_facade_fetch);
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_DTOR).write_volatile(recording_guard_destroy);
        core::ptr::addr_of_mut!(PATH_COMPONENT_FACADE_QUERY)
            .write_volatile(recording_facade_query);
        let mut ops = core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile();
        ops.release_payload = recording_release;
        core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(ops);
    }

    #[test]
    fn worker_scopes_the_facade_query_and_preserves_every_abi_word() {
        let _worker_lock = PATH_COMPONENT_QUERY_WORKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _probe_lock = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = unsafe { SeamGuard::new() };

        unsafe {
            install_recording();
            QUERY_STATUS = 0x5a5a_f00d;
            let path_object = core::ptr::addr_of_mut!(PATH_OBJECT);
            assert_eq!(path_component_query_worker(path_object, 0x1020_3040), QUERY_STATUS);
            assert_eq!(EVENT_COUNT, 4);
            assert_eq!(EVENTS[..4], [1, 2, 3, 4]);
            assert_eq!(FETCH_GUARD, CTOR_GUARD, "one r0-r3 guard spill flows into fetch");
            assert_eq!(DESTROY_GUARD, CTOR_GUARD, "destructor receives the original guard");
            assert_eq!(CTOR_HINT, 0x1020_3040, "r1 reaches the guard constructor");
            assert_eq!(FETCH_SELECTOR, FACADE_SELECTOR);
            assert_eq!(QUERY_FACADE, core::ptr::addr_of_mut!(MOCK_FACADE));
            assert_eq!(QUERY_PATH, path_object, "r4 becomes the facade query's r1");
        }
    }

    #[test]
    fn c_string_wrapper_constructs_queries_and_destroys_for_edge_statuses() {
        let _worker_lock = PATH_COMPONENT_QUERY_WORKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _probe_lock = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _string_lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = unsafe { SeamGuard::new() };
        const PATH: &[u8] = b"iPod_Control/Device\\0";

        unsafe {
            for (base_hint, status) in [(0, 0), (1, 13), (0x5a5a_f00d, 53)] {
                install_recording();
                QUERY_STATUS = status;
                assert_eq!(path_component_query(PATH.as_ptr(), base_hint), status);
                assert_eq!(EVENT_COUNT, 5);
                assert_eq!(EVENTS, [1, 2, 3, 4, 5]);
                assert_eq!(CTOR_HINT, base_hint, "the wrapper forwards every r1 value");
                assert_eq!(QUERY_PATH, RELEASED_STORAGE, "the query receives constructed storage");
                assert_eq!(
                    QUERY_VTABLE,
                    PATH_OBJECT_VTABLE_ADDRESS,
                    "the query sees the derived path object before destruction",
                );
                assert_eq!(
                    RELEASED_VTABLE,
                    &STRING_OBJECT_VTABLE as *const _ as usize,
                    "destruction restores the base vtable before releasing",
                );
            }
        }
    }
}
