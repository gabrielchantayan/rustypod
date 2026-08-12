//! The path-exists query wrapper: build a scoped path object from a C
//! string, run the exists query against the filesystem facade, tear the
//! path object down, and hand back the query's status.
//!
//! Port:
//! - [`path_exists`] — original: `FUN_080f4aa8` @ 0x080f4aa8 (48 bytes;
//!   **66 `bl` call sites**, grep on `decomp/osos.asm`).
//!
//! ## What it is
//!
//! A scoped-guard wrapper — the C++ source shape is
//! `PathObject p(path); return exists_worker(p, flags);` with the
//! destructor run on scope exit. Decoded from the raw ARM at
//! 0x080f4aa8:
//!
//! ```text
//! 080f4aa8  stmdb sp!, {r2, r3, r4, lr}  @ the r2/r3 spill slots ARE the
//!                                        @  8-byte guard object on sp
//! 080f4aac  mov   r4, r1            @ save flags (arg2)
//! 080f4ab0  mov   r1, r0            @ path (arg1)
//! 080f4ab4  mov   r0, sp            @ &guard
//! 080f4ab8  bl    0x08279284        @ path_object_construct(&guard, path)
//! 080f4abc  mov   r1, r4            @ flags
//! 080f4ac0  bl    0x080f4ad8        @ exists_worker(ctor_return, flags)
//! 080f4ac4  mov   r4, r0            @ save the query status
//! 080f4ac8  mov   r0, sp            @ &guard — NOT the ctor's return
//! 080f4acc  bl    0x082792fc        @ string_object_destroy_veneer(&guard)
//! 080f4ad0  mov   r0, r4            @ return the query status verbatim
//! 080f4ad4  ldmia sp!, {r2, r3, r4, pc}
//! ```
//!
//! The guard pair is the StringObject-derived **path object**: the
//! constructor veneer @ 0x08279284 (ported as
//! [`crate::app::path_object_construct::path_object_construct`]) runs
//! the ported
//! [`string_object_construct_from_cstr`](crate::cxx::string_object::string_object_construct_from_cstr)
//! @ 0x08277304 and then
//! overwrites the vtable word with the derived path-class vtable
//! 0x089a60d8 (literal pool @ 0x08279298, binary-verified against
//! osos.dec); the destructor is the ported
//! [`string_object_destroy_veneer`] @ 0x082792fc (`b 0x08277484`).
//! The object is exactly the two-word [`StringObject`] — the wrapper's
//! r2/r3 spill slots are its whole storage.
//!
//! The worker @ 0x080f4ad8 (ported as
//! [`crate::app::path_probe::path_probe_via_facade`], the
//! [`PATH_EXISTS_WORKER`] seam's wired default) is the mutex-guarded
//! (0x08206e40/0x08206e6c) filesystem-facade query the
//! `vtable_set.rs` family documents: fetch the facade from 0x0818a0bc,
//! indirect-call its vtable slot **+0x50** with the path object (the
//! sibling remove @ 0x08084d58 is slot +0x5c on the same facade).
//!
//! ## Why "exists"
//!
//! All 66 call sites pass a path C string in r0 and 0 in r1, and every
//! one branches on the status being nonzero. The deciders:
//! `FUN_08164bf4` gates reading `"iPod_Control/Device/1da_..."` on a
//! nonzero return; `FUN_08264c94` counts upward
//! (`while (path_exists(indexed_path, 0) != 0) i++`) to enumerate
//! consecutively-indexed existing paths; `FUN_0811b254` probes the
//! literal `"iPod_Control/Device/radio_..."`. The exact +0x50 operation
//! is not established beyond that (a stat-family query that also
//! answers directories would look identical at these sites), so the
//! name carries the semantics every observable caller relies on.
//!
//! ## Faithful details
//!
//! - The worker's first argument is the **constructor's return**, not
//!   the guard address (the original's r0 flows straight from the
//!   `bl 0x08279284` into the `bl 0x080f4ad8`). The destructor, by
//!   contrast, is handed `sp` — the guard STORAGE — unconditionally.
//!   Observable when a constructor returns anything but `this`;
//!   reproduced and pinned by tests.
//! - The query status is saved across the destructor (`mov r4, r0`)
//!   and returned verbatim (`mov r0, r4`); the destructor's own return
//!   is discarded.
//! - arg3/arg4 (r2/r3) are DEAD: their spill slots become the guard
//!   object, so the constructor's first store overwrites them before
//!   anything reads them, and the epilogue restores r2/r3 from the
//!   object's final words. No call site sets them deliberately —
//!   Ghidra's `param_3`/`param_4` in
//!   `decomp/c/008/080f4aa8_FUN_080f4aa8.c` are phantom.
//!
//! ## Deviations
//!
//! - **The constructor rides the [`PATH_OBJECT_CTOR`] seam** with the
//!   ported [`crate::app::path_object_construct::path_object_construct`]
//!   @ 0x08279284 as the wired default (the
//!   [`PATH_EXISTS_WORKER`]-to-`path_probe_via_facade` rewiring
//!   precedent) — base construction, then the
//!   [`crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS`]
//!   identity word over the vtable slot (the `StringObjectVtable`
//!   ROM-identity precedent; nothing ported dereferences it).
//! - **The worker rides the [`PATH_EXISTS_WORKER`] seam** with the
//!   ported [`crate::app::path_probe::path_probe_via_facade`] @
//!   0x080f4ad8 as the wired default — the mutex-guarded
//!   filesystem-facade vtable-slot-+0x50 query. Its guard ctor/fetch/
//!   dtor callees remain in retailOS and the ported defaults call
//!   their fixed firmware addresses on `target_os = "none"` (host
//!   builds fail closed to 0, "does not exist"), so this symbol IS
//!   hook-ready.
//! - **The destructor is called directly** — the ported
//!   [`string_object_destroy_veneer`] (the transition_addon.rs
//!   ported-callees-called-directly precedent).

use core::mem::MaybeUninit;

use crate::cxx::string_object::{
    string_object_destroy_veneer, StringObject, StringObjectVtable,
};

/// The path-object constructor veneer @ 0x08279284: an ADS C++
/// converting constructor, takes the raw storage and the source C
/// string, returns `this`. Ported as
/// [`crate::app::path_object_construct::path_object_construct`].
pub type PathObjectCtor =
    unsafe extern "C" fn(this: *mut StringObject, path: *const u8) -> *mut StringObject;

/// The active path-object constructor — the dispatch seam for
/// 0x08279284 (`bl` @ 0x080f4ab8). Host tests install a recording mock;
/// the wired default is the ported
/// [`crate::app::path_object_construct::path_object_construct`].
pub static mut PATH_OBJECT_CTOR: PathObjectCtor =
    crate::app::path_object_construct::path_object_construct;

/// The exists-query worker @ 0x080f4ad8: takes the constructed path
/// object (the constructor's RETURN, per the wrapper's r0 flow) and the
/// caller's flags word, returns the query status.
pub type PathExistsWorker =
    unsafe extern "C" fn(path_object: *mut StringObject, flags: u32) -> u32;

/// The active exists-query worker — the dispatch seam for 0x080f4ad8
/// (`bl` @ 0x080f4ac0). Host tests install a recording mock; the wired
/// default is the ported
/// [`crate::app::path_probe::path_probe_via_facade`] (the
/// mutex-guarded facade slot-+0x50 query; its own unported callees
/// are retailOS boundaries that fail closed on host).
pub static mut PATH_EXISTS_WORKER: PathExistsWorker =
    crate::app::path_probe::path_probe_via_facade;

/// path_exists — original: `FUN_080f4aa8` @ 0x080f4aa8 (48 bytes;
/// **66 `bl` call sites**, grep on `decomp/osos.asm`; every site passes
/// a path C string in r0 and 0 in r1 and branches on the returned
/// status).
///
/// Builds a scoped path object from `path`, runs the filesystem
/// facade's exists query with `flags`, destroys the path object, and
/// returns the query status verbatim. See the module header for the
/// stock instruction sequence, the faithful-details list, and the seam
/// policy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_exists(path: *const u8, flags: u32) -> u32 {
    // The original's r2/r3 spill slots: the whole 8-byte (on target)
    // guard object, addressed as `sp` throughout the body.
    let mut guard = MaybeUninit::<StringObject>::uninit();
    let guard = guard.as_mut_ptr();
    let ctor = core::ptr::addr_of!(PATH_OBJECT_CTOR).read_volatile();
    let path_object = ctor(guard, path);
    let worker = core::ptr::addr_of!(PATH_EXISTS_WORKER).read_volatile();
    let status = worker(path_object, flags);
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

    /// Serializes the tests that swap [`PATH_OBJECT_CTOR`] /
    /// [`PATH_EXISTS_WORKER`] (the vtable_query.rs `SLOT_TEST_LOCK`
    /// precedent). The StringObject release slot is serialized by
    /// [`STRING_OBJECT_OPS_TEST_LOCK`], which every test here also
    /// holds — this module's lock is always acquired FIRST, so the two
    /// locks can never be taken in opposite orders.
    static PATH_EXISTS_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores both seams and the StringObject release slot on drop,
    /// even when a test panics (the templates.rs OpsGuard precedent).
    struct SeamGuard {
        saved_ops: StringObjectOps,
    }

    impl SeamGuard {
        unsafe fn new() -> Self {
            let saved_ops = core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile();
            SeamGuard { saved_ops }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_OBJECT_CTOR)
                    .write_volatile(crate::app::path_object_construct::path_object_construct);
                core::ptr::addr_of_mut!(PATH_EXISTS_WORKER)
                    .write_volatile(crate::app::path_probe::path_probe_via_facade);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.saved_ops);
            }
        }
    }

    // Event tags for the call-order recording.
    const EVENT_CTOR: u8 = 1;
    const EVENT_WORKER: u8 = 2;
    const EVENT_DTOR: u8 = 3;

    static mut EVENTS: [u8; 16] = [0; 16];
    static mut EVENT_COUNT: usize = 0;

    static mut CTOR_THIS: *mut StringObject = core::ptr::null_mut();
    static mut CTOR_PATH: *const u8 = core::ptr::null();
    /// When non-NULL, the recording constructor returns this instead of
    /// `this` — the stand-in for a constructor that does not return its
    /// own storage.
    static mut CTOR_RETURN: *mut StringObject = core::ptr::null_mut();

    static mut WORKER_PATH_OBJECT: *mut StringObject = core::ptr::null_mut();
    static mut WORKER_FLAGS: u32 = 0;
    /// The status the recording worker hands back.
    static mut WORKER_RESULT: u32 = 0;
    /// The object state the worker observed DURING the query — captured
    /// here because the destructor re-plants the vtable before the
    /// caller can look.
    static mut WORKER_SEEN_VTABLE: *const StringObjectVtable = core::ptr::null();
    static mut WORKER_SEEN_PAYLOAD: *mut u8 = core::ptr::null_mut();

    static mut DTOR_THIS: *mut StringObject = core::ptr::null_mut();
    /// What the destructor body observed: the vtable re-planted by
    /// `string_object_destroy` before the release runs.
    static mut DTOR_VTABLE: *const StringObjectVtable = core::ptr::null();

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn recording_ctor(
        this: *mut StringObject,
        path: *const u8,
    ) -> *mut StringObject {
        record(EVENT_CTOR);
        CTOR_THIS = this;
        CTOR_PATH = path;
        if !CTOR_RETURN.is_null() {
            return CTOR_RETURN;
        }
        this
    }

    unsafe extern "C" fn recording_worker(
        path_object: *mut StringObject,
        flags: u32,
    ) -> u32 {
        record(EVENT_WORKER);
        WORKER_PATH_OBJECT = path_object;
        WORKER_FLAGS = flags;
        WORKER_SEEN_VTABLE = (*path_object).vtable;
        WORKER_SEEN_PAYLOAD = (*path_object).payload;
        WORKER_RESULT
    }

    /// Records the destructor's arrival at the payload release — the
    /// last observable act of `string_object_destroy_veneer`, reached
    /// only after it re-plants the base vtable.
    unsafe extern "C" fn recording_release(this: *mut StringObject) {
        record(EVENT_DTOR);
        DTOR_THIS = this;
        DTOR_VTABLE = (*this).vtable;
    }

    /// A distinct stand-in pointer for the constructor's return, to
    /// prove the worker — and NOT the destructor — receives it.
    static mut SENTINEL_OBJECT: StringObject = StringObject {
        vtable: core::ptr::null(),
        payload: core::ptr::null_mut(),
    };

    /// Resets the recording state and installs the recording mocks,
    /// including the release-slot observation of the ported destructor.
    unsafe fn install_recording() {
        EVENTS = [0; 16];
        EVENT_COUNT = 0;
        CTOR_THIS = core::ptr::null_mut();
        CTOR_PATH = core::ptr::null();
        CTOR_RETURN = core::ptr::null_mut();
        WORKER_PATH_OBJECT = core::ptr::null_mut();
        WORKER_FLAGS = 0;
        WORKER_RESULT = 0;
        WORKER_SEEN_VTABLE = core::ptr::null();
        WORKER_SEEN_PAYLOAD = core::ptr::null_mut();
        DTOR_THIS = core::ptr::null_mut();
        DTOR_VTABLE = core::ptr::null();
        core::ptr::addr_of_mut!(PATH_OBJECT_CTOR).write_volatile(recording_ctor);
        core::ptr::addr_of_mut!(PATH_EXISTS_WORKER).write_volatile(recording_worker);
        let mut ops = core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile();
        ops.release_payload = recording_release;
        core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(ops);
    }

    /// Takes both locks, tolerating poisoning from an earlier failed
    /// test (the string_object.rs lock precedent) — the recording
    /// state is reset by `install_recording` anyway.
    fn take_locks() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let lock = PATH_EXISTS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let string_lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        (lock, string_lock)
    }

    static PATH: &[u8] = b"iPod_Control/Device/radio_test\0";

    #[test]
    fn call_order_is_construct_query_destroy() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            path_exists(PATH.as_ptr(), 0);
            assert_eq!(EVENT_COUNT, 3, "exactly ctor, worker, dtor");
            assert_eq!(EVENTS[0], EVENT_CTOR, "the guard is built first");
            assert_eq!(EVENTS[1], EVENT_WORKER, "the query runs inside the scope");
            assert_eq!(EVENTS[2], EVENT_DTOR, "the guard is destroyed last");
        }
    }

    #[test]
    fn ctor_receives_the_storage_and_the_path_verbatim() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            path_exists(PATH.as_ptr(), 0);
            assert!(!CTOR_THIS.is_null(), "the constructor ran");
            assert_eq!(CTOR_PATH, PATH.as_ptr(), "arg1 flows to the ctor untouched");
        }
    }

    #[test]
    fn worker_receives_the_ctor_return_not_the_storage() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            CTOR_RETURN = core::ptr::addr_of_mut!(SENTINEL_OBJECT);
            path_exists(PATH.as_ptr(), 0);
            assert_eq!(
                WORKER_PATH_OBJECT,
                core::ptr::addr_of_mut!(SENTINEL_OBJECT),
                "the original's r0 flows straight from the ctor into the worker"
            );
            assert_ne!(
                WORKER_PATH_OBJECT, CTOR_THIS,
                "the worker's first argument is NOT the guard storage"
            );
        }
    }

    #[test]
    fn dtor_receives_the_storage_even_when_the_ctor_returns_elsewhere() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            CTOR_RETURN = core::ptr::addr_of_mut!(SENTINEL_OBJECT);
            path_exists(PATH.as_ptr(), 0);
            assert_eq!(
                DTOR_THIS, CTOR_THIS,
                "the destructor is handed sp — the guard storage, never the ctor's return"
            );
            assert_eq!(
                DTOR_VTABLE as usize,
                &STRING_OBJECT_VTABLE as *const _ as usize,
                "string_object_destroy re-plants the base vtable before the release"
            );
        }
    }

    #[test]
    fn flags_flow_to_the_worker_verbatim() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            for flags in [0u32, 1, 0x5a5a_f00d] {
                WORKER_FLAGS = 0xdead_beef;
                path_exists(PATH.as_ptr(), flags);
                assert_eq!(WORKER_FLAGS, flags, "arg2 reaches the worker unmodified");
            }
        }
    }

    #[test]
    fn the_query_status_survives_the_destructor_and_returns_verbatim() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            for status in [0u32, 1, 0xdead_beef] {
                WORKER_RESULT = status;
                let result = path_exists(PATH.as_ptr(), 0);
                assert_eq!(result, status, "mov r4, r0 / mov r0, r4: the status is verbatim");
                assert_eq!(EVENT_COUNT % 3, 0, "the destructor still ran on every call");
            }
        }
    }

    #[test]
    fn default_ctor_builds_the_derived_path_object() {
        let _locks = take_locks();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            // Restore ONLY the ctor seam to its wired default; the
            // recording worker inspects the object the default built.
            core::ptr::addr_of_mut!(PATH_OBJECT_CTOR)
                .write_volatile(crate::app::path_object_construct::path_object_construct);
            WORKER_RESULT = 1;
            let result = path_exists(PATH.as_ptr(), 0);
            assert_eq!(result, 1);
            assert!(!WORKER_PATH_OBJECT.is_null(), "the default ctor ran");
            assert_eq!(
                WORKER_SEEN_VTABLE as usize,
                crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS,
                "the derived path-class vtable replaces the base one"
            );
            assert!(
                WORKER_SEEN_PAYLOAD.is_null(),
                "the default assign-cstr allocation boundary fails closed, so no payload"
            );
            // The ported destructor ran on the constructed object.
            assert_eq!(DTOR_THIS, WORKER_PATH_OBJECT);
            assert_eq!(
                DTOR_VTABLE as usize,
                &STRING_OBJECT_VTABLE as *const _ as usize,
                "the destructor re-planted the base vtable over the derived one"
            );
        }
    }

    #[test]
    fn default_worker_is_the_ported_probe_and_fails_closed_on_host() {
        let _locks = take_locks();
        // This test drives the ported worker through its own seams, so
        // it serializes against path_probe.rs's tests (taken after the
        // string-object lock; path_probe tests take only their own
        // lock, so no order cycle is possible).
        let _probe_lock = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            // The wired default IS the ported 0x080f4ad8.
            let wired = core::ptr::addr_of!(PATH_EXISTS_WORKER).read_volatile();
            assert_eq!(
                wired as usize,
                crate::app::path_probe::path_probe_via_facade as usize,
                "the seam's wired default is the ported probe"
            );
            // All defaults wired: the faithful ctor builds a real (if
            // payload-less) path object, the ported worker's host
            // boundaries fail closed (0 = "does not exist"), and the
            // ported destructor tears the object down — its release is
            // a NULL-payload no-op, observed by the mock.
            install_recording();
            core::ptr::addr_of_mut!(PATH_OBJECT_CTOR)
                .write_volatile(crate::app::path_object_construct::path_object_construct);
            core::ptr::addr_of_mut!(PATH_EXISTS_WORKER)
                .write_volatile(crate::app::path_probe::path_probe_via_facade);
            assert_eq!(
                path_exists(PATH.as_ptr(), 0),
                0,
                "the ported probe's host boundaries fail closed: does not exist"
            );
            // The default ctor and the ported worker record nothing
            // here; only the ported destructor's release is observed.
            assert_eq!(EVENT_COUNT, 1, "the destructor still ran behind the defaults");
            assert_eq!(EVENTS[0], EVENT_DTOR);
        }
    }
}
