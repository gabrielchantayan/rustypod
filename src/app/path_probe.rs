//! The mutex-guarded filesystem-facade path probe: the worker behind
//! [`crate::app::path_exists`] and the direct "does this path object
//! exist" primitive of seventeen other call sites.
//!
//! Port:
//! - [`path_probe_via_facade`] — original: `FUN_080f4ad8` @ 0x080f4ad8
//!   (68 bytes; **18 `bl` call sites**, grep on `decomp/osos.asm`).
//!
//! ## What it is
//!
//! A scoped-lock facade query — the C++ source shape is
//!
//! ```text
//! InterfaceGuard guard;                       // 0x08206e40
//! Facade *f = facade_from_guard(&guard, 1);   // 0x0818a0bc
//! u32 status = f->vtable->slot_0x50(f, path); // ldr/blx
//! guard.~InterfaceGuard();                    // 0x08206e6c
//! return status;
//! ```
//!
//! Decoded from the raw ARM at 0x080f4ad8:
//!
//! ```text
//! 080f4ad8  stmdb sp!, {r0, r1, r2, r3, r4, lr}  @ the r0-r3 spill
//!                                               @  slots ARE the
//!                                               @  16-byte guard
//! 080f4adc  mov   r4, r0            @ save path_object (arg1)
//! 080f4ae0  mov   r0, sp            @ &guard
//! 080f4ae4  bl    0x08206e40        @ interface_guard_construct(&guard)
//! 080f4ae8  mov   r1, #0x1          @ selector 1
//! 080f4aec  mov   r0, sp            @ &guard
//! 080f4af0  bl    0x0818a0bc        @ facade = fetch(guard.interface, 1)
//! 080f4af4  ldr   r1, [r0, #0x0]    @ facade->vtable
//! 080f4af8  ldr   r2, [r1, #0x50]   @ vtable slot +0x50: the path probe
//! 080f4afc  mov   r1, r4            @ path_object
//! 080f4b00  blx   r2                @ status = probe(facade, path_object)
//! 080f4b04  mov   r4, r0            @ save the query status
//! 080f4b08  mov   r0, sp            @ &guard
//! 080f4b0c  bl    0x08206e6c        @ interface_guard_destroy(&guard)
//! 080f4b10  mov   r0, r4            @ return the query status verbatim
//! 080f4b14  add   sp, sp, #0x10     @ drop the r0-r3 spill slots
//! 080f4b18  ldmia sp!, {r4, pc}
//! ```
//!
//! The guard object is exactly the r0-r3 spill slots: the constructor @
//! 0x08206e40 plants the guard-class vtable (+0x00, literal @
//! 0x08206e68 over the base from 0x0818a0c4), the interface pointer
//! (+0x04, from 0x0818a06c), two flag bytes (+0x08/+0x09) and runs the
//! lock acquire @ 0x0818a144 on the +0x0c word; the destructor @
//! 0x08206e6c re-plants its vtable (literal @ 0x08206e88), unlocks via
//! 0x0818a164 on +0x0c, and tail-runs the base teardown @ 0x0818a0fc.
//! The facade accessor @ 0x0818a0bc is a two-instruction veneer:
//! `ldr r0, [r0, #0x4]` (the guard's interface) tail-branching to
//! 0x08296ec0, which waits out a NULL `interface->field_8` and returns
//! that field — the facade object.
//!
//! ## The callees are retailOS boundaries
//!
//! All three callees (0x08206e40 / 0x0818a0bc / 0x08206e6c) remain in
//! retailOS, so — the ui/object_state.rs `firmware_clock_sample`
//! precedent — the seams' wired defaults call their fixed firmware load
//! addresses on `target_os = "none"` and this symbol IS hook-ready.
//! Host builds cannot call retailOS: the guard ctor/dtor defaults are
//! no-ops and the fetch default fails closed with a stand-in facade
//! whose slot +0x50 answers 0 ("does not exist" — the vtable_set.rs
//! `store_ctor_unported` fail-closed policy), so the default chain is
//! total on host and returns the same 0 every call site treats as
//! absent.
//!
//! ## Call-site census
//!
//! 18 `bl` sites: 0x08072b24, 0x08097b6c, 0x080ac088, 0x080f4ac0 (the
//! [`crate::app::path_exists`] wrapper), 0x080ff940, 0x08100a20,
//! 0x08117938, 0x0811796c, 0x081186e0, 0x081ee798, 0x081eeeb0,
//! 0x0827ef64, 0x0827ef80, 0x0827f798, 0x0827f7b4, 0x0827fb4c,
//! 0x0827fb98 and 0x08399474. Every site passes a path object (a
//! 0x08279284-family construction, often a stack object or an embedded
//! object field) in r0 and a small flag (0, or a sign-extended byte)
//! in r1, and branches on the returned status being nonzero — the
//! exists semantics the wrapper's name carries.
//!
//! ## Faithful details
//!
//! - **arg2 (`flags`) is DEAD**: it is spilled into the guard frame at
//!   entry and never reloaded — the vtable call receives only
//!   `(facade, path_object)`. Ghidra's `param_2` in
//!   `decomp/c/008/080f4ad8_FUN_080f4ad8.c` is the spill, not a use.
//! - The query status is saved across the guard destructor
//!   (`mov r4, r0`) and returned verbatim (`mov r0, r4`); the
//!   destructor's own return (its `this`, via the 0x0818a0fc tail) is
//!   discarded.
//! - The facade's vtable is fetched AFTER the guard's lock is held and
//!   the slot is read before the unlock — the probe runs inside the
//!   critical section.
//!
//! ## Deviations
//!
//! - The three unported callees ride the [`PATH_PROBE_GUARD_CTOR`] /
//!   [`PATH_PROBE_FACADE_FETCH`] / [`PATH_PROBE_GUARD_DTOR`] seams
//!   (read_volatile dispatch; host tests install recording mocks). On
//!   `target_os = "none"` the defaults call the fixed retailOS
//!   addresses; on host they fail closed (see above).

use core::mem::MaybeUninit;

use crate::cxx::string_object::StringObject;

/// Firmware load address of the interface-guard constructor (the `bl`
/// @ 0x080f4ae4). Kept as an identity constant for the boundary
/// default.
pub const GUARD_CTOR_ADDRESS: usize = 0x0820_6e40;

/// Firmware load address of the facade accessor veneer (the `bl` @
/// 0x080f4af0): `ldr r0, [r0, #0x4]; b 0x08296ec0`.
pub const FACADE_FETCH_ADDRESS: usize = 0x0818_a0bc;

/// Firmware load address of the interface-guard destructor (the `bl`
/// @ 0x080f4b0c).
pub const GUARD_DTOR_ADDRESS: usize = 0x0820_6e6c;

/// The selector immediate the original hands the facade accessor
/// (`mov r1, #0x1` @ 0x080f4ae8).
pub const FACADE_SELECTOR: u32 = 1;

/// Byte offset of the path-probe slot in the facade vtable
/// (`ldr r2, [r1, #0x50]` @ 0x080f4af8).
pub const FACADE_PATH_PROBE_SLOT: usize = 0x50;

/// [`FACADE_PATH_PROBE_SLOT`] as a vtable word index.
pub const FACADE_PATH_PROBE_SLOT_INDEX: usize = FACADE_PATH_PROBE_SLOT / 4;

/// The modeled facade vtable extent: every slot up to and including
/// the path probe. Only slot [`FACADE_PATH_PROBE_SLOT_INDEX`] is
/// decoded; the rest are held as raw words (the StringIdRecordVtable
/// serialized-slots precedent).
pub const FACADE_VTABLE_SLOTS: usize = FACADE_PATH_PROBE_SLOT_INDEX + 1;

/// The 16-byte scoped interface guard — exactly the original's r0-r3
/// spill frame. Layout (from the constructor/destructor bodies):
/// +0x00 guard-class vtable, +0x04 interface pointer, +0x08/+0x09 flag
/// bytes, +0x0c lock token.
#[repr(C)]
pub struct InterfaceGuard {
    /// The four spilled words the guard subsystem constructs over.
    pub words: [u32; 4],
}

/// The facade class vtable, modeled down to its twenty-one serialized
/// slots. Only slot [`FACADE_PATH_PROBE_SLOT_INDEX`] (+0x50, the path
/// probe) is decoded; the owning class is unidentified (the accessor
/// returns `interface->field_8` of an object the guard subsystem
/// fetches from a registry via 0x0814a130).
#[repr(C)]
pub struct FacadeVtable {
    /// The raw slot words; slot 20 is a [`PathProbeQuery`] code
    /// pointer.
    pub slots: [usize; FACADE_VTABLE_SLOTS],
}

/// The facade object returned by the accessor: +0x00 is the vtable
/// pointer the original dereferences for the slot-+0x50 probe.
#[repr(C)]
pub struct FacadeObject {
    /// +0x00 — the class vtable (`ldr r1, [r0, #0x0]` @ 0x080f4af4).
    pub vtable: *const FacadeVtable,
}

/// The facade's vtable-slot-+0x50 path probe: takes the facade object
/// in r0 and the path object in r1, returns the query status.
pub type PathProbeQuery =
    unsafe extern "C" fn(facade: *mut FacadeObject, path_object: *mut StringObject) -> u32;

/// The interface-guard constructor @ 0x08206e40: builds the scoped
/// lock over the 16-byte frame (the original returns `this`; the
/// caller discards it — `mov r0, sp` re-establishes the frame).
pub type GuardConstruct = unsafe extern "C" fn(this: *mut InterfaceGuard);

/// The facade accessor @ 0x0818a0bc: takes the constructed guard and
/// the [`FACADE_SELECTOR`] immediate, returns the facade object.
pub type FacadeFetch =
    unsafe extern "C" fn(guard: *mut InterfaceGuard, selector: u32) -> *mut FacadeObject;

/// The interface-guard destructor @ 0x08206e6c: unlocks and tears the
/// guard down (the original returns `this` via the 0x0818a0fc tail;
/// the caller discards it — `mov r0, r4` restores the status).
pub type GuardDestroy = unsafe extern "C" fn(this: *mut InterfaceGuard);

/// Boundary default for the guard constructor: calls the stock
/// 0x08206e40, which remains in retailOS (the ui/object_state.rs
/// `firmware_clock_sample` precedent). The host default is a no-op —
/// the fail-closed fetch never reads the guard.
unsafe extern "C" fn firmware_guard_construct(this: *mut InterfaceGuard) {
    #[cfg(target_os = "none")]
    {
        let construct: GuardConstruct = core::mem::transmute(GUARD_CTOR_ADDRESS);
        construct(this)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = this;
    }
}

/// Host-only stand-in facade vtable for the fail-closed fetch default,
/// laid out at runtime (static initializers cannot hold a function
/// pointer beside null words without const-eval pointer casts — the
/// vtable_set.rs `STUB_STORE_VTABLE` precedent).
#[cfg(not(target_os = "none"))]
static mut STUB_FACADE_VTABLE: FacadeVtable = FacadeVtable {
    slots: [0; FACADE_VTABLE_SLOTS],
};

/// Host-only stand-in facade object for the fail-closed fetch default.
#[cfg(not(target_os = "none"))]
static mut STUB_FACADE: FacadeObject = FacadeObject {
    vtable: core::ptr::null(),
};

/// The fail-closed slot-+0x50 stand-in: answers 0 ("does not exist" —
/// the value every call site treats as absent).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn stub_path_probe_query(
    _facade: *mut FacadeObject,
    _path_object: *mut StringObject,
) -> u32 {
    0
}

/// Boundary default for the facade accessor: calls the stock
/// 0x0818a0bc, which remains in retailOS. The host default fails
/// closed (the vtable_set.rs `store_ctor_unported` policy): it returns
/// a stand-in facade whose slot +0x50 answers 0, keeping the ported
/// probe total on host with the same observable result the fail-closed
/// policy promises.
unsafe extern "C" fn firmware_facade_fetch(
    guard: *mut InterfaceGuard,
    selector: u32,
) -> *mut FacadeObject {
    #[cfg(target_os = "none")]
    {
        let fetch: FacadeFetch = core::mem::transmute(FACADE_FETCH_ADDRESS);
        fetch(guard, selector)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = guard;
        let _ = selector;
        let vtable = core::ptr::addr_of_mut!(STUB_FACADE_VTABLE);
        (*vtable).slots[FACADE_PATH_PROBE_SLOT_INDEX] = stub_path_probe_query as usize;
        let facade = core::ptr::addr_of_mut!(STUB_FACADE);
        (*facade).vtable = vtable as *const FacadeVtable;
        facade
    }
}

/// Boundary default for the guard destructor: calls the stock
/// 0x08206e6c, which remains in retailOS. The host default is a no-op
/// (the fail-closed chain never locked anything).
unsafe extern "C" fn firmware_guard_destroy(this: *mut InterfaceGuard) {
    #[cfg(target_os = "none")]
    {
        let destroy: GuardDestroy = core::mem::transmute(GUARD_DTOR_ADDRESS);
        destroy(this)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = this;
    }
}

/// The active interface-guard constructor — the dispatch seam for
/// 0x08206e40 (`bl` @ 0x080f4ae4). Host tests install a recording
/// mock; the wired default is the retailOS boundary.
pub static mut PATH_PROBE_GUARD_CTOR: GuardConstruct = firmware_guard_construct;

/// The active facade accessor — the dispatch seam for 0x0818a0bc
/// (`bl` @ 0x080f4af0). Host tests install a recording mock; the wired
/// default is the retailOS boundary (fail-closed on host).
pub static mut PATH_PROBE_FACADE_FETCH: FacadeFetch = firmware_facade_fetch;

/// The active interface-guard destructor — the dispatch seam for
/// 0x08206e6c (`bl` @ 0x080f4b0c). Host tests install a recording
/// mock; the wired default is the retailOS boundary.
pub static mut PATH_PROBE_GUARD_DTOR: GuardDestroy = firmware_guard_destroy;

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

/// path_probe_via_facade — original: `FUN_080f4ad8` @ 0x080f4ad8 (68
/// bytes; **18 `bl` call sites**, grep on `decomp/osos.asm`; every
/// site passes a path object in r0 and a small flag in r1 and branches
/// on the returned status being nonzero).
///
/// Constructs the scoped interface guard, fetches the filesystem
/// facade through it, runs the facade's vtable-slot-+0x50 path probe
/// with `path_object`, destroys the guard, and returns the query
/// status verbatim. `flags` is dead in the original (spilled into the
/// guard frame, never reloaded). See the module header for the stock
/// instruction sequence, the callee analysis, and the seam policy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_probe_via_facade(
    path_object: *mut StringObject,
    flags: u32,
) -> u32 {
    // The original's r0-r3 spill slots: the whole 16-byte guard
    // object, addressed as `sp` throughout the body. arg2's spill
    // (sp+4) is never read back — flags is dead.
    let _ = flags;
    let mut guard = MaybeUninit::<InterfaceGuard>::uninit();
    let guard = guard.as_mut_ptr();
    guard_ctor_fn()(guard);
    let facade = facade_fetch_fn()(guard, FACADE_SELECTOR);
    // ldr r1, [r0, #0x0]; ldr r2, [r1, #0x50]; mov r1, r4; blx r2:
    // the probe runs with the facade in r0 and the path object in r1,
    // inside the guard's critical section.
    let slot = (*(*facade).vtable).slots[FACADE_PATH_PROBE_SLOT_INDEX];
    let query: PathProbeQuery = core::mem::transmute(slot);
    let status = query(facade, path_object);
    guard_dtor_fn()(guard);
    status
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that swap the three probe seams (the
    /// vtable_query.rs `SLOT_TEST_LOCK` precedent). `pub(crate)` so
    /// path_exists.rs's default-chain integration test can serialize
    /// against these; path_probe tests never take any sibling lock,
    /// so no lock-order cycle is possible.
    pub(crate) static PATH_PROBE_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores all three seams to their wired defaults on drop, even
    /// when a test panics (the templates.rs OpsGuard precedent).
    struct SeamGuard;

    impl SeamGuard {
        unsafe fn new() -> Self {
            SeamGuard
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_PROBE_GUARD_CTOR)
                    .write_volatile(firmware_guard_construct);
                core::ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH)
                    .write_volatile(firmware_facade_fetch);
                core::ptr::addr_of_mut!(PATH_PROBE_GUARD_DTOR)
                    .write_volatile(firmware_guard_destroy);
            }
        }
    }

    // Event tags for the call-order recording.
    const EVENT_GUARD_CTOR: u8 = 1;
    const EVENT_FETCH: u8 = 2;
    const EVENT_QUERY: u8 = 3;
    const EVENT_GUARD_DTOR: u8 = 4;
    /// A vtable slot OTHER than +0x50 fired — the port read the wrong
    /// word.
    const EVENT_WRONG_SLOT: u8 = 5;

    static mut EVENTS: [u8; 16] = [0; 16];
    static mut EVENT_COUNT: usize = 0;

    static mut CTOR_THIS: *mut InterfaceGuard = core::ptr::null_mut();
    static mut FETCH_GUARD: *mut InterfaceGuard = core::ptr::null_mut();
    static mut FETCH_SELECTOR: u32 = 0;
    static mut QUERY_FACADE: *mut FacadeObject = core::ptr::null_mut();
    static mut QUERY_PATH_OBJECT: *mut StringObject = core::ptr::null_mut();
    static mut DTOR_THIS: *mut InterfaceGuard = core::ptr::null_mut();
    /// The status the recording query hands back.
    static mut QUERY_RESULT: u32 = 0;

    /// The mock facade and its vtable; every slot but +0x50 is the
    /// wrong-slot trap. Laid out at install time (static initializers
    /// cannot hold function pointers — the STUB_STORE_VTABLE
    /// precedent).
    static mut MOCK_VTABLE: FacadeVtable = FacadeVtable {
        slots: [0; FACADE_VTABLE_SLOTS],
    };
    static mut MOCK_FACADE: FacadeObject = FacadeObject {
        vtable: core::ptr::null(),
    };

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn recording_guard_ctor(this: *mut InterfaceGuard) {
        record(EVENT_GUARD_CTOR);
        CTOR_THIS = this;
    }

    unsafe extern "C" fn recording_fetch(
        guard: *mut InterfaceGuard,
        selector: u32,
    ) -> *mut FacadeObject {
        record(EVENT_FETCH);
        FETCH_GUARD = guard;
        FETCH_SELECTOR = selector;
        core::ptr::addr_of_mut!(MOCK_FACADE)
    }

    unsafe extern "C" fn recording_query(
        facade: *mut FacadeObject,
        path_object: *mut StringObject,
    ) -> u32 {
        record(EVENT_QUERY);
        QUERY_FACADE = facade;
        QUERY_PATH_OBJECT = path_object;
        QUERY_RESULT
    }

    unsafe extern "C" fn recording_wrong_slot(
        _facade: *mut FacadeObject,
        _path_object: *mut StringObject,
    ) -> u32 {
        record(EVENT_WRONG_SLOT);
        0xdead_beef
    }

    unsafe extern "C" fn recording_guard_dtor(this: *mut InterfaceGuard) {
        record(EVENT_GUARD_DTOR);
        DTOR_THIS = this;
    }

    /// Resets the recording state, installs the recording mocks, and
    /// lays out the mock facade with the wrong-slot trap in every
    /// slot but +0x50.
    unsafe fn install_recording() {
        EVENTS = [0; 16];
        EVENT_COUNT = 0;
        CTOR_THIS = core::ptr::null_mut();
        FETCH_GUARD = core::ptr::null_mut();
        FETCH_SELECTOR = 0;
        QUERY_FACADE = core::ptr::null_mut();
        QUERY_PATH_OBJECT = core::ptr::null_mut();
        DTOR_THIS = core::ptr::null_mut();
        QUERY_RESULT = 0;
        let vtable = core::ptr::addr_of_mut!(MOCK_VTABLE);
        for slot in 0..FACADE_VTABLE_SLOTS {
            (*vtable).slots[slot] = recording_wrong_slot as usize;
        }
        (*vtable).slots[FACADE_PATH_PROBE_SLOT_INDEX] = recording_query as usize;
        (*core::ptr::addr_of_mut!(MOCK_FACADE)).vtable = vtable as *const FacadeVtable;
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_CTOR)
            .write_volatile(recording_guard_ctor);
        core::ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH).write_volatile(recording_fetch);
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_DTOR)
            .write_volatile(recording_guard_dtor);
    }

    /// Takes the lock, tolerating poisoning from an earlier failed
    /// test (the string_object.rs lock precedent) — the recording
    /// state is reset by `install_recording` anyway.
    fn take_lock() -> std::sync::MutexGuard<'static, ()> {
        PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// A stand-in path object; the probe never dereferences it (the
    /// facade's query would, but the mock only records the pointer).
    static mut PATH_OBJECT: StringObject = StringObject {
        vtable: core::ptr::null(),
        payload: core::ptr::null_mut(),
    };

    #[test]
    fn call_order_is_guard_fetch_query_unguard() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            path_probe_via_facade(core::ptr::addr_of_mut!(PATH_OBJECT), 0);
            assert_eq!(EVENT_COUNT, 4, "exactly ctor, fetch, query, dtor");
            assert_eq!(EVENTS[0], EVENT_GUARD_CTOR, "the guard is constructed first");
            assert_eq!(EVENTS[1], EVENT_FETCH, "the facade is fetched inside the guard");
            assert_eq!(EVENTS[2], EVENT_QUERY, "the probe runs inside the guard");
            assert_eq!(EVENTS[3], EVENT_GUARD_DTOR, "the guard is destroyed last");
        }
    }

    #[test]
    fn the_same_guard_frame_flows_through_ctor_fetch_and_dtor() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            path_probe_via_facade(core::ptr::addr_of_mut!(PATH_OBJECT), 0);
            assert!(!CTOR_THIS.is_null(), "the guard constructor ran");
            assert_eq!(FETCH_GUARD, CTOR_THIS, "mov r0, sp ahead of both bls");
            assert_eq!(DTOR_THIS, CTOR_THIS, "the destructor is handed the same sp");
        }
    }

    #[test]
    fn fetch_receives_selector_one_and_flags_is_dead() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            for flags in [0u32, 1, 0x5a5a_f00d] {
                FETCH_SELECTOR = 0xdead_beef;
                path_probe_via_facade(core::ptr::addr_of_mut!(PATH_OBJECT), flags);
                assert_eq!(
                    FETCH_SELECTOR, FACADE_SELECTOR,
                    "mov r1, #0x1: the selector is the immediate, never arg2"
                );
            }
        }
    }

    #[test]
    fn query_dispatches_through_slot_50_with_the_fetched_facade_and_path_verbatim() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            let path_object = core::ptr::addr_of_mut!(PATH_OBJECT);
            path_probe_via_facade(path_object, 0);
            assert_eq!(EVENT_COUNT, 4, "no wrong-slot trap fired");
            assert_eq!(
                QUERY_FACADE,
                core::ptr::addr_of_mut!(MOCK_FACADE),
                "the probe's r0 is the fetch's return"
            );
            assert_eq!(
                QUERY_PATH_OBJECT, path_object,
                "mov r1, r4: the saved arg1 reaches the probe untouched"
            );
        }
    }

    #[test]
    fn the_query_status_survives_the_guard_dtor_and_returns_verbatim() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            install_recording();
            for status in [0u32, 1, 0xdead_beef] {
                EVENT_COUNT = 0;
                QUERY_RESULT = status;
                let result =
                    path_probe_via_facade(core::ptr::addr_of_mut!(PATH_OBJECT), 0);
                assert_eq!(result, status, "mov r4, r0 / mov r0, r4: the status is verbatim");
                assert_eq!(EVENT_COUNT, 4, "the destructor still ran on every call");
                assert_eq!(EVENTS[3], EVENT_GUARD_DTOR);
            }
        }
    }

    #[test]
    fn default_chain_fails_closed_on_host() {
        let _lock = take_lock();
        let _restore = unsafe { SeamGuard::new() };
        unsafe {
            // All wired defaults (the guard restores them, and
            // install_recording is deliberately NOT called): the
            // no-op guard boundaries and the fail-closed stand-in
            // facade answer 0 — "does not exist".
            EVENT_COUNT = 0;
            assert_eq!(
                path_probe_via_facade(core::ptr::addr_of_mut!(PATH_OBJECT), 0),
                0,
                "the host boundary chain is total and fails closed"
            );
            assert_eq!(EVENT_COUNT, 0, "no recording mock is installed");
        }
    }
}
