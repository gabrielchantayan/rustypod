//! `event_hub_broadcast` — original: `FUN_08257b60` @ 0x08257b60
//! (100 bytes: 96 of code plus a one-word literal pool; the next
//! function opens at 0x08257bc4 — extent binary-verified, Ghidra's 96
//! is the code only). **42 `bl` call sites, verified by decoding every
//! B/BL word in osos.dec**: 38 plain, 4 predicated (2 `blne`, 2
//! `bleq`). The predicated sites gate on the *caller's* own
//! precondition (a range check at 0x0818f1f8, NULL checks at
//! 0x08192420 / 0x08192d58 / 0x081931ac), never on hub state — the
//! callee itself has no guards beyond the init guard below.
//!
//! # What it is
//!
//! The single public entry into retailOS's process-wide event hub:
//! thirteen listener lists (the singleton @ 0x082579a0 allocates
//! 0x9c = 13 * 12 bytes — thirteen `begin`/`end`/`capacity` vector
//! triplets — via the ported `operator_new` and constructs them through
//! the array-ctor adapter 0x082ab234), one list per event kind. A
//! broadcast walks list `kind` and invokes each listener's vtable slot
//! +0x04 with `(listener, kind, arg, payload, payload_len)` — that walk
//! is `FUN_082579d0`, not ported here. Listeners are registered by the
//! sibling `FUN_08257aec` (a vector `push_back` into list `kind`).
//!
//! # Algorithm
//!
//! ```text
//!     push {r3-r9, lr}
//!     r4 = 0x089cca00               ; local-static block
//!     if ([r4+4] & 1) == 0 {        ; guard word @ 0x089cca04, tst #1
//!         if cxa_guard_acquire(&guard) != 0 {
//!             [r4+8] = FUN_082579a0()   ; hub instance @ 0x089cca08
//!             cxa_guard_release(&guard)
//!         }
//!     }
//!     r0 = [r4+8]                   ; ALWAYS reloaded, never the
//!     FUN_082579d0(r0, kind, arg, payload, payload_len)  ; init return
//!     pop {r3-r9, pc}
//! ```
//!
//! An ADS function-local static, but over a *cached pointer* to the
//! hub singleton rather than a fixed object: the getter @ 0x082579a0
//! keeps its own cache at 0x089cca00, this function keeps the guard at
//! +0x04 and its own copy of the instance at +0x08. The guard pair is
//! the ported `cxa_guard_acquire` / `cxa_guard_release`
//! (`runtime/cxa_guard.rs`), called directly.
//!
//! `payload` is not always a pointer: call sites pass
//! `(8, 0, 0xd, 4)` and `(8, 0, 0xb, 4)` — small immediates with a
//! length — so it is typed `usize`, never dereferenced here. (Ghidra
//! decorates two call sites with phantom 5th/6th arguments; the binary
//! proves only r0–r3 are consumed.)
//!
//! # Deviations
//!
//! - Guard and cache are crate statics ([`EVENT_HUB_GUARD`],
//!   [`EVENT_HUB_INSTANCE`]) rather than the .bss words @ 0x089cca04 /
//!   0x089cca08 — the `media_command_facade.rs` deviation; zero is the
//!   exact pre-init state either way.
//! - Both callees are unported (neither appears in names.yaml) and sit
//!   behind [`EVENT_HUB_OPS`]: the singleton getter `FUN_082579a0`
//!   (`bl` @ 0x08257b94) and the dispatch `FUN_082579d0` (`bl` @
//!   0x08257bb8). The defaults are inert (NULL instance, no-op
//!   dispatch), so this symbol is NOT hook-ready until they are ported
//!   — a broadcast against the defaults reaches nobody.

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

/// The one-time-initialization guard (original: the word @ 0x089cca04,
/// loaded as `[0x089cca00 + 4]`; the fast path tests bit 0 only, the
/// `tst r0, #1` @ 0x08257b74).
pub static mut EVENT_HUB_GUARD: u32 = 0;

/// The cached hub instance (original: the word @ 0x089cca08). Stored
/// after a successful acquire, reloaded on every call — including the
/// fast path — exactly like the original's `ldr r0, [r4, #8]` @
/// 0x08257ba8.
pub static mut EVENT_HUB_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The singleton getter — original: `FUN_082579a0` @ 0x082579a0.
pub type EventHubInstanceGet = unsafe extern "C" fn() -> *mut u8;

/// The list walk — original: `FUN_082579d0` @ 0x082579d0. Its fifth
/// argument rides the stack on the target (the original's
/// `str r8, [sp]` @ 0x08257ba4); the extern "C" ABI places it there.
pub type EventHubDispatch =
    unsafe extern "C" fn(hub: *mut u8, kind: u32, arg: u32, payload: usize, payload_len: u32);

/// Indirect dispatch for the two unported callees (see the module
/// header). Host tests install recording models; the real ports replace
/// the defaults when they land.
#[derive(Clone, Copy)]
pub struct EventHubOps {
    /// `FUN_082579a0`: returns the hub singleton, constructing the
    /// thirteen listener lists on first use.
    pub instance_get: EventHubInstanceGet,
    /// `FUN_082579d0`: broadcasts to every listener registered for
    /// `kind`, plus the kind-0/len-0x14 system-event fan-out.
    pub dispatch: EventHubDispatch,
}

/// Default for the unported getter: no hub. Faithful only in that the
/// dispatch then observes the NULL the init block stored.
unsafe extern "C" fn null_instance_get() -> *mut u8 {
    core::ptr::null_mut()
}

/// Default for the unported walk: reaches nobody (see the header's
/// NOT-hook-ready note).
unsafe extern "C" fn noop_dispatch(
    _hub: *mut u8,
    _kind: u32,
    _arg: u32,
    _payload: usize,
    _payload_len: u32,
) {
}

/// The shipped defaults: inert stand-ins for the two unported callees.
pub const DEFAULT_EVENT_HUB_OPS: EventHubOps = EventHubOps {
    instance_get: null_instance_get,
    dispatch: noop_dispatch,
};

/// The active callees — the dispatch seams for `FUN_082579a0` and
/// `FUN_082579d0`. Host tests install recording mocks; the real ports
/// replace the defaults when they exist.
pub static mut EVENT_HUB_OPS: EventHubOps = DEFAULT_EVENT_HUB_OPS;

/// Volatile read so LLVM cannot fold the defaults in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn ops() -> EventHubOps {
    core::ptr::read_volatile(core::ptr::addr_of!(EVENT_HUB_OPS))
}

/// event_hub_broadcast — original: `FUN_08257b60` @ 0x08257b60
/// (100 bytes with the pool word; 42 `bl` call sites, binary-verified).
///
/// Lazily caches the event-hub singleton behind the ADS guard pair,
/// then broadcasts `(kind, arg, payload, payload_len)` to every
/// listener registered for `kind`. See the module header for the
/// algorithm and the seam contract.
///
/// Faithful details:
/// - The fast path tests bit 0 of the guard (`tst r0, #1`) while
///   [`cxa_guard_acquire`] tests the whole word: a nonzero guard with
///   bit 0 clear — a state this pair never produces — takes the slow
///   path, is turned away, and the broadcast goes out with the stale
///   cache.
/// - The instance word is reloaded after the init block on *every*
///   call, never reused from a register — so a re-entrant broadcast
///   from inside the getter (the guard is already published by
///   acquire) dispatches with the not-yet-stored NULL, exactly like
///   the original.
/// - A refused acquire skips the store *and* the release, matching the
///   original's `beq 0x08257ba4`.
/// - There is no NULL guard on the hub: if the getter handed out NULL,
///   the dispatch sees NULL, precisely the original's data flow.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_hub_broadcast(
    kind: u32,
    arg: u32,
    payload: usize,
    payload_len: u32,
) {
    let guard = core::ptr::addr_of_mut!(EVENT_HUB_GUARD);
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let hub = (ops().instance_get)();
        core::ptr::addr_of_mut!(EVENT_HUB_INSTANCE).write_volatile(hub);
        cxa_guard_release(guard);
    }
    let hub = core::ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile();
    (ops().dispatch)(hub, kind, arg, payload, payload_len);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test below: the guard, the cache and the ops
    /// table are all process-wide.
    static EVENT_HUB_LOCK: Mutex<()> = Mutex::new(());

    /// Calls each recording seam saw, in order.
    static mut TRACE: Vec<&'static str> = Vec::new();
    /// What the recording getter returns.
    static mut GETTER_RESULT: *mut u8 = ptr::null_mut();
    /// The guard word the recording getter observed (proves acquire
    /// published the flag *before* the getter ran).
    static mut GUARD_DURING_GET: u32 = 0;
    /// Every dispatch's arguments, in order.
    static mut DISPATCHED: Vec<(*mut u8, u32, u32, usize, u32)> = Vec::new();
    /// When set, the recording getter re-enters the broadcast once.
    static mut REENTER: bool = false;

    unsafe extern "C" fn recording_instance_get() -> *mut u8 {
        (*ptr::addr_of_mut!(TRACE)).push("get");
        GUARD_DURING_GET = ptr::addr_of!(EVENT_HUB_GUARD).read_volatile();
        if ptr::addr_of!(REENTER).read_volatile() {
            REENTER = false;
            event_hub_broadcast(3, 0, 0, 0);
        }
        ptr::addr_of!(GETTER_RESULT).read_volatile()
    }

    unsafe extern "C" fn recording_dispatch(
        hub: *mut u8,
        kind: u32,
        arg: u32,
        payload: usize,
        payload_len: u32,
    ) {
        (*ptr::addr_of_mut!(TRACE)).push("dispatch");
        (*ptr::addr_of_mut!(DISPATCHED)).push((hub, kind, arg, payload, payload_len));
    }

    /// Installs the recording seams and clears the statics.
    fn mock(getter_result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = EVENT_HUB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            EVENT_HUB_OPS = EventHubOps {
                instance_get: recording_instance_get,
                dispatch: recording_dispatch,
            };
            EVENT_HUB_GUARD = 0;
            EVENT_HUB_INSTANCE = ptr::null_mut();
            GETTER_RESULT = getter_result;
            GUARD_DURING_GET = 0;
            REENTER = false;
            (*ptr::addr_of_mut!(TRACE)).clear();
            (*ptr::addr_of_mut!(DISPATCHED)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            EVENT_HUB_OPS = DEFAULT_EVENT_HUB_OPS;
            EVENT_HUB_GUARD = 0;
            EVENT_HUB_INSTANCE = ptr::null_mut();
        }
        drop(guard);
    }

    fn trace() -> Vec<&'static str> {
        unsafe { (*ptr::addr_of!(TRACE)).clone() }
    }

    fn dispatched() -> Vec<(*mut u8, u32, u32, usize, u32)> {
        unsafe { (*ptr::addr_of!(DISPATCHED)).clone() }
    }

    #[test]
    fn the_first_broadcast_initializes_then_dispatches_every_argument() {
        let hub = 0x1234_5000usize as *mut u8;
        let guard = mock(hub);
        let mut payload = [0xabu8; 0x14];

        unsafe { event_hub_broadcast(9, 0, payload.as_mut_ptr() as usize, 0x800) };

        assert_eq!(trace(), std::vec!["get", "dispatch"]);
        assert_eq!(
            dispatched(),
            std::vec![(hub, 9, 0, payload.as_mut_ptr() as usize, 0x800)]
        );
        unsafe {
            assert_eq!(ptr::addr_of!(EVENT_HUB_GUARD).read_volatile(), 1, "acquire published");
            assert_eq!(
                ptr::addr_of!(GUARD_DURING_GET).read_volatile(),
                1,
                "the guard is spent before the getter runs"
            );
            assert_eq!(
                ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile(),
                hub,
                "the getter's return is cached"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_second_broadcast_skips_initialization_but_still_dispatches() {
        let hub = 0x1234_5000usize as *mut u8;
        let guard = mock(hub);

        unsafe {
            event_hub_broadcast(0, 0, 0, 0x14);
            event_hub_broadcast(8, 0, 0xd, 4);
        }

        assert_eq!(trace(), std::vec!["get", "dispatch", "dispatch"]);
        assert_eq!(
            dispatched(),
            std::vec![(hub, 0, 0, 0, 0x14), (hub, 8, 0, 0xd, 4)],
            "payload may be a small immediate; every word forwards verbatim"
        );
        restore(guard);
    }

    #[test]
    fn the_fast_path_reloads_the_cache_it_never_computed() {
        let guard = mock(ptr::null_mut());
        let planted = 0x0bad_f000usize as *mut u8;
        unsafe {
            // Pre-initialized statics: guard spent, cache seeded by
            // someone else. No getter call may happen.
            EVENT_HUB_GUARD = 1;
            EVENT_HUB_INSTANCE = planted;
            event_hub_broadcast(2, 7, 0, 0xc);
        }
        assert_eq!(trace(), std::vec!["dispatch"]);
        assert_eq!(dispatched(), std::vec![(planted, 2, 7, 0, 0xc)]);
        restore(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit_zero_clear_is_turned_away_by_acquire() {
        let guard = mock(ptr::null_mut());
        let stale = 0x0d15ea5eusize as *mut u8;
        unsafe {
            // A state the real pair never produces: the fast path's
            // `tst #1` fails, but acquire tests the whole word and
            // refuses — init is skipped, release is skipped, the
            // broadcast rides the stale cache.
            EVENT_HUB_GUARD = 2;
            EVENT_HUB_INSTANCE = stale;
            event_hub_broadcast(1, 0, 0, 0);
            assert_eq!(ptr::addr_of!(EVENT_HUB_GUARD).read_volatile(), 2, "untouched");
            assert_eq!(ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile(), stale);
        }
        assert_eq!(trace(), std::vec!["dispatch"]);
        assert_eq!(dispatched(), std::vec![(stale, 1, 0, 0, 0)]);
        restore(guard);
    }

    #[test]
    fn a_reentrant_broadcast_from_the_getter_sees_the_not_yet_stored_null() {
        let hub = 0x1234_5000usize as *mut u8;
        let guard = mock(hub);
        unsafe {
            REENTER = true;
            event_hub_broadcast(5, 0, 0, 0);
        }
        // The inner broadcast runs after acquire published the guard
        // but before the outer call stored the instance: it takes the
        // fast path and dispatches NULL, exactly like the original.
        assert_eq!(trace(), std::vec!["get", "dispatch", "dispatch"]);
        assert_eq!(
            dispatched(),
            std::vec![(ptr::null_mut(), 3, 0, 0, 0), (hub, 5, 0, 0, 0)]
        );
        restore(guard);
    }

    #[test]
    fn the_shipped_defaults_are_inert() {
        let guard = EVENT_HUB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            EVENT_HUB_OPS = DEFAULT_EVENT_HUB_OPS;
            EVENT_HUB_GUARD = 0;
            EVENT_HUB_INSTANCE = ptr::null_mut();
            // Must not fault: NULL getter, no-op dispatch.
            event_hub_broadcast(0, 0, 0, 0x14);
            assert_eq!(ptr::addr_of!(EVENT_HUB_GUARD).read_volatile(), 1);
            assert_eq!(ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile(), ptr::null_mut());
        }
        restore(guard);
    }
}
