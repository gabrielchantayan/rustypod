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
//! triplets — via the ported `operator_new`). Its local array-constructor
//! adapter @ 0x08257b4c tail-branches to the ported
//! [`crate::runtime::cpp_array_construct::cpp_array_construct`] with
//! `(storage, 0x0802df58, 12, 13)`. `0x0802df58` is not a verified function
//! entry: it is carried as the original raw callback word, without an
//! invented callee identity. One list exists per event kind. A broadcast
//! walks list `kind` and invokes each listener's vtable slot +0x04 with
//! `(listener, kind, arg, payload, payload_len)` — that walk is
//! `FUN_082579d0`, not ported here. Listeners are registered by
//! [`event_hub_subscribe`], which de-duplicates each kind's listener list.
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
//! - The singleton getter is ported directly as
//!   [`event_hub_instance_get`]. Its inner generic array helper
//!   `FUN_082b498c` remains behind the existing
//!   [`crate::cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS`] seam.
//! - The dispatch `FUN_082579d0` remains behind
//!   [`EVENT_HUB_OPS`]. Its default is inert, so this symbol cannot deliver
//!   events until that list walk is ported.

use crate::cxx::templates::VectorStorage;
use crate::heap::veneers::operator_new;
use crate::runtime::cpp_array_construct::cpp_array_construct;
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

/// The cached event-hub singleton (original: the word @ 0x089cca00,
/// addressed through literal-pool word 0x082579cc). It is independent from
/// [`EVENT_HUB_INSTANCE`], the broadcast wrapper's function-local-static
/// cache at 0x089cca08.
pub static mut EVENT_HUB_SINGLETON_CACHE: *mut u8 = core::ptr::null_mut();

/// `mov r0, #0x9c` immediately before `bl 0x082aadd4`.
const EVENT_HUB_LIST_STORAGE_SIZE: usize = 0x9c;
/// The adapter's raw `r1` literal. Raw disassembly shows this lands within
/// code, not at a verified function entry, so it deliberately has no callee
/// identity.
const EVENT_HUB_LIST_CONSTRUCTOR_WORD: u32 = 0x0802_df58;
const EVENT_HUB_LIST_SIZE: u32 = 12;
const EVENT_HUB_LIST_COUNT: u32 = 13;

/// The thirteen `{begin, end, end_of_storage}` listener vectors allocated by
/// [`event_hub_instance_get`]. On ARMv5 this is exactly 0x9c bytes; typed
/// fields keep its pointers non-overlapping in 64-bit host fixtures.
#[repr(C)]
pub struct EventHub {
    pub listener_lists: [VectorStorage; EVENT_HUB_LIST_COUNT as usize],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x9c] = [0; core::mem::size_of::<EventHub>()];

/// ABI of `FUN_083e52dc`, the unported vector insertion/reallocation helper
/// reached after the listener-absence scan.
type EventHubListenerListInsert =
    unsafe extern "C" fn(*mut VectorStorage, *mut *mut u8, *const *mut u8);

#[derive(Clone, Copy)]
struct EventHubListenerListOps {
    insert: EventHubListenerListInsert,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_event_hub_listener_list_insert(
    list: *mut VectorStorage,
    end: *mut *mut u8,
    listener: *const *mut u8,
) {
    let insert: EventHubListenerListInsert = unsafe { core::mem::transmute(0x083e_52dcusize) };
    unsafe { insert(list, end, listener) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_hub_listener_list_insert(
    _list: *mut VectorStorage,
    _end: *mut *mut u8,
    _listener: *const *mut u8,
) {
    panic!("event_hub_subscribe requires vector insertion helper 0x083e52dc")
}

#[cfg(target_os = "none")]
const DEFAULT_EVENT_HUB_LIST_OPS: EventHubListenerListOps = EventHubListenerListOps {
    insert: retail_event_hub_listener_list_insert,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_EVENT_HUB_LIST_OPS: EventHubListenerListOps = EventHubListenerListOps {
    insert: missing_event_hub_listener_list_insert,
};

/// The target calls the retail vector helper directly; host tests install a
/// concrete model of its allocation path.
static mut EVENT_HUB_LIST_OPS: EventHubListenerListOps = DEFAULT_EVENT_HUB_LIST_OPS;

#[inline(always)]
unsafe fn listener_list_ops() -> EventHubListenerListOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_HUB_LIST_OPS)) }
}

/// The list walk — original: `FUN_082579d0` @ 0x082579d0. Its fifth
/// argument rides the stack on the target (the original's
/// `str r8, [sp]` @ 0x08257ba4); the extern "C" ABI places it there.

pub type EventHubDispatch =
    unsafe extern "C" fn(hub: *mut u8, kind: u32, arg: u32, payload: usize, payload_len: u32);

/// Indirect dispatch for the unported list walk. The singleton getter is
/// called directly now that it is ported.
#[derive(Clone, Copy)]
pub struct EventHubOps {
    /// `FUN_082579d0`: broadcasts to every listener registered for
    /// `kind`, plus the kind-0/len-0x14 system-event fan-out.
    pub dispatch: EventHubDispatch,
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

/// The shipped default: inert stand-in for the unported list walk.
pub const DEFAULT_EVENT_HUB_OPS: EventHubOps = EventHubOps {
    dispatch: noop_dispatch,
};

/// The active dispatch seam. Host tests install a recording model; the real
/// port replaces the default when it exists.
pub static mut EVENT_HUB_OPS: EventHubOps = DEFAULT_EVENT_HUB_OPS;

/// Volatile read so LLVM cannot fold the defaults in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn ops() -> EventHubOps {
    core::ptr::read_volatile(core::ptr::addr_of!(EVENT_HUB_OPS))
}

/// event_hub_instance_get — original: `FUN_082579a0` @ 0x082579a0
/// (48 bytes: 44 bytes of instructions plus literal-pool word 0x089cca00;
/// the next independent function starts at 0x082579d0). **11 `bl` call
/// sites, all unconditional, and no tail-branch sites**, verified by decoding
/// every ARM B/BL immediate in `osos.dec`.
///
/// Returns the cached 13-list event hub. On a NULL cache it allocates 0x9c
/// bytes with `operator_new`, calls the local 13-by-12-byte-list constructor,
/// caches that constructor's return, then reloads and returns the cache.
/// There is deliberately no NULL guard between allocation and construction.
///
/// Deviation: the original calls its 16-byte local adapter @ 0x08257b4c,
/// which only loads the raw, non-entry callback word 0x0802df58 and
/// tail-branches to [`cpp_array_construct`]. This port calls the already
/// ported adapter directly with those recovered arguments. The raw word has
/// no invented callee identity.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_hub_instance_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(EVENT_HUB_SINGLETON_CACHE);
    if cache.read_volatile().is_null() {
        let storage = operator_new(EVENT_HUB_LIST_STORAGE_SIZE);
        let constructed = cpp_array_construct(
            storage.cast(),
            EVENT_HUB_LIST_CONSTRUCTOR_WORD,
            EVENT_HUB_LIST_SIZE,
            EVENT_HUB_LIST_COUNT,
        );
        cache.write_volatile(constructed.cast());
    }
    cache.read_volatile()
}

/// event_hub_subscribe — original: `FUN_08257aec` @ 0x08257aec (96 bytes).
/// The next independently linked function starts at 0x08257b4c. **10 `bl`
/// call sites, all unconditional, and no predicated `bl` or plain-`b` tail
/// callers**, verified by decoding every ARM B/BL immediate in `osos.dec`.
///
/// Selects `hub.listener_lists[kind]`, linearly scans its half-open pointer
/// range for `listener`, and inserts one copied pointer only when absent.
/// It returns 0 when already subscribed and 1 after delegating insertion.
/// There are no NULL, `kind`, or capacity guards before the raw accesses.
///
/// Deliberate deviation: the original calls the four-byte
/// `thunk_FUN_083ea6dc` veneer to perform the pointer scan; this port inlines
/// that verified scan. The grow path still calls its actual unported target
/// `FUN_083e52dc` at 0x083e52dc on device through a volatile seam, while host
/// tests install a concrete model.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_hub_subscribe(
    hub: *mut EventHub,
    listener: *mut u8,
    kind: u32,
) -> u32 {
    let list = unsafe { (*hub).listener_lists.as_mut_ptr().add(kind as usize) };
    let end = unsafe { (*list).end.cast::<*mut u8>() };
    let mut current = unsafe { (*list).begin.cast::<*mut u8>() };

    while current != end {
        if unsafe { current.read() } == listener {
            return 0;
        }
        current = unsafe { current.add(1) };
    }

    let listener_slot = listener;
    unsafe { (listener_list_ops().insert)(list, end, &listener_slot) };
    1
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
        let hub = event_hub_instance_get();
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
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the cache, broadcast state, and dispatch seam.
    static EVENT_HUB_LOCK: Mutex<()> = Mutex::new(());
    /// Calls made through the already-ported array adapter.
    static mut ARRAY_CALLS: Vec<(usize, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32)> =
        Vec::new();
    static mut ARRAY_RETURN: *mut u32 = ptr::null_mut();
    static mut DISPATCHED: Vec<(*mut u8, u32, u32, usize, u32)> = Vec::new();
    static mut LIST_INSERT_CALLS: Vec<(usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_listener_list_insert(
        list: *mut VectorStorage,
        end: *mut *mut u8,
        listener: *const *mut u8,
    ) {
        unsafe {
            (*ptr::addr_of_mut!(LIST_INSERT_CALLS)).push((list as usize, end as usize, listener.read() as usize));
            end.write(listener.read());
            (*list).end = end.add(1).cast();
        }
    }

    const RECORDING_EVENT_HUB_LIST_OPS: EventHubListenerListOps = EventHubListenerListOps {
        insert: recording_listener_list_insert,
    };

    fn empty_listener_list() -> VectorStorage {
        VectorStorage {
            begin: ptr::null_mut(),
            end: ptr::null_mut(),
            end_of_storage: ptr::null_mut(),
        }
    }

    fn listener_list(storage: &mut [*mut u8; 2], len: usize) -> VectorStorage {
        VectorStorage {
            begin: storage.as_mut_ptr().cast(),
            end: unsafe { storage.as_mut_ptr().add(len).cast() },
            end_of_storage: unsafe { storage.as_mut_ptr().add(storage.len()).cast() },
        }
    }

    unsafe extern "C" fn recording_array_reset(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        allocation_header_bytes: u32,
        initializer_argument: u32,
        element_initializer: u32,
        initializer_context: u32,
        allocator_callback: u32,
        allocator_context: u32,
        allocation_flags: u32,
        zero_initialize: u32,
    ) -> *mut u32 {
        (*ptr::addr_of_mut!(ARRAY_CALLS)).push((
            this as usize,
            field_count,
            field_size,
            allocation_header_bytes,
            initializer_argument,
            element_initializer,
            initializer_context,
            allocator_callback,
            allocator_context,
            allocation_flags,
            zero_initialize,
        ));
        ptr::addr_of!(ARRAY_RETURN).read_volatile()
    }

    const RECORDING_ARRAY_OPS: PairHeaderElementArrayOps = PairHeaderElementArrayOps {
        reset: recording_array_reset,
    };

    unsafe extern "C" fn recording_dispatch(
        hub: *mut u8,
        kind: u32,
        arg: u32,
        payload: usize,
        payload_len: u32,
    ) {
        (*ptr::addr_of_mut!(DISPATCHED)).push((hub, kind, arg, payload, payload_len));
    }

    fn lock_hub() -> MutexGuard<'static, ()> {
        EVENT_HUB_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    unsafe fn reset_hub_state() {
        EVENT_HUB_GUARD = 0;
        EVENT_HUB_INSTANCE = ptr::null_mut();
        EVENT_HUB_SINGLETON_CACHE = ptr::null_mut();
        EVENT_HUB_OPS = DEFAULT_EVENT_HUB_OPS;
        EVENT_HUB_LIST_OPS = DEFAULT_EVENT_HUB_LIST_OPS;
        (*ptr::addr_of_mut!(DISPATCHED)).clear();
        (*ptr::addr_of_mut!(LIST_INSERT_CALLS)).clear();
    }

    #[test]
    fn singleton_allocates_and_constructs_thirteen_twelve_byte_lists_once() {
        let hub_guard = lock_hub();
        let array_guard = crate::testing::CPP_ARRAY_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        let saved_array_ops = unsafe { ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile() };
        let allocated = crate::heap::veneers::tests::mock_block();
        let constructed = 0x1234_5000usize as *mut u32;

        unsafe {
            reset_hub_state();
            ARRAY_RETURN = constructed;
            (*ptr::addr_of_mut!(ARRAY_CALLS)).clear();
            PAIR_HEADER_ELEMENT_ARRAY_OPS = RECORDING_ARRAY_OPS;

            assert_eq!(event_hub_instance_get(), constructed.cast());
            assert_eq!(event_hub_instance_get(), constructed.cast(), "cache is reloaded");
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x9c, 2));
            assert_eq!(
                (*ptr::addr_of!(ARRAY_CALLS)).as_slice(),
                [(
                    allocated as usize,
                    13,
                    12,
                    0,
                    0,
                    0x0802_df58,
                    0,
                    0,
                    0,
                    0,
                    0,
                )],
                "the local adapter's recovered arguments reach the generic helper"
            );
            assert_eq!(
                ptr::addr_of!(EVENT_HUB_SINGLETON_CACHE).read_volatile(),
                constructed.cast(),
                "the constructor return, not the raw allocation, is cached"
            );
            PAIR_HEADER_ELEMENT_ARRAY_OPS = saved_array_ops;
            crate::heap::veneers::HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            crate::heap::types::DEFAULT_HEAP = ptr::null_mut();
            reset_hub_state();
        }
        drop(heap_guard);
        drop(array_guard);
        drop(hub_guard);
    }

    #[test]
    fn subscribe_deduplicates_then_inserts_at_the_selected_list_end() {
        let hub_guard = lock_hub();
        let existing = 0x1234_5000usize as *mut u8;
        let added = 0x2468_a000usize as *mut u8;
        let mut storage = [existing, ptr::null_mut()];
        let mut hub = EventHub {
            listener_lists: core::array::from_fn(|_| empty_listener_list()),
        };

        unsafe {
            reset_hub_state();
            EVENT_HUB_LIST_OPS = RECORDING_EVENT_HUB_LIST_OPS;
            hub.listener_lists[6] = listener_list(&mut storage, 1);

            assert_eq!(event_hub_subscribe(&mut hub, existing, 6), 0);
            assert!((*ptr::addr_of!(LIST_INSERT_CALLS)).is_empty(), "existing listener never grows");

            assert_eq!(event_hub_subscribe(&mut hub, added, 6), 1);
            assert_eq!(storage, [existing, added]);
            assert_eq!(
                (*ptr::addr_of!(LIST_INSERT_CALLS)).as_slice(),
                [(
                    ptr::addr_of_mut!(hub.listener_lists[6]) as usize,
                    storage.as_mut_ptr().add(1) as usize,
                    added as usize,
                )],
                "only the selected kind's end pointer and copied listener reach growth"
            );
            reset_hub_state();
        }
        drop(hub_guard);
    }

    #[test]
    fn subscribe_forwards_a_null_listener_from_an_empty_list() {
        let hub_guard = lock_hub();
        let mut storage = [0xaaaa_5000usize as *mut u8, ptr::null_mut()];
        let mut hub = EventHub {
            listener_lists: core::array::from_fn(|_| empty_listener_list()),
        };

        unsafe {
            reset_hub_state();
            EVENT_HUB_LIST_OPS = RECORDING_EVENT_HUB_LIST_OPS;
            hub.listener_lists[0] = listener_list(&mut storage, 0);

            assert_eq!(event_hub_subscribe(&mut hub, ptr::null_mut(), 0), 1);
            assert_eq!(storage[0], ptr::null_mut(), "no NULL listener guard");
            assert_eq!((&*ptr::addr_of!(LIST_INSERT_CALLS))[0].2, 0);
            reset_hub_state();
        }
        drop(hub_guard);
    }

    #[test]
    fn singleton_calls_constructor_even_when_allocation_is_null() {
        let hub_guard = lock_hub();
        let array_guard = crate::testing::CPP_ARRAY_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        let saved_array_ops = unsafe { ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile() };
        let constructor_return = 0x2468_0000usize as *mut u32;

        unsafe {
            reset_hub_state();
            crate::heap::veneers::tests::set_alloc_ret(ptr::null_mut());
            ARRAY_RETURN = constructor_return;
            (*ptr::addr_of_mut!(ARRAY_CALLS)).clear();
            PAIR_HEADER_ELEMENT_ARRAY_OPS = RECORDING_ARRAY_OPS;

            assert_eq!(event_hub_instance_get(), constructor_return.cast());
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x9c, 2));
            assert_eq!((*ptr::addr_of!(ARRAY_CALLS)).len(), 1, "no NULL guard skips construction");
            assert_eq!((&*ptr::addr_of!(ARRAY_CALLS))[0].0, 0, "NULL allocation is forwarded");

            PAIR_HEADER_ELEMENT_ARRAY_OPS = saved_array_ops;
            crate::heap::veneers::HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            crate::heap::types::DEFAULT_HEAP = ptr::null_mut();
            reset_hub_state();
        }
        drop(heap_guard);
        drop(array_guard);
        drop(hub_guard);
    }

    #[test]
    fn first_broadcast_caches_the_direct_singleton_then_dispatches_every_argument() {
        let hub_guard = lock_hub();
        let hub = 0x1234_5000usize as *mut u8;
        let mut payload = [0xabu8; 0x14];

        unsafe {
            reset_hub_state();
            EVENT_HUB_SINGLETON_CACHE = hub;
            EVENT_HUB_OPS = EventHubOps { dispatch: recording_dispatch };
            event_hub_broadcast(9, 0, payload.as_mut_ptr() as usize, 0x800);
            assert_eq!(ptr::addr_of!(EVENT_HUB_GUARD).read_volatile(), 1, "acquire published");
            assert_eq!(ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile(), hub);
            assert_eq!(
                (*ptr::addr_of!(DISPATCHED)).as_slice(),
                [(hub, 9, 0, payload.as_mut_ptr() as usize, 0x800)]
            );
            reset_hub_state();
        }
        drop(hub_guard);
    }

    #[test]
    fn spent_broadcast_guard_reloads_its_cache_without_calling_the_getter() {
        let hub_guard = lock_hub();
        let planted = 0x0bad_f000usize as *mut u8;

        unsafe {
            reset_hub_state();
            EVENT_HUB_GUARD = 1;
            EVENT_HUB_INSTANCE = planted;
            EVENT_HUB_OPS = EventHubOps { dispatch: recording_dispatch };
            event_hub_broadcast(8, 0, 0xd, 4);
            assert_eq!((*ptr::addr_of!(DISPATCHED)).as_slice(), [(planted, 8, 0, 0xd, 4)]);
            reset_hub_state();
        }
        drop(hub_guard);
    }
}
