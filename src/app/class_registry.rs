//! The constructor of the global **class registry** — the static-init
//! half of `app/registry.rs`.
//!
//! | address | name | size | sites |
//! |---|---|---|---|
//! | 0x0810e64c | [`class_registry_construct`] | 96 | 9 `bl` + 1 tail `b` |
//!
//! (Call-site count binary-scanned over osos.dec; one of the nine `bl`s
//! is the static-init chain @ 0x082afb6c, which runs it against the
//! statically-allocated registry object @ 0x08a79ca4 — the crate's
//! [`CLASS_REGISTRY`].)
//!
//! ## Algorithm
//!
//! ```text
//! class_registry_construct(registry):
//!     registry = container_construct(registry, 8, 4)     // 0x08135308
//!     if (REGISTRY_OBSERVER == 0) {
//!         observer = observer_construct(operator_new(8)) // 0x082028a4
//!         REGISTRY_OBSERVER = observer
//!         observer->vtable->attach(observer)             // slot +0x18
//!     }
//!     set_observer(registry, REGISTRY_OBSERVER)          // 0x08135040
//!     observable_set_notify_enabled(registry, 1)         // 0x08134ff8
//!     return registry
//! ```
//!
//! - `container_construct` @ 0x08135308 is the registry's container
//!   base ctor: it layers two vtables over the object (base @
//!   0x08271cec, container vtable 0x08984770 stored at +0x00), then
//!   `FUN_08135110` initialises the container state — capacity 8 at
//!   +0x10, growth step 4 at +0x18, zeroed count/observer words, the
//!   +0x20 "changed" byte raised, the +0x21 "notify enabled" byte
//!   cleared — and installs a *default* observer singleton picked by
//!   capacity.
//! - The second singleton is the registry's own observer: an 8-byte
//!   object (vtable 0x089910ac + one word) constructed lazily by
//!   `FUN_082028a4` over `operator_new(8)`, cached in the global word @
//!   0x089d01ac (the literal @ 0x0810e6ac), then initialised through
//!   slot +0x18 of its own vtable. The cache is stored **before** the
//!   dispatch (the original's `str r0, [r4]` ahead of the `blx`), and
//!   re-loaded after it (the `ldr r1, [r4, #0]` @ 0x0810e68c), so an
//!   attach that rewrites the cache wins. Reproduced.
//! - `set_observer` @ 0x08135040 replaces the container's default
//!   observer (at +0x24) with the registry observer, detaching the old
//!   one through its vtable +0x1c and notifying through the registry's
//!   own +0x60/+0x68 slots.
//! - `observable_set_notify_enabled` @ 0x08134ff8 is already ported
//!   (`app/registry.rs`), so it is called directly: construction ends
//!   with notifications switched on, which fires the first change
//!   notification through the freshly installed vtable.
//!
//! `operator new` @ 0x082aadd4 is already ported
//! (`heap::veneers::operator_new`), so it is called directly. The
//! container ctor, the observer ctor and the observer swap are the
//! unported C++ container/observer machinery, so they sit behind the
//! [`CLASS_REGISTRY_OPS`] dispatch table — the `app/singletons.rs`
//! pattern — whose documented stubs are:
//!
//! - `container_construct`: returns `this` **unchanged** — the object
//!   keeps its pre-init all-zero state, vtable NULL, the same
//!   fault-on-first-dispatch contract `registry.rs` documents;
//! - `observer_construct`: the zeroing stub (8 bytes), which installs
//!   no vtable;
//! - `set_observer`: a no-op.
//!
//! **Not hook-ready.** With the default stubs the attach dispatch reads
//! a NULL observer vtable, so branching stock static-init here would
//! fault where the original succeeds; the port exists because the
//! *constructor's own* logic (capacity/growth immediates, the lazy
//! 8-byte singleton, the store-then-dispatch-then-reload ordering, the
//! observer swap, the final notification enable) is fully recovered.
//! The ops slots are the documented boundary, exactly like
//! `SINGLETON_CTORS`.
//!
//! ## Deviations
//!
//! - The observer cache word is the crate static [`REGISTRY_OBSERVER`]
//!   instead of the global @ 0x089d01ac (the `block_mgr.rs` /
//!   `singletons.rs` deviation: the 0x089dxxxx RW page is
//!   runtime-initialized; the decrypted image holds stale data there).
//!   NULL until first construction, exactly the pre-init state.
//! - A NULL-returning observer ctor caches NULL and faults on the
//!   attach dispatch — precisely what the original's
//!   `ldr r1, [r0]; ldr r1, [r1, #0x18]; blx r1` does. No guard added;
//!   adding one would be a behavior change.

use crate::app::registry::{observable_set_notify_enabled, Registry};
use crate::heap::veneers::operator_new;

/// The container's initial capacity (`mov r1, #0x8` @ 0x0810e654).
pub const REGISTRY_INITIAL_CAPACITY: u32 = 8;

/// The container's growth step (`mov r2, #0x4` @ 0x0810e650).
pub const REGISTRY_GROWTH_STEP: u32 = 4;

/// Allocation size of the registry observer singleton (`mov r0, #0x8`
/// @ 0x0810e670): a vtable pointer plus one word.
pub const REGISTRY_OBSERVER_SIZE: usize = 8;

/// The registry observer's vtable, modeled down to the one slot
/// [`class_registry_construct`] dispatches. The filler array reproduces
/// the original byte offset on the 32-bit target and keeps the named
/// slot disjoint on a 64-bit host (the `registry.rs` rule).
#[repr(C)]
pub struct RegistryObserverVtable {
    /// Slots +0x00..+0x14: not dispatched here.
    pub unresolved_00: [usize; 6],
    /// +0x18: `attach(this)` — the post-construction initialiser the
    /// constructor dispatches exactly once, right after caching the
    /// singleton. Its result is discarded, exactly like the original
    /// (the `blx` is followed by a fresh `ldr r1, [r4, #0]`).
    pub attach: unsafe extern "C" fn(this: *mut RegistryObserver) -> *mut u8,
}

/// The 8-byte registry observer object, modeled down to its vtable
/// pointer; the second word belongs to the unported observer class.
#[repr(C)]
pub struct RegistryObserver {
    /// +0x00: the observer's vtable (original: the literal 0x089910ac,
    /// stored by the ctor @ 0x082028a4).
    pub vtable: *const RegistryObserverVtable,
    /// +0x04: the observer class's own state.
    pub reserved: u32,
}

/// The registry observer singleton (original: the global word @
/// 0x089d01ac — see the module-header deviation). NULL until
/// [`class_registry_construct`] first runs.
pub static mut REGISTRY_OBSERVER: *mut RegistryObserver = core::ptr::null_mut();

/// Indirect dispatch table for the three unported callees (see the
/// module header for the default-stub contract).
#[derive(Clone, Copy)]
pub struct ClassRegistryOps {
    /// The container base ctor @ 0x08135308
    /// `(this, capacity, growth) -> this`.
    pub container_construct: unsafe extern "C" fn(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) -> *mut Registry,
    /// The registry observer's ctor @ 0x082028a4: an ADS C++
    /// constructor, takes the raw block, returns `this`.
    pub observer_construct: unsafe extern "C" fn(this: *mut u8) -> *mut u8,
    /// The observer swap @ 0x08135040 `(observable, observer)`:
    /// detaches the old observer (+0x24) through its vtable +0x1c,
    /// installs the new one, attaches it (vtable +0x18) and notifies
    /// through the observable's own +0x60/+0x68 slots. The original's
    /// result is discarded by the constructor, so the slot's is too.
    pub set_observer: unsafe extern "C" fn(
        observable: *mut Registry,
        observer: *mut RegistryObserver,
    ) -> *mut u8,
}

/// Default container-ctor stub: returns `this` untouched — fail
/// closed, leaving the object in its pre-init all-zero state (see the
/// module header).
unsafe extern "C" fn stub_container_construct(
    this: *mut Registry,
    _capacity: u32,
    _growth: u32,
) -> *mut Registry {
    this
}

/// Default observer-ctor stub: zeroes the 8-byte block and returns it
/// (the `singletons.rs` zeroing precedent — a faithful *subset* of the
/// original's stores, but no vtable, which is why the module header
/// calls this port not hook-ready). Volatile stores: a plain loop is
/// rewritten by LLVM into a call to `__aeabi_memclr`, a symbol that
/// does not exist in this build (the strcat.rs trap).
unsafe extern "C" fn stub_observer_construct(this: *mut u8) -> *mut u8 {
    if !this.is_null() {
        for offset in 0..REGISTRY_OBSERVER_SIZE {
            this.add(offset).write_volatile(0);
        }
    }
    this
}

/// Default observer-swap stub: no-op (see the module header).
unsafe extern "C" fn stub_set_observer(
    _observable: *mut Registry,
    _observer: *mut RegistryObserver,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired defaults (documented stubs until the container/observer
/// classes are ported).
pub(crate) const DEFAULT_CLASS_REGISTRY_OPS: ClassRegistryOps = ClassRegistryOps {
    container_construct: stub_container_construct,
    observer_construct: stub_observer_construct,
    set_observer: stub_set_observer,
};

/// The active implementation table. Host tests install recording mocks;
/// the real ports replace the defaults when they exist.
pub static mut CLASS_REGISTRY_OPS: ClassRegistryOps = DEFAULT_CLASS_REGISTRY_OPS;

/// Reads one op (volatile — same rationale as every dispatch table: the
/// slot is meant to be swapped at runtime, and a build in which nothing
/// swaps it must not constant-fold the default in).
macro_rules! ops {
    ($field:ident) => {
        core::ptr::read_volatile(core::ptr::addr_of!(CLASS_REGISTRY_OPS.$field))
    };
}

/// class_registry_construct — original: `FUN_0810e64c` @ 0x0810e64c
/// (96 bytes; 9 `bl` + 1 tail `b` call sites, binary-scanned — one `bl`
/// is the static-init chain @ 0x082afb6c constructing the global
/// registry @ 0x08a79ca4, the crate's [`CLASS_REGISTRY`]).
///
/// Constructs the registry container (capacity 8, growth 4), lazily
/// builds and caches the 8-byte observer singleton, swaps it in for the
/// container's default observer, enables change notifications and
/// returns the container ctor's result. See the module header for the
/// full algorithm and the dispatch-slot boundaries.
///
/// Faithful details:
///
/// - The capacity/growth immediates are the original's
///   `mov r1, #0x8` / `mov r2, #0x4`.
/// - The cache store lands **before** the attach dispatch, and the
///   observer handed to `set_observer` is re-loaded from the cache
///   after it — an attach that rewrites the cache is honored (the
///   original's `str r0, [r4]` / `blx` / `ldr r1, [r4, #0]`).
/// - The attach goes through the observer's own vtable pointer rather
///   than a crate-level hook, so a subclass (or test) vtable installed
///   by the ctor is dispatched — the `object_cast_to_class` precedent.
/// - Everything downstream — `set_observer` and the notification
///   enable — runs on the container ctor's *result* (r5), not on the
///   raw argument.
///
/// [`CLASS_REGISTRY`]: crate::app::registry::CLASS_REGISTRY
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_registry_construct(registry: *mut Registry) -> *mut Registry {
    let registry = (ops!(container_construct))(
        registry,
        REGISTRY_INITIAL_CAPACITY,
        REGISTRY_GROWTH_STEP,
    );
    let cache = core::ptr::addr_of_mut!(REGISTRY_OBSERVER);
    if core::ptr::read_volatile(cache).is_null() {
        let observer =
            (ops!(observer_construct))(operator_new(REGISTRY_OBSERVER_SIZE)) as *mut RegistryObserver;
        core::ptr::write_volatile(cache, observer);
        let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observer).vtable));
        ((*vtable).attach)(observer);
    }
    let observer = core::ptr::read_volatile(cache);
    (ops!(set_observer))(registry, observer);
    observable_set_notify_enabled(registry, 1);
    registry
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::registry::RegistryVtable;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below.
    static CONSTRUCT_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out.
    static mut ARENA: [u8; REGISTRY_OBSERVER_SIZE] = [0xa5; REGISTRY_OBSERVER_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Ordered trace of the mock calls.
    static mut TRACE: Vec<&'static str> = Vec::new();

    /// The container-ctor arguments, recorded on every call.
    static mut CONTAINER_ARGS: Vec<(*mut Registry, u32, u32)> = Vec::new();

    /// The observer/set_observer arguments, recorded on every call.
    static mut OBSERVER_ARGS: Vec<*mut RegistryObserver> = Vec::new();

    /// What the mock container ctor returns.
    static mut CONTAINER_RESULT: *mut Registry = ptr::null_mut();

    /// Attachments dispatched through the observer vtable, in order.
    static mut ATTACHED: Vec<*mut RegistryObserver> = Vec::new();

    fn trace() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(TRACE) }
    }

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    unsafe extern "C" fn mock_container_construct(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) -> *mut Registry {
        trace().push("container_construct");
        (*ptr::addr_of_mut!(CONTAINER_ARGS)).push((this, capacity, growth));
        ptr::read_volatile(ptr::addr_of!(CONTAINER_RESULT))
    }

    unsafe extern "C" fn mock_observer_construct(this: *mut u8) -> *mut u8 {
        trace().push("observer_construct");
        // The real ctor stores the observer vtable at +0x00; the mock
        // installs the recording vtable so the attach dispatch has
        // somewhere to go.
        (this as *mut RegistryObserver).write(RegistryObserver {
            vtable: ptr::addr_of!(MOCK_OBSERVER_VTABLE),
            reserved: 0,
        });
        this
    }

    unsafe extern "C" fn mock_attach(this: *mut RegistryObserver) -> *mut u8 {
        trace().push("attach");
        (*ptr::addr_of_mut!(ATTACHED)).push(this);
        ptr::null_mut()
    }

    unsafe extern "C" fn mock_set_observer(
        observable: *mut Registry,
        observer: *mut RegistryObserver,
    ) -> *mut u8 {
        trace().push("set_observer");
        (*ptr::addr_of_mut!(OBSERVER_ARGS)).push(observer);
        observable as *mut u8
    }

    static MOCK_OBSERVER_VTABLE: RegistryObserverVtable = RegistryObserverVtable {
        unresolved_00: [0; 6],
        attach: mock_attach,
    };

    // ---- the registry the mock container ctor "builds" ----

    /// Ordered trace of the registry vtable's notification pair.
    unsafe extern "C" fn mock_notify_deferred(_this: *mut Registry) -> *mut u8 {
        trace().push("notify_deferred");
        ptr::null_mut()
    }

    unsafe extern "C" fn mock_notify_changed(_this: *mut Registry) -> *mut u8 {
        trace().push("notify_changed");
        ptr::null_mut()
    }

    unsafe extern "C" fn unimplemented_insert(
        _this: *mut Registry,
        _entry: *const crate::app::registry::RegistryEntry,
    ) -> usize {
        unreachable!()
    }

    unsafe extern "C" fn unimplemented_assign_at(
        _this: *mut Registry,
        _index: i32,
        _entry: *const crate::app::registry::RegistryEntry,
    ) -> usize {
        unreachable!()
    }

    unsafe extern "C" fn unimplemented_entry_at(
        _this: *mut Registry,
        _index: i32,
        _out: *mut crate::app::registry::RegistryEntry,
    ) -> *mut crate::app::registry::RegistryEntry {
        unreachable!()
    }

    unsafe extern "C" fn unimplemented_index_of(_this: *mut Registry, _key: *const u32) -> i32 {
        unreachable!()
    }

    unsafe extern "C" fn unimplemented_has_pending_changes(_this: *mut Registry) -> *mut u8 {
        unreachable!()
    }

    static MOCK_REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unimplemented_insert,
        unresolved_20: 0,
        assign_at: unimplemented_assign_at,
        unresolved_28: [0; 5],
        entry_at: unimplemented_entry_at,
        unresolved_40: [0; 3],
        index_of: unimplemented_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unimplemented_has_pending_changes,
        notify_deferred: mock_notify_deferred,
        notify_changed: mock_notify_changed,
    };

    /// The registry object the mock container ctor returns (distinct
    /// from the argument, so the r5 threading is observable).
    static mut CONSTRUCTED_REGISTRY: Registry = Registry {
        vtable: ptr::null(),
        container: [0; 7],
        changed: 0,
        notify_enabled: 0,
        reserved: [0; 2],
        observer: ptr::null_mut(),
    };

    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    fn constructed() -> *mut Registry {
        ptr::addr_of_mut!(CONSTRUCTED_REGISTRY)
    }

    fn observer_cache() -> *mut *mut RegistryObserver {
        ptr::addr_of_mut!(REGISTRY_OBSERVER)
    }

    /// Installs the stub allocator plus the recording ops and resets
    /// every recorder.
    fn mock() -> MutexGuard<'static, ()> {
        let guard = CONSTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut heap = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            heap.alloc = stub_alloc;
            heap.create = stub_create;
            HEAP_OPS = heap;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            CLASS_REGISTRY_OPS = ClassRegistryOps {
                container_construct: mock_container_construct,
                observer_construct: mock_observer_construct,
                set_observer: mock_set_observer,
            };
            ptr::addr_of_mut!(CONSTRUCTED_REGISTRY).write(Registry {
                vtable: ptr::addr_of!(MOCK_REGISTRY_VTABLE),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            });
            CONTAINER_RESULT = constructed();
            REGISTRY_OBSERVER = ptr::null_mut();
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CONTAINER_ARGS)).clear();
            (*ptr::addr_of_mut!(OBSERVER_ARGS)).clear();
            (*ptr::addr_of_mut!(ATTACHED)).clear();
            trace().clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            CLASS_REGISTRY_OPS = DEFAULT_CLASS_REGISTRY_OPS;
            REGISTRY_OBSERVER = ptr::null_mut();
            ptr::addr_of_mut!(CONSTRUCTED_REGISTRY).write(Registry {
                vtable: ptr::null(),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            });
        }
        drop(guard);
    }

    /// A scratch registry passed in as the constructor argument.
    fn argument() -> *mut Registry {
        0x2000 as *mut Registry
    }

    #[test]
    fn construct_builds_the_container_with_capacity_8_and_growth_4() {
        let guard = mock();
        unsafe {
            assert_eq!(class_registry_construct(argument()), constructed());
            assert_eq!(
                *ptr::addr_of!(CONTAINER_ARGS),
                std::vec![(argument(), 8, 4)],
                "the original's mov r1, #0x8 / mov r2, #0x4"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_observer_is_allocated_constructed_cached_and_attached_once() {
        let guard = mock();
        unsafe {
            class_registry_construct(argument());
            let observer = ptr::read_volatile(observer_cache());
            assert_eq!(observer, ptr::addr_of_mut!(ARENA) as *mut RegistryObserver);
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![REGISTRY_OBSERVER_SIZE]);
            assert_eq!(*ptr::addr_of!(ATTACHED), std::vec![observer]);
            assert_eq!(
                *trace(),
                std::vec![
                    "container_construct",
                    "observer_construct",
                    "attach",
                    "set_observer",
                    "notify_deferred",
                    "notify_changed"
                ],
                "the full first-construction sequence, in the original's order"
            );

            trace().clear();
            class_registry_construct(argument());
            assert_eq!(
                *trace(),
                std::vec!["container_construct", "set_observer", "notify_deferred", "notify_changed"],
                "the second call hits the cache: no allocation, no ctor, no attach"
            );
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!(*ptr::addr_of!(OBSERVER_ARGS), std::vec![observer, observer]);
        }
        restore(guard);
    }

    #[test]
    fn the_cache_is_stored_before_the_attach_dispatch() {
        // The original's `str r0, [r4]` lands ahead of the `blx`.
        unsafe extern "C" fn cache_checking_attach(this: *mut RegistryObserver) -> *mut u8 {
            trace().push("attach");
            assert_eq!(ptr::read_volatile(observer_cache()), this, "cached before attach runs");
            ptr::null_mut()
        }
        static CACHE_CHECK_VTABLE: RegistryObserverVtable = RegistryObserverVtable {
            unresolved_00: [0; 6],
            attach: cache_checking_attach,
        };
        unsafe extern "C" fn cache_check_ctor(this: *mut u8) -> *mut u8 {
            (this as *mut RegistryObserver).write(RegistryObserver {
                vtable: ptr::addr_of!(CACHE_CHECK_VTABLE),
                reserved: 0,
            });
            this
        }
        let guard = mock();
        unsafe {
            CLASS_REGISTRY_OPS.observer_construct = cache_check_ctor;
            class_registry_construct(argument());
        }
        restore(guard);
    }

    #[test]
    fn the_observer_is_reloaded_from_the_cache_after_attach() {
        // The original's `ldr r1, [r4, #0]` after the `blx`: an attach
        // that rewrites the cache wins over the ctor's return value.
        let replacement = 0x4800 as *mut RegistryObserver;
        unsafe extern "C" fn rewriting_attach(_this: *mut RegistryObserver) -> *mut u8 {
            REGISTRY_OBSERVER = 0x4800 as *mut RegistryObserver;
            ptr::null_mut()
        }
        static REWRITING_VTABLE: RegistryObserverVtable = RegistryObserverVtable {
            unresolved_00: [0; 6],
            attach: rewriting_attach,
        };
        unsafe extern "C" fn rewriting_ctor(this: *mut u8) -> *mut u8 {
            (this as *mut RegistryObserver).write(RegistryObserver {
                vtable: ptr::addr_of!(REWRITING_VTABLE),
                reserved: 0,
            });
            this
        }
        let guard = mock();
        unsafe {
            CLASS_REGISTRY_OPS.observer_construct = rewriting_ctor;
            class_registry_construct(argument());
            assert_eq!(
                *ptr::addr_of!(OBSERVER_ARGS),
                std::vec![replacement],
                "set_observer sees the reloaded cache, not the ctor result"
            );
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_observer_cache_short_circuits_the_lazy_build() {
        let guard = mock();
        unsafe {
            let seeded = 0x5000 as *mut RegistryObserver;
            REGISTRY_OBSERVER = seeded;
            class_registry_construct(argument());
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty(), "no allocation");
            assert!((*ptr::addr_of!(ATTACHED)).is_empty(), "no attach");
            assert_eq!(
                *trace(),
                std::vec!["container_construct", "set_observer", "notify_deferred", "notify_changed"]
            );
            assert_eq!(*ptr::addr_of!(OBSERVER_ARGS), std::vec![seeded]);
            assert_eq!(ptr::read_volatile(observer_cache()), seeded, "the cache is untouched");
        }
        restore(guard);
    }

    #[test]
    fn everything_downstream_runs_on_the_container_ctors_result() {
        // r5, not the raw argument: `argument()` is never dereferenced.
        let guard = mock();
        unsafe {
            assert_eq!(class_registry_construct(argument()), constructed());
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(CONSTRUCTED_REGISTRY.notify_enabled)),
                1,
                "observable_set_notify_enabled(registry, 1) ran on the ctor result"
            );
        }
        restore(guard);
    }

    #[test]
    fn construction_ends_with_notifications_enabled_firing_once() {
        let guard = mock();
        unsafe {
            class_registry_construct(argument());
            assert_eq!(
                trace()[trace().len() - 2..],
                std::vec!["notify_deferred", "notify_changed"],
                "the enable fires the first change notification through the new vtable"
            );
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CONSTRUCTED_REGISTRY.notify_enabled)), 1);
        }
        restore(guard);
    }

    // ---- the default stubs ----

    #[test]
    fn the_default_container_stub_returns_this_unchanged() {
        let guard = CONSTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut registry = Registry {
                vtable: ptr::null(),
                container: [0xdead_beef; 7],
                changed: 0xa5,
                notify_enabled: 0x5a,
                reserved: [0; 2],
                observer: 0x1234 as *mut u8,
            };
            let this = ptr::addr_of_mut!(registry);
            assert_eq!(stub_container_construct(this, 8, 4), this);
            assert_eq!(registry.container, [0xdead_beef; 7], "nothing is written");
            assert_eq!(registry.changed, 0xa5);
            assert_eq!(registry.notify_enabled, 0x5a);
        }
        restore(guard);
    }

    #[test]
    fn the_default_observer_stub_zeroes_the_8_byte_block() {
        let guard = CONSTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..REGISTRY_OBSERVER_SIZE {
                block.add(offset).write(0xa5);
            }
            assert_eq!(stub_observer_construct(block), block);
            assert!((0..REGISTRY_OBSERVER_SIZE).all(|offset| block.add(offset).read() == 0));
            assert!(stub_observer_construct(ptr::null_mut()).is_null(), "NULL-safe");
        }
        restore(guard);
    }

    #[test]
    fn the_default_set_observer_stub_is_a_noop() {
        let guard = CONSTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert!(stub_set_observer(argument(), 0x6000 as *mut RegistryObserver).is_null());
        }
        restore(guard);
    }

    #[test]
    fn the_original_immediates_are_the_literal_constants() {
        assert_eq!(REGISTRY_INITIAL_CAPACITY, 8);
        assert_eq!(REGISTRY_GROWTH_STEP, 4);
        assert_eq!(REGISTRY_OBSERVER_SIZE, 8);
    }
}
