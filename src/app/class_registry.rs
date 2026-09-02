//! The constructor of the global **class registry** — the static-init
//! half of `app/registry.rs`.
//!
//! | address | name | size | sites |
//! |---|---|---:|---:|
//! | 0x0810dddc | [`registry_observer_base_construct`] | 20 | 24 `bl` |
//! | 0x0810e64c | [`class_registry_construct`] | 96 | 9 `bl` + 1 tail `b` |
//! | 0x08135110 | [`registry_container_initialize`] | 168 | 4 `bl` + 3 virtual calls |
//! | 0x08135308 | [`registry_container_construct`] | 48 | 6 `bl` |
//! | 0x0813533c | [`registry_container_construct_default`] | 44 | 23 `bl` |
//! | 0x082028a4 | [`registry_observer_construct`] | 20 | 3 `bl` |
//! (Call-site counts are binary-scanned over osos.dec; one of the nine
//! class-registry `bl`s is the static-init chain @ 0x082afb6c, which runs it
//! against the statically allocated registry object @ 0x08a79ca4 — the
//! crate's [`CLASS_REGISTRY`].)
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
//! - [`registry_container_construct`] @ 0x08135308 is the registry's
//!   concrete observable-array constructor. It invokes the ported
//!   [`observable_array_construct`] base @ 0x08271cec (vtable + three
//!   zero words at +0x00..+0x0c), overwrites the returned object's vtable
//!   with 0x08984770, then calls [`registry_container_initialize`] with
//!   the original capacity and growth.
//! - [`registry_container_initialize`] initializes the container words at
//!   +0x10..+0x24 and chooses one of two lazily allocated default observers:
//!   the 0x08988eb0 class only for capacity 4, and the 0x08989ca4 class for
//!   every other capacity. It caches an observer before its first +0x18
//!   dispatch, stores it at +0x24, and dispatches +0x18 again; a newly
//!   allocated observer is therefore attached twice.
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
//! (`heap::veneers::operator_new`) and
//! [`registry_container_construct`] @ 0x08135308 is its direct dependency,
//! so both calls reproduce the original's direct `bl`s. The observer swap is
//! ported below and wired directly into [`CLASS_REGISTRY_OPS`].
//!
//! ## Deviations
//!
//! - The observer cache words are crate statics rather than the globals at
//!   0x089cc904/0x089cc908. They are NULL until first construction, matching
//!   the runtime state observed by the stock initializer.
//! - The registry observer cache word is the crate static
//!   [`REGISTRY_OBSERVER`] instead of the global @ 0x089d01ac (the
//!   `block_mgr.rs` / `singletons.rs` deviation: the 0x089dxxxx RW page is
//!   runtime-initialized; the decrypted image holds stale data there).
//!   NULL until first construction, exactly the pre-init state.
//! - A NULL-returning observer ctor caches NULL and faults on the
//!   attach dispatch — precisely what the original's
//!   `ldr r1, [r0]; ldr r1, [r1, #0x18]; blx r1` does. No guard added;
//!   adding one would be a behavior change.
//!

use crate::app::registry::{observable_set_notify_enabled, Registry};
use crate::cxx::observable_array::{observable_array_construct, ObservableArray};
use crate::heap::veneers::operator_new;

/// The container's initial capacity (`mov r1, #0x8` @ 0x0810e654).
pub const REGISTRY_INITIAL_CAPACITY: u32 = 8;

/// The container's growth step (`mov r2, #0x4` @ 0x0810e650).
pub const REGISTRY_GROWTH_STEP: u32 = 4;

/// Allocation size of the registry observer singleton (`mov r0, #0x8`
/// @ 0x0810e670): a vtable pointer plus one word.
pub const REGISTRY_OBSERVER_SIZE: usize = 8;

/// The concrete registry-container vtable literal loaded from 0x08135338
/// and written at +0x00 by [`registry_container_construct`].
pub const REGISTRY_CONTAINER_VTABLE_ADDRESS: usize = 0x0898_4770;

/// The registry observer's vtable, modeled down to the two slots the
/// constructors and [`registry_set_observer`] dispatch. The filler array
/// reproduces the original byte offset on the 32-bit target and keeps the
/// named slots disjoint on a 64-bit host (the `registry.rs` rule).
#[repr(C)]
pub struct RegistryObserverVtable {
    /// Slots +0x00..+0x14: not dispatched here.
    pub unresolved_00: [usize; 6],
    /// +0x18: `attach(this)` — the post-construction initialiser the
    /// constructor dispatches exactly once, right after caching the
    /// singleton. Its result is discarded, exactly like the original
    /// (the `blx` is followed by a fresh `ldr r1, [r4, #0]`).
    pub attach: unsafe extern "C" fn(this: *mut RegistryObserver) -> *mut u8,
    /// +0x1c: `detach(this)` — dispatched by [`registry_set_observer`]
    /// on the non-NULL observer installed before the swap. Its result is
    /// discarded.
    pub detach: unsafe extern "C" fn(this: *mut RegistryObserver) -> *mut u8,
}

/// The 8-byte registry observer object: a base vtable plus its base state
/// word. [`registry_observer_base_construct`] sets the state word to zero;
/// its derived constructor only replaces the vtable.
#[repr(C)]
pub struct RegistryObserver {
    /// +0x00: class vtable. The base constructor first installs
    /// [`REGISTRY_OBSERVER_BASE_VTABLE_ADDRESS`], then the derived
    /// [`registry_observer_construct`] installs `0x089910ac`.
    pub vtable: *const RegistryObserverVtable,
    /// +0x04: base-class state, cleared by
    /// [`registry_observer_base_construct`].
    pub state: u32,
}

/// The parent observer vtable literal installed by the inlined
/// `FUN_08147288` base step.
pub const REGISTRY_OBSERVER_PARENT_VTABLE_ADDRESS: usize = 0x0898_6408;

/// The registry-observer base vtable literal loaded from 0x0810ddf0 and
/// installed at +0x00 after its parent base step.
pub const REGISTRY_OBSERVER_BASE_VTABLE_ADDRESS: usize = 0x0898_14fc;

/// The derived registry observer vtable installed by
/// [`registry_observer_construct`] (`ldr r1, [pc, #4]` loads it from
/// 0x082028b8 in the original).
pub const REGISTRY_OBSERVER_VTABLE_ADDRESS: usize = 0x0899_10ac;

/// The registry observer singleton (original: the global word @
/// 0x089d01ac — see the module-header deviation). NULL until
/// [`class_registry_construct`] first runs.
pub static mut REGISTRY_OBSERVER: *mut RegistryObserver = core::ptr::null_mut();
/// The two caches addressed by the literal at 0x081351b8. The first is
/// selected only when [`registry_container_initialize`] receives capacity 4;
/// the other is selected for all remaining capacities.
static mut CAPACITY_FOUR_CONTAINER_OBSERVER: *mut RegistryObserver = core::ptr::null_mut();
static mut OTHER_CONTAINER_OBSERVER: *mut RegistryObserver = core::ptr::null_mut();

/// Vtable installed by the capacity-four default observer constructor
/// (`FUN_0816f70c`).
pub const CAPACITY_FOUR_CONTAINER_OBSERVER_VTABLE_ADDRESS: usize = 0x0898_8eb0;

/// Vtable installed by the non-four-capacity default observer constructor
/// (`FUN_081991f4`).
pub const OTHER_CONTAINER_OBSERVER_VTABLE_ADDRESS: usize = 0x0898_9ca4;

/// Indirect dispatch table for the registry observer constructor and observer
/// replacement (see the module header).
#[derive(Clone, Copy)]
pub struct ClassRegistryOps {
    /// The state/default-observer initializer @ 0x08135110, called by
    /// [`registry_container_construct`] after it installs the registry
    /// vtable. The shipped default is [`registry_container_initialize`].
    pub container_initialize: unsafe extern "C" fn(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ),
    /// The registry observer's complete ctor @ 0x082028a4. Its default
    /// is the port below; retaining this seam preserves callers that
    /// replace the complete original constructor.
    pub observer_construct: unsafe extern "C" fn(this: *mut u8) -> *mut u8,
    /// The observer swap @ 0x08135040. Tests may replace this direct
    /// dependency of [`class_registry_construct`], but the wired default is
    /// [`registry_set_observer`].
    pub set_observer: unsafe extern "C" fn(
        observable: *mut Registry,
        observer: *mut RegistryObserver,
    ) -> *mut u8,
}
/// Constructs either capacity-selected observer over an allocation. Both
/// original derived constructors call [`registry_observer_base_construct`]
/// then overwrite +0x00 with their own vtable literal.
unsafe extern "C" fn construct_container_observer(
    this: *mut RegistryObserver,
    vtable: *const RegistryObserverVtable,
) -> *mut RegistryObserver {
    let observer = registry_observer_base_construct(this);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*observer).vtable), vtable);
    observer
}

#[cfg(test)]
type ContainerObserverConstruct =
    unsafe extern "C" fn(*mut RegistryObserver, *const RegistryObserverVtable) -> *mut RegistryObserver;

/// Host tests substitute the derived constructor solely because firmware
/// vtable literals are not valid host addresses. Firmware builds directly
/// execute the construction sequence above.
#[cfg(test)]
static mut CONTAINER_OBSERVER_CONSTRUCT: ContainerObserverConstruct = construct_container_observer;

#[cfg(test)]
unsafe fn container_observer_construct(
    this: *mut RegistryObserver,
    vtable: *const RegistryObserverVtable,
) -> *mut RegistryObserver {
    let construct = core::ptr::read_volatile(core::ptr::addr_of!(CONTAINER_OBSERVER_CONSTRUCT));
    construct(this, vtable)
}

#[cfg(not(test))]
unsafe fn container_observer_construct(
    this: *mut RegistryObserver,
    vtable: *const RegistryObserverVtable,
) -> *mut RegistryObserver {
    construct_container_observer(this, vtable)
}

/// registry_container_initialize — original: `FUN_08135110` @ 0x08135110
/// (168 bytes; 4 direct `bl` calls and 3 +0x18 vtable dispatches).
///
/// Initializes the concrete container portion of `this`: capacity at +0x10,
/// count at +0x14, growth at +0x18, and an auxiliary word at +0x1c. It marks
/// the observable changed (+0x20), disables notifications (+0x21), and clears
/// its observer slot (+0x24). Capacity exactly four selects the lazily cached
/// `0x08988eb0` observer; every other capacity selects `0x08989ca4`.
///
/// On a cache miss, stock allocates eight bytes, calls the selected derived
/// constructor (each calls `FUN_0810dddc`), caches the result, and dispatches
/// its +0x18 initializer. It then stores the selected observer at +0x24 and
/// dispatches that same initializer a second time. Both dispatch results are
/// discarded. There are no allocation, cache, or vtable NULL guards.
///
/// Raw ARM stores capacity and growth before zeroing the count/auxiliary
/// words, then clears +0x24 before selecting the cache. The volatile stores
/// and cache reloads retain that externally observable ordering.
///
/// Deviation: host-only tests inject the two derived constructors because
/// firmware vtable literal addresses are not host-callable; target builds
/// call [`construct_container_observer`] directly.
///
/// # Safety
///
/// `this` must be a writable registry object. The selected cache and its
/// observer must be valid; NULL allocations and invalid vtables fault in
/// stock and are likewise invalid here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_container_initialize(
    this: *mut Registry,
    capacity: u32,
    growth: u32,
) {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).container[3]), capacity as usize);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).container[5]), growth as usize);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).container[4]), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).container[6]), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).changed), 1);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).notify_enabled), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).observer), core::ptr::null_mut());

    let (cache, vtable) = if capacity == 4 {
        (
            core::ptr::addr_of_mut!(CAPACITY_FOUR_CONTAINER_OBSERVER),
            CAPACITY_FOUR_CONTAINER_OBSERVER_VTABLE_ADDRESS as *const RegistryObserverVtable,
        )
    } else {
        (
            core::ptr::addr_of_mut!(OTHER_CONTAINER_OBSERVER),
            OTHER_CONTAINER_OBSERVER_VTABLE_ADDRESS as *const RegistryObserverVtable,
        )
    };

    let mut observer = core::ptr::read_volatile(cache);
    if observer.is_null() {
        observer = container_observer_construct(operator_new(REGISTRY_OBSERVER_SIZE).cast(), vtable);
        core::ptr::write_volatile(cache, observer);
        let observer_vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observer).vtable));
        ((*observer_vtable).attach)(observer);
    }

    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).observer), observer.cast());
    let observer_vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observer).vtable));
    ((*observer_vtable).attach)(observer);
}

/// registry_container_construct — original: `FUN_08135308` @ 0x08135308
/// (48 bytes; 6 `bl` call sites).
///
/// Constructs the registry's concrete observable-array base. It first calls
/// [`observable_array_construct`] (`FUN_08271cec`) on `this`, overwrites the
/// vtable at +0x00 of *that returned pointer* with literal `0x08984770`,
/// then invokes [`registry_container_initialize`] with the original capacity
/// and growth values. The saved base-constructor return, rather than the
/// state initializer's return, is returned in r0.
///
/// Raw ARM saves r1/r2 before `bl 0x08271cec`, stores the vtable before
/// restoring them for `bl 0x08135110`, then returns r4. There is no NULL
/// guard: the base constructor's first store faults for an invalid `this`,
/// exactly as stock firmware does.
///
/// # Safety
///
/// `this` must address a writable registry object; a NULL or invalid pointer
/// faults during base construction.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_container_construct(
    this: *mut Registry,
    capacity: u32,
    growth: u32,
) -> *mut Registry {
    let registry = observable_array_construct(this.cast::<ObservableArray>()).cast::<Registry>();
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*registry).vtable),
        REGISTRY_CONTAINER_VTABLE_ADDRESS as *const _,
    );
    let initialize =
        core::ptr::read_volatile(core::ptr::addr_of!(CLASS_REGISTRY_OPS.container_initialize));
    initialize(registry, capacity, growth);
    registry
}

/// registry_container_construct_default — original: `FUN_0813533c` @
/// 0x0813533c (40 bytes of code plus the 4-byte vtable literal @
/// 0x08135364 — Ghidra's size of 40 drops the trailing literal-pool
/// word; the next function starts @ 0x08135368. 23 `bl` call sites,
/// 0 predicated, binary-scanned by decoding every B/BL word in
/// osos.dec).
///
/// The ADS default constructor of the same registry-container class as
/// [`registry_container_construct`]: it binds the identical vtable
/// literal `0x08984770` and differs only in hardcoding capacity and
/// growth to 4 (`mov r1, #4` / `mov r2, #4` @ 0x08135350/0x08135354)
/// instead of taking them as arguments. It calls
/// [`observable_array_construct`] (`FUN_08271cec`) on `this`, overwrites
/// the vtable at +0x00 of *that returned pointer*, then invokes
/// [`registry_container_initialize`](`FUN_08135110`) on the same
/// pointer. The saved base-constructor return (r4), not the
/// initializer's return, is returned in r0.
///
/// Capacity exactly four is the case that selects the lazily cached
/// `0x08988eb0` default observer inside `registry_container_initialize`,
/// so every one of the 23 callers builds a capacity-4-observer
/// container. No NULL guard: an invalid `this` faults in the base
/// constructor's first store, exactly as stock firmware does.
///
/// # Safety
///
/// `this` must address a writable registry object; a NULL or invalid
/// pointer faults during base construction.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_container_construct_default(
    this: *mut Registry,
) -> *mut Registry {
    let registry = observable_array_construct(this.cast::<ObservableArray>()).cast::<Registry>();
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*registry).vtable),
        REGISTRY_CONTAINER_VTABLE_ADDRESS as *const _,
    );
    let initialize =
        core::ptr::read_volatile(core::ptr::addr_of!(CLASS_REGISTRY_OPS.container_initialize));
    initialize(registry, 4, 4);
    registry
}

/// registry_observer_base_construct — original: `FUN_0810dddc` @
/// 0x0810dddc (20 bytes; 24 `bl` call sites).
///
/// Constructs the common 8-byte registry-observer base at `this`: it writes
/// its vtable literal `0x089814fc` at +0x00, clears the base state word at
/// +0x04, and returns the original pointer. Its direct caller
/// [`registry_observer_construct`] immediately replaces the vtable with its
/// derived-class literal while retaining the cleared state word.
///
/// The first two writes reproduce the called parent constructor
/// `FUN_08147288`: it installs `0x08986408` then clears +0x04. Stock
/// `FUN_0810dddc` then overwrites only +0x00 with its `0x089814fc` literal
/// and returns with the parent's unmodified r0. The parent has no callback
/// or error path, so those three observable stores are kept inline here.
/// No NULL guard is present in stock; `this` must be a writable, aligned
/// [`RegistryObserver`].
///
/// # Safety
///
/// `this` must address a writable registry-observer base. A NULL or invalid
/// pointer faults in the original and is likewise invalid here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_observer_base_construct(
    this: *mut RegistryObserver,
) -> *mut RegistryObserver {
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*this).vtable),
        REGISTRY_OBSERVER_PARENT_VTABLE_ADDRESS as *const RegistryObserverVtable,
    );
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).state), 0);
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*this).vtable),
        REGISTRY_OBSERVER_BASE_VTABLE_ADDRESS as *const RegistryObserverVtable,
    );
    this
}


/// registry_observer_construct — original: `FUN_082028a4` @ 0x082028a4
/// (20 bytes; 3 `bl` call sites, including
/// [`class_registry_construct`]).
///
/// ADS C++ constructor for the registry's 8-byte observer singleton.
/// It forwards the raw allocation to the directly ported base constructor
/// ([`registry_observer_base_construct`] @ 0x0810dddc), writes the literal
/// vtable `0x089910ac` at offset +0x00 of the returned pointer, then returns
/// that same pointer.
///
/// Raw ARM establishes both ordering and ABI: `bl 0x0810dddc` completes the
/// base vtable/state writes before `str r1, [r0]` replaces only +0x00, and
/// `pop {r4, pc}` returns that unmodified r0 value. There is intentionally
/// no NULL guard; neither the ARM `str` nor this volatile store makes a
/// failed allocation safe.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_observer_construct(this: *mut u8) -> *mut u8 {
    let observer = registry_observer_base_construct(this.cast()).cast::<u8>();
    core::ptr::write_volatile(
        observer.cast::<*const RegistryObserverVtable>(),
        REGISTRY_OBSERVER_VTABLE_ADDRESS as *const RegistryObserverVtable,
    );
    observer
}

/// registry_set_observer — original: `FUN_08135040` @ 0x08135040
/// (96 bytes; 10 direct `bl` call sites).
///
/// Replaces `observable`'s +0x24 observer with `observer`: if a prior
/// observer exists, dispatches its +0x1c `detach` slot; stores the new
/// observer; then dispatches its +0x18 `attach` slot. It next dispatches the
/// observable's +0x60 pending-change query. A NULL query result is returned;
/// otherwise it tail-dispatches the observable's +0x68 notification and
/// returns that result.
///
/// The body is a base-observable operation used by several object families,
/// but this local port intentionally models the registry-observer ABI because
/// its sole cutover caller is [`class_registry_construct`]. Raw ARM proves
/// the ordering: detach (if non-NULL), `str r5, [r4, #0x24]`, attach, query,
/// then reload the observable vtable for the notification tail path. Attach
/// and detach return values are discarded. `observer` is dereferenced
/// unconditionally after the store; NULL is therefore invalid just as in
/// stock firmware.
///
/// # Safety
///
/// `observable` must be a writable registry with a valid vtable, and
/// `observer` and any installed old observer must have valid observer
/// vtables. Invalid pointers (including a NULL new observer) fault in the
/// original and are likewise invalid here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.registry_set_observer"))]
pub unsafe extern "C" fn registry_set_observer(
    observable: *mut Registry,
    observer: *mut RegistryObserver,
) -> *mut u8 {
    let old = core::ptr::read_volatile(core::ptr::addr_of!((*observable).observer))
        .cast::<RegistryObserver>();
    if !old.is_null() {
        let old_vtable = core::ptr::read_volatile(core::ptr::addr_of!((*old).vtable));
        ((*old_vtable).detach)(old);
    }

    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*observable).observer),
        observer.cast::<u8>(),
    );
    let new_vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observer).vtable));
    ((*new_vtable).attach)(observer);

    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observable).vtable));
    let pending = ((*vtable).has_pending_changes)(observable);
    if pending.is_null() {
        return pending;
    }

    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*observable).vtable));
    ((*vtable).notify_changed)(observable)
}

/// Wired defaults for the three ported construction operations. The ops table
/// remains swappable for parent-constructor tests and callers that replace a
/// firmware class implementation.
pub(crate) const DEFAULT_CLASS_REGISTRY_OPS: ClassRegistryOps = ClassRegistryOps {
    container_initialize: registry_container_initialize,
    observer_construct: registry_observer_construct,
    set_observer: registry_set_observer,
};

/// Runtime-replaceable construction operations.
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
    let registry = registry_container_construct(
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

    /// Alignment-safe host backing for the target's 8-byte observer
    /// allocation. [`RegistryObserver`] remains exactly that 8-byte,
    /// pointer-plus-word layout on the 32-bit firmware target, while its
    /// native host alignment makes the volatile vtable load valid.
    static mut ARENA: RegistryObserver = RegistryObserver {
        vtable: ptr::null(),
        state: 0,
    };

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Ordered trace of the mock calls.
    static mut TRACE: Vec<&'static str> = Vec::new();


    /// Vtable literals selected by direct container-initializer tests.
    static mut CONTAINER_OBSERVER_VTABLE_LITERALS: Vec<usize> = Vec::new();

    unsafe extern "C" fn mock_container_observer_construct(
        this: *mut RegistryObserver,
        vtable: *const RegistryObserverVtable,
    ) -> *mut RegistryObserver {
        trace().push("container_observer_construct");
        (*ptr::addr_of_mut!(CONTAINER_OBSERVER_VTABLE_LITERALS)).push(vtable as usize);
        this.write(RegistryObserver {
            vtable: ptr::addr_of!(MOCK_OBSERVER_VTABLE),
            state: 0,
        });
        this
    }
    /// Arguments observed through the constructor-wrapper test seam.
    static mut CONTAINER_INITIALIZE_ARGS: Vec<(*mut Registry, u32, u32)> = Vec::new();

    /// The observer/set_observer arguments, recorded on every call.
    static mut OBSERVER_ARGS: Vec<*mut RegistryObserver> = Vec::new();


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


    unsafe extern "C" fn mock_container_initialize(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) {
        assert_eq!(
            ptr::read_volatile(this.cast::<[u32; 4]>()),
            [REGISTRY_CONTAINER_VTABLE_ADDRESS as u32, 0, 0, 0],
            "FUN_08135110 is called after the base zeroes and derived-vtable store"
        );
        trace().push("container_initialize");
        (*ptr::addr_of_mut!(CONTAINER_INITIALIZE_ARGS)).push((this, capacity, growth));
        if this == constructed() {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*this).vtable),
                ptr::addr_of!(MOCK_REGISTRY_VTABLE),
            );
        }
    }

    unsafe extern "C" fn mock_observer_construct(this: *mut u8) -> *mut u8 {
        trace().push("observer_construct");
        // The real ctor stores the observer vtable at +0x00; the mock
        // installs the recording vtable so the attach dispatch has
        // somewhere to go.
        (this as *mut RegistryObserver).write(RegistryObserver {
            vtable: ptr::addr_of!(MOCK_OBSERVER_VTABLE),
            state: 0,
        });
        this
    }

    unsafe extern "C" fn mock_attach(this: *mut RegistryObserver) -> *mut u8 {
        trace().push("attach");
        (*ptr::addr_of_mut!(ATTACHED)).push(this);
        ptr::null_mut()
    }

    unsafe extern "C" fn mock_detach(_this: *mut RegistryObserver) -> *mut u8 {
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
        detach: mock_detach,
    };

    // ---- the registry the real container constructor builds ----

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

    static mut SWAP_OBSERVABLE: *mut Registry = ptr::null_mut();
    static mut SWAP_PENDING: *mut u8 = ptr::null_mut();
    static mut SWAP_NOTIFICATION: *mut u8 = ptr::null_mut();
    static mut SWAP_VTABLE_AFTER_QUERY: *const RegistryVtable = ptr::null();

    unsafe extern "C" fn swap_detach(_this: *mut RegistryObserver) -> *mut u8 {
        trace().push("detach");
        0x11 as *mut u8
    }

    unsafe extern "C" fn swap_attach(this: *mut RegistryObserver) -> *mut u8 {
        trace().push("attach");
        assert_eq!(
            ptr::read_volatile(ptr::addr_of!((*SWAP_OBSERVABLE).observer)),
            this.cast::<u8>(),
            "the +0x24 observer store precedes the attach dispatch"
        );
        0x22 as *mut u8
    }

    unsafe extern "C" fn swap_has_pending_changes(this: *mut Registry) -> *mut u8 {
        trace().push("has_pending_changes");
        let replacement = SWAP_VTABLE_AFTER_QUERY;
        if !replacement.is_null() {
            ptr::write_volatile(ptr::addr_of_mut!((*this).vtable), replacement);
        }
        SWAP_PENDING
    }

    unsafe extern "C" fn swap_notify_changed(_this: *mut Registry) -> *mut u8 {
        trace().push("notify_changed");
        SWAP_NOTIFICATION
    }

    unsafe extern "C" fn swap_reloaded_notify_changed(_this: *mut Registry) -> *mut u8 {
        trace().push("reloaded_notify_changed");
        SWAP_NOTIFICATION
    }

    static SWAP_OBSERVER_VTABLE: RegistryObserverVtable = RegistryObserverVtable {
        unresolved_00: [0; 6],
        attach: swap_attach,
        detach: swap_detach,
    };

    static SWAP_REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unimplemented_insert,
        unresolved_20: 0,
        assign_at: unimplemented_assign_at,
        unresolved_28: [0; 5],
        entry_at: unimplemented_entry_at,
        unresolved_40: [0; 3],
        index_of: unimplemented_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: swap_has_pending_changes,
        notify_deferred: mock_notify_deferred,
        notify_changed: swap_notify_changed,
    };

    static SWAP_RELOADED_REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unimplemented_insert,
        unresolved_20: 0,
        assign_at: unimplemented_assign_at,
        unresolved_28: [0; 5],
        entry_at: unimplemented_entry_at,
        unresolved_40: [0; 3],
        index_of: unimplemented_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: swap_has_pending_changes,
        notify_deferred: mock_notify_deferred,
        notify_changed: swap_reloaded_notify_changed,
    };

    /// The registry object passed through the real container constructor.
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
                container_initialize: mock_container_initialize,
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
            REGISTRY_OBSERVER = ptr::null_mut();
            CAPACITY_FOUR_CONTAINER_OBSERVER = ptr::null_mut();
            OTHER_CONTAINER_OBSERVER = ptr::null_mut();
            CONTAINER_OBSERVER_CONSTRUCT = construct_container_observer;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CONTAINER_INITIALIZE_ARGS)).clear();
            (*ptr::addr_of_mut!(OBSERVER_ARGS)).clear();
            (*ptr::addr_of_mut!(ATTACHED)).clear();
            (*ptr::addr_of_mut!(CONTAINER_OBSERVER_VTABLE_LITERALS)).clear();
            trace().clear();
            SWAP_OBSERVABLE = ptr::null_mut();
            SWAP_PENDING = ptr::null_mut();
            SWAP_NOTIFICATION = ptr::null_mut();
            SWAP_VTABLE_AFTER_QUERY = ptr::null();
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
            CAPACITY_FOUR_CONTAINER_OBSERVER = ptr::null_mut();
            OTHER_CONTAINER_OBSERVER = ptr::null_mut();
            CONTAINER_OBSERVER_CONSTRUCT = construct_container_observer;
            ptr::addr_of_mut!(CONSTRUCTED_REGISTRY).write(Registry {
                vtable: ptr::null(),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            });
            SWAP_OBSERVABLE = ptr::null_mut();
            SWAP_PENDING = ptr::null_mut();
            SWAP_NOTIFICATION = ptr::null_mut();
            SWAP_VTABLE_AFTER_QUERY = ptr::null();
        }
        drop(guard);
    }

    /// A writable registry passed through the constructor's direct
    /// container-construction call.
    fn argument() -> *mut Registry {
        constructed()
    }

    #[test]
    fn construct_builds_the_container_with_capacity_8_and_growth_4() {
        let guard = mock();
        unsafe {
            assert_eq!(class_registry_construct(argument()), argument());
            assert_eq!(
                *ptr::addr_of!(CONTAINER_INITIALIZE_ARGS),
                std::vec![(argument(), 8, 4)],
                "the original's mov r1, #0x8 / mov r2, #0x4"
            );
        }
        restore(guard);
    }

    #[test]
    fn registry_container_constructor_initializes_observable_base_before_container_state() {
        let guard = mock();
        unsafe {
            let mut registry = Registry {
                vtable: 0xdead_beefusize as *const RegistryVtable,
                container: [usize::MAX; 7],
                changed: 0xa5,
                notify_enabled: 0x5a,
                reserved: [0xa5; 2],
                observer: usize::MAX as *mut u8,
            };
            let this = ptr::addr_of_mut!(registry);

            assert_eq!(registry_container_construct(this, 0x0c, 5), this);
            assert_eq!(
                ptr::read_volatile(this.cast::<[u32; 4]>()),
                [REGISTRY_CONTAINER_VTABLE_ADDRESS as u32, 0, 0, 0],
                "the base call zeros +0x04..+0x0c before the derived vtable replaces +0x00"
            );
            assert_eq!(
                *ptr::addr_of!(CONTAINER_INITIALIZE_ARGS),
                std::vec![(this, 0x0c, 5)],
                "the original restores saved r1/r2 for FUN_08135110"
            );
            assert_eq!(
                *trace(),
                std::vec!["container_initialize"],
                "the state initializer is called only after both vtable stores"
            );
        }
        restore(guard);
    }

    #[test]
    fn registry_container_default_constructor_hardcodes_capacity_4_and_growth_4() {
        let guard = mock();
        unsafe {
            let mut registry = Registry {
                vtable: 0xdead_beefusize as *const RegistryVtable,
                container: [usize::MAX; 7],
                changed: 0xa5,
                notify_enabled: 0x5a,
                reserved: [0xa5; 2],
                observer: usize::MAX as *mut u8,
            };
            let this = ptr::addr_of_mut!(registry);

            assert_eq!(registry_container_construct_default(this), this);
            assert_eq!(
                ptr::read_volatile(this.cast::<[u32; 4]>()),
                [REGISTRY_CONTAINER_VTABLE_ADDRESS as u32, 0, 0, 0],
                "the base call zeros +0x04..+0x0c before the derived vtable replaces +0x00"
            );
            assert_eq!(
                *ptr::addr_of!(CONTAINER_INITIALIZE_ARGS),
                std::vec![(this, 4, 4)],
                "the original's mov r1, #4 / mov r2, #4 @ 0x08135350/0x08135354"
            );
            assert_eq!(
                *trace(),
                std::vec!["container_initialize"],
                "the state initializer is called only after both vtable stores"
            );
        }
        restore(guard);
    }

    #[test]
    fn container_initializer_writes_every_state_field_and_builds_capacity_four_observer() {
        let guard = mock();
        unsafe {
            CONTAINER_OBSERVER_CONSTRUCT = mock_container_observer_construct;
            let mut registry = Registry {
                vtable: ptr::addr_of!(MOCK_REGISTRY_VTABLE),
                container: [usize::MAX; 7],
                changed: 0xa5,
                notify_enabled: 0x5a,
                reserved: [0x31, 0x62],
                observer: usize::MAX as *mut u8,
            };
            let this = ptr::addr_of_mut!(registry);

            registry_container_initialize(this, 4, 0x17);

            assert_eq!(registry.container, [usize::MAX, usize::MAX, usize::MAX, 4, 0, 0x17, 0]);
            assert_eq!(registry.changed, 1);
            assert_eq!(registry.notify_enabled, 0);
            assert_eq!(registry.reserved, [0x31, 0x62], "the initializer does not touch +0x22..+0x23");

            let observer = ptr::addr_of_mut!(ARENA) as *mut RegistryObserver;
            assert_eq!(registry.observer, observer.cast());
            assert_eq!(CAPACITY_FOUR_CONTAINER_OBSERVER, observer);
            assert!(OTHER_CONTAINER_OBSERVER.is_null());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![REGISTRY_OBSERVER_SIZE]);
            assert_eq!(
                *ptr::addr_of!(CONTAINER_OBSERVER_VTABLE_LITERALS),
                std::vec![CAPACITY_FOUR_CONTAINER_OBSERVER_VTABLE_ADDRESS]
            );
            assert_eq!(*ptr::addr_of!(ATTACHED), std::vec![observer, observer]);
            assert_eq!(
                *trace(),
                std::vec!["container_observer_construct", "attach", "attach"],
                "a cache miss initializes through +0x18 before and after the +0x24 store"
            );
        }
        restore(guard);
    }

    #[test]
    fn container_initializer_selects_and_reuses_the_non_four_observer() {
        let guard = mock();
        unsafe {
            CONTAINER_OBSERVER_CONSTRUCT = mock_container_observer_construct;
            let mut registry = Registry {
                vtable: ptr::addr_of!(MOCK_REGISTRY_VTABLE),
                container: [0; 7],
                changed: 0,
                notify_enabled: 1,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            };
            let this = ptr::addr_of_mut!(registry);

            registry_container_initialize(this, 6, 3);
            registry_container_initialize(this, 0, 9);

            let observer = ptr::addr_of_mut!(ARENA) as *mut RegistryObserver;
            assert_eq!(OTHER_CONTAINER_OBSERVER, observer);
            assert!(CAPACITY_FOUR_CONTAINER_OBSERVER.is_null());
            assert_eq!(registry.container[3..], [0, 0, 9, 0]);
            assert_eq!(registry.observer, observer.cast());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![REGISTRY_OBSERVER_SIZE]);
            assert_eq!(
                *ptr::addr_of!(CONTAINER_OBSERVER_VTABLE_LITERALS),
                std::vec![OTHER_CONTAINER_OBSERVER_VTABLE_ADDRESS],
                "every capacity other than four selects FUN_081991f4"
            );
            assert_eq!(*ptr::addr_of!(ATTACHED), std::vec![observer, observer, observer]);
            assert_eq!(
                *trace(),
                std::vec!["container_observer_construct", "attach", "attach", "attach"],
                "the cached observer skips allocation but still receives the final +0x18 dispatch"
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
                    "container_initialize",
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
                std::vec!["container_initialize", "set_observer", "notify_deferred", "notify_changed"],
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
            detach: mock_detach,
        };
        unsafe extern "C" fn cache_check_ctor(this: *mut u8) -> *mut u8 {
            (this as *mut RegistryObserver).write(RegistryObserver {
                vtable: ptr::addr_of!(CACHE_CHECK_VTABLE),
                state: 0,
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
            detach: mock_detach,
        };
        unsafe extern "C" fn rewriting_ctor(this: *mut u8) -> *mut u8 {
            (this as *mut RegistryObserver).write(RegistryObserver {
                vtable: ptr::addr_of!(REWRITING_VTABLE),
                state: 0,
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
                std::vec!["container_initialize", "set_observer", "notify_deferred", "notify_changed"]
            );
            assert_eq!(*ptr::addr_of!(OBSERVER_ARGS), std::vec![seeded]);
            assert_eq!(ptr::read_volatile(observer_cache()), seeded, "the cache is untouched");
        }
        restore(guard);
    }

    #[test]
    fn construction_enables_notifications_on_the_constructed_registry() {
        let guard = mock();
        unsafe {
            assert_eq!(class_registry_construct(argument()), argument());
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

    #[test]
    fn registry_set_observer_detaches_installs_attaches_and_reloads_notification_vtable() {
        let guard = mock();
        unsafe {
            let mut old = RegistryObserver {
                vtable: ptr::addr_of!(SWAP_OBSERVER_VTABLE),
                state: 0,
            };
            let mut new = RegistryObserver {
                vtable: ptr::addr_of!(SWAP_OBSERVER_VTABLE),
                state: 0,
            };
            let mut observable = Registry {
                vtable: ptr::addr_of!(SWAP_REGISTRY_VTABLE),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::addr_of_mut!(old).cast::<u8>(),
            };
            SWAP_OBSERVABLE = ptr::addr_of_mut!(observable);
            SWAP_PENDING = 0x33 as *mut u8;
            SWAP_NOTIFICATION = 0x44 as *mut u8;
            SWAP_VTABLE_AFTER_QUERY = ptr::addr_of!(SWAP_RELOADED_REGISTRY_VTABLE);

            assert_eq!(
                registry_set_observer(ptr::addr_of_mut!(observable), ptr::addr_of_mut!(new)),
                SWAP_NOTIFICATION,
                "the notification return, not either observer callback result, is forwarded"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(observable.observer)),
                ptr::addr_of_mut!(new).cast::<u8>()
            );
            assert_eq!(
                *trace(),
                std::vec!["detach", "attach", "has_pending_changes", "reloaded_notify_changed"],
                "old detach, new store/attach, query, then the reloaded +0x68 dispatch"
            );
        }
        restore(guard);
    }

    #[test]
    fn registry_set_observer_returns_null_and_skips_notification_without_pending_change() {
        let guard = mock();
        unsafe {
            let mut new = RegistryObserver {
                vtable: ptr::addr_of!(SWAP_OBSERVER_VTABLE),
                state: 0,
            };
            let mut observable = Registry {
                vtable: ptr::addr_of!(SWAP_REGISTRY_VTABLE),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            };
            SWAP_OBSERVABLE = ptr::addr_of_mut!(observable);

            assert!(registry_set_observer(ptr::addr_of_mut!(observable), ptr::addr_of_mut!(new)).is_null());
            assert_eq!(
                *trace(),
                std::vec!["attach", "has_pending_changes"],
                "a NULL +0x60 result skips both old detach and +0x68 notification"
            );
        }
        restore(guard);
    }

    // ---- the directly ported observer base ----

    #[test]
    fn registry_observer_base_constructor_sets_layout_and_returns_this() {
        const OLD_VTABLE: usize = 0xdead_beef;
        let guard = CONSTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::addr_of_mut!(ARENA).write(RegistryObserver {
                vtable: OLD_VTABLE as *const RegistryObserverVtable,
                state: u32::MAX,
            });
            let this = ptr::addr_of_mut!(ARENA);

            assert_eq!(registry_observer_base_construct(this), this);
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(ARENA.vtable)) as usize,
                REGISTRY_OBSERVER_BASE_VTABLE_ADDRESS,
                "the final base vtable literal lands at +0x00"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(ARENA.state)),
                0,
                "the inherited state word at +0x04 is cleared"
            );
        }
        restore(guard);
    }

    #[test]
    fn registry_observer_constructor_replaces_base_vtable_after_base_layout() {
        const OLD_VTABLE: usize = 0xdead_beef;
        let guard = mock();
        unsafe {
            ptr::addr_of_mut!(ARENA).write(RegistryObserver {
                vtable: OLD_VTABLE as *const RegistryObserverVtable,
                state: u32::MAX,
            });
            let observer = ptr::addr_of_mut!(ARENA);

            assert_eq!(registry_observer_construct(observer.cast()), observer.cast());
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(ARENA.state)),
                0,
                "the base layout initialization runs before the derived store"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(ARENA.vtable)) as usize,
                REGISTRY_OBSERVER_VTABLE_ADDRESS,
                "the derived constructor's +0x00 store follows the base vtable"
            );
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
