//! task_registry_register — original: `FUN_0826d64c` @ 0x0826d64c
//! (156 bytes; 43 `bl` call sites, binary-scanned over osos.dec — every
//! `bl` whose computed target is the function; 0 predicated forms).
//!
//! The per-task companion of `app/registry.rs`'s global class registry:
//! each task's context block carries its own `class id -> instance` map
//! at ctx+0x38, and this function is its registering writer. The sole
//! construction site of that registry, so the map exists exactly when a
//! task has registered at least one pair:
//!
//! ```text
//! ctx = current_task_ctx_block()             ; 0x080cb828, ported
//! registry = ctx->+0x38
//! if (registry == NULL) {
//!     registry = container_construct(operator_new(0x28), 8, 4)   ; 0x08135308
//!     observer = observer_construct(operator_new(8))             ; 0x081f6b14
//!     registry->vtable->attach_observer(registry, observer)      ; slot +0x54
//!     current_task_ctx_block()->+0x38 = registry   ; ctx RE-FETCHED
//! }
//! entry = {class_id, instance}               ; the spilled r0/r1 pair
//! if (registry->vtable->query(registry, &entry, 4) == -1)        ; slot +0x48
//!     registry->vtable->insert(registry, &{entry.class_id, instance})  ; +0x1c
//! ```
//!
//! Faithful details, all from the raw ARM (the extent was verified
//! against the bytes: `pop {r0..r6, pc}` @ 0x0826d6e4, the sibling
//! `FUN_0826d6e8` prologue starts at 0x0826d6e8 — Ghidra's 156 is exact):
//!
//! - The query's entry pointer IS the spilled incoming-argument pair
//!   (`add r1, sp, #8` addresses the `push {r0, r1, ...}` slots), so the
//!   query may rewrite the pair through it. On a miss the original
//!   RE-READS the class-id word from that stack slot (`ldr r0,
//!   [sp, #8]`; `stm sp, {r0, r5}`) while the instance comes from r5 —
//!   the register copy the query cannot touch. Reproduced: the inserted
//!   entry is `{entry.class_id, instance}` re-read after the query.
//! - The context block is fetched twice on the lazy path — once before
//!   construction and again for the +0x38 store (`bl 0x080cb828` @
//!   0x0826d6a0) — so a task switch mid-construction installs the
//!   registry on the *current* task, not necessarily the original one.
//!   Reproduced by the second [`TaskRegistryOps::current_task_ctx`] call.
//! - The registry vtable pointer is reloaded for every dispatch (`ldr
//!   r0, [r4]` ahead of each `blx`); the `read_volatile` per dispatch
//!   keeps those re-reads (the registry.rs rule).
//! - Neither the context-block pointer nor any allocation is
//!   NULL-checked: with no current task the original's `ldr r4,
//!   [r0, #0x38]` faults; the port keeps the unchecked dereference.
//! - Slot roles are inferred (the cold image's container vtable page
//!   0x08984770 is 0x55-fill — the registry.rs caveat): +0x1c is the
//!   known `insert`, +0x48 is a three-argument query whose -1 result
//!   gates the insert (the `cmn r0, #1`), +0x54 takes the freshly built
//!   observer during construction. The query's third argument is the
//!   literal 4 (`mov r2, #4`).
//!
//! ## Deviations
//!
//! - The three callees sit behind [`TASK_REGISTRY_OPS`] (the
//!   class_registry.rs `CLASS_REGISTRY_OPS` pattern) so host tests can
//!   install recording mocks: [`current_task_ctx_block`] @ 0x080cb828
//!   and [`registry_container_construct`] @ 0x08135308 are ported and
//!   wired directly as defaults; the observer constructor `FUN_081f6b14`
//!   @ 0x081f6b14 is NOT ported, so its default
//!   ([`task_registry_observer_construct`]) models it faithfully over
//!   the ported base constructor — `bl 0x0810dddc`, then the vtable
//!   literal 0x0899073c stored at +0x00 (24 bytes including the literal
//!   pool word @ 0x081f6b28; exactly 1 `bl` call site — this function).
//! - `operator new` @ 0x082aadd4 is ported (`heap::veneers::operator_new`)
//!   and called directly, exactly like the original's two `bl`s.

use crate::app::class_registry::{
    registry_container_construct, registry_observer_base_construct, RegistryObserver,
    RegistryObserverVtable,
};
use crate::app::registry::{Registry, RegistryEntry};
use crate::heap::veneers::operator_new;
use crate::kernel::task::{current_task_ctx_block, TaskCtx};
use core::ptr;

/// Registry allocation size (`mov r0, #0x28` @ 0x0826d668).
pub const TASK_REGISTRY_OBJECT_SIZE: usize = 0x28;

/// Observer allocation size (`mov r0, #0x8` @ 0x0826d680): a vtable
/// pointer plus one state word.
pub const TASK_REGISTRY_OBSERVER_SIZE: usize = 8;

/// Container capacity/growth immediates (`mov r1, #8` / `mov r2, #4` @
/// 0x0826d674/0x0826d670 — the same pair the global registry uses).
pub const TASK_REGISTRY_INITIAL_CAPACITY: u32 = 8;
pub const TASK_REGISTRY_GROWTH_STEP: u32 = 4;

/// The query slot's third argument (`mov r2, #4` @ 0x0826d6ac).
pub const TASK_REGISTRY_QUERY_OPERAND: u32 = 4;

/// The vtable literal the unported observer constructor `FUN_081f6b14`
/// installs (the literal pool word @ 0x081f6b28).
pub const TASK_REGISTRY_OBSERVER_VTABLE_ADDRESS: usize = 0x0899_073c;

/// The registry container's vtable, modeled down to the three slots this
/// function dispatches (the registry.rs rule). The filler arrays
/// reproduce the original byte offsets on the 32-bit target and keep the
/// named slots disjoint on a 64-bit host. Slot roles are inferred — see
/// the module header.
#[repr(C)]
pub struct TaskRegistryVtable {
    /// Slots +0x00..+0x18: not dispatched here.
    pub unresolved_00: [usize; 7],
    /// +0x1c: `insert(this, entry)` — the same slot registry.rs's
    /// accessor family dispatches.
    pub insert: unsafe extern "C" fn(this: *mut Registry, entry: *const RegistryEntry) -> usize,
    /// Slots +0x20..+0x44: not dispatched here.
    pub unresolved_20: [usize; 10],
    /// +0x48: `query(this, entry, 4)` — role inferred; a -1 result gates
    /// the +0x1c insert. The entry pointer is writable (the original
    /// re-reads the class id through it on the miss path).
    pub query: unsafe extern "C" fn(
        this: *mut Registry,
        entry: *mut RegistryEntry,
        operand: u32,
    ) -> i32,
    /// Slots +0x4c..+0x50: not dispatched here (+0x4c is registry.rs's
    /// `index_of`).
    pub unresolved_4c: [usize; 2],
    /// +0x54: `attach_observer(this, observer)` — role inferred;
    /// dispatched once with the freshly constructed observer while the
    /// per-task registry is built.
    pub attach_observer:
        unsafe extern "C" fn(this: *mut Registry, observer: *mut u8) -> usize,
}

// Target-exact slot offsets.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(TaskRegistryVtable, insert)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x48] = [0; core::mem::offset_of!(TaskRegistryVtable, query)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x54] = [0; core::mem::offset_of!(TaskRegistryVtable, attach_observer)];

/// task_registry_observer_construct — the [`TASK_REGISTRY_OPS`] default
/// for the unported observer constructor `FUN_081f6b14` @ 0x081f6b14
/// (24 bytes including its literal pool word; exactly 1 `bl` call site —
/// [`task_registry_register`]).
///
/// Raw ARM: `push {r4, lr}; bl 0x0810dddc; ldr r1, [pc, #4]; str r1,
/// [r0]; pop {r4, pc}` with literal 0x0899073c @ 0x081f6b28. It forwards
/// the allocation to the ported base constructor
/// ([`registry_observer_base_construct`] @ 0x0810dddc — which installs
/// the base vtable 0x089814fc and clears the state word), replaces only
/// +0x00 with the derived vtable, and returns the base's unchanged r0.
/// No NULL guard: a failed allocation faults in the base constructor's
/// first store, exactly like stock.
unsafe extern "C" fn task_registry_observer_construct(this: *mut u8) -> *mut u8 {
    let observer = registry_observer_base_construct(this as *mut RegistryObserver);
    ptr::write_volatile(
        ptr::addr_of_mut!((*observer).vtable),
        TASK_REGISTRY_OBSERVER_VTABLE_ADDRESS as *const RegistryObserverVtable,
    );
    observer as *mut u8
}

/// Indirect dispatch table for the three callees (see the module
/// header). The ported functions are the wired defaults; the observer
/// constructor default is the faithful model above until `FUN_081f6b14`
/// is ported in its own right.
#[derive(Clone, Copy)]
pub struct TaskRegistryOps {
    /// `current_task_ctx_block` @ 0x080cb828 (ported, kernel/task.rs) —
    /// called twice on the lazy path, like the original.
    pub current_task_ctx: unsafe extern "C" fn() -> *mut TaskCtx,
    /// `registry_container_construct` @ 0x08135308 (ported,
    /// app/class_registry.rs).
    pub construct_container: unsafe extern "C" fn(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) -> *mut Registry,
    /// `FUN_081f6b14` @ 0x081f6b14 (unported) — the default models it
    /// over the ported base constructor (see the module header).
    pub construct_observer: unsafe extern "C" fn(this: *mut u8) -> *mut u8,
}

/// Wired defaults: the two ported callees plus the faithful observer
/// constructor model.
pub(crate) const DEFAULT_TASK_REGISTRY_OPS: TaskRegistryOps = TaskRegistryOps {
    current_task_ctx: current_task_ctx_block,
    construct_container: registry_container_construct,
    construct_observer: task_registry_observer_construct,
};

/// Runtime-replaceable callees of [`task_registry_register`].
pub static mut TASK_REGISTRY_OPS: TaskRegistryOps = DEFAULT_TASK_REGISTRY_OPS;

/// Reads the ops table (volatile — the slot is meant to be swapped at
/// runtime, and a build in which nothing swaps it must not
/// constant-fold the defaults in; the heap/veneers.rs rule).
#[inline(always)]
fn ops() -> TaskRegistryOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(TASK_REGISTRY_OPS)) }
}

/// Reloads the registry's vtable for one dispatch — the original's
/// `ldr r0, [r4]` ahead of every `blx`; volatile keeps each re-read so a
/// dispatch that swaps the vtable is honored (the registry.rs rule).
#[inline(always)]
unsafe fn vtable(this: *mut Registry) -> *const TaskRegistryVtable {
    ptr::read_volatile(ptr::addr_of!((*this).vtable)) as *const TaskRegistryVtable
}

/// task_registry_register — original: `FUN_0826d64c` @ 0x0826d64c
/// (156 bytes; 43 `bl` call sites, binary-scanned).
///
/// Registers the `(class_id, instance)` pair in the current task's
/// context-block registry (ctx+0x38), constructing that registry —
/// container capacity 8 / growth 4, one attached observer — on first
/// use. The pair is inserted only when the container's +0x48 query
/// answers -1; the query's -1 gate, the re-read class id, and the
/// double context-block fetch are all the original's behavior (see the
/// module header).
///
/// The original returns nothing meaningful (`pop {r0, r1, ...}` restores
/// the incoming argument registers; Ghidra's `undefined8` is that
/// spilled pair, not a result).
///
/// # Safety
///
/// The current task's context block must exist — the original does not
/// NULL-check `current_task_ctx_block`'s result and neither does this
/// port. The installed registry must carry a valid container vtable;
/// NULL allocations fault in the original and are likewise invalid here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_registry_register(class_id: u32, instance: *mut u8) {
    let ops = ops();
    let ctx = (ops.current_task_ctx)();
    let mut registry = (*ctx).registry as *mut Registry;
    if registry.is_null() {
        registry = (ops.construct_container)(
            operator_new(TASK_REGISTRY_OBJECT_SIZE) as *mut Registry,
            TASK_REGISTRY_INITIAL_CAPACITY,
            TASK_REGISTRY_GROWTH_STEP,
        );
        let observer = (ops.construct_observer)(operator_new(TASK_REGISTRY_OBSERVER_SIZE));
        ((*vtable(registry)).attach_observer)(registry, observer);
        let ctx = (ops.current_task_ctx)();
        (*ctx).registry = registry as *mut u8;
    }
    let mut entry = RegistryEntry { class_id, instance };
    if ((*vtable(registry)).query)(registry, &mut entry, TASK_REGISTRY_QUERY_OPERAND) == -1 {
        let entry = RegistryEntry { class_id: entry.class_id, instance };
        ((*vtable(registry)).insert)(registry, &entry);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below.
    static LOCK: Mutex<()> = Mutex::new(());

    /// The current task's context block.
    static mut CTX: TaskCtx = TaskCtx::ZERO;
    /// The registry the container-constructor mock hands back.
    static mut REGISTRY: Registry = Registry {
        vtable: ptr::null(),
        container: [0; 7],
        changed: 0,
        notify_enabled: 0,
        reserved: [0; 2],
        observer: ptr::null_mut(),
    };
    /// Backing for the observer allocation.
    static mut OBSERVER_ARENA: RegistryObserver = RegistryObserver {
        vtable: ptr::null(),
        state: 0,
    };
    /// Backing for the registry allocation (the constructor mock
    /// ignores it, but `operator new` must still land somewhere).
    static mut REGISTRY_ARENA: [u8; 0x28] = [0; 0x28];
    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached (the class_registry.rs
    /// pattern).
    static mut FAKE_HEAP: usize = 0;

    /// Ordered trace of the mock calls.
    static mut TRACE: Vec<&'static str> = Vec::new();
    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();
    /// (this, capacity, growth) observed by the container mock.
    static mut CONTAINER_ARGS: Vec<(*mut Registry, u32, u32)> = Vec::new();
    /// (registry, observer) pairs observed by the attach mock.
    static mut ATTACHED: Vec<(*mut Registry, *mut u8)> = Vec::new();
    /// (registry, class_id, instance, operand) observed by the query
    /// mock, with the entry contents at dispatch time.
    static mut QUERY_ARGS: Vec<(*mut Registry, u32, usize, u32)> = Vec::new();
    /// (class_id, instance) pairs observed by the insert mock.
    static mut INSERTED: Vec<(u32, usize)> = Vec::new();

    /// What the query mock returns.
    static mut QUERY_RET: i32 = -1;
    /// When non-zero, the query mock rewrites the entry's class id to
    /// this value (the entry pointer is writable — see the header).
    static mut QUERY_REWRITE: u32 = 0;

    fn trace() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(TRACE) }
    }

    unsafe extern "C" fn mock_current_task_ctx() -> *mut TaskCtx {
        trace().push("current_task_ctx");
        ptr::addr_of_mut!(CTX)
    }

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        trace().push("alloc");
        (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        match size {
            TASK_REGISTRY_OBJECT_SIZE => ptr::addr_of_mut!(REGISTRY_ARENA) as *mut u8,
            TASK_REGISTRY_OBSERVER_SIZE => ptr::addr_of_mut!(OBSERVER_ARENA) as *mut u8,
            _ => unreachable!("unexpected allocation size {size}"),
        }
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    unsafe extern "C" fn mock_construct_container(
        this: *mut Registry,
        capacity: u32,
        growth: u32,
    ) -> *mut Registry {
        trace().push("construct_container");
        (*ptr::addr_of_mut!(CONTAINER_ARGS)).push((this, capacity, growth));
        let registry = ptr::addr_of_mut!(REGISTRY);
        ptr::write_volatile(
            ptr::addr_of_mut!((*registry).vtable),
            ptr::addr_of!(MOCK_VTABLE) as *const crate::app::registry::RegistryVtable,
        );
        registry
    }

    unsafe extern "C" fn mock_construct_observer(this: *mut u8) -> *mut u8 {
        trace().push("construct_observer");
        this
    }

    unsafe extern "C" fn mock_attach_observer(
        this: *mut Registry,
        observer: *mut u8,
    ) -> usize {
        trace().push("attach_observer");
        (*ptr::addr_of_mut!(ATTACHED)).push((this, observer));
        0
    }

    unsafe extern "C" fn mock_query(
        this: *mut Registry,
        entry: *mut RegistryEntry,
        operand: u32,
    ) -> i32 {
        trace().push("query");
        (*ptr::addr_of_mut!(QUERY_ARGS)).push((
            this,
            (*entry).class_id,
            (*entry).instance as usize,
            operand,
        ));
        let rewrite = QUERY_REWRITE;
        if rewrite != 0 {
            (*entry).class_id = rewrite;
        }
        QUERY_RET
    }

    unsafe extern "C" fn mock_insert(
        _this: *mut Registry,
        entry: *const RegistryEntry,
    ) -> usize {
        trace().push("insert");
        (*ptr::addr_of_mut!(INSERTED)).push(((*entry).class_id, (*entry).instance as usize));
        0
    }

    static MOCK_VTABLE: TaskRegistryVtable = TaskRegistryVtable {
        unresolved_00: [0; 7],
        insert: mock_insert,
        unresolved_20: [0; 10],
        query: mock_query,
        unresolved_4c: [0; 2],
        attach_observer: mock_attach_observer,
    };

    /// Installs the mocks, seeds the fixture registry vtable, and resets
    /// every recorder.
    fn mock() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut heap = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            heap.alloc = stub_alloc;
            heap.create = stub_create;
            HEAP_OPS = heap;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            TASK_REGISTRY_OPS = TaskRegistryOps {
                current_task_ctx: mock_current_task_ctx,
                construct_container: mock_construct_container,
                construct_observer: mock_construct_observer,
            };
            ptr::addr_of_mut!(CTX).write(TaskCtx::ZERO);
            ptr::addr_of_mut!(REGISTRY).write(Registry {
                vtable: ptr::addr_of!(MOCK_VTABLE) as *const crate::app::registry::RegistryVtable,
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            });
            QUERY_RET = -1;
            QUERY_REWRITE = 0;
            trace().clear();
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CONTAINER_ARGS)).clear();
            (*ptr::addr_of_mut!(ATTACHED)).clear();
            (*ptr::addr_of_mut!(QUERY_ARGS)).clear();
            (*ptr::addr_of_mut!(INSERTED)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            TASK_REGISTRY_OPS = DEFAULT_TASK_REGISTRY_OPS;
            ptr::addr_of_mut!(CTX).write(TaskCtx::ZERO);
        }
        drop(guard);
    }

    fn registry() -> *mut Registry {
        ptr::addr_of_mut!(REGISTRY)
    }

    #[test]
    fn miss_inserts_the_pair_into_the_existing_registry() {
        let guard = mock();
        unsafe {
            CTX.registry = registry() as *mut u8;

            task_registry_register(0x1d80, 0x1100_0000 as *mut u8);

            assert_eq!(
                *trace(),
                std::vec!["current_task_ctx", "query", "insert"],
                "no construction when ctx+0x38 is already installed"
            );
            assert_eq!(
                *ptr::addr_of!(QUERY_ARGS),
                std::vec![(registry(), 0x1d80, 0x1100_0000usize, TASK_REGISTRY_QUERY_OPERAND)],
                "the query sees the spilled class-id/instance pair and the mov r2, #4 literal"
            );
            assert_eq!(
                *ptr::addr_of!(INSERTED),
                std::vec![(0x1d80, 0x1100_0000usize)],
                "the -1 gate fell through to the +0x1c insert"
            );
            assert!((*ptr::addr_of_mut!(ALLOC_SIZES)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn hit_skips_the_insert() {
        let guard = mock();
        unsafe {
            CTX.registry = registry() as *mut u8;
            QUERY_RET = 0;

            task_registry_register(0x1300, 0x2200_0000 as *mut u8);

            assert_eq!(*trace(), std::vec!["current_task_ctx", "query"]);
            assert!((*ptr::addr_of_mut!(INSERTED)).is_empty(), "only -1 inserts");
        }
        restore(guard);
    }

    #[test]
    fn first_registration_builds_the_registry_then_queries() {
        let guard = mock();
        unsafe {
            task_registry_register(0x5200, 0x3300_0000 as *mut u8);

            assert_eq!(
                *trace(),
                std::vec![
                    "current_task_ctx",
                    "alloc",
                    "construct_container",
                    "alloc",
                    "construct_observer",
                    "attach_observer",
                    "current_task_ctx",
                    "query",
                    "insert",
                ],
                "lazy construction, then the second ctx fetch, then the query/insert pair"
            );
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![TASK_REGISTRY_OBJECT_SIZE, TASK_REGISTRY_OBSERVER_SIZE],
                "the original's mov r0, #0x28 and mov r0, #0x8"
            );
            assert_eq!(
                *ptr::addr_of!(CONTAINER_ARGS),
                std::vec![(
                    ptr::addr_of_mut!(REGISTRY_ARENA) as *mut Registry,
                    TASK_REGISTRY_INITIAL_CAPACITY,
                    TASK_REGISTRY_GROWTH_STEP,
                )],
                "the container is constructed over the 0x28 allocation with capacity 8, growth 4"
            );
            assert_eq!(
                *ptr::addr_of!(ATTACHED),
                std::vec![(registry(), ptr::addr_of!(OBSERVER_ARENA) as *mut u8)],
                "the freshly built observer goes to the +0x54 slot before the ctx store"
            );
            assert_eq!(
                CTX.registry,
                registry() as *mut u8,
                "the constructor's result lands at ctx+0x38"
            );
            assert_eq!(
                *ptr::addr_of!(INSERTED),
                std::vec![(0x5200, 0x3300_0000usize)]
            );
        }
        restore(guard);
    }

    #[test]
    fn miss_re_reads_the_class_id_the_query_rewrote() {
        let guard = mock();
        unsafe {
            CTX.registry = registry() as *mut u8;
            QUERY_REWRITE = 0xdead_beef;

            task_registry_register(0x1080, 0x4400_0000 as *mut u8);

            assert_eq!(
                *ptr::addr_of!(INSERTED),
                std::vec![(0xdead_beef, 0x4400_0000usize)],
                "the inserted class id is re-read from the stack slot the query \
                 could write (ldr r0, [sp, #8]); the instance is the register copy"
            );
        }
        restore(guard);
    }

    #[test]
    fn default_observer_ctor_models_fun_081f6b14() {
        let guard = mock();
        unsafe {
            let observer = ptr::addr_of_mut!(OBSERVER_ARENA) as *mut u8;
            observer.write_bytes(0xa5, 8);

            let result = task_registry_observer_construct(observer);

            assert_eq!(result, observer, "the base constructor's r0 is forwarded");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!((*(observer as *mut RegistryObserver)).vtable))
                    as usize,
                TASK_REGISTRY_OBSERVER_VTABLE_ADDRESS,
                "the derived vtable literal replaces +0x00"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!((*(observer as *mut RegistryObserver)).state)),
                0,
                "the ported base cleared the state word before the vtable swap"
            );
        }
        restore(guard);
    }

    #[test]
    fn defaults_are_the_ported_callees() {
        let ops = DEFAULT_TASK_REGISTRY_OPS;
        assert_eq!(
            ops.current_task_ctx as usize,
            current_task_ctx_block as *const () as usize
        );
        assert_eq!(
            ops.construct_container as usize,
            registry_container_construct as *const () as usize
        );
        assert_eq!(
            ops.construct_observer as usize,
            task_registry_observer_construct as *const () as usize
        );
    }
}
