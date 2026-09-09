//! inner_set_state_4 — original: `FUN_0813b7c4` @ 0x0813b7c4 (12 bytes;
//! 1 `bl` call site: the query runner `FUN_080feb68` @ 0x080feba4).
//!
//! A three-instruction forwarding wrapper:
//!
//! ```text
//! ldr r0, [r0, #0x40]   @ inner = this->inner
//! mov r1, #0x4
//! b   0x08067ca4        @ tail: inner->+0xe38 = 4  (str r1,[r0,#0xe38]; bx lr)
//! ```
//!
//! `this` is the 72-byte stack-local query object built by the
//! constructor `FUN_0813e474` and torn down by `FUN_0813e5c4`; its word
//! at +0x40 points at a much larger inner object (fields observed out to
//! +0xf68, a count/limit word). The word at inner+0xe38 is a small
//! state/mode word: other code stores 1 (`FUN_08053f9c` @ 0x08053fdc,
//! alongside the +0xef9/+0xefa flag bytes), 3 (0x08054038) and 5
//! (0x08061020) into it, and the reader @ 0x0808cf4c compares it against
//! 1 to pick a result code. The sole caller stores 4 right before
//! running query 0x32 through the sibling wrappers `FUN_0813bd10`
//! (inner forward with constant 0) and `FUN_0813d064`. The exact enum is
//! not identified; the function is ported on observable behavior.
//!
//! Sits immediately after the util/berec.rs big-endian record reader
//! cluster @ 0x0813b714..0x0813b7b0 but is NOT one of them: no record
//! handle, no big-endian decode — an object-state setter.
//!
//! Deviation: the original tail-branches to the 8-byte setter
//! `FUN_08067ca4` @ 0x08067ca4 (`str r1,[r0,#0xe38]; bx lr`); the port
//! inlines that store (it is the callee's whole body), so the ARM build
//! is `ldr/mov/str/bx` instead of `ldr/mov/b`. Byte-offset addressing on
//! a `*mut u8` (the util/state_flags.rs precedent) keeps the layout
//! exact on a 64-bit test host.
//!
//! # inner_result_count — original: `FUN_0813b7d0` @ 0x0813b7d0 (8 bytes)
//!
//! 1 `bl` call site: the query runner `FUN_080feb68` @ 0x080febc8, two
//! instructions after its `inner_set_state_4` call. A two-instruction
//! forwarding wrapper — the read-side sibling of `inner_set_state_4`:
//!
//! ```text
//! ldr r0, [r0, #0x40]   @ inner = this->inner
//! b   0x080542a0        @ tail: materialize-and-count(inner)
//! ```
//!
//! The tail target `FUN_080542a0` @ 0x080542a0 (20 bytes, 3 `bl` call
//! sites) calls the lazy materializer `FUN_08086694` @ 0x08086694 (480
//! bytes: when the cached result-array pointer at inner+0xeec is NULL it
//! builds the array under a mutex, caching the array at +0xeec, an aux
//! pointer at +0xef0 and the result count at +0xef4 — a no-op otherwise)
//! and returns the count word at inner+0xef4. The sole caller uses the
//! result as the loop bound over the per-index record fetch
//! `FUN_0813b898` after running query 0x32 — the number of records the
//! query produced.
//!
//! # inner_set_state — original: `FUN_08067ca4` @ 0x08067ca4 (8 bytes)
//!
//! The state/mode setter that `inner_set_state_4` tail-branches into:
//!
//! ```text
//! str r1, [r0, #0xe38]   @ inner->state = state
//! bx  lr
//! ```
//!
//! Unlike the wrapper, callers pass the inner object directly (they
//! load the +0x40 slot themselves). 11 `bl` call sites: a switch over
//! query ids @ 0x08111368..0x081113c4 stores states 0..6, and the
//! query-family wrappers `FUN_0813c02c`/`FUN_0813c6c0` (4),
//! `FUN_0813c700` (7), `FUN_0813d974`/`FUN_0813deb0`/`FUN_0813e474`
//! (5) and `FUN_0817a238` (5, then a variable) call it with the inner
//! object from the query object's +0x40 slot — the same state/mode
//! word the writers @ 0x08053fdc (1), 0x08054038 (3), 0x08061020 (5)
//! poke inline and the reader @ 0x0808cf4c compares against 1. The
//! exact enum is not identified; the function is ported on observable
//! behavior. This is the symbol `inner_set_state_4`'s port inlined;
//! it gets its own per-address symbol here.
//!
//! Deviation: the materializer is unported firmware (it allocates,
//! walks a record table and locks a mutex through nine further
//! callees), so the whole tail target sits behind the
//! [`INNER_MATERIALIZE_COUNT`] dispatch slot (the app/class_registry.rs
//! pattern). The default stub is the materializer's no-op path: it
//! reads the cached count word at +0xef4 without materializing — exact
//! once a query has populated the cache, which is the only state the
//! sole caller ever observes (it runs query 0x32 before asking).

/// Byte offset of the inner-object pointer inside the query object.
const INNER: usize = 0x40;

/// Byte offset of the state/mode word inside the inner object.
const STATE: usize = 0xe38;

/// The state value this wrapper always stores.
const STATE_4: u32 = 4;

/// Byte offset of the result-count word inside the inner object
/// (written by the lazy materializer @ 0x08086694, read back by the
/// tail target @ 0x080542a0).
const RESULT_COUNT: usize = 0xef4;
/// Byte offset of the materialized result-array pointer. The object layout is
/// 32-bit even in host tests, so cache pointer fields are always read as u32.
const CACHED_RESULTS: usize = 0xeec;

/// Byte offset of the auxiliary allocation paired with [`CACHED_RESULTS`].
const CACHED_AUXILIARY: usize = 0xef0;


/// query_object_create — original: `FUN_082597a0` @ 0x082597a0 (32 bytes;
/// 25 verified `bl` call sites, all unconditional).
///
/// Allocates exactly 0x48 bytes with tag-2 [`crate::heap::veneers::operator_new`],
/// then tail-calls the query-object constructor `FUN_0813e474` with id zero
/// and the caller's `mode`. The constructor's return, rather than the raw
/// allocation, is returned. Stock has no allocation NULL guard: construction
/// is attempted even for a NULL allocator result. The port calls the existing
/// query-constructor seam; on target it reaches 0x0813e474 directly, while
/// host tests make its inputs and return observable. This guarded call replaces
/// the stock tail branch; the result and call arguments are unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn query_object_create(mode: u32) -> *mut u8 {
    let object = crate::heap::veneers::operator_new(0x48);
    crate::fp::fp_misc::query_object_construct(object, 0, mode)
}

/// inner_set_state_4 — original: `FUN_0813b7c4` @ 0x0813b7c4 (12 bytes).
///
/// Loads the inner object from `object + 0x40` and stores 4 into its
/// state word at +0xe38. Returns nothing (the original is a tail branch
/// to a void setter; the sole caller discards r0).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_set_state_4(object: *mut u8) {
    let inner = (object.add(INNER) as *const *mut u8).read();
    (inner.add(STATE) as *mut u32).write(STATE_4);
}

/// inner_set_state — original: `FUN_08067ca4` @ 0x08067ca4 (8 bytes).
///
/// Stores `state` into the inner object's state/mode word at +0xe38
/// and returns. The tail target of `inner_set_state_4`; here callers
/// pass the inner object itself, having loaded the +0x40 slot.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_set_state(inner: *mut u8, state: u32) {
    (inner.add(STATE) as *mut u32).write(state);
}

/// inner_clear_cached_results — original: `FUN_08059a98` @ 0x08059a98
/// (60 bytes; 17 verified `bl` call sites, all unconditional).
///
/// Releases the cached result array at `inner + 0xeec` with the existing
/// tag-4 MemH free veneer. Only when that primary pointer was nonzero, it
/// clears it, releases the auxiliary allocation at `inner + 0xef0` if
/// nonzero, and clears that field. It always clears the cached result count at
/// `inner + 0xef4`. In particular, a zero primary pointer leaves a nonzero
/// auxiliary pointer untouched; that asymmetric invariant is encoded by the
/// original's branch around both the primary free and the auxiliary check.
///
/// Fields are explicitly 32-bit words rather than host-width pointers: this
/// preserves the target's adjacent +0xeec/+0xef0 layout on 64-bit hosts.
/// There are no other deviations: [`crate::heap::veneers::free_tag4`] is the
/// already-ported direct callee at 0x0805d070.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_clear_cached_results(inner: *mut u8) {
    let results = (inner.add(CACHED_RESULTS) as *const u32).read();
    if results != 0 {
        crate::heap::veneers::free_tag4(results as usize as *mut u8);
        (inner.add(CACHED_RESULTS) as *mut u32).write(0);

        let auxiliary = (inner.add(CACHED_AUXILIARY) as *const u32).read();
        if auxiliary != 0 {
            crate::heap::veneers::free_tag4(auxiliary as usize as *mut u8);
            (inner.add(CACHED_AUXILIARY) as *mut u32).write(0);
        }
    }
    (inner.add(RESULT_COUNT) as *mut u32).write(0);
}

/// The callback-root field of an inner query resource. `repr(C)` preserves
/// its target offset while using a host-width pointer in host fixtures.
#[repr(C)]
struct InnerResourceCallbackOwner {
    _before_callback_root: [u8; 0x40],
    callback_root: *mut u8,
}

/// Literal callback continuation loaded from `0x08059b20`.
const SELECTED_RESOURCE_CALLBACK: usize = 0x080d_43c4;

type ResolveSelectedResource = unsafe extern "C" fn(object: *mut u8) -> *mut u8;
type IsResourceSelected = unsafe extern "C" fn(inner: *mut u8, object: *mut u8) -> u32;
type SetResourceSelected = unsafe extern "C" fn(selected: u32, inner: *mut u8, object: *mut u8);
type DispatchSelectedResource = unsafe extern "C" fn(
    callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32;

#[derive(Clone, Copy)]
struct InnerSelectedResourceOps {
    resolve: ResolveSelectedResource,
    is_selected: IsResourceSelected,
    set_selected: SetResourceSelected,
    dispatch: DispatchSelectedResource,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resolve_selected_resource(object: *mut u8) -> *mut u8 {
    let resolve: ResolveSelectedResource = core::mem::transmute(0x0805_1ce4usize);
    resolve(object)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_is_resource_selected(inner: *mut u8, object: *mut u8) -> u32 {
    let is_selected: IsResourceSelected = core::mem::transmute(0x0805_4710usize);
    is_selected(inner, object)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_set_resource_selected(
    selected: u32,
    inner: *mut u8,
    object: *mut u8,
) {
    let set_selected: SetResourceSelected = core::mem::transmute(0x0806_7450usize);
    set_selected(selected, inner, object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_dispatch_selected_resource(
    callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32 {
    crate::app::resource::cache::resource_callback_dispatch(callback_root, callback, context)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve_selected_resource(_object: *mut u8) -> *mut u8 {
    panic!("inner_dispatch_selected_resource requires resolver 0x08051ce4")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_resource_selected(_inner: *mut u8, _object: *mut u8) -> u32 {
    panic!("inner_dispatch_selected_resource requires selection test 0x08054710")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_resource_selected(
    _selected: u32,
    _inner: *mut u8,
    _object: *mut u8,
) {
    panic!("inner_dispatch_selected_resource requires selection setter 0x08067450")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch_selected_resource(
    _callback_root: *mut u8,
    _callback: usize,
    _context: *mut u8,
) -> i32 {
    panic!("inner_dispatch_selected_resource requires resource callback dispatch")
}

#[cfg(target_os = "none")]
const DEFAULT_INNER_SELECTED_RESOURCE_OPS: InnerSelectedResourceOps = InnerSelectedResourceOps {
    resolve: firmware_resolve_selected_resource,
    is_selected: firmware_is_resource_selected,
    set_selected: firmware_set_resource_selected,
    dispatch: firmware_dispatch_selected_resource,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_INNER_SELECTED_RESOURCE_OPS: InnerSelectedResourceOps = InnerSelectedResourceOps {
    resolve: missing_resolve_selected_resource,
    is_selected: missing_is_resource_selected,
    set_selected: missing_set_resource_selected,
    dispatch: missing_dispatch_selected_resource,
};

/// The three unported inner-resource helpers and callback dispatcher used by
/// [`inner_dispatch_selected_resource`]. The target defaults preserve their
/// original call boundaries; host tests replace the complete operation set.
static mut INNER_SELECTED_RESOURCE_OPS: InnerSelectedResourceOps =
    DEFAULT_INNER_SELECTED_RESOURCE_OPS;

/// inner_dispatch_selected_resource — original: `FUN_08059ad4` @
/// 0x08059ad4 (76 bytes: 72 instruction bytes plus literal callback word at
/// 0x08059b20; next entry 0x08059b24).
///
/// Raw decoding of every ARM B/BL word in `osos.dec` finds 16 direct call
/// sites, all unconditional `bl`; no predicated call or data-word occurrence
/// exists. One additional unconditional `b` at 0x0813d044 tail-branches here.
///
/// Resolves the object’s active inner resource, returns zero when resolution
/// fails or its selection bit for `object + 1` is clear, otherwise clears that
/// bit and dispatches callback continuation 0x080d43c4 over the inner’s
/// callback-root at `+0x40`. The dispatcher status is returned unchanged.
///
/// The three simple but unported helpers at 0x08051ce4, 0x08054710, and
/// 0x08067450 remain direct firmware calls on target. The callback literal
/// enters the middle of a larger firmware routine and is not given an invented
/// identity; the existing resource dispatcher supplies its recovered r4/r2
/// callback register contract. Deliberate deviation: ARM tail-branches to the
/// dispatcher after restoring registers, while Rust makes an ordinary call
/// through the volatile operation slot so host tests can observe the boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_dispatch_selected_resource(object: *mut u8) -> i32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(INNER_SELECTED_RESOURCE_OPS));
    let inner = (ops.resolve)(object);
    if inner.is_null() || (ops.is_selected)(inner, object) == 0 {
        return 0;
    }

    (ops.set_selected)(0, inner, object);
    let owner = inner.cast::<InnerResourceCallbackOwner>();
    let callback_root = core::ptr::addr_of!((*owner).callback_root).read();
    (ops.dispatch)(callback_root, SELECTED_RESOURCE_CALLBACK, object)
}

/// Default [`INNER_MATERIALIZE_COUNT`] stub: the no-op path of the
/// unported materialize-and-count tail target `FUN_080542a0` @
/// 0x080542a0 — reads the cached result-count word at inner+0xef4
/// without running the unported 480-byte materializer @ 0x08086694
/// (exact once the query has populated the cache; see the module
/// header).
unsafe extern "C" fn materialize_count_stub(inner: *mut u8) -> u32 {
    (inner.add(RESULT_COUNT) as *const u32).read()
}

/// Indirect dispatch for the unported materialize-and-count tail target
/// @ 0x080542a0 (the app/class_registry.rs pattern). Host tests install
/// a recording mock; the real port replaces the default stub when the
/// materializer @ 0x08086694 is ported.
pub static mut INNER_MATERIALIZE_COUNT: unsafe extern "C" fn(inner: *mut u8) -> u32 =
    materialize_count_stub;

/// inner_result_count — original: `FUN_0813b7d0` @ 0x0813b7d0 (8 bytes).
///
/// Loads the inner object from `object + 0x40` and tail-branches to the
/// materialize-and-count getter, returning the query's result count
/// (the word at inner+0xef4 after the lazy materializer has run).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_result_count(object: *mut u8) -> u32 {
    let inner = (object.add(INNER) as *const *mut u8).read();
    // Volatile slot read — the class_registry.rs `ops!` rationale: the
    // slot is meant to be swapped at runtime, and a build in which
    // nothing swaps it must not constant-fold the default in.
    let materialize =
        core::ptr::read_volatile(core::ptr::addr_of!(INNER_MATERIALIZE_COUNT));
    materialize(inner)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use crate::fp::fp_misc::QUERY_OBJECT_CONSTRUCT;
    use crate::heap::veneers::tests::{
        alloc_log, free_log, mock_block, mock_heap, set_alloc_ret,
    };

    const QUERY_CONSTRUCT_RESULT: usize = 0xa110_0048;
    static QUERY_FACTORY_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY_CONSTRUCT_CALLS: usize = 0;
    static mut QUERY_CONSTRUCT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut QUERY_CONSTRUCT_ID: u32 = 0;
    static mut QUERY_CONSTRUCT_MODE: u32 = 0;

    unsafe extern "C" fn mock_query_construct(object: *mut u8, id: u32, mode: u32) -> *mut u8 {
        QUERY_CONSTRUCT_CALLS += 1;
        QUERY_CONSTRUCT_OBJECT = object;
        QUERY_CONSTRUCT_ID = id;
        QUERY_CONSTRUCT_MODE = mode;
        QUERY_CONSTRUCT_RESULT as *mut u8
    }

    struct QueryConstructRestore(usize);

    impl Drop for QueryConstructRestore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT).write(self.0) };
        }
    }

    fn install_query_construct_mock() -> QueryConstructRestore {
        unsafe {
            QUERY_CONSTRUCT_CALLS = 0;
            QUERY_CONSTRUCT_OBJECT = core::ptr::null_mut();
            QUERY_CONSTRUCT_ID = u32::MAX;
            QUERY_CONSTRUCT_MODE = u32::MAX;
            let prior = core::ptr::addr_of!(QUERY_OBJECT_CONSTRUCT).read_volatile();
            core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT).write(mock_query_construct as usize);
            QueryConstructRestore(prior)
        }
    }

    const INNER_LEN: usize = RESULT_COUNT + 4;
    // The +0x40 slot is pointer-wide: 4 bytes on the target, 8 on a
    // 64-bit test host.
    const OUTER_LEN: usize = INNER + core::mem::size_of::<*mut u8>();
    const SENTINEL: u8 = 0xa5;

    /// Serializes the tests that swap `INNER_MATERIALIZE_COUNT` (the
    /// wstr_casecmp.rs `FOLD_TEST_LOCK` precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// A stand-in outer object whose +0x40 slot points at a stand-in
    /// inner object, both filled with sentinel bytes.
    struct Fixture {
        outer: [u8; OUTER_LEN],
        inner: [u8; INNER_LEN],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture { outer: [SENTINEL; OUTER_LEN], inner: [SENTINEL; INNER_LEN] }
        }
        /// Writes a genuine host pointer into the +0x40 slot — on the
        /// 32-bit target this is exactly the original's word store.
        fn link(&mut self) {
            let ptr = self.inner.as_mut_ptr();
            unsafe { (self.outer.as_mut_ptr().add(INNER) as *mut *mut u8).write(ptr) };
        }
        fn call(&mut self) {
            unsafe { inner_set_state_4(self.outer.as_mut_ptr()) }
        }
        fn state(&self) -> u32 {
            u32::from_le_bytes(self.inner[STATE..STATE + 4].try_into().unwrap())
        }
    }

    #[test]
    fn query_object_create_allocates_72_bytes_and_forwards_mode() {
        let _query_guard = QUERY_FACTORY_TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        let _restore = install_query_construct_mock();

        let result = unsafe { query_object_create(u32::MAX) };

        assert_eq!(result, QUERY_CONSTRUCT_RESULT as *mut u8);
        assert_eq!(alloc_log(), (1, 0x48, 2), "one tag-2 allocation");
        unsafe {
            assert_eq!(QUERY_CONSTRUCT_CALLS, 1);
            assert_eq!(QUERY_CONSTRUCT_OBJECT, mock_block());
            assert_eq!(QUERY_CONSTRUCT_ID, 0);
            assert_eq!(QUERY_CONSTRUCT_MODE, u32::MAX);
        }
    }

    #[test]
    fn query_object_create_constructs_even_when_allocation_is_null() {
        let _query_guard = QUERY_FACTORY_TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        let _restore = install_query_construct_mock();

        let result = unsafe { query_object_create(2) };

        assert_eq!(result, QUERY_CONSTRUCT_RESULT as *mut u8);
        assert_eq!(alloc_log(), (1, 0x48, 2), "allocation remains unguarded");
        unsafe {
            assert_eq!(QUERY_CONSTRUCT_CALLS, 1);
            assert!(QUERY_CONSTRUCT_OBJECT.is_null());
            assert_eq!(QUERY_CONSTRUCT_ID, 0);
            assert_eq!(QUERY_CONSTRUCT_MODE, 2);
        }
    }

    #[test]
    fn stores_4_into_the_inner_state_word() {
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }

    #[test]
    fn touches_only_the_two_words_it_owns() {
        let mut fixture = Fixture::new();
        let inner_before = fixture.inner;
        fixture.link();
        fixture.call();

        // Outer object: only the +0x40 slot may differ (it does not).
        assert_eq!(&fixture.outer[..INNER], &[SENTINEL; INNER]);

        // Inner object: only the state word at +0xe38 changed.
        for offset in 0..INNER_LEN {
            let expect = if (STATE..STATE + 4).contains(&offset) {
                [4u8, 0, 0, 0][offset - STATE]
            } else {
                inner_before[offset]
            };
            assert_eq!(fixture.inner[offset], expect, "inner +{offset:#x}");
        }
    }

    #[test]
    fn overwrites_a_previous_state_value() {
        let mut fixture = Fixture::new();
        fixture.link();
        // Preload state 1, the value the 0x08053fdc writer stores.
        fixture.inner[STATE..STATE + 4].copy_from_slice(&1u32.to_le_bytes());
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }

    #[test]
    fn is_idempotent() {
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.call();
        fixture.call();
        assert_eq!(fixture.state(), STATE_4);
    }

    // ---- inner_set_state ---------------------------------------------

    #[test]
    fn direct_setter_stores_the_given_state() {
        let mut fixture = Fixture::new();
        let inner_base = fixture.inner.as_mut_ptr();
        unsafe { inner_set_state(inner_base, 5) };
        assert_eq!(fixture.state(), 5);
    }

    #[test]
    fn direct_setter_round_trips_every_observed_state() {
        let mut fixture = Fixture::new();
        let inner_base = fixture.inner.as_mut_ptr();
        // 0..7 are the values the 11 bl call sites store; u32::MAX
        // proves the store is a full word, not a byte.
        for state in [0u32, 1, 2, 3, 4, 5, 6, 7, u32::MAX] {
            unsafe { inner_set_state(inner_base, state) };
            assert_eq!(fixture.state(), state);
        }
    }

    #[test]
    fn direct_setter_touches_only_the_state_word() {
        let mut fixture = Fixture::new();
        let inner_before = fixture.inner;
        let inner_base = fixture.inner.as_mut_ptr();
        unsafe { inner_set_state(inner_base, 3) };
        for offset in 0..INNER_LEN {
            let expect = if (STATE..STATE + 4).contains(&offset) {
                [3u8, 0, 0, 0][offset - STATE]
            } else {
                inner_before[offset]
            };
            assert_eq!(fixture.inner[offset], expect, "inner +{offset:#x}");
        }
    }

    // ---- inner_clear_cached_results ------------------------------------

    /// A target-layout cache tail: fields remain u32 words even though the
    /// backing allocation is a normal 64-bit host object.
    #[repr(align(4))]
    struct CacheFixture {
        bytes: [u8; INNER_LEN],
    }

    impl CacheFixture {
        fn new() -> Self {
            CacheFixture { bytes: [SENTINEL; INNER_LEN] }
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn clear(&mut self) {
            unsafe { inner_clear_cached_results(self.bytes.as_mut_ptr()) };
        }
    }

    #[test]
    fn cache_clear_releases_the_primary_result_and_zeros_all_cache_words() {
        let _heap_guard = mock_heap();
        let mut fixture = CacheFixture::new();
        fixture.set_word(CACHED_RESULTS, 0x1111_2222);
        fixture.set_word(CACHED_AUXILIARY, 0);
        fixture.set_word(RESULT_COUNT, u32::MAX);

        fixture.clear();

        assert_eq!(free_log(), (1, 0x1111_2222usize as *mut u8, 4));
        assert_eq!(fixture.word(CACHED_RESULTS), 0);
        assert_eq!(fixture.word(CACHED_AUXILIARY), 0);
        assert_eq!(fixture.word(RESULT_COUNT), 0);
    }

    #[test]
    fn cache_clear_releases_the_auxiliary_only_after_the_primary() {
        let _heap_guard = mock_heap();
        let mut fixture = CacheFixture::new();
        fixture.set_word(CACHED_RESULTS, 0x3333_4444);
        fixture.set_word(CACHED_AUXILIARY, 0x5555_6666);
        fixture.set_word(RESULT_COUNT, 7);

        fixture.clear();

        assert_eq!(free_log(), (2, 0x5555_6666usize as *mut u8, 4));
        assert_eq!(fixture.word(CACHED_RESULTS), 0);
        assert_eq!(fixture.word(CACHED_AUXILIARY), 0);
        assert_eq!(fixture.word(RESULT_COUNT), 0);
    }

    #[test]
    fn cache_clear_preserves_auxiliary_when_primary_is_absent() {
        let _heap_guard = mock_heap();
        let mut fixture = CacheFixture::new();
        fixture.set_word(CACHED_RESULTS, 0);
        fixture.set_word(CACHED_AUXILIARY, 0x7777_8888);
        fixture.set_word(RESULT_COUNT, 0xabcd_ef01);

        fixture.clear();

        assert_eq!(free_log().0, 0, "the auxiliary check is primary-gated");
        assert_eq!(fixture.word(CACHED_RESULTS), 0);
        assert_eq!(fixture.word(CACHED_AUXILIARY), 0x7777_8888);
        assert_eq!(fixture.word(RESULT_COUNT), 0);
    }

    // ---- inner_dispatch_selected_resource -----------------------------

    static SELECTED_RESOURCE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SELECTED_RESOURCE_INNER: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_IS_SELECTED: u32 = 0;
    static mut SELECTED_RESOURCE_STATUS: i32 = 0;
    static mut SELECTED_RESOURCE_RESOLVE_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_SELECT_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_SET_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_DISPATCH_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_RESOLVE_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SELECT_INNER: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SELECT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SET_SELECTED: u32 = u32::MAX;
    static mut SELECTED_RESOURCE_SET_INNER: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SET_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_DISPATCH_ROOT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_DISPATCH_CALLBACK: usize = 0;
    static mut SELECTED_RESOURCE_DISPATCH_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_RESOLVE_STAGE: u32 = 0;
    static mut SELECTED_RESOURCE_SELECT_STAGE: u32 = 0;
    static mut SELECTED_RESOURCE_SET_STAGE: u32 = 0;
    static mut SELECTED_RESOURCE_DISPATCH_STAGE: u32 = 0;
    static mut SELECTED_RESOURCE_STAGE: u32 = 0;

    unsafe extern "C" fn mock_resolve_selected_resource(object: *mut u8) -> *mut u8 {
        SELECTED_RESOURCE_RESOLVE_CALLS += 1;
        SELECTED_RESOURCE_RESOLVE_OBJECT = object;
        SELECTED_RESOURCE_STAGE += 1;
        SELECTED_RESOURCE_RESOLVE_STAGE = SELECTED_RESOURCE_STAGE;
        SELECTED_RESOURCE_INNER
    }

    unsafe extern "C" fn mock_is_resource_selected(inner: *mut u8, object: *mut u8) -> u32 {
        SELECTED_RESOURCE_SELECT_CALLS += 1;
        SELECTED_RESOURCE_SELECT_INNER = inner;
        SELECTED_RESOURCE_SELECT_OBJECT = object;
        SELECTED_RESOURCE_STAGE += 1;
        SELECTED_RESOURCE_SELECT_STAGE = SELECTED_RESOURCE_STAGE;
        SELECTED_RESOURCE_IS_SELECTED
    }

    unsafe extern "C" fn mock_set_resource_selected(
        selected: u32,
        inner: *mut u8,
        object: *mut u8,
    ) {
        SELECTED_RESOURCE_SET_CALLS += 1;
        SELECTED_RESOURCE_SET_SELECTED = selected;
        SELECTED_RESOURCE_SET_INNER = inner;
        SELECTED_RESOURCE_SET_OBJECT = object;
        SELECTED_RESOURCE_STAGE += 1;
        SELECTED_RESOURCE_SET_STAGE = SELECTED_RESOURCE_STAGE;
    }

    unsafe extern "C" fn mock_dispatch_selected_resource(
        callback_root: *mut u8,
        callback: usize,
        context: *mut u8,
    ) -> i32 {
        SELECTED_RESOURCE_DISPATCH_CALLS += 1;
        SELECTED_RESOURCE_DISPATCH_ROOT = callback_root;
        SELECTED_RESOURCE_DISPATCH_CALLBACK = callback;
        SELECTED_RESOURCE_DISPATCH_CONTEXT = context;
        SELECTED_RESOURCE_STAGE += 1;
        SELECTED_RESOURCE_DISPATCH_STAGE = SELECTED_RESOURCE_STAGE;
        SELECTED_RESOURCE_STATUS
    }

    struct SelectedResourceOpsRestore;

    impl Drop for SelectedResourceOpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INNER_SELECTED_RESOURCE_OPS)
                    .write_volatile(DEFAULT_INNER_SELECTED_RESOURCE_OPS);
            }
        }
    }

    fn install_selected_resource_mocks() -> SelectedResourceOpsRestore {
        unsafe {
            SELECTED_RESOURCE_INNER = core::ptr::null_mut();
            SELECTED_RESOURCE_IS_SELECTED = 0;
            SELECTED_RESOURCE_STATUS = 0;
            SELECTED_RESOURCE_RESOLVE_CALLS = 0;
            SELECTED_RESOURCE_SELECT_CALLS = 0;
            SELECTED_RESOURCE_SET_CALLS = 0;
            SELECTED_RESOURCE_DISPATCH_CALLS = 0;
            SELECTED_RESOURCE_RESOLVE_OBJECT = core::ptr::null_mut();
            SELECTED_RESOURCE_SELECT_INNER = core::ptr::null_mut();
            SELECTED_RESOURCE_SELECT_OBJECT = core::ptr::null_mut();
            SELECTED_RESOURCE_SET_SELECTED = u32::MAX;
            SELECTED_RESOURCE_SET_INNER = core::ptr::null_mut();
            SELECTED_RESOURCE_SET_OBJECT = core::ptr::null_mut();
            SELECTED_RESOURCE_DISPATCH_ROOT = core::ptr::null_mut();
            SELECTED_RESOURCE_DISPATCH_CALLBACK = 0;
            SELECTED_RESOURCE_DISPATCH_CONTEXT = core::ptr::null_mut();
            SELECTED_RESOURCE_RESOLVE_STAGE = 0;
            SELECTED_RESOURCE_SELECT_STAGE = 0;
            SELECTED_RESOURCE_SET_STAGE = 0;
            SELECTED_RESOURCE_DISPATCH_STAGE = 0;
            SELECTED_RESOURCE_STAGE = 0;
            core::ptr::addr_of_mut!(INNER_SELECTED_RESOURCE_OPS).write_volatile(
                InnerSelectedResourceOps {
                    resolve: mock_resolve_selected_resource,
                    is_selected: mock_is_resource_selected,
                    set_selected: mock_set_resource_selected,
                    dispatch: mock_dispatch_selected_resource,
                },
            );
        }
        SelectedResourceOpsRestore
    }

    #[repr(C)]
    struct SelectedResourceInnerFixture {
        before_callback_root: [u8; 0x40],
        callback_root: *mut u8,
    }

    #[test]
    fn selected_resource_returns_zero_without_testing_a_missing_inner() {
        let _lock = SELECTED_RESOURCE_TEST_LOCK.lock();
        let _restore = install_selected_resource_mocks();
        let mut object = [SENTINEL; 2];

        let result = unsafe { inner_dispatch_selected_resource(object.as_mut_ptr()) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(SELECTED_RESOURCE_RESOLVE_CALLS, 1);
            assert_eq!(SELECTED_RESOURCE_RESOLVE_OBJECT, object.as_mut_ptr());
            assert_eq!(SELECTED_RESOURCE_SELECT_CALLS, 0);
            assert_eq!(SELECTED_RESOURCE_SET_CALLS, 0);
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CALLS, 0);
        }
    }

    #[test]
    fn selected_resource_leaves_a_clear_selection_bit_untouched() {
        let _lock = SELECTED_RESOURCE_TEST_LOCK.lock();
        let _restore = install_selected_resource_mocks();
        let mut object = [SENTINEL; 2];
        let mut inner = SelectedResourceInnerFixture {
            before_callback_root: [SENTINEL; 0x40],
            callback_root: 0x1234_5678usize as *mut u8,
        };
        unsafe {
            SELECTED_RESOURCE_INNER = (&mut inner as *mut SelectedResourceInnerFixture).cast();
        }

        let result = unsafe { inner_dispatch_selected_resource(object.as_mut_ptr()) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(SELECTED_RESOURCE_RESOLVE_CALLS, 1);
            assert_eq!(SELECTED_RESOURCE_SELECT_CALLS, 1);
            assert_eq!(SELECTED_RESOURCE_SELECT_INNER, (&mut inner as *mut SelectedResourceInnerFixture).cast());
            assert_eq!(SELECTED_RESOURCE_SELECT_OBJECT, object.as_mut_ptr());
            assert_eq!(SELECTED_RESOURCE_SET_CALLS, 0);
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CALLS, 0);
        }
    }

    #[test]
    fn selected_resource_clears_then_dispatches_and_propagates_status() {
        let _lock = SELECTED_RESOURCE_TEST_LOCK.lock();
        let _restore = install_selected_resource_mocks();
        let mut object = [SENTINEL; 2];
        let mut callback_root = [0; 1];
        let mut inner = SelectedResourceInnerFixture {
            before_callback_root: [SENTINEL; 0x40],
            callback_root: callback_root.as_mut_ptr(),
        };
        unsafe {
            SELECTED_RESOURCE_INNER = (&mut inner as *mut SelectedResourceInnerFixture).cast();
            SELECTED_RESOURCE_IS_SELECTED = 1;
            SELECTED_RESOURCE_STATUS = -0x32;
        }

        let result = unsafe { inner_dispatch_selected_resource(object.as_mut_ptr()) };

        assert_eq!(result, -0x32);
        unsafe {
            assert_eq!(SELECTED_RESOURCE_SET_SELECTED, 0);
            assert_eq!(SELECTED_RESOURCE_SET_INNER, (&mut inner as *mut SelectedResourceInnerFixture).cast());
            assert_eq!(SELECTED_RESOURCE_SET_OBJECT, object.as_mut_ptr());
            assert_eq!(SELECTED_RESOURCE_DISPATCH_ROOT, callback_root.as_mut_ptr());
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CALLBACK, SELECTED_RESOURCE_CALLBACK);
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CONTEXT, object.as_mut_ptr());
            assert_eq!(
                (
                    SELECTED_RESOURCE_RESOLVE_STAGE,
                    SELECTED_RESOURCE_SELECT_STAGE,
                    SELECTED_RESOURCE_SET_STAGE,
                    SELECTED_RESOURCE_DISPATCH_STAGE,
                ),
                (1, 2, 3, 4),
            );
        }
    }

    // ---- inner_result_count -------------------------------------------

    static mut MOCK_SEEN: *mut u8 = core::ptr::null_mut();
    static mut MOCK_CALLS: u32 = 0;
    const MOCK_COUNT: u32 = 0x5a5a_0007;

    unsafe extern "C" fn recording_materialize(inner: *mut u8) -> u32 {
        MOCK_SEEN = inner;
        MOCK_CALLS += 1;
        MOCK_COUNT
    }

    /// Restores the default stub on drop, even when a test panics.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INNER_MATERIALIZE_COUNT)
                    .write_volatile(materialize_count_stub)
            };
        }
    }

    #[test]
    fn forwards_the_inner_pointer_and_returns_the_count() {
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        fixture.link();
        let inner_base = fixture.inner.as_mut_ptr();
        unsafe {
            MOCK_SEEN = core::ptr::null_mut();
            MOCK_CALLS = 0;
            core::ptr::addr_of_mut!(INNER_MATERIALIZE_COUNT)
                .write_volatile(recording_materialize);

            let count = inner_result_count(fixture.outer.as_mut_ptr());

            assert_eq!(count, MOCK_COUNT);
            assert_eq!(MOCK_CALLS, 1, "exactly one tail call");
            assert_eq!(MOCK_SEEN, inner_base, "the +0x40 slot value is forwarded");
        }
    }

    #[test]
    fn default_stub_reads_the_cached_count_word() {
        let _lock = SLOT_TEST_LOCK.lock();
        let mut fixture = Fixture::new();
        fixture.link();
        // Preload the count the materializer would have cached.
        fixture.inner[RESULT_COUNT..RESULT_COUNT + 4]
            .copy_from_slice(&0x2au32.to_le_bytes());
        let inner_before = fixture.inner;

        let count = unsafe { inner_result_count(fixture.outer.as_mut_ptr()) };

        assert_eq!(count, 0x2a);
        // The no-op path reads only: every inner byte is untouched.
        assert_eq!(fixture.inner, inner_before);
        // And the outer object (including the +0x40 slot) is untouched.
        let mut outer_expect = [SENTINEL; OUTER_LEN];
        let ptr = fixture.inner.as_mut_ptr();
        unsafe {
            (outer_expect.as_mut_ptr().add(INNER) as *mut *mut u8).write(ptr);
        }
        assert_eq!(fixture.outer, outer_expect);
    }

    #[test]
    fn default_stub_returns_a_zero_count_for_a_fresh_object() {
        let _lock = SLOT_TEST_LOCK.lock();
        let mut fixture = Fixture::new();
        fixture.link();
        fixture.inner = [0; INNER_LEN];
        let count = unsafe { inner_result_count(fixture.outer.as_mut_ptr()) };
        assert_eq!(count, 0);
    }
}
