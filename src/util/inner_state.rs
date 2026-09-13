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

/// Byte offset of the transient option inside the inner object.
const TRANSIENT_OPTION: usize = 0xe3c;

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

/// Byte offset of a tag-4 allocation released by
/// [`inner_release_buffer_and_reset_cursor`].
const BUFFER_ALLOCATION: usize = 0xe90;

/// Byte offsets delimiting the 16-byte cursor reset by
/// [`inner_release_buffer_and_reset_cursor`].
const BUFFER_CURSOR_BEGIN: usize = 0xebc;
const BUFFER_CURSOR_END: usize = 0xec0;

/// Byte offset of the sentinel index reset with the buffer cursor.
const BUFFER_INDEX: usize = 0x1c;

/// Byte offset of the u16 selection reset with the buffer cursor.
const BUFFER_SELECTION: usize = 0x82c;


/// Byte offsets of the transient resource pointers reset by
/// [`inner_reset_transient_state`].
const TRANSIENT_PRIMARY: usize = 0xe7c;
const TRANSIENT_SECONDARY: usize = 0xe80;
const TRANSIENT_TERTIARY: usize = 0xe84;
const TRANSIENT_MARKER: usize = 0xe88;
const TRANSIENT_RECORD_BEGIN: usize = 0xeb0;
const TRANSIENT_RECORD_END: usize = 0xeb4;
const TRANSIENT_SELECTION: usize = 0x62c;
const TRANSIENT_STATUS: usize = 0xe8c;
const TRANSIENT_ACTIVE: usize = 0xef9;


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


/// inner_set_transient_option — original: `FUN_08067c9c` @ `0x08067c9c`
/// (8 bytes: `strb r1,[r0,#0xe3c]; bx lr`).
///
/// Raw decoding of every ARM immediate B/BL word in `osos.dec` finds seven
/// direct callers, all unconditional `bl` at `0x0813c048`, `0x0813c6dc`,
/// `0x0813c71c`, `0x0813d994`, `0x0813debc`, `0x0817a290`, and
/// `0x0817a2bc`; two additional unconditional tail branches enter at
/// `0x081113d4` and `0x0813d48c`. There are no predicated call forms.
///
/// Stores the supplied byte at `inner + 0xe3c`. Query setup callers clear
/// the byte, while `FUN_0817a238` saves and restores it around a query
/// operation; its exact enum is not recovered. Deliberate deviation: none.
///
/// # Safety
///
/// `inner` must address writable storage at `+0xe3c`; as in stock, there is
/// no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_set_transient_option(inner: *mut u8, option: u8) {
    inner.add(TRANSIENT_OPTION).write(option);
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

/// inner_release_buffer_and_reset_cursor — original: `FUN_080be134` @
/// `0x080be134` (144 instruction bytes, followed by the literal
/// `0x0000082c` at `0x080be1c4`; the next separately entered function starts
/// at `0x080be1c8`).
///
/// Raw decoding of every ARM immediate B/BL word in `osos.dec` finds exactly
/// 10 direct callers, all plain unconditional `bl`: `0x08066428`,
/// `0x080664b4`, `0x080664e8`, `0x08066564`, `0x080665fc`, `0x08066780`,
/// `0x08066a18`, `0x08066b50`, `0x08068ec8`, and `0x0809dc0c`.
///
/// Releases a nonzero tag-4 allocation at `inner + 0xe90`, clears that word,
/// rewinds the 16-byte cursor at `+0xebc/+0xec0`, stores -1 at `+0x1c`, and
/// clears the u16 selection at `+0x82c`. Under the target invariant that
/// differing begin/end cursor addresses are 16-byte aligned, it leaves
/// `+0xebc` alone and sets `+0xec0` to it.
///
/// Ghidra presents a 16-byte record copy, but raw ARM has `r0 = r9 = end`
/// before its predicated `ldmne`/`stmne`, making that copy loop unreachable.
/// Deliberate deviation: Rust omits both that dead copy and the subsequent
/// side-effect-free 16-byte walker, directly applying its wrapping rewind.
/// Thus malformed cursor endpoints with mismatched low four bits return
/// rather than reproducing the stock walker's nontermination. Valid target
/// behavior is unchanged. The existing [`crate::heap::veneers::free_tag4`]
/// callee preserves the tag-4 dispatch.
///
/// # Safety
///
/// `inner` must address writable, suitably aligned storage through `+0xec3`;
/// a nonzero allocation word must be valid for `free_tag4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_release_buffer_and_reset_cursor(inner: *mut u8) {
    let allocation = (inner.add(BUFFER_ALLOCATION) as *const u32).read();
    if allocation != 0 {
        crate::heap::veneers::free_tag4(allocation as usize as *mut u8);
        (inner.add(BUFFER_ALLOCATION) as *mut u32).write(0);
    }

    let begin = (inner.add(BUFFER_CURSOR_BEGIN) as *const u32).read();
    let end = (inner.add(BUFFER_CURSOR_END) as *const u32).read();
    if begin != end {
        let rewound = end.wrapping_sub(end.wrapping_sub(begin) & !0xf);
        (inner.add(BUFFER_CURSOR_END) as *mut u32).write(rewound);
    }

    (inner.add(BUFFER_INDEX) as *mut u32).write(u32::MAX);
    (inner.add(BUFFER_SELECTION) as *mut u16).write(0);
}

/// inner_reset_transient_state — original: `FUN_08059644` @ `0x08059644`
/// (184 bytes: 180 instruction bytes plus the literal at `0x080596fc`; the
/// next function starts at `0x08059700`).
///
/// Raw decoding of every ARM immediate B/BL word in `osos.dec` finds 11
/// direct callers, all plain `bl` (no predicated call forms): `0x08054020`,
/// `0x080664ac`, `0x080664d8`, `0x0806655c`, `0x080665f4`, `0x080667a8`,
/// `0x080668d4`, `0x08066a40`, `0x08066b70`, `0x08068ec0`, and
/// `0x0813d020`.
///
/// Releases and clears three tag-4 transient allocations, clears their
/// marker, then erases the logical contents of the 24-byte-record vector at
/// `+0xeb0`. It stores -1 at `+0x18`, clears the u16 selection at `+0x62c`,
/// and clears the `+0xe8c` and `+0xef9` status bytes. The raw vector path
/// invokes `0x083e9b68` with an empty source range (`end..end`), receives
/// `begin`, then walks that result to `end` without an element action. Its
/// resulting end value is `end - ((end - begin) / 24) * 24`, using the
/// existing signed ADS divide port.
///
/// Deliberate deviation: the empty copy and no-op iterator walk are expressed
/// as their resulting arithmetic, rather than adding a seam for the
/// unported helper at `0x083e9b68`; the observed memory effects are identical.
/// The existing direct `free_tag4` callee preserves the three release calls.
///
/// # Safety
///
/// `inner` must address writable, suitably aligned inner-object storage
/// through byte `+0xef9`. Its nonzero transient words must be valid tag-4
/// allocations. The vector bounds must be target 32-bit addresses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inner_reset_transient_state(inner: *mut u8) {
    let primary = (inner.add(TRANSIENT_PRIMARY) as *const u32).read();
    if primary != 0 {
        crate::heap::veneers::free_tag4(primary as usize as *mut u8);
        (inner.add(TRANSIENT_PRIMARY) as *mut u32).write(0);
    }

    let tertiary = (inner.add(TRANSIENT_TERTIARY) as *const u32).read();
    if tertiary != 0 {
        crate::heap::veneers::free_tag4(tertiary as usize as *mut u8);
        (inner.add(TRANSIENT_TERTIARY) as *mut u32).write(0);
    }

    let secondary = (inner.add(TRANSIENT_SECONDARY) as *const u32).read();
    if secondary != 0 {
        crate::heap::veneers::free_tag4(secondary as usize as *mut u8);
        (inner.add(TRANSIENT_SECONDARY) as *mut u32).write(0);
    }

    (inner.add(TRANSIENT_MARKER) as *mut u32).write(0);

    let begin = (inner.add(TRANSIENT_RECORD_BEGIN) as *const u32).read();
    let end = (inner.add(TRANSIENT_RECORD_END) as *const u32).read();
    if begin != end {
        let element_count = crate::runtime::rt_div::__rt_sdiv(
            end.wrapping_sub(begin) as i32,
            24,
        ) as u32;
        (inner.add(TRANSIENT_RECORD_END) as *mut u32)
            .write(end.wrapping_sub(element_count.wrapping_mul(24)));
    }

    (inner.add(0x18) as *mut u32).write(u32::MAX);
    (inner.add(TRANSIENT_SELECTION) as *mut u16).write(0);
    inner.add(TRANSIENT_STATUS).write(0);
    inner.add(TRANSIENT_ACTIVE).write(0);
}
/// Object word holding the selected resource pointer.
const SELECTED_RESOURCE: usize = 4;
/// Object word holding the selected resource's table index.
const SELECTED_RESOURCE_INDEX: usize = 8;
/// Backend word pointing at the selected-resource table.
const RESOURCE_TABLE: usize = 0xf64;
/// Backend word containing the selected-resource table length.
const RESOURCE_COUNT: usize = 0xf68;
/// Stock error returned for a negative or out-of-range resource index.
const RESOURCE_INDEX_OUT_OF_RANGE: i32 = -50;

type ActivateResource = unsafe extern "C" fn(resource: *mut u8, mode: u32);
type ObjectCleanup = unsafe extern "C" fn(object: *mut u8);

#[derive(Clone, Copy)]
struct ObjectSelectionOps {
    activate_resource: ActivateResource,
    call_080be1c8: ObjectCleanup,
    call_08059870: ObjectCleanup,
    call_08059700: ObjectCleanup,
    call_08059820: ObjectCleanup,
    call_08059a04: ObjectCleanup,
    call_0805997c: ObjectCleanup,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_activate_resource(resource: *mut u8, mode: u32) {
    let activate: unsafe extern "C" fn(*mut u8, u32) -> i32 =
        core::mem::transmute(0x0806_cf80usize);
    let _ = activate(resource, mode);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_080be1c8(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x080b_e1c8usize);
    call(object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_08059870(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x0805_9870usize);
    call(object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_08059700(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x0805_9700usize);
    call(object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_08059820(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x0805_9820usize);
    call(object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_08059a04(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x0805_9a04usize);
    call(object);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_call_0805997c(object: *mut u8) {
    let call: ObjectCleanup = core::mem::transmute(0x0805_997cusize);
    call(object);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_activate_resource(_resource: *mut u8, _mode: u32) {
    panic!("object_select_resource_index requires activation 0x0806cf80")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_cleanup(_object: *mut u8) {
    panic!("object_select_resource_index requires an unported object cleanup")
}

#[cfg(target_os = "none")]
const DEFAULT_OBJECT_SELECTION_OPS: ObjectSelectionOps = ObjectSelectionOps {
    activate_resource: firmware_activate_resource,
    call_080be1c8: firmware_call_080be1c8,
    call_08059870: firmware_call_08059870,
    call_08059700: firmware_call_08059700,
    call_08059820: firmware_call_08059820,
    call_08059a04: firmware_call_08059a04,
    call_0805997c: firmware_call_0805997c,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_OBJECT_SELECTION_OPS: ObjectSelectionOps = ObjectSelectionOps {
    activate_resource: missing_activate_resource,
    call_080be1c8: missing_object_cleanup,
    call_08059870: missing_object_cleanup,
    call_08059700: missing_object_cleanup,
    call_08059820: missing_object_cleanup,
    call_08059a04: missing_object_cleanup,
    call_0805997c: missing_object_cleanup,
};

/// Unported operations which flank the already-ported inner-state resets.
/// Target defaults preserve every original direct call; host tests replace
/// the operations to make the complete reset sequence observable.
static mut OBJECT_SELECTION_OPS: ObjectSelectionOps = DEFAULT_OBJECT_SELECTION_OPS;

/// object_select_resource_index — original: `FUN_0806673c` @ `0x0806673c`
/// (152 bytes; next independent function starts at `0x080667d4`).
///
/// Raw decoding of every ARM B/BL word in `osos.dec` finds eight direct
/// callers, all unconditional `bl` (`0x08111674`, `0x081118ec`,
/// `0x0813c054`, `0x0813c6e8`, `0x0813c728`, `0x0813ccd8`,
/// `0x0813d4a0`, `0x0813e524`), plus one unconditional tail `b` at
/// `0x0813bd18`; no predicated call enters this function.
///
/// Resolves the object's kind-1 backend or kind-2 proxy, rejects a negative
/// index or one outside the backend's `+0xf68` resource-table count with
/// -50, then stores that table entry and its index at object `+0x04/+0x08`.
/// It activates the selected resource with mode zero and resets all
/// selection-dependent object state in the stock call order, returning zero
/// even when the final callback-dispatch reset reports a status.
///
/// Deliberate deviation: seven unported callees remain volatile operation
/// slots on host and direct firmware calls on target. Their identities are
/// not inferred from their addresses; the four already ported cleanup calls
/// remain direct Rust calls. This preserves the ARM call boundaries and lets
/// host tests observe the full sequence.
///
/// # Safety
///
/// `object` must satisfy [`crate::ui::object_state::object_backend_for_kind`]
/// and be writable through all invoked cleanup fields. Its resolved backend
/// must contain aligned u32 words at `+0xf64/+0xf68`; a valid index requires
/// a readable table entry.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_select_resource_index(object: *mut u8, index: i32) -> i32 {
    let backend = crate::ui::object_state::object_backend_for_kind(object);
    if index < 0 || (index as u32) >= (backend.add(RESOURCE_COUNT) as *const u32).read() {
        return RESOURCE_INDEX_OUT_OF_RANGE;
    }

    let resource_table = (backend.add(RESOURCE_TABLE) as *const u32).read() as usize as *const u32;
    let resource = resource_table.add(index as usize).read();
    (object.add(SELECTED_RESOURCE) as *mut u32).write(resource);
    (object.add(SELECTED_RESOURCE_INDEX) as *mut u32).write(index as u32);

    let ops = core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_SELECTION_OPS));
    (ops.activate_resource)(resource as usize as *mut u8, 0);
    inner_release_buffer_and_reset_cursor(object);
    (ops.call_080be1c8)(object);
    (ops.call_08059870)(object);
    (ops.call_08059700)(object);
    (ops.call_08059820)(object);
    inner_reset_transient_state(object);
    (ops.call_08059a04)(object);
    (ops.call_0805997c)(object);
    inner_clear_cached_results(object);
    let _ = inner_dispatch_selected_resource(object);
    0
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
type DispatchSelectedResource = unsafe extern "C" fn(
    callback_root: *mut u8,
    callback: usize,
    context: *mut u8,
) -> i32;

#[derive(Clone, Copy)]
struct InnerSelectedResourceOps {
    resolve: ResolveSelectedResource,
    is_selected: IsResourceSelected,
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
    dispatch: firmware_dispatch_selected_resource,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_INNER_SELECTED_RESOURCE_OPS: InnerSelectedResourceOps = InnerSelectedResourceOps {
    resolve: missing_resolve_selected_resource,
    is_selected: missing_is_resource_selected,
    dispatch: missing_dispatch_selected_resource,
};

/// The two unported inner-resource helpers used by
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
/// The two unported helpers at 0x08051ce4 and 0x08054710 remain direct
/// firmware calls on target. The selection setter 0x08067450 is ported as
/// [`crate::ui::object_state::set_resource_selected`]. The callback literal
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

    crate::ui::object_state::set_resource_selected(0, inner, object);
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

    // ---- inner_set_transient_option ----------------------------------

    #[test]
    fn transient_option_setter_round_trips_full_byte_range() {
        let mut fixture = Fixture::new();
        let inner_base = fixture.inner.as_mut_ptr();
        for option in 0..=u8::MAX {
            unsafe { inner_set_transient_option(inner_base, option) };
            assert_eq!(fixture.inner[TRANSIENT_OPTION], option);
        }
    }

    #[test]
    fn transient_option_setter_touches_only_its_byte() {
        let mut fixture = Fixture::new();
        let inner_before = fixture.inner;
        let inner_base = fixture.inner.as_mut_ptr();

        unsafe { inner_set_transient_option(inner_base, 0x7e) };

        for offset in 0..INNER_LEN {
            let expect = if offset == TRANSIENT_OPTION {
                0x7e
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

    // ---- inner_release_buffer_and_reset_cursor --------------------------

    const BUFFER_RESET_LEN: usize = BUFFER_CURSOR_END + 4;

    #[repr(align(4))]
    struct BufferResetFixture {
        bytes: [u8; BUFFER_RESET_LEN],
    }

    impl BufferResetFixture {
        fn new() -> Self {
            BufferResetFixture { bytes: [SENTINEL; BUFFER_RESET_LEN] }
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn halfword(&self, offset: usize) -> u16 {
            u16::from_le_bytes(self.bytes[offset..offset + 2].try_into().unwrap())
        }

        fn set_halfword(&mut self, offset: usize, value: u16) {
            self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }

        fn reset(&mut self) {
            unsafe { inner_release_buffer_and_reset_cursor(self.bytes.as_mut_ptr()) };
        }
    }

    #[test]
    fn buffer_reset_releases_allocation_rewinds_aligned_cursor_and_resets_fields() {
        let _heap_guard = mock_heap();
        let mut fixture = BufferResetFixture::new();
        fixture.set_word(BUFFER_ALLOCATION, 0x1111_2222);
        fixture.set_word(BUFFER_CURSOR_BEGIN, 0x1000);
        fixture.set_word(BUFFER_CURSOR_END, 0x1030);
        fixture.set_word(BUFFER_INDEX, 7);
        fixture.set_halfword(BUFFER_SELECTION, u16::MAX);
        let mut expected = fixture.bytes;
        expected[BUFFER_ALLOCATION..BUFFER_ALLOCATION + 4].copy_from_slice(&0u32.to_le_bytes());
        expected[BUFFER_CURSOR_END..BUFFER_CURSOR_END + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        expected[BUFFER_INDEX..BUFFER_INDEX + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        expected[BUFFER_SELECTION..BUFFER_SELECTION + 2].copy_from_slice(&0u16.to_le_bytes());

        fixture.reset();

        assert_eq!(free_log(), (1, 0x1111_2222usize as *mut u8, 4));
        assert_eq!(fixture.word(BUFFER_CURSOR_BEGIN), 0x1000);
        assert_eq!(fixture.bytes, expected);
    }

    #[test]
    fn buffer_reset_skips_null_release_and_preserves_an_empty_cursor() {
        let _heap_guard = mock_heap();
        let mut fixture = BufferResetFixture::new();
        fixture.set_word(BUFFER_ALLOCATION, 0);
        fixture.set_word(BUFFER_CURSOR_BEGIN, 0x2000);
        fixture.set_word(BUFFER_CURSOR_END, 0x2000);
        fixture.set_word(BUFFER_INDEX, 0);
        fixture.set_halfword(BUFFER_SELECTION, 0x1234);

        fixture.reset();

        assert_eq!(free_log().0, 0);
        assert_eq!(fixture.word(BUFFER_ALLOCATION), 0);
        assert_eq!(fixture.word(BUFFER_CURSOR_BEGIN), 0x2000);
        assert_eq!(fixture.word(BUFFER_CURSOR_END), 0x2000);
        assert_eq!(fixture.word(BUFFER_INDEX), u32::MAX);
        assert_eq!(fixture.halfword(BUFFER_SELECTION), 0);
    }

    // ---- inner_reset_transient_state ------------------------------------

    const INNER_RESET_LEN: usize = TRANSIENT_ACTIVE + 1;

    #[repr(align(4))]
    struct ResetFixture {
        bytes: [u8; INNER_RESET_LEN],
    }

    impl ResetFixture {
        fn new() -> Self {
            ResetFixture { bytes: [SENTINEL; INNER_RESET_LEN] }
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn halfword(&self, offset: usize) -> u16 {
            u16::from_le_bytes(self.bytes[offset..offset + 2].try_into().unwrap())
        }

        fn set_halfword(&mut self, offset: usize, value: u16) {
            self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }

        fn reset(&mut self) {
            unsafe { inner_reset_transient_state(self.bytes.as_mut_ptr()) };
        }
    }

    #[test]
    fn transient_reset_releases_all_three_allocations_and_only_resets_its_fields() {
        let _heap_guard = mock_heap();
        let mut fixture = ResetFixture::new();
        fixture.set_word(TRANSIENT_PRIMARY, 0x1111_2222);
        fixture.set_word(TRANSIENT_TERTIARY, 0x3333_4444);
        fixture.set_word(TRANSIENT_SECONDARY, 0x5555_6666);
        fixture.set_word(TRANSIENT_MARKER, 0x7777_8888);
        fixture.set_word(TRANSIENT_RECORD_BEGIN, 0x1000);
        fixture.set_word(TRANSIENT_RECORD_END, 0x1048);
        fixture.set_word(0x18, 7);
        fixture.set_halfword(TRANSIENT_SELECTION, 0x1234);
        fixture.bytes[TRANSIENT_STATUS] = 0x56;
        fixture.bytes[TRANSIENT_ACTIVE] = 0x78;
        let mut expected = fixture.bytes;
        for offset in [TRANSIENT_PRIMARY, TRANSIENT_TERTIARY, TRANSIENT_SECONDARY, TRANSIENT_MARKER] {
            expected[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        expected[TRANSIENT_RECORD_END..TRANSIENT_RECORD_END + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        expected[0x18..0x1c].copy_from_slice(&u32::MAX.to_le_bytes());
        expected[TRANSIENT_SELECTION..TRANSIENT_SELECTION + 2].copy_from_slice(&0u16.to_le_bytes());
        expected[TRANSIENT_STATUS] = 0;
        expected[TRANSIENT_ACTIVE] = 0;

        fixture.reset();

        assert_eq!(free_log(), (3, 0x5555_6666usize as *mut u8, 4));
        assert_eq!(fixture.word(TRANSIENT_RECORD_BEGIN), 0x1000);
        assert_eq!(fixture.bytes, expected);
    }

    #[test]
    fn transient_reset_skips_null_allocations_and_preserves_an_empty_vector_end() {
        let _heap_guard = mock_heap();
        let mut fixture = ResetFixture::new();
        fixture.set_word(TRANSIENT_PRIMARY, 0);
        fixture.set_word(TRANSIENT_TERTIARY, 0);
        fixture.set_word(TRANSIENT_SECONDARY, 0);
        fixture.set_word(TRANSIENT_RECORD_BEGIN, 0x2000);
        fixture.set_word(TRANSIENT_RECORD_END, 0x2000);
        fixture.set_halfword(TRANSIENT_SELECTION, u16::MAX);

        fixture.reset();

        assert_eq!(free_log().0, 0);
        assert_eq!(fixture.word(TRANSIENT_RECORD_END), 0x2000);
        assert_eq!(fixture.word(0x18), u32::MAX);
        assert_eq!(fixture.halfword(TRANSIENT_SELECTION), 0);
        assert_eq!(fixture.bytes[TRANSIENT_STATUS], 0);
        assert_eq!(fixture.bytes[TRANSIENT_ACTIVE], 0);
    }

    #[test]
    fn transient_reset_uses_signed_division_to_rewind_a_partial_record_span() {
        let _heap_guard = mock_heap();
        let mut fixture = ResetFixture::new();
        fixture.set_word(TRANSIENT_PRIMARY, 0);
        fixture.set_word(TRANSIENT_TERTIARY, 0);
        fixture.set_word(TRANSIENT_SECONDARY, 0);
        fixture.set_word(TRANSIENT_RECORD_BEGIN, 0x1000);
        fixture.set_word(TRANSIENT_RECORD_END, 0x1019);

        fixture.reset();

        assert_eq!(free_log().0, 0);
        assert_eq!(fixture.word(TRANSIENT_RECORD_END), 0x1001);
    }

    // ---- inner_dispatch_selected_resource -----------------------------

    static SELECTED_RESOURCE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SELECTED_RESOURCE_INNER: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_IS_SELECTED: u32 = 0;
    static mut SELECTED_RESOURCE_STATUS: i32 = 0;
    static mut SELECTED_RESOURCE_RESOLVE_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_SELECT_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_DISPATCH_CALLS: u32 = 0;
    static mut SELECTED_RESOURCE_RESOLVE_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SELECT_INNER: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_SELECT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_DISPATCH_ROOT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_DISPATCH_CALLBACK: usize = 0;
    static mut SELECTED_RESOURCE_DISPATCH_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut SELECTED_RESOURCE_RESOLVE_STAGE: u32 = 0;
    static mut SELECTED_RESOURCE_SELECT_STAGE: u32 = 0;
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
            SELECTED_RESOURCE_DISPATCH_CALLS = 0;
            SELECTED_RESOURCE_RESOLVE_OBJECT = core::ptr::null_mut();
            SELECTED_RESOURCE_SELECT_INNER = core::ptr::null_mut();
            SELECTED_RESOURCE_SELECT_OBJECT = core::ptr::null_mut();
            SELECTED_RESOURCE_DISPATCH_ROOT = core::ptr::null_mut();
            SELECTED_RESOURCE_DISPATCH_CALLBACK = 0;
            SELECTED_RESOURCE_DISPATCH_CONTEXT = core::ptr::null_mut();
            SELECTED_RESOURCE_RESOLVE_STAGE = 0;
            SELECTED_RESOURCE_SELECT_STAGE = 0;
            SELECTED_RESOURCE_DISPATCH_STAGE = 0;
            SELECTED_RESOURCE_STAGE = 0;
            core::ptr::addr_of_mut!(INNER_SELECTED_RESOURCE_OPS).write_volatile(
                InnerSelectedResourceOps {
                    resolve: mock_resolve_selected_resource,
                    is_selected: mock_is_resource_selected,
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
        after_callback_root: [u8; 0x1ad - 0x40 - core::mem::size_of::<*mut u8>()],
        selection_flags: u8,
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
            after_callback_root: [SENTINEL; 0x1ad - 0x40 - core::mem::size_of::<*mut u8>()],
            selection_flags: SENTINEL,
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
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CALLS, 0);
        }
    }

    #[test]
    fn selected_resource_clears_then_dispatches_and_propagates_status() {
        let _lock = SELECTED_RESOURCE_TEST_LOCK.lock();
        let _restore = install_selected_resource_mocks();
        let mut object = [SENTINEL; 2];
        object[1] = 2;
        let mut callback_root = [0; 1];
        let mut inner = SelectedResourceInnerFixture {
            before_callback_root: [SENTINEL; 0x40],
            callback_root: callback_root.as_mut_ptr(),
            after_callback_root: [SENTINEL; 0x1ad - 0x40 - core::mem::size_of::<*mut u8>()],
            selection_flags: 0xff,
        };
        unsafe {
            SELECTED_RESOURCE_INNER = (&mut inner as *mut SelectedResourceInnerFixture).cast();
            SELECTED_RESOURCE_IS_SELECTED = 1;
            SELECTED_RESOURCE_STATUS = -0x32;
        }

        let result = unsafe { inner_dispatch_selected_resource(object.as_mut_ptr()) };

        assert_eq!(result, -0x32);
        unsafe {
            assert_eq!(inner.selection_flags, 0xfb, "the port clears object+1's bit");
            assert_eq!(SELECTED_RESOURCE_DISPATCH_ROOT, callback_root.as_mut_ptr());
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CALLBACK, SELECTED_RESOURCE_CALLBACK);
            assert_eq!(SELECTED_RESOURCE_DISPATCH_CONTEXT, object.as_mut_ptr());
            assert_eq!(
                (
                    SELECTED_RESOURCE_RESOLVE_STAGE,
                    SELECTED_RESOURCE_SELECT_STAGE,
                    SELECTED_RESOURCE_DISPATCH_STAGE,
                ),
                (1, 2, 3),
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
    // ---- object_select_resource_index -----------------------------------

    static OBJECT_SELECTION_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBJECT_SELECTION_CALL_COUNT: usize = 0;
    static mut OBJECT_SELECTION_STAGES: [u8; 7] = [0; 7];
    static mut OBJECT_SELECTION_OBJECTS: [usize; 7] = [0; 7];
    static mut OBJECT_SELECTION_RESOURCE: *mut u8 = core::ptr::null_mut();
    static mut OBJECT_SELECTION_MODE: u32 = u32::MAX;

    unsafe fn record_object_selection_call(stage: u8, object: *mut u8) {
        OBJECT_SELECTION_STAGES[OBJECT_SELECTION_CALL_COUNT] = stage;
        OBJECT_SELECTION_OBJECTS[OBJECT_SELECTION_CALL_COUNT] = object as usize;
        OBJECT_SELECTION_CALL_COUNT += 1;
    }

    unsafe extern "C" fn mock_activate_selected_resource(resource: *mut u8, mode: u32) {
        OBJECT_SELECTION_RESOURCE = resource;
        OBJECT_SELECTION_MODE = mode;
        record_object_selection_call(1, resource);
    }

    unsafe extern "C" fn mock_call_080be1c8(object: *mut u8) {
        record_object_selection_call(2, object);
    }

    unsafe extern "C" fn mock_call_08059870(object: *mut u8) {
        record_object_selection_call(3, object);
    }

    unsafe extern "C" fn mock_call_08059700(object: *mut u8) {
        record_object_selection_call(4, object);
    }

    unsafe extern "C" fn mock_call_08059820(object: *mut u8) {
        record_object_selection_call(5, object);
    }

    unsafe extern "C" fn mock_call_08059a04(object: *mut u8) {
        record_object_selection_call(6, object);
    }

    unsafe extern "C" fn mock_call_0805997c(object: *mut u8) {
        record_object_selection_call(7, object);
    }

    struct ObjectSelectionOpsRestore;

    impl Drop for ObjectSelectionOpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OBJECT_SELECTION_OPS)
                    .write_volatile(DEFAULT_OBJECT_SELECTION_OPS);
            }
        }
    }

    fn install_object_selection_mocks() -> ObjectSelectionOpsRestore {
        unsafe {
            OBJECT_SELECTION_CALL_COUNT = 0;
            OBJECT_SELECTION_STAGES = [0; 7];
            OBJECT_SELECTION_OBJECTS = [0; 7];
            OBJECT_SELECTION_RESOURCE = core::ptr::null_mut();
            OBJECT_SELECTION_MODE = u32::MAX;
            core::ptr::addr_of_mut!(OBJECT_SELECTION_OPS).write_volatile(
                ObjectSelectionOps {
                    activate_resource: mock_activate_selected_resource,
                    call_080be1c8: mock_call_080be1c8,
                    call_08059870: mock_call_08059870,
                    call_08059700: mock_call_08059700,
                    call_08059820: mock_call_08059820,
                    call_08059a04: mock_call_08059a04,
                    call_0805997c: mock_call_0805997c,
                },
            );
        }
        ObjectSelectionOpsRestore
    }

    #[test]
    fn selected_resource_index_rejects_negative_and_past_end_without_writes() {
        let mut object = [SENTINEL; RESOURCE_COUNT + 4];
        object[0] = 1; // kind-1 backend
        object[RESOURCE_COUNT..RESOURCE_COUNT + 4].copy_from_slice(&3u32.to_le_bytes());
        let before = object;

        assert_eq!(
            unsafe { object_select_resource_index(object.as_mut_ptr(), -1) },
            RESOURCE_INDEX_OUT_OF_RANGE
        );
        assert_eq!(
            unsafe { object_select_resource_index(object.as_mut_ptr(), 3) },
            RESOURCE_INDEX_OUT_OF_RANGE
        );
        assert_eq!(object, before, "both bounds checks precede every store and call");
    }

    #[test]
    fn selected_resource_index_stores_entry_and_resets_in_stock_order() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let _selection_guard = OBJECT_SELECTION_TEST_LOCK.lock();
        let _dispatch_guard = SELECTED_RESOURCE_TEST_LOCK.lock();
        let _selection_restore = install_object_selection_mocks();
        let _dispatch_restore = install_selected_resource_mocks();
        let Some(object) = try_map_u32_slab(hints::OBJECT_SELECT_RESOURCE_INDEX, 0x2000) else {
            assert!(note_missing_u32_fixture("util/inner_state::object_select_resource_index"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(object, 0, 0x2000);
            object.write(1); // kind-1 backend
            let table = object.add(0x1000).cast::<u32>();
            table.write(0x1122_3344);
            table.add(1).write(0x5566_7788);
            table.add(2).write(0x89ab_cdef);
            object.add(RESOURCE_TABLE).cast::<u32>().write(table as usize as u32);
            object.add(RESOURCE_COUNT).cast::<u32>().write(3);

            object.add(BUFFER_CURSOR_BEGIN).cast::<u32>().write(0x1000);
            object.add(BUFFER_CURSOR_END).cast::<u32>().write(0x1040);
            object.add(BUFFER_INDEX).cast::<u32>().write(7);
            object.add(BUFFER_SELECTION).cast::<u16>().write(u16::MAX);
            object.add(TRANSIENT_MARKER).cast::<u32>().write(0xaabb_ccdd);
            object.add(TRANSIENT_SELECTION).cast::<u16>().write(0x1234);
            object.add(TRANSIENT_STATUS).write(0x56);
            object.add(TRANSIENT_ACTIVE).write(0x78);
            object.add(CACHED_AUXILIARY).cast::<u32>().write(0xfeed_cafe);
            object.add(RESULT_COUNT).cast::<u32>().write(9);

            assert_eq!(object_select_resource_index(object, 2), 0);

            assert_eq!(object.add(SELECTED_RESOURCE).cast::<u32>().read(), 0x89ab_cdef);
            assert_eq!(object.add(SELECTED_RESOURCE_INDEX).cast::<u32>().read(), 2);
            assert_eq!(OBJECT_SELECTION_RESOURCE, 0x89ab_cdefusize as *mut u8);
            assert_eq!(OBJECT_SELECTION_MODE, 0);
            assert_eq!(OBJECT_SELECTION_CALL_COUNT, 7);
            assert_eq!(OBJECT_SELECTION_STAGES, [1, 2, 3, 4, 5, 6, 7]);
            assert_eq!(OBJECT_SELECTION_OBJECTS[1..], [object as usize; 6]);
            assert_eq!(object.add(BUFFER_CURSOR_END).cast::<u32>().read(), 0x1000);
            assert_eq!(object.add(BUFFER_INDEX).cast::<u32>().read(), u32::MAX);
            assert_eq!(object.add(BUFFER_SELECTION).cast::<u16>().read(), 0);
            assert_eq!(object.add(TRANSIENT_MARKER).cast::<u32>().read(), 0);
            assert_eq!(object.add(TRANSIENT_SELECTION).cast::<u16>().read(), 0);
            assert_eq!(object.add(TRANSIENT_STATUS).read(), 0);
            assert_eq!(object.add(TRANSIENT_ACTIVE).read(), 0);
            assert_eq!(object.add(CACHED_AUXILIARY).cast::<u32>().read(), 0xfeed_cafe);
            assert_eq!(object.add(RESULT_COUNT).cast::<u32>().read(), 0);
            assert_eq!(SELECTED_RESOURCE_RESOLVE_CALLS, 1);
            assert_eq!(SELECTED_RESOURCE_SELECT_CALLS, 0);
        }
    }
}
