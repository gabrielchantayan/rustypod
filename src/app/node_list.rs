//! The view-list singleton and its walker.
//!
//! Ports:
//! - [`node_list_drain`] — original: `FUN_0810fb48` @ 0x0810fb48
//!   (640 bytes) — removes list nodes while driving their virtual lifecycle.
//! - [`node_list_construct`] — original: `FUN_0811000c` @ 0x0811000c
//!   (52 bytes) — constructs the view-list singleton in place.
//! - [`node_list_get`] — original: `FUN_0810fa30` @ 0x0810fa30 (72
//!   bytes; 168 `bl` call sites, binary-verified) — the singleton's
//!   accessor, a textbook ADS function-local-static initializer.
//! - [`list_count_until_match`] — original: `FUN_0810fa90` @ 0x0810fa90
//!   (84 bytes; 125 `bl` call sites, binary-scanned).
//! - [`list_count_unflagged_before_key`] — original: `FUN_0810faf4` @
//!   0x0810faf4 (84 bytes) — counts unflagged nodes before a nonzero key.
//!
//! `list_count_until_match` walks the singly-linked node list hanging
//! off a list object and returns how many nodes it visited. When the
//! object carries a nonzero *stop key* the walk ends at (and counts)
//! the first node whose vtable slot +0x68 returns that key, so the
//! result is the node's 1-based position; with a zero stop key nothing
//! can match and the result is the full node count.
//!
//! The list object is a C++ singleton — its accessor `FUN_0810fa30` is
//! a function-local-static initializer (guard word @ 0x089cc834, ADS
//! guard helpers @ 0x082ab31c / 0x082ab338) that returns the fixed
//! object @ 0x08a79c74, and the getter @ 0x0810fa88 hands out its head
//! pointer. Its sibling [`node_list_drain`] removes heads until its
//! stop condition, preserving the final node as the new head.
//!
//! ```text
//! list +0x00  vtable (+0x00 = drain-complete callback)
//! list +0x04  head node
//! list +0x08  stop key          0 = no key stop
//! list +0x0c  draining flag
//! list +0x10  embedded drain state (+0x3c enumerate, +0xbc finish)
//! list +0x20  completion context
//! list +0x24  completion flag byte
//! list +0x28  final callback
//! list +0x2c  final callback argument
//! node +0x00  vtable
//! node +0x14  next node
//! node +0x20  continue-draining flag
//! node +0x21  evict-on-transition flag
//! ```
//!
//! Fields are typed struct members, never literal byte offsets: the
//! 32-bit target layout is exact (asserted in `layout_checks`) while a
//! 64-bit host keeps the fields disjoint.

/// Callback slot +0x04 of a node vtable.
pub type NodeRelease = unsafe extern "C" fn(this: *mut Node);
/// Callback slot +0x54 of a node vtable.
pub type NodeSetActive = unsafe extern "C" fn(this: *mut Node, active: u32);
/// Callback slots that take only their node.
pub type NodeAction = unsafe extern "C" fn(this: *mut Node);
/// Callback slots that return a node property.
pub type NodeProperty = unsafe extern "C" fn(this: *mut Node) -> u32;

/// The node's vtable slots dispatched by the count and drain operations.
#[repr(C)]
pub struct NodeVtable {
    /// +0x00: RTTI / base slot, not called here.
    pub unresolved_00: usize,
    /// +0x04: drops the node after it has been unlinked.
    pub release: NodeRelease,
    /// +0x08..+0x50: not dispatched here.
    pub unresolved_08_50: [usize; 19],
    /// +0x54: transitions a node's active state.
    pub set_active: NodeSetActive,
    /// +0x58: evicts a transition-marked node.
    pub evict: NodeAction,
    /// +0x5c..+0x64: not dispatched here.
    pub unresolved_5c_64: [usize; 3],
    /// +0x68: node key, compared against the list's stop key.
    pub key: NodeProperty,
    /// +0x6c: reports whether +0x78 work is needed.
    pub requires_capture: NodeProperty,
    /// +0x70: not dispatched here.
    pub unresolved_70: usize,
    /// +0x74: reports whether +0x80 preparation is needed.
    pub requires_prepare: NodeProperty,
    /// +0x78: captures the node before it is activated.
    pub capture: NodeAction,
    /// +0x7c: not dispatched here.
    pub unresolved_7c: usize,
    /// +0x80: prepares a node before its active state is toggled.
    pub prepare: NodeProperty,
    /// +0x84..+0x94: not dispatched here.
    pub unresolved_84_94: [usize; 5],
    /// +0x98: successor mode used to derive the next transition mode.
    pub mode: NodeProperty,
}

/// A list node, modeled down to the fields used by the walker and drain.
#[repr(C)]
pub struct Node {
    /// +0x00: the node's vtable.
    pub vtable: *const NodeVtable,
    /// +0x04..+0x13: not read by these operations.
    pub opaque: [u32; 4],
    /// +0x14: next node.
    pub next: *mut Node,
    /// +0x18..+0x1f: not read by this operation.
    pub opaque_after_next: [u8; 8],
    /// +0x20: whether this node remains the drain's terminal head.
    pub continues_drain: u8,
    /// +0x21: selects eviction rather than active-state transitions.
    pub evict_when_transitioning: u8,
}

/// Slot +0x00 in the list vtable, invoked once a drain stops.
pub type NodeListComplete =
    unsafe extern "C" fn(this: *mut NodeList, context: *mut c_void, flag: u8);
/// Slot +0x90 dispatches one list advance iteration.
pub type NodeListAdvance =
    unsafe extern "C" fn(this: *mut NodeList, is_subsequent: u32, zero: u32, target: i32);
/// Slot +0x94 measures the current position against an advance target.
pub type NodeListMeasure = unsafe extern "C" fn(this: *mut NodeList, target: i32) -> i32;
/// Callback stored at list +0x28.
pub type NodeListFinalCallback = unsafe extern "C" fn(argument: *mut c_void);

/// The list-vtable slots dispatched by drain and advance operations.
#[repr(C)]
pub struct NodeListVtable {
    /// +0x00: completes a node-list drain.
    pub complete_drain: NodeListComplete,
    /// +0x04..+0x8c: not dispatched here.
    pub unresolved_04_8c: [usize; 35],
    /// +0x90: advances the list toward a target.
    pub advance: NodeListAdvance,
    /// +0x94: measures position relative to a target.
    pub measure: NodeListMeasure,
}

/// The embedded list +0x10 state.
#[repr(C)]
pub struct DrainState {
    /// +0x00: the state vtable.
    pub vtable: *const DrainStateVtable,
    /// +0x04: state consumed (negated) by its finish callback.
    pub state: i32,
    /// +0x08..+0x0c: not read here.
    pub opaque: [u32; 2],
}

/// Slot +0x3c enumerates a retained node; +0xbc closes the state.
pub type DrainStateEnumerate =
    unsafe extern "C" fn(this: *mut DrainState, index: i32, node_out: *mut *mut Node) -> u32;
pub type DrainStateFinish = unsafe extern "C" fn(this: *mut DrainState, state: i32);

#[repr(C)]
pub struct DrainStateVtable {
    pub unresolved_00_38: [usize; 15],
    pub enumerate: DrainStateEnumerate,
    pub unresolved_40_b8: [usize; 31],
    pub finish: DrainStateFinish,
}

/// The list object (the singleton @ 0x08a79c74 on device).
#[repr(C)]
pub struct NodeList {
    /// +0x00: completion vtable.
    pub vtable: *const NodeListVtable,
    /// +0x04: first node.
    pub head: *mut Node,
    /// +0x08: stop key; 0 means no key stop.
    pub stop_key: u32,
    /// +0x0c: set for the duration of a drain.
    pub is_draining: u8,
    /// +0x0d..+0x0f: target-layout padding.
    pub padding: [u8; 3],
    /// +0x10: tracks retained nodes while draining.
    pub drain_state: DrainState,
    /// +0x20: non-null enables the vtable completion callback.
    pub completion_context: *mut c_void,
    /// +0x24: passed to the vtable completion callback.
    pub completion_flag: u8,
    /// +0x25..+0x27: target-layout padding.
    pub completion_padding: [u8; 3],
    /// +0x28: optional final callback, retained after invocation.
    pub final_callback: Option<NodeListFinalCallback>,
    /// +0x2c: argument to [`NodeList::final_callback`].
    pub final_callback_argument: *mut c_void,
}

// Target-exact layout.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x04] = [0; core::mem::offset_of!(NodeVtable, release)];
    const _: [u8; 0x54] = [0; core::mem::offset_of!(NodeVtable, set_active)];
    const _: [u8; 0x58] = [0; core::mem::offset_of!(NodeVtable, evict)];
    const _: [u8; 0x68] = [0; core::mem::offset_of!(NodeVtable, key)];
    const _: [u8; 0x98] = [0; core::mem::offset_of!(NodeVtable, mode)];
    const _: [u8; 0x14] = [0; core::mem::offset_of!(Node, next)];
    const _: [u8; 0x20] = [0; core::mem::offset_of!(Node, continues_drain)];
    const _: [u8; 0x21] = [0; core::mem::offset_of!(Node, evict_when_transitioning)];
    const _: [u8; 0x3c] = [0; core::mem::offset_of!(DrainStateVtable, enumerate)];
    const _: [u8; 0xbc] = [0; core::mem::offset_of!(DrainStateVtable, finish)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(NodeList, head)];
    const _: [u8; 0x08] = [0; core::mem::offset_of!(NodeList, stop_key)];
    const _: [u8; 0x0c] = [0; core::mem::offset_of!(NodeList, is_draining)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(NodeList, drain_state)];
    const _: [u8; 0x20] = [0; core::mem::offset_of!(NodeList, completion_context)];
    const _: [u8; 0x28] = [0; core::mem::offset_of!(NodeList, final_callback)];
    const _: [u8; 0x90] = [0; core::mem::offset_of!(NodeListVtable, advance)];
    const _: [u8; 0x94] = [0; core::mem::offset_of!(NodeListVtable, measure)];
    const _: [u8; NODE_LIST_SIZE] = [0; core::mem::size_of::<NodeList>()];
}

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Byte size of the singleton object on target (original: the .bss
/// object @ 0x08a79c74). [`node_list_construct`] writes all fields
/// except the untouched word at +0x24: the [`NodeList`] header
/// (+0x00..+0x0b), the draining flag byte (+0x0c), an embedded
/// sub-object (+0x10), and the drain-callback words (+0x20, +0x28,
/// +0x2c) used by the drain @ 0x0810fb48.
pub const NODE_LIST_SIZE: usize = 0x30;

/// `__dso_handle` — the same literal @ 0x089ca09c every ADS
/// static-initialization site passes to `cxa_atexit` (here: pool word @
/// 0x0810fa80). See runtime/shutdown_chain.rs.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The singleton's target-layout storage (original: fixed .bss object
/// @ 0x08a79c74). A byte block keeps its device offsets exact even when
/// host pointers are wider than target pointers.
#[repr(C, align(4))]
struct NodeListStorage {
    bytes: [u8; NODE_LIST_SIZE],
}

/// The singleton object, zero-initialized as in the firmware image.
static mut NODE_LIST: NodeListStorage = NodeListStorage { bytes: [0; NODE_LIST_SIZE] };


/// The one-time-initialization guard word (original: the .bss word @
/// 0x089cc834, reached through pool word @ 0x0810fa78).
static mut NODE_LIST_GUARD: u32 = 0;

/// node_list_construct — original: `FUN_0811000c` @ 0x0811000c (52
/// bytes).
///
/// Reference: `ipod-decomp/decomp/c/010/0811000c_FUN_0811000c.c`;
/// the embedded +0x10 sub-object's effects come from
/// `decomp/c/026/08271cec_FUN_08271cec.c` and
/// `decomp/c/026/08275bb8_FUN_08275bb8.c`.
///
/// Installs the list vtable at +0x00, clears its head and stop key,
/// constructs the embedded drain-callback sub-object at +0x10, clears
/// its flag and callback words, and returns `this`. The stock sequence
/// deliberately does not write the word at +0x24, so this port does not
/// turn the constructor into a whole-object zeroing operation.
const NODE_LIST_VTABLE: u32 = 0x0898_165c;
const NODE_LIST_DRAIN_VTABLE: u32 = 0x089a_5d0c;

#[inline(always)]
unsafe fn node_list_store_word(this: *mut u8, offset: usize, value: u32) {
    this.add(offset).cast::<u32>().write_volatile(value);
}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_construct(this: *mut u8) -> *mut u8 {
    // `*param_1 = DAT_08110040; param_1[2] = 0`.
    node_list_store_word(this, 0x00, NODE_LIST_VTABLE);
    node_list_store_word(this, 0x08, 0);

    // `FUN_08271cec(param_1 + 4)`, including its
    // `FUN_08275bb8` base-constructor call.
    node_list_store_word(this, 0x10, NODE_LIST_DRAIN_VTABLE);
    node_list_store_word(this, 0x14, 0);
    node_list_store_word(this, 0x18, 0);
    node_list_store_word(this, 0x1c, 0);

    // The caller's stores relative to the returned +0x10 sub-object.
    node_list_store_word(this, 0x28, 0);
    node_list_store_word(this, 0x2c, 0);
    node_list_store_word(this, 0x04, 0);
    this.add(0x0c).write_volatile(0);
    node_list_store_word(this, 0x20, 0);
    this
}

/// The destructor registered with `cxa_atexit` — original: the shared
/// `mov r0, #1; ldmia sp!, {r4, pc}` stub @ 0x0810516c (pool word @
/// 0x0810fa84; binary-verified). That stub is a shared epilogue for
/// functions that return 1 after pushing {r4, lr} — run as a shutdown
/// handler it would pop a frame it never pushed, so the registration
/// could never actually fire; retailOS never runs `exit`'s chain
/// anyway (runtime/shutdown_chain.rs: the sole runner caller is
/// `exit_stdio_cleanup`). A no-op matches every observable path.
unsafe extern "C" fn node_list_destructor(_object: *mut c_void) {}

/// node_list_get — original: `FUN_0810fa30` @ 0x0810fa30 (72 bytes;
/// 168 `bl` call sites, binary-verified).
///
/// The process-wide view-list singleton's accessor — a textbook ADS
/// function-local static over a fixed .bss object, NOT the
/// `operator_new` cache pattern of the singletons.rs getters:
///
/// ```text
/// ldr r0, =0x089cc834      ; pool @ 0x0810fa78: the guard word
/// ldr r0, [r0]; tst r0, #1
/// bne done                 ; inlined fast path: bit 0 = initialized
/// bl  cxa_guard_acquire    ; 0x082ab31c (ported)
/// cmp r0, #0; beq done
/// ldr r0, =0x08a79c74      ; pool @ 0x0810fa7c: the object
/// bl  0x0811000c           ; the constructor, returns `this` in r0
/// ldr r2, =0x089ca09c      ; pool @ 0x0810fa80: __dso_handle
/// ldr r1, =0x0810516c      ; pool @ 0x0810fa84: the "destructor"
/// bl  cxa_atexit           ; 0x082ab1c8 (ported)
/// bl  cxa_guard_release    ; 0x082ab338 (ported)
/// done:
/// ldr r0, =0x08a79c74      ; reloaded — NOT the ctor's return
/// ```
///
/// The guard pair, `cxa_atexit`, and [`node_list_construct`] are
/// ported and called directly.
///
/// Faithful details:
/// - The return value is always the fixed object's address, reloaded
///   after the init block (the original's second
///   `ldr r0, [0x810fa7c]`) — never the constructor's return. The
///   constructor returns that same in-place address, which is registered
///   with `cxa_atexit`.
/// - The inlined fast path tests bit 0 only (`tst r0, #1`) while
///   [`cxa_guard_acquire`] tests the whole word, so a nonzero guard
///   with bit 0 clear (never produced by this pair) takes the slow
///   path and is still turned away. Reproduced.
/// - A refused acquire (a re-entrant initializer) skips construction
///   and still hands out the object half-built — the guard is spent
///   either way. Inherited from the ported guard pair.
///
/// Deviations:
/// - The guard word and the object are crate statics rather than the
///   .bss words @ 0x089cc834 / 0x08a79c74 (the block_mgr.rs deviation:
///   the 0x089cxxxx RW pages are runtime-initialized and the image's
///   contents there are stale). Both zero-init, the exact pre-init
///   state.
/// - The registered destructor is a module-local no-op; see
///   [`node_list_destructor`] for why that is faithful.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_get() -> *mut NodeList {
    let guard = core::ptr::addr_of_mut!(NODE_LIST_GUARD);
    let object = core::ptr::addr_of_mut!(NODE_LIST) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 {
        if cxa_guard_acquire(guard) != 0 {
            let this = node_list_construct(object);
            cxa_atexit(this as *mut c_void, node_list_destructor, DSO_HANDLE);
            cxa_guard_release(guard);
        }
    }
    object as *mut NodeList
}

/// list_count_until_match — original: `FUN_0810fa90` @ 0x0810fa90
/// (84 bytes).
///
/// Returns the 1-based position of the node matching the list's stop
/// key, or the total node count when the key is 0 or unmatched.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_count_until_match(list: *mut NodeList) -> u32 {
    let mut node = (*list).head;
    let mut count: u32 = 0;

    while !node.is_null() {
        count = count.wrapping_add(1);
        if (*list).stop_key != 0 {
            let key = ((*(*node).vtable).key)(node);
            // Re-read: the original reloads list + 8 after the call.
            if key == (*list).stop_key {
                break;
            }
        }
        node = (*node).next;
    }
    count
}

/// list_count_unflagged_before_key — original: `FUN_0810faf4` @
/// 0x0810faf4 (84 bytes).
///
/// Reference: `ipod-decomp/decomp/c/010/0810faf4_FUN_0810faf4.c`.
///
/// Walks from the list head, dispatching every node's vtable +0x68 key
/// accessor before inspecting its +0x20 flag. A nonzero returned key equal
/// to `stop_key` ends the walk without counting that node; key 0 never
/// matches. Each prior node whose flag is clear contributes one to the
/// wrapping count, then the walker follows its +0x14 next link.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_count_unflagged_before_key(
    list: *mut NodeList,
    stop_key: u32,
) -> u32 {
    let mut node = (*list).head;
    let mut unflagged_count = 0_u32;

    while !node.is_null() {
        let node_key = ((*(*node).vtable).key)(node);
        if node_key != 0 && node_key == stop_key {
            break;
        }
        if (*node).continues_drain == 0 {
            unflagged_count = unflagged_count.wrapping_add(1);
        }
        node = (*node).next;
    }
    unflagged_count
}
/// node_list_advance_until — original: `FUN_0810fdc8` @ 0x0810fdc8
/// (164 bytes).
///
/// Reference: `ipod-decomp/decomp/c/010/0810fdc8_FUN_0810fdc8.c`.
///
/// Advances the list toward `target`. With a nonzero `threshold`, it
/// repeatedly measures through the list vtable's +0x94 slot, subtracts
/// the threshold with ARM's wrapping `i32` arithmetic, and advances
/// through +0x90 while that signed difference is positive. With a zero
/// threshold, it instead walks from the current head, stopping at null or
/// at the first node whose +0x68 vtable key equals `target`; every
/// nonmatching head is advanced through +0x90.
/// The advance callback receives a zero iteration flag first, then one on
/// every subsequent iteration; its middle argument is always zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_advance_until(
    list: *mut NodeList,
    target: i32,
    threshold: i32,
) {
    let mut is_subsequent = 0_u32;

    if threshold != 0 {
        while ((*(*list).vtable).measure)(list, target).wrapping_sub(threshold) > 0 {
            ((*(*list).vtable).advance)(list, is_subsequent, 0, target);
            is_subsequent = 1;
        }
        return;
    }

    loop {
        let head = (*list).head;
        if head.is_null() || ((*(*head).vtable).key)(head) == target as u32 {
            return;
        }
        ((*(*list).vtable).advance)(list, is_subsequent, 0, target);
        is_subsequent = 1;
    }
}


/// node_list_drain — original: `FUN_0810fb48` @ 0x0810fb48 (640 bytes).
///
/// Reference: `ipod-decomp/decomp/c/010/0810fb48_FUN_0810fb48.c`.
///
/// Drains heads from the view list until it reaches an empty list, a node
/// that asks to remain, or a node whose key equals the list's stop key.
/// Each removed head is either evicted or put through an inactive/active
/// transition, then released through its own vtable. The successor's mode
/// derives the next transition choice; it is prepared, its retained nodes
/// are released through the embedded drain state, and that state is
/// finished before the next iteration. On exit the draining flag is cleared
/// and the list-vtable completion callback and final callback run in order.
///
/// The stock code requires a non-null successor after every removal and
/// enters its non-returning assertion path otherwise; this port uses
/// `assert!` for that invariant.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_drain(
    list: *mut NodeList,
    mut transition_mode: u32,
    successor_mode: u32,
    successor_key: u32,
) {
    let mut keep_draining = true;
    (*list).is_draining = 1;

    loop {
        let head = (*list).head;
        if head.is_null()
            || !keep_draining
            || ((*list).stop_key != 0 && ((*(*head).vtable).key)(head) == (*list).stop_key)
        {
            (*list).is_draining = 0;
            if !(*list).completion_context.is_null() {
                ((*(*list).vtable).complete_drain)(
                    list,
                    (*list).completion_context,
                    (*list).completion_flag,
                );
                (*list).completion_context = core::ptr::null_mut();
                (*list).completion_flag = 0;
            }
            if let Some(callback) = (*list).final_callback {
                callback((*list).final_callback_argument);
            }
            return;
        }

        // Every virtual dispatch below reloads `list->head`, just as the
        // source repeatedly loads `param_1[1]`; callbacks may mutate it.
        let current = (*list).head;
        let requires_prepare = ((*(*current).vtable).requires_prepare)(current) != 0;
        if requires_prepare
            && !(transition_mode != 0 && (*(*list).head).evict_when_transitioning != 0)
        {
            let current = (*list).head;
            ((*(*current).vtable).prepare)(current);
        }
        if transition_mode != 0 && (*(*list).head).evict_when_transitioning != 0 {
            let current = (*list).head;
            ((*(*current).vtable).evict)(current);
        } else {
            let current = (*list).head;
            ((*(*current).vtable).set_active)(current, 0);
            let current = (*list).head;
            ((*(*current).vtable).set_active)(current, 1);
        }

        let removed = (*list).head;
        (*list).head = (*removed).next;
        ((*(*removed).vtable).release)(removed);

        // `FUN_08030f44()` is a non-returning invariant failure if a
        // removal left no successor.
        let successor = (*list).head;
        assert!(!successor.is_null(), "node_list_drain requires a successor");

        transition_mode = if successor_mode == 0 {
            if successor_key != 0 && ((*(*successor).vtable).key)(successor) != successor_key {
                1
            } else {
                0
            }
        } else if ((*(*successor).vtable).mode)(successor) == successor_mode {
            0
        } else {
            1
        };

        if transition_mode != 0 && (*(*list).head).evict_when_transitioning != 0 {
            let current = (*list).head;
            ((*(*current).vtable).evict)(current);
        } else {
            let current = (*list).head;
            ((*(*current).vtable).set_active)(current, 0);
            let current = (*list).head;
            if ((*(*current).vtable).requires_capture)(current) != 0 {
                let current = (*list).head;
                ((*(*current).vtable).capture)(current);
            }
            let current = (*list).head;
            ((*(*current).vtable).set_active)(current, 1);
        }

        let drain_state = &mut (*list).drain_state;
        let mut index = -2_i32;
        loop {
            index = if index == -2 { 0 } else { index.wrapping_add(1) };
            let mut retained = core::ptr::null_mut();
            if ((*(*drain_state).vtable).enumerate)(drain_state, index, &mut retained) == 0 {
                break;
            }
            if !retained.is_null() {
                ((*(*retained).vtable).release)(retained);
            }
        }
        ((*(*drain_state).vtable).finish)(drain_state, (*drain_state).state.wrapping_neg());

        // This is deliberately reloaded after the state callbacks.
        keep_draining = (*(*list).head).continues_drain != 0;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// A node whose key accessor returns a stored value and records the
    /// call.
    #[repr(C)]
    struct TestNode {
        vtable: *const NodeVtable,
        opaque: [u32; 4],
        next: *mut Node,
        opaque_after_next: [u8; 8],
        continues_drain: u8,
        evict_when_transitioning: u8,
        key: u32,
        /// Shared visit log (raw pointer so the node stays `repr(C)`
        /// compatible past the fields the port reads).
        visits: *mut Vec<u32>,
    }

    unsafe extern "C" fn test_key(this: *mut Node) -> u32 {
        let node = this as *mut TestNode;
        (*(*node).visits).push((*node).key);
        (*node).key
    }

    unsafe extern "C" fn ignore_release(_this: *mut Node) {}
    unsafe extern "C" fn ignore_set_active(_this: *mut Node, _active: u32) {}
    unsafe extern "C" fn ignore_action(_this: *mut Node) {}
    unsafe extern "C" fn ignore_property(_this: *mut Node) -> u32 {
        0
    }
    unsafe extern "C" fn ignore_list_advance(
        _this: *mut NodeList,
        _is_subsequent: u32,
        _zero: u32,
        _target: i32,
    ) {
    }

    unsafe extern "C" fn ignore_list_measure(_this: *mut NodeList, _target: i32) -> i32 {
        0
    }

    const fn count_vtable(key: NodeProperty) -> NodeVtable {
        NodeVtable {
            unresolved_00: 0,
            release: ignore_release,
            unresolved_08_50: [0; 19],
            set_active: ignore_set_active,
            evict: ignore_action,
            unresolved_5c_64: [0; 3],
            key,
            requires_capture: ignore_property,
            unresolved_70: 0,
            requires_prepare: ignore_property,
            capture: ignore_action,
            unresolved_7c: 0,
            prepare: ignore_property,
            unresolved_84_94: [0; 5],
            mode: ignore_property,
        }
    }

    static TEST_VTABLE: NodeVtable = count_vtable(test_key);
    unsafe extern "C" fn key_that_sets_continues_drain(this: *mut Node) -> u32 {
        let node = this as *mut TestNode;
        (*(*node).visits).push((*node).key);
        (*node).continues_drain = 1;
        (*node).key
    }

    static FLAG_MUTATING_VTABLE: NodeVtable = count_vtable(key_that_sets_continues_drain);
    fn node(key: u32, visits: *mut Vec<u32>) -> TestNode {
        TestNode {
            vtable: &TEST_VTABLE,
            opaque: [0; 4],
            next: ptr::null_mut(),
            opaque_after_next: [0; 8],
            continues_drain: 0,
            evict_when_transitioning: 0,
            key,
            visits,
        }
    }

    /// Links the nodes head-to-tail and returns the head.
    fn chain(nodes: &mut [TestNode]) -> *mut Node {
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &mut nodes[i + 1] as *mut TestNode as *mut Node;
        }
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    fn list(head: *mut Node, stop_key: u32) -> NodeList {
        NodeList {
            vtable: ptr::null(),
            head,
            stop_key,
            is_draining: 0,
            padding: [0; 3],
            drain_state: DrainState {
                vtable: ptr::null(),
                state: 0,
                opaque: [0; 2],
            },
            completion_context: ptr::null_mut(),
            completion_flag: 0,
            completion_padding: [0; 3],
            final_callback: None,
            final_callback_argument: ptr::null_mut(),
        }
    }

    #[test]
    fn an_empty_list_counts_zero_and_dispatches_nothing() {
        let mut visits: Vec<u32> = Vec::new();
        let mut list = list(ptr::null_mut(), 7);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 0);
        assert!(visits.is_empty(), "no node, no dispatch");
        let _ = &mut visits;
    }

    #[test]
    fn a_zero_stop_key_counts_every_node_without_dispatching() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert!(visits.is_empty(), "a zero key short-circuits before the vtable call");
    }

    #[test]
    fn the_matching_node_is_counted_and_the_walk_stops_there() {
        let mut visits = Vec::new();
        let mut nodes =
            [node(10, &mut visits), node(20, &mut visits), node(30, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 20);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 2, "1-based position");
        assert_eq!(visits, std::vec![10, 20], "the third node is never asked");
    }

    #[test]
    fn the_head_matching_returns_one() {
        let mut visits = Vec::new();
        let mut nodes = [node(5, &mut visits), node(6, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 5);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 1);
        assert_eq!(visits, std::vec![5]);
    }

    #[test]
    fn an_unmatched_key_falls_through_to_the_full_count() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 99);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert_eq!(visits, std::vec![1, 2, 3], "every node is asked");
    }

    #[test]
    fn a_single_node_list_counts_one_either_way() {
        let mut visits = Vec::new();
        let mut nodes = [node(4, &mut visits)];
        let head = chain_single(&mut nodes);
        let mut with_key = list(head, 4);
        assert_eq!(unsafe { list_count_until_match(&mut with_key) }, 1);
        let mut without = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut without) }, 1);
    }

    /// `chain` needs at least two nodes; this is the one-node case.
    fn chain_single(nodes: &mut [TestNode; 1]) -> *mut Node {
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    #[test]
    fn a_key_accessor_that_clears_the_stop_key_ends_the_matching() {
        // The original reloads list + 8 after the call, so a callee
        // that rewrites the key is honored on the very same iteration.
        static mut LIST_UNDER_TEST: *mut NodeList = ptr::null_mut();

        unsafe extern "C" fn clearing_key(this: *mut Node) -> u32 {
            let node = this as *mut TestNode;
            (*(*node).visits).push((*node).key);
            (*(*core::ptr::addr_of!(LIST_UNDER_TEST))).stop_key = 0;
            (*node).key
        }
        static CLEARING_VTABLE: NodeVtable = count_vtable(clearing_key);

        let mut visits = Vec::new();
        let mut nodes = [node(8, &mut visits), node(9, &mut visits)];
        nodes[0].vtable = &CLEARING_VTABLE;
        nodes[1].vtable = &CLEARING_VTABLE;
        let head = chain(&mut nodes);
        let mut list = list(head, 8);
        unsafe {
            LIST_UNDER_TEST = &mut list;
            // The first node's key is 8 and would have matched, but the
            // accessor zeroed the stop key first, so the reload sees 0.
            assert_eq!(list_count_until_match(&mut list), 2);
        }
        assert_eq!(visits, std::vec![8], "the second node skips the call: key is now 0");
    }

    #[test]
    fn count_unflagged_before_key_handles_a_null_head() {
        let mut list = list(ptr::null_mut(), 0);
        assert_eq!(
            unsafe { list_count_unflagged_before_key(&mut list, 7) },
            0,
            "a null head enters neither dispatch nor count"
        );
    }

    #[test]
    fn count_unflagged_before_key_stops_at_a_matching_node_without_counting_it() {
        let mut visits = Vec::new();
        let mut nodes = [node(10, &mut visits), node(20, &mut visits), node(30, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 0);

        assert_eq!(unsafe { list_count_unflagged_before_key(&mut list, 20) }, 1);
        assert_eq!(visits, std::vec![10, 20], "the matching key is dispatched but not counted");
    }

    #[test]
    fn count_unflagged_before_key_visits_every_node_when_the_key_misses() {
        let mut visits = Vec::new();
        let mut nodes = [node(0, &mut visits), node(4, &mut visits), node(7, &mut visits)];
        nodes[1].continues_drain = 1;
        let head = chain(&mut nodes);
        let mut list = list(head, 0);

        assert_eq!(unsafe { list_count_unflagged_before_key(&mut list, 99) }, 2);
        assert_eq!(visits, std::vec![0, 4, 7], "a zero node key never matches");
    }

    #[test]
    fn count_unflagged_before_key_reads_the_flag_after_key_dispatch_then_follows_next() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits)];
        nodes[0].vtable = &FLAG_MUTATING_VTABLE;
        let head = chain(&mut nodes);
        let mut list = list(head, 0);

        assert_eq!(unsafe { list_count_unflagged_before_key(&mut list, 99) }, 1);
        assert_eq!(
            visits,
            std::vec![1, 2],
            "the callback marks node one before its flag is counted, then the +0x14 link advances"
        );
    }
    #[derive(Debug, PartialEq, Eq)]
    enum AdvanceEvent {
        Measure(i32),
        Advance { is_subsequent: u32, zero: u32, target: i32 },
    }

    #[repr(C)]
    struct AdvanceTestList {
        list: NodeList,
        measurements: *mut Vec<i32>,
        events: *mut Vec<AdvanceEvent>,
    }

    unsafe extern "C" fn advance_measure(this: *mut NodeList, target: i32) -> i32 {
        let fixture = this as *mut AdvanceTestList;
        (*(*fixture).events).push(AdvanceEvent::Measure(target));
        (*(*fixture).measurements).remove(0)
    }

    unsafe extern "C" fn advance_head(
        this: *mut NodeList,
        is_subsequent: u32,
        zero: u32,
        target: i32,
    ) {
        let fixture = this as *mut AdvanceTestList;
        (*(*fixture).events).push(AdvanceEvent::Advance {
            is_subsequent,
            zero,
            target,
        });
        let head = (*this).head;
        if !head.is_null() {
            (*this).head = (*head).next;
        }
    }

    static ADVANCE_LIST_VTABLE: NodeListVtable = NodeListVtable {
        complete_drain: ignore_complete_drain,
        unresolved_04_8c: [0; 35],
        advance: advance_head,
        measure: advance_measure,
    };

    unsafe extern "C" fn ignore_complete_drain(
        _this: *mut NodeList,
        _context: *mut c_void,
        _flag: u8,
    ) {
    }

    fn advance_list(
        head: *mut Node,
        measurements: *mut Vec<i32>,
        events: *mut Vec<AdvanceEvent>,
    ) -> AdvanceTestList {
        AdvanceTestList {
            list: NodeList {
                vtable: &ADVANCE_LIST_VTABLE,
                head,
                stop_key: 0,
                is_draining: 0,
                padding: [0; 3],
                drain_state: DrainState {
                    vtable: ptr::null(),
                    state: 0,
                    opaque: [0; 2],
                },
                completion_context: ptr::null_mut(),
                completion_flag: 0,
                completion_padding: [0; 3],
                final_callback: None,
                final_callback_argument: ptr::null_mut(),
            },
            measurements,
            events,
        }
    }

    #[test]
    fn advance_until_threshold_mode_dispatches_list_slots_with_signed_comparison() {
        let mut measurements = std::vec![-1, -2, -3];
        let mut events = Vec::new();
        let mut fixture = advance_list(ptr::null_mut(), &mut measurements, &mut events);

        unsafe { node_list_advance_until(&mut fixture.list, 41, -3) };

        assert_eq!(
            events,
            std::vec![
                AdvanceEvent::Measure(41),
                AdvanceEvent::Advance {
                    is_subsequent: 0,
                    zero: 0,
                    target: 41,
                },
                AdvanceEvent::Measure(41),
                AdvanceEvent::Advance {
                    is_subsequent: 1,
                    zero: 0,
                    target: 41,
                },
                AdvanceEvent::Measure(41),
            ],
            "signed -1/-2 are greater than -3; equality terminates without an advance"
        );
        assert!(measurements.is_empty(), "the terminating measurement is dispatched");
    }
    #[test]
    fn advance_until_threshold_mode_keeps_the_arm_subtraction_wraparound() {
        let mut measurements = std::vec![i32::MAX];
        let mut events = Vec::new();
        let mut fixture = advance_list(ptr::null_mut(), &mut measurements, &mut events);

        unsafe { node_list_advance_until(&mut fixture.list, 9, -1) };

        assert_eq!(
            events,
            std::vec![AdvanceEvent::Measure(9)],
            "i32::MAX - -1 wraps negative, so the signed result is not greater than zero"
        );
        assert!(measurements.is_empty());
    }

    #[test]
    fn advance_until_zero_threshold_walks_heads_until_a_node_key_matches() {
        let mut visits = Vec::new();
        let mut nodes = [
            node(1, &mut visits),
            node(u32::MAX, &mut visits),
            node(3, &mut visits),
        ];
        let head = chain(&mut nodes);
        let mut measurements = Vec::new();
        let mut events = Vec::new();
        let mut fixture = advance_list(head, &mut measurements, &mut events);

        unsafe { node_list_advance_until(&mut fixture.list, -1, 0) };

        assert_eq!(visits, std::vec![1, u32::MAX], "the matching head terminates the walk");
        assert_eq!(
            events,
            std::vec![AdvanceEvent::Advance {
                is_subsequent: 0,
                zero: 0,
                target: -1,
            }],
            "only the first nonmatching head is advanced"
        );
        assert_eq!(
            fixture.list.head,
            &mut nodes[1] as *mut TestNode as *mut Node,
            "the action owns traversal; the port rechecks the current head"
        );
        assert!(measurements.is_empty(), "zero threshold never calls the +0x94 measurement slot");
    }

    #[test]
    fn advance_until_zero_threshold_terminates_on_an_empty_list() {
        let mut measurements = Vec::new();
        let mut events = Vec::new();
        let mut fixture = advance_list(ptr::null_mut(), &mut measurements, &mut events);

        unsafe { node_list_advance_until(&mut fixture.list, 7, 0) };

        assert!(events.is_empty());
        assert!(measurements.is_empty());
    }



    #[derive(Debug, PartialEq, Eq)]
    enum DrainEvent {
        Prepare(u32),
        SetActive(u32, u32),
        Evict(u32),
        Release(u32),
        Capture(u32),
        Finish(i32),
        Complete(u8),
        Final,
    }

    static DRAIN_EVENTS: Mutex<Vec<DrainEvent>> = Mutex::new(Vec::new());
    static DRAIN_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RETAINED_NODE: *mut Node = ptr::null_mut();

    fn record_drain(event: DrainEvent) {
        DRAIN_EVENTS.lock().unwrap().push(event);
    }

    fn take_drain_events() -> Vec<DrainEvent> {
        core::mem::take(&mut *DRAIN_EVENTS.lock().unwrap())
    }

    #[repr(C)]
    struct DrainTestNode {
        node: Node,
        id: u32,
        key: u32,
        mode: u32,
        requires_capture: u32,
        requires_prepare: u32,
    }

    unsafe fn drain_test_node(this: *mut Node) -> *mut DrainTestNode {
        this.cast()
    }

    unsafe extern "C" fn drain_release(this: *mut Node) {
        record_drain(DrainEvent::Release((*drain_test_node(this)).id));
    }

    unsafe extern "C" fn drain_set_active(this: *mut Node, active: u32) {
        record_drain(DrainEvent::SetActive((*drain_test_node(this)).id, active));
    }

    unsafe extern "C" fn drain_evict(this: *mut Node) {
        record_drain(DrainEvent::Evict((*drain_test_node(this)).id));
    }

    unsafe extern "C" fn drain_key(this: *mut Node) -> u32 {
        (*drain_test_node(this)).key
    }

    unsafe extern "C" fn drain_requires_capture(this: *mut Node) -> u32 {
        (*drain_test_node(this)).requires_capture
    }

    unsafe extern "C" fn drain_requires_prepare(this: *mut Node) -> u32 {
        (*drain_test_node(this)).requires_prepare
    }

    unsafe extern "C" fn drain_capture(this: *mut Node) {
        record_drain(DrainEvent::Capture((*drain_test_node(this)).id));
    }

    unsafe extern "C" fn drain_prepare(this: *mut Node) -> u32 {
        record_drain(DrainEvent::Prepare((*drain_test_node(this)).id));
        0
    }

    unsafe extern "C" fn drain_mode(this: *mut Node) -> u32 {
        (*drain_test_node(this)).mode
    }

    static DRAIN_NODE_VTABLE: NodeVtable = NodeVtable {
        unresolved_00: 0,
        release: drain_release,
        unresolved_08_50: [0; 19],
        set_active: drain_set_active,
        evict: drain_evict,
        unresolved_5c_64: [0; 3],
        key: drain_key,
        requires_capture: drain_requires_capture,
        unresolved_70: 0,
        requires_prepare: drain_requires_prepare,
        capture: drain_capture,
        unresolved_7c: 0,
        prepare: drain_prepare,
        unresolved_84_94: [0; 5],
        mode: drain_mode,
    };

    unsafe extern "C" fn enumerate_retained(
        _this: *mut DrainState,
        index: i32,
        node_out: *mut *mut Node,
    ) -> u32 {
        if index == 0 {
            node_out.write(RETAINED_NODE);
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn finish_drain_state(_this: *mut DrainState, state: i32) {
        record_drain(DrainEvent::Finish(state));
    }

    static DRAIN_STATE_VTABLE: DrainStateVtable = DrainStateVtable {
        unresolved_00_38: [0; 15],
        enumerate: enumerate_retained,
        unresolved_40_b8: [0; 31],
        finish: finish_drain_state,
    };

    unsafe extern "C" fn complete_drain(
        _this: *mut NodeList,
        _context: *mut c_void,
        flag: u8,
    ) {
        record_drain(DrainEvent::Complete(flag));
    }

    static DRAIN_LIST_VTABLE: NodeListVtable = NodeListVtable {
        complete_drain,
        unresolved_04_8c: [0; 35],
        advance: ignore_list_advance,
        measure: ignore_list_measure,
    };

    unsafe extern "C" fn final_drain_callback(_argument: *mut c_void) {
        record_drain(DrainEvent::Final);
    }

    fn drain_node(
        id: u32,
        key: u32,
        continues_drain: u8,
        requires_capture: u32,
        requires_prepare: u32,
    ) -> DrainTestNode {
        DrainTestNode {
            node: Node {
                vtable: &DRAIN_NODE_VTABLE,
                opaque: [0; 4],
                next: ptr::null_mut(),
                opaque_after_next: [0; 8],
                continues_drain,
                evict_when_transitioning: 0,
            },
            id,
            key,
            mode: 0,
            requires_capture,
            requires_prepare,
        }
    }

    #[test]
    fn drain_orders_lifecycle_callbacks_releases_owned_nodes_and_keeps_terminal_head() {
        let _serial = DRAIN_TEST_LOCK.lock().unwrap();
        take_drain_events();

        let mut removed = drain_node(1, 10, 1, 0, 1);
        let mut terminal = drain_node(2, 20, 0, 1, 0);
        let mut retained = drain_node(3, 30, 0, 0, 0);
        removed.node.next = &mut terminal.node;

        let mut list = list(&mut removed.node, 0);
        list.vtable = &DRAIN_LIST_VTABLE;
        list.drain_state = DrainState {
            vtable: &DRAIN_STATE_VTABLE,
            state: 3,
            opaque: [0; 2],
        };
        list.completion_context = core::ptr::dangling_mut();
        list.completion_flag = 7;
        list.final_callback = Some(final_drain_callback);
        list.final_callback_argument = core::ptr::dangling_mut();

        unsafe {
            RETAINED_NODE = &mut retained.node;
            node_list_drain(&mut list, 0, 0, 999);
            RETAINED_NODE = ptr::null_mut();
        }

        assert!(core::ptr::eq(list.head, &mut terminal.node));
        assert_eq!(list.is_draining, 0);
        assert!(list.completion_context.is_null(), "completion context is consumed");
        assert_eq!(list.completion_flag, 0, "completion flag is consumed");
        assert_eq!(
            take_drain_events(),
            std::vec![
                DrainEvent::Prepare(1),
                DrainEvent::SetActive(1, 0),
                DrainEvent::SetActive(1, 1),
                DrainEvent::Release(1),
                DrainEvent::SetActive(2, 0),
                DrainEvent::Capture(2),
                DrainEvent::SetActive(2, 1),
                DrainEvent::Release(3),
                DrainEvent::Finish(-3),
                DrainEvent::Complete(7),
                DrainEvent::Final,
            ],
        );
    }
    #[test]
    fn drain_stops_at_the_matching_key_without_touching_that_head() {
        let _serial = DRAIN_TEST_LOCK.lock().unwrap();
        take_drain_events();

        let mut matching = drain_node(4, 0x55, 0, 0, 0);
        let mut list = list(&mut matching.node, 0x55);
        unsafe { node_list_drain(&mut list, 1, 0, 0) };

        assert!(core::ptr::eq(list.head, &mut matching.node));
        assert_eq!(list.is_draining, 0);
        assert!(take_drain_events().is_empty(), "the matching head is not transitioned or released");
    }
    // --- node_list_get: the function-local-static accessor ---


    /// Serializes the tests below: the guard word, storage, and
    /// process-wide shutdown chain are all global.
    static GETTER_LOCK: Mutex<()> = Mutex::new(());


    /// Box-backed node allocator pair for the shutdown chain (the
    /// shipped defaults are the firmware malloc/free, wrong for host
    /// memory — the shutdown_chain.rs test pattern).
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: node_list_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(ptr: *mut u8) {
        drop(Box::from_raw(ptr as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(NODE_LIST) as *mut u8
    }

    fn word_at(block: *const u8, offset: usize) -> u32 {
        unsafe { ptr::read_unaligned(block.add(offset).cast::<u32>()) }
    }

    /// Installs the Box allocator pair and resets the guard, storage,
    /// and chain to their pre-init state.
    fn reset_getter() -> MutexGuard<'static, ()> {
        let guard = GETTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            NODE_LIST_GUARD = 0;
            let block = storage();
            for offset in 0..core::mem::size_of::<NodeListStorage>() {
                block.add(offset).write(0xa5);
            }
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            // Drain leftover registrations BEFORE restoring the
            // firmware allocator pair, so the nodes are freed by the
            // allocator that made them.
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            NODE_LIST_GUARD = 0;
        }
        drop(guard);
    }

    #[test]
    fn the_first_call_constructs_registers_and_caches() {
        let guard = reset_getter();
        unsafe {
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)),
                1,
                "acquire published the flag"
            );
            assert_eq!(word_at(storage(), 0x00), NODE_LIST_VTABLE);
            assert_eq!(word_at(storage(), 0x04), 0);
            assert_eq!(word_at(storage(), 0x08), 0);

            // Exactly one registration: the object, the shared-stub
            // destructor, the __dso_handle key.
            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "the ctor's return was registered");
            assert_eq!((*head).arg as *mut u8, storage());
            assert_eq!((*head).handler as usize, node_list_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
            assert!((*head).next.is_null(), "registered exactly once");

            // The second call takes the bit-0 fast path, preserving a
            // post-construction mutation rather than reconstructing.
            node_list_store_word(storage(), 0x08, 0xfeed_beef);
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x08), 0xfeed_beef, "no reconstruction");
            assert!((*(*shutdown_chain_head())).next.is_null(), "no second registration");
        }
        restore(guard);
    }

    #[test]
    fn a_guard_with_bit0_set_short_circuits_everything() {
        let guard = reset_getter();
        unsafe {
            NODE_LIST_GUARD = 3; // bit 0 set: `tst r0, #1` -> bne done
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x00), 0xa5a5_a5a5, "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)), 3, "untouched");
        }
        restore(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit0_clear_is_still_turned_away_by_acquire() {
        // The fast path tests bit 0, cxa_guard_acquire the whole word:
        // this state is never produced by the guard pair, but the
        // original's two-level test defines its behavior.
        let guard = reset_getter();
        unsafe {
            NODE_LIST_GUARD = 2;
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x00), 0xa5a5_a5a5, "acquire refused: no construction");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)), 2, "a refused acquire never writes");
        }
        restore(guard);
    }


    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = reset_getter();
        unsafe {
            node_list_get();
            node_list_store_word(storage(), 0x08, 0xa5a5_a5a5);
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!(word_at(storage(), 0x08), 0xa5a5_a5a5, "the no-op destructor touched nothing");
        }
        restore(guard);
    }

    #[test]
    fn constructor_writes_only_the_stock_fields_and_returns_this() {
        #[repr(align(4))]
        struct AlignedBlock([u8; NODE_LIST_SIZE]);

        let _guard = GETTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut block = AlignedBlock([0xa5; NODE_LIST_SIZE]);
            let this = block.0.as_mut_ptr();
            assert_eq!(node_list_construct(this), this);
            assert_eq!(word_at(this, 0x00), NODE_LIST_VTABLE);
            assert_eq!(word_at(this, 0x04), 0);
            assert_eq!(word_at(this, 0x08), 0);
            assert_eq!(block.0[0x0c], 0);
            assert_eq!(&block.0[0x0d..0x10], &[0xa5; 3], "only the flag byte is cleared");
            assert_eq!(word_at(this, 0x10), NODE_LIST_DRAIN_VTABLE);
            for offset in [0x14, 0x18, 0x1c, 0x20, 0x28, 0x2c] {
                assert_eq!(word_at(this, offset), 0, "word at +{offset:#x}");
            }
            assert_eq!(&block.0[0x24..0x28], &[0xa5; 4], "+0x24 is untouched");
        }
    }
}
