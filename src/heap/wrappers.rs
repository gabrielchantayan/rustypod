//! Heap wrappers, heap locking and the named-heap registry from the
//! retailOS app-level heap cluster (0x0819cd5c..0x0819d9d8).
//!
//! # Allocation wrappers
//!
//! Thin register-shuffling veneers over the core dispatcher
//! `FUN_0819d048` @ 0x0819d048 (ported separately in alloc_core.rs). The
//! dispatcher takes 7 arguments:
//!
//! ```text
//! core(desc, size, zerofill, tag, oldptr, copy_on_move, suppress_oom_report)
//!   r0 = desc, r1 = size, r2 = zerofill, r3 = tag (truncated to a byte by
//!   the core), stack: oldptr, copy_on_move, suppress_oom_report
//! ```
//!
//! - `heap_alloc` — original: `FUN_0819d67c` @ 0x0819d67c (36 bytes).
//!   `core(desc, size, zerofill=0, tag, oldptr=0, copy=0, oom=0)`.
//! - `heap_alloc_tag1` — original: `FUN_0819d2f0` @ 0x0819d2f0 (36 bytes,
//!   7 call sites). Identical to `heap_alloc` except the third stack slot
//!   is 1: `core(desc, size, 0, tag, 0, 0, suppress_oom_report=1)`. The
//!   constant lands in the *seventh* core parameter (the byte the core
//!   tests to skip the OOM debug-print path), not in the tag — the tag is
//!   passed through in r3 like the other veneers.
//! - `heap_alloc_zero` — original: `FUN_0819ce00` @ 0x0819ce00 (36 bytes).
//!   calloc-style: `core(desc, size, zerofill=1, tag, 0, 0, 0)`; the core
//!   zeroes the user area when `zerofill == 1`.
//! - `heap_realloc` — original: `FUN_0819d6a0` @ 0x0819d6a0 (44 bytes).
//!   `core(desc, new_size, zerofill=0, tag, oldptr, copy_on_move, 0)`.
//!   `copy_on_move` is the veneer's 5th (stack) argument; when nonzero the
//!   core copies min(old_block-8, new_size) bytes into a relocated block.
//!
//! # Heap locking
//!
//! - `heap_lock` — original: `FUN_0819d6cc` @ 0x0819d6cc (72 bytes). If
//!   `desc->mutex_state` (0xb4) is 1, tail-calls the RTXC semaphore wait
//!   veneer 0x0807f5c4 with r0 = &desc->mutex_handle (0xb8). Otherwise it
//!   checks the kernel-running flag via 0x0809444c and returns quietly when
//!   the kernel is not up yet (pre-kernel allocations stay unlocked). When
//!   the kernel is running it sets `mutex_state2` (0xb5, "creation in
//!   progress"), creates the RTXC semaphore via 0x080744a4 (which writes
//!   the handle to the slot and zeroes slot+1), clears `mutex_state2`,
//!   sets `mutex_state = 1`, and loops back to take the semaphore — the
//!   re-check handles a racing creator on another CPU/task.
//! - `heap_unlock` — original: `FUN_0819cde4` @ 0x0819cde4 (16 bytes).
//!   If `mutex_state == 1`, tail-calls the RTXC semaphore signal veneer
//!   0x0807f6a0 with r0 = &desc->mutex_handle; otherwise a plain return.
//!
//! # Named-heap registry
//!
//! A 3-slot table of 16-byte, refcounted name nodes; the table is the
//! original global @ 0x08ad7860. Node layout (the original nodes are C++
//! string objects with an appended heap pointer and refcount):
//!
//! ```text
//! +0x0  string-object vtable (0x089a6044 while alive) — kept for layout
//! +0x4  name: owned copy of the heap name (NUL-terminated)
//! +0x8  desc: heap descriptor created by the factory
//! +0xc  refcount
//! ```
//!
//! - `named_heap_lookup` — original: `FUN_0819d804` @ 0x0819d804
//!   (16 bytes). Returns `table[index]->desc`. No bounds or NULL checks in
//!   the original (callers only pass live indexes); kept faithful.
//! - `named_heap_release` — original: `FUN_0819d818` @ 0x0819d818
//!   (60 bytes). Decrements the node's refcount (helper
//!   `FUN_0819d944` @ 0x0819d944: decrement unless already 0, report
//!   "reached zero"); when it reaches zero, destroys the node (helper
//!   `FUN_0819d9b8` @ 0x0819d9b8: release the heap descriptor via
//!   0x0804c360, free the name), frees the node via the tag-2 delete
//!   veneer 0x082aad24 and clears the slot.
//! - `named_heap_add` — original: `FUN_0819d858` @ 0x0819d858 (228 bytes).
//!   Scans the table for a node whose name matches; on a hit it bumps the
//!   refcount and returns the index. Otherwise it allocates a 16-byte node
//!   (tag-2 new veneer 0x082aadd4), constructs it (helper
//!   `FUN_0819d964` @ 0x0819d964: copy the name, NULL the desc, then call
//!   the heap factory — original global fn-ptr @ 0x089d017c, invoked
//!   through 0x0804d348 as factory(name, 0, &node->desc) — and set
//!   refcount = 1 iff the factory returned status 0). Factory failure
//!   (refcount 0) destroys and frees the node and returns -1; success
//!   installs the node into the first free slot and returns it, or
//!   returns -1 when the table is full (leaking the node, as the
//!   original does).
//!
//! # Hook dispatch (deviation, by necessity)
//!
//! The core dispatcher 0x0819d048 lives in alloc_core.rs and the free
//! path in free_path.rs — both ported concurrently and not importable
//! from here. The RTXC kernel (semaphore ops 0x0807f5c4/0x0807f6a0/
//! 0x080744a4, kernel-running check 0x0809444c), the tag-2 operator
//! new/delete veneers (0x082aadd4/0x082aad24), the heap factory global
//! (0x089d017c via 0x0804d348), the heap release 0x0804c360 and the C++
//! string name copy/free are likewise not yet ported. All of these are
//! routed through the `HEAP_CORE_HOOKS` fn-pointer table (pattern from
//! runtime/malloc_rt.rs), which defaults to documented stubs: the core
//! dispatch and node allocator spin/return NULL (they cannot produce
//! memory), the kernel is reported "not running" (so locking degrades to
//! the original's pre-kernel no-op path), the mutex ops are no-ops, the
//! factory reports failure, and the delete/free/release ops silently
//! leak. Host tests swap in mocks; once the real pieces land the table
//! can point at them.
//!
//! The eventual link contract (not referenced yet — declaring without
//! referencing emits no undefined symbols):
//!
//! ```text
//! extern "C" {
//!     fn heap_core_dispatch(desc, size, zerofill, tag,      // 0x0819d048
//!                           oldptr, copy, oom) -> *mut u8;  // (alloc_core.rs)
//!     fn rtxc_kernel_running() -> u32;                      // 0x0809444c
//!     fn rtxc_semaphore_create(slot: *mut u32);             // 0x080744a4
//!     fn rtxc_semaphore_wait(slot: *mut u32);               // 0x0807f5c4
//!     fn rtxc_semaphore_signal(slot: *mut u32);             // 0x0807f6a0
//!     fn os_operator_new_tag2(size: usize) -> *mut u8;      // 0x082aadd4
//!     fn os_operator_delete_tag2(ptr: *mut u8);             // 0x082aad24
//!     fn os_heap_release_descriptor(desc);                  // 0x0804c360
//! }
//! ```
//!
//! # Simplifications
//!
//! - The registry's name comparison in the original copy-constructs a
//!   temporary C++ string from the query (0x08277304), extracts its c-str
//!   (0x082a50b0), compares with strcmp (0x08276d64) and destroys the
//!   temporary (0x08277484). The net effect is `strcmp(node->name, query)
//!   == 0`, which is what the port does directly (names are plain
//!   NUL-terminated C strings at the ABI boundary).
//! - The node's C++ vtable word is kept only for layout fidelity and is
//!   always 0; destruction order (release heap, then free name) matches
//!   the original dtor 0x0819d9b8.
//! - The original null-factory path leaves `refcount` uninitialized and
//!   `named_heap_add` reads it anyway; the hook table always has a
//!   factory entry and the default stub reports failure, so `add` fails
//!   cleanly instead.
//! - The original dereferences the operator-new result and the table
//!   slots without NULL checks; `named_heap_add` guards the allocation
//!   result (returns -1 on NULL) because the default `node_new` stub
//!   cannot allocate. `named_heap_lookup`/`named_heap_release` stay
//!   faithful (no checks).
//! - `named_heap_add` passes the original's constant node size (16) to
//!   `node_new`. On 64-bit hosts the pointer fields widen the struct
//!   beyond 16 bytes (same situation as the sentinel in types.rs) — host
//!   mocks must return a buffer of at least `size_of::<NamedHeapNode>()`.

use crate::heap::types::HeapDescriptor;

/// Number of slots in the named-heap registry (original table
/// @ 0x08ad7860 has exactly 3).
pub const NAMED_HEAP_SLOTS: usize = 3;

/// Node allocation size in the original (`FUN_082aadd4(0x10)`).
pub const NAMED_HEAP_NODE_SIZE: usize = 16;

/// Refcounted named-heap node (16 bytes on ARM; see the module header).
#[repr(C)]
pub struct NamedHeapNode {
    /// C++ string-object vtable in the original; layout filler here.
    pub vtable: u32,
    /// Owned copy of the heap name (NUL-terminated).
    pub name: *mut u8,
    /// Heap descriptor created by the factory.
    pub desc: *mut HeapDescriptor,
    /// Reference count (1 per `named_heap_add` hit).
    pub refcount: u32,
}

/// The registry table — original global @ 0x08ad7860.
pub static mut NAMED_HEAP_TABLE: [*mut NamedHeapNode; NAMED_HEAP_SLOTS] =
    [core::ptr::null_mut(); NAMED_HEAP_SLOTS];

/// Indirect dispatch table for the not-yet-ported pieces (see the module
/// header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct HeapCoreHooks {
    /// Core heap dispatcher @ 0x0819d048 (alloc_core.rs, ported
    /// concurrently). `zerofill != 0` zeroes the user area, `tag` is the
    /// caller tag byte (the core truncates to u8), `oldptr != NULL`
    /// reallocates that block (copying min(old-8, size) bytes when
    /// `copy_on_move != 0`), `suppress_oom_report != 0` skips the OOM
    /// debug-print path in the core.
    pub dispatch: unsafe extern "C" fn(
        desc: *mut HeapDescriptor,
        size: usize,
        zerofill: u32,
        tag: u32,
        oldptr: *mut u8,
        copy_on_move: u32,
        suppress_oom_report: u32,
    ) -> *mut u8,
    /// Kernel-running check @ 0x0809444c: nonzero once the RTXC kernel is
    /// up and heap locking must engage.
    pub kernel_running: unsafe extern "C" fn() -> u32,
    /// RTXC semaphore create @ 0x080744a4: writes the new handle to
    /// `*slot` and zeroes `slot.add(1)` (the descriptor's pad word).
    pub mutex_create: unsafe extern "C" fn(slot: *mut u32),
    /// RTXC semaphore wait (P) veneer @ 0x0807f5c4: loads the handle from
    /// `*slot` and waits on it.
    pub mutex_wait: unsafe extern "C" fn(slot: *mut u32),
    /// RTXC semaphore signal (V) veneer @ 0x0807f6a0: loads the handle
    /// from `*slot` and signals it.
    pub mutex_signal: unsafe extern "C" fn(slot: *mut u32),
    /// Tag-2 operator-new veneer @ 0x082aadd4 (retailOS alloc @
    /// 0x080eb67c with tag 2). Returns NULL on failure.
    pub node_new: unsafe extern "C" fn(size: usize) -> *mut NamedHeapNode,
    /// Tag-2 operator-delete veneer @ 0x082aad24 (NULL-guarded retailOS
    /// free @ 0x080e7970 with tag 2).
    pub node_delete: unsafe extern "C" fn(node: *mut NamedHeapNode),
    /// Heap-name duplication — the original's C++ string copy-assign
    /// (0x08277304 -> 0x0827639c) which heap-allocates the c-str copy.
    pub name_dup: unsafe extern "C" fn(name: *const u8) -> *mut u8,
    /// Heap-name free — the original's base string dtor (0x08275d74)
    /// releasing the c-str copy.
    pub name_free: unsafe extern "C" fn(name: *mut u8),
    /// Named-heap factory — original global fn-ptr @ 0x089d017c, invoked
    /// through 0x0804d348 as `factory(name, 0, out_desc)`. Creates the
    /// heap for `name`, stores its descriptor to `*out_desc` and returns
    /// a status; the original node ctor sets `refcount = 1` iff the
    /// status is 0 (`rsbs r0, r0, #1; movcc r0, #0`).
    pub heap_factory: unsafe extern "C" fn(
        name: *const u8,
        flags: u32,
        out_desc: *mut *mut HeapDescriptor,
    ) -> u32,
    /// Heap-descriptor release @ 0x0804c360, called by the node dtor on
    /// the node's heap (NULL-tolerant in the original).
    pub heap_release: unsafe extern "C" fn(desc: *mut HeapDescriptor),
}

/// Default stub: the core heap is not linked yet — spin (on real hardware
/// `HEAP_CORE_HOOKS` must be installed before the heap is touched).
unsafe extern "C" fn missing_dispatch(
    _desc: *mut HeapDescriptor,
    _size: usize,
    _zerofill: u32,
    _tag: u32,
    _oldptr: *mut u8,
    _copy_on_move: u32,
    _suppress_oom_report: u32,
) -> *mut u8 {
    loop {}
}

/// Default stub: no kernel — `heap_lock` takes its pre-kernel no-op path.
unsafe extern "C" fn missing_kernel_running() -> u32 {
    0
}

/// Default stub: unreachable with the default `kernel_running` (locking
/// never engages); a no-op so a partially installed table stays harmless.
unsafe extern "C" fn missing_mutex_op(_slot: *mut u32) {}

/// Default stub: cannot allocate without the heap — report failure.
unsafe extern "C" fn missing_node_new(_size: usize) -> *mut NamedHeapNode {
    core::ptr::null_mut()
}

/// Default stub: freeing into a nonexistent heap leaks — harmless.
unsafe extern "C" fn missing_node_delete(_node: *mut NamedHeapNode) {}

/// Default stub: cannot copy the name without the heap — NULL.
unsafe extern "C" fn missing_name_dup(_name: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default stub: nothing to free without the heap — harmless leak.
unsafe extern "C" fn missing_name_free(_name: *mut u8) {}

/// Default stub: no factory installed — report failure (status != 0), so
/// `named_heap_add` fails cleanly instead of reading the uninitialized
/// refcount the original's null-factory path would leave behind.
unsafe extern "C" fn missing_heap_factory(
    _name: *const u8,
    _flags: u32,
    _out_desc: *mut *mut HeapDescriptor,
) -> u32 {
    1
}

/// Default stub: no heap to release — harmless no-op.
unsafe extern "C" fn missing_heap_release(_desc: *mut HeapDescriptor) {}

/// The active hooks. Defaults to the documented stubs above; replaced by
/// host tests (mocks) and eventually by the ported core/kernel. Written
/// once at init on target; tests serialize access.
pub static mut HEAP_CORE_HOOKS: HeapCoreHooks = HeapCoreHooks {
    dispatch: missing_dispatch,
    kernel_running: missing_kernel_running,
    mutex_create: missing_mutex_op,
    mutex_wait: missing_mutex_op,
    mutex_signal: missing_mutex_op,
    node_new: missing_node_new,
    node_delete: missing_node_delete,
    name_dup: missing_name_dup,
    name_free: missing_name_free,
    heap_factory: missing_heap_factory,
    heap_release: missing_heap_release,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the loads
/// to the default stubs (see malloc_rt.rs, where folding collapsed
/// `malloc` into a branch-to-self in the ARM release build).
#[inline(always)]
fn hooks() -> HeapCoreHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_CORE_HOOKS)) }
}

/// heap_alloc — original: `FUN_0819d67c` @ 0x0819d67c (36 bytes).
///
/// Plain allocation veneer: `core(desc, size, zerofill=0, tag, oldptr=0,
/// copy=0, oom=0)`.
#[no_mangle]
pub unsafe extern "C" fn heap_alloc(
    desc: *mut HeapDescriptor,
    size: usize,
    tag: u32,
) -> *mut u8 {
    (hooks().dispatch)(desc, size, 0, tag, core::ptr::null_mut(), 0, 0)
}

/// heap_alloc_tag1 — original: `FUN_0819d2f0` @ 0x0819d2f0 (36 bytes,
/// 7 call sites).
///
/// Same as `heap_alloc` but with the seventh core argument (the
/// OOM-report suppression byte) set to 1.
#[no_mangle]
pub unsafe extern "C" fn heap_alloc_tag1(
    desc: *mut HeapDescriptor,
    size: usize,
    tag: u32,
) -> *mut u8 {
    (hooks().dispatch)(desc, size, 0, tag, core::ptr::null_mut(), 0, 1)
}

/// heap_alloc_zero — original: `FUN_0819ce00` @ 0x0819ce00 (36 bytes).
///
/// calloc-style veneer: `core(desc, size, zerofill=1, tag, 0, 0, 0)`.
#[no_mangle]
pub unsafe extern "C" fn heap_alloc_zero(
    desc: *mut HeapDescriptor,
    size: usize,
    tag: u32,
) -> *mut u8 {
    (hooks().dispatch)(desc, size, 1, tag, core::ptr::null_mut(), 0, 0)
}

/// heap_realloc — original: `FUN_0819d6a0` @ 0x0819d6a0 (44 bytes).
///
/// Realloc veneer: `core(desc, new_size, zerofill=0, tag, oldptr,
/// copy_on_move, 0)`. `copy_on_move` is the original's 5th (stack)
/// argument.
#[no_mangle]
pub unsafe extern "C" fn heap_realloc(
    desc: *mut HeapDescriptor,
    oldptr: *mut u8,
    new_size: usize,
    tag: u32,
    copy_on_move: u32,
) -> *mut u8 {
    (hooks().dispatch)(desc, new_size, 0, tag, oldptr, copy_on_move, 0)
}

/// heap_lock — original: `FUN_0819d6cc` @ 0x0819d6cc (72 bytes).
///
/// Takes the heap's RTXC semaphore, lazily creating it once the kernel is
/// running. Before the kernel is up this is a no-op (pre-kernel heap
/// access is single-threaded). The create path loops back to re-check
/// `mutex_state`, exactly like the original, so a racing creator wins.
#[no_mangle]
pub unsafe extern "C" fn heap_lock(desc: *mut HeapDescriptor) {
    let h = hooks();
    while (*desc).mutex_state != 1 {
        if (h.kernel_running)() == 0 {
            return;
        }
        (*desc).mutex_state2 = 1;
        (h.mutex_create)(&mut (*desc).mutex_handle);
        (*desc).mutex_state2 = 0;
        (*desc).mutex_state = 1;
    }
    (h.mutex_wait)(&mut (*desc).mutex_handle);
}

/// heap_unlock — original: `FUN_0819cde4` @ 0x0819cde4 (16 bytes).
///
/// Signals the heap's RTXC semaphore when locking has engaged
/// (`mutex_state == 1`); a plain return otherwise.
#[no_mangle]
pub unsafe extern "C" fn heap_unlock(desc: *mut HeapDescriptor) {
    if (*desc).mutex_state == 1 {
        (hooks().mutex_signal)(&mut (*desc).mutex_handle);
    }
}

/// named_heap_lookup — original: `FUN_0819d804` @ 0x0819d804 (16 bytes).
///
/// Returns the heap descriptor registered under `index`
/// (`table[index]->desc`). No bounds or NULL checks, as in the original
/// (get_unchecked keeps the ARM build free of panic_bounds_check).
#[no_mangle]
pub unsafe extern "C" fn named_heap_lookup(index: usize) -> *mut HeapDescriptor {
    let table = (*core::ptr::addr_of!(NAMED_HEAP_TABLE)).as_slice();
    let node = *table.get_unchecked(index);
    (*node).desc
}

/// named_heap_release — original: `FUN_0819d818` @ 0x0819d818 (60 bytes).
///
/// Drops one reference to the node in slot `index`; when the refcount
/// reaches zero the node is destroyed (heap released, name freed),
/// deleted and the slot cleared.
#[no_mangle]
pub unsafe extern "C" fn named_heap_release(index: usize) {
    let table = (*core::ptr::addr_of_mut!(NAMED_HEAP_TABLE)).as_mut_slice();
    let node = *table.get_unchecked(index);
    if !node_decref(node) {
        return;
    }
    if !node.is_null() {
        node_destroy(node);
        (hooks().node_delete)(node);
    }
    *table.get_unchecked_mut(index) = core::ptr::null_mut();
}

/// Refcount decrement — original: `FUN_0819d944` @ 0x0819d944 (28 bytes).
///
/// Decrements unless already zero; returns true when the refcount is zero
/// afterwards — including when it was zero on entry (quirk of the
/// original's predicated `moveq r0, #1`), which the release path treats
/// as "destroy now".
unsafe fn node_decref(node: *mut NamedHeapNode) -> bool {
    let mut refs = (*node).refcount;
    if refs != 0 {
        refs -= 1;
        (*node).refcount = refs;
    }
    refs == 0
}

/// Node constructor — original: `FUN_0819d964` @ 0x0819d964 (76 bytes).
///
/// Copies the name, NULLs the descriptor, then asks the factory to create
/// the heap; `refcount = 1` iff the factory returned status 0.
unsafe fn node_init(raw: *mut NamedHeapNode, name: *const u8) -> *mut NamedHeapNode {
    let h = hooks();
    (*raw).vtable = 0; // C++ string vtable in the original; not modeled.
    (*raw).name = (h.name_dup)(name);
    (*raw).desc = core::ptr::null_mut();
    // Original: only calls the factory when the global @ 0x089d017c is
    // non-null (and leaves refcount unset otherwise). The hook table
    // always has an entry; the default stub reports failure.
    let status = (h.heap_factory)(name, 0, &mut (*raw).desc);
    (*raw).refcount = if status == 0 { 1 } else { 0 };
    raw
}

/// Node destructor — original: `FUN_0819d9b8` @ 0x0819d9b8 (36 bytes).
///
/// Releases the node's heap descriptor, then frees the owned name copy
/// (the original's base string dtor). Does not free the node itself —
/// that is the tag-2 delete at the call site.
unsafe fn node_destroy(node: *mut NamedHeapNode) {
    let h = hooks();
    (h.heap_release)((*node).desc);
    (h.name_free)((*node).name);
}

/// named_heap_add — original: `FUN_0819d858` @ 0x0819d858 (228 bytes).
///
/// Finds-or-registers the heap named `name`. A name match bumps the
/// node's refcount and returns its slot; otherwise a new node is created
/// via the factory and installed into the first free slot. Returns -1
/// when the factory fails or all 3 slots are taken.
#[no_mangle]
pub unsafe extern "C" fn named_heap_add(name: *const u8) -> i32 {
    let h = hooks();
    // get_unchecked: indexes are bounded by NAMED_HEAP_SLOTS and the
    // original emits no bounds checks (avoids a panic_bounds_check call).
    let table = (*core::ptr::addr_of_mut!(NAMED_HEAP_TABLE)).as_mut_slice();
    for index in 0..NAMED_HEAP_SLOTS {
        let node = *table.get_unchecked(index);
        if node.is_null() {
            continue;
        }
        // Original: temp C++ string copy of `name`, c-str extract, strcmp,
        // temp dtor — the net effect is this comparison.
        if c_str_eq((*node).name, name) {
            (*node).refcount += 1;
            return index as i32;
        }
    }
    let raw = (h.node_new)(NAMED_HEAP_NODE_SIZE);
    if raw.is_null() {
        return -1; // original dereferences blindly; the stub cannot allocate
    }
    let node = node_init(raw, name);
    if (*node).refcount == 0 {
        node_destroy(node);
        (h.node_delete)(node);
        return -1;
    }
    for index in 0..NAMED_HEAP_SLOTS {
        if table.get_unchecked(index).is_null() {
            *table.get_unchecked_mut(index) = node;
            return index as i32;
        }
    }
    -1 // table full: the original leaks the new node here too
}

/// Byte-wise C-string equality (the original's strcmp @ 0x08276d64
/// reduced to its equality result). Volatile reads so LLVM's idiom
/// recognition cannot rewrite the loop into a libc `strcmp`/`memcmp`
/// call, which does not exist on the target.
unsafe fn c_str_eq(a: *const u8, b: *const u8) -> bool {
    let mut i = 0;
    loop {
        let ca = core::ptr::read_volatile(a.add(i));
        let cb = core::ptr::read_volatile(b.add(i));
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap the global hook table / registry.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    // --- mock core dispatcher log ---
    static mut DISPATCH_CALLS: usize = 0;
    static mut LAST_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    static mut LAST_SIZE: usize = 0;
    static mut LAST_ZEROFILL: u32 = 0;
    static mut LAST_TAG: u32 = 0;
    static mut LAST_OLDPTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_COPY: u32 = 0;
    static mut LAST_OOM: u32 = 0;
    static mut DISPATCH_RET: *mut u8 = core::ptr::null_mut();

    // --- mock lock state ---
    static mut KERNEL_UP: u32 = 0;
    static mut EVENTS: Vec<u8> = Vec::new(); // b'k' kernel-check, b'c' create, b'w' wait, b's' signal
    static mut CREATE_STATE2_DURING: u8 = 0xff;
    static mut CURRENT_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    const MOCK_HANDLE: u32 = 0xCAFE_0001;

    // --- mock registry state ---
    static mut NEW_CALLS: usize = 0;
    static mut NEW_RET_NULL: bool = false;
    static mut DELETE_CALLS: usize = 0;
    static mut LAST_DELETE: *mut NamedHeapNode = core::ptr::null_mut();
    static mut FACTORY_CALLS: usize = 0;
    static mut FACTORY_STATUS: u32 = 0;
    static mut FACTORY_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    static mut RELEASE_CALLS: usize = 0;
    static mut LAST_RELEASED: *mut HeapDescriptor = core::ptr::null_mut();
    static mut NAME_FREE_CALLS: usize = 0;
    static mut LAST_NAME_FREE: *mut u8 = core::ptr::null_mut();
    // Mock node pool: 8 slots of 64 bytes (struct widens on 64-bit hosts).
    static mut NODE_POOL: [[u8; 64]; 8] = [[0; 64]; 8];
    static mut NODE_POOL_NEXT: usize = 0;
    // Mock name pool: 8 slots of 32 bytes.
    static mut NAME_POOL: [[u8; 32]; 8] = [[0; 32]; 8];
    static mut NAME_POOL_NEXT: usize = 0;

    const RESULT_A: usize = 0xA110_0000;
    const RESULT_B: usize = 0xB220_0000;

    unsafe extern "C" fn mock_dispatch(
        desc: *mut HeapDescriptor,
        size: usize,
        zerofill: u32,
        tag: u32,
        oldptr: *mut u8,
        copy_on_move: u32,
        suppress_oom_report: u32,
    ) -> *mut u8 {
        DISPATCH_CALLS += 1;
        LAST_DESC = desc;
        LAST_SIZE = size;
        LAST_ZEROFILL = zerofill;
        LAST_TAG = tag;
        LAST_OLDPTR = oldptr;
        LAST_COPY = copy_on_move;
        LAST_OOM = suppress_oom_report;
        DISPATCH_RET
    }

    unsafe extern "C" fn mock_kernel_running() -> u32 {
        EVENTS.push(b'k');
        KERNEL_UP
    }

    unsafe extern "C" fn mock_mutex_create(slot: *mut u32) {
        EVENTS.push(b'c');
        CREATE_STATE2_DURING = (*CURRENT_DESC).mutex_state2;
        *slot = MOCK_HANDLE;
        *slot.add(1) = 0;
    }

    unsafe extern "C" fn mock_mutex_wait(slot: *mut u32) {
        EVENTS.push(b'w');
        assert_eq!(*slot, MOCK_HANDLE, "wait must see the created handle");
    }

    unsafe extern "C" fn mock_mutex_signal(slot: *mut u32) {
        EVENTS.push(b's');
        assert_eq!(*slot, MOCK_HANDLE, "signal must see the created handle");
    }

    unsafe extern "C" fn mock_node_new(_size: usize) -> *mut NamedHeapNode {
        NEW_CALLS += 1;
        if NEW_RET_NULL || NODE_POOL_NEXT >= 8 {
            return core::ptr::null_mut();
        }
        let p = NODE_POOL[NODE_POOL_NEXT].as_mut_ptr() as *mut NamedHeapNode;
        NODE_POOL_NEXT += 1;
        p
    }

    unsafe extern "C" fn mock_node_delete(node: *mut NamedHeapNode) {
        DELETE_CALLS += 1;
        LAST_DELETE = node;
    }

    unsafe extern "C" fn mock_name_dup(name: *const u8) -> *mut u8 {
        let dst = NAME_POOL[NAME_POOL_NEXT].as_mut_ptr();
        NAME_POOL_NEXT += 1;
        let mut i = 0;
        loop {
            let c = *name.add(i);
            *dst.add(i) = c;
            if c == 0 {
                break;
            }
            i += 1;
        }
        dst
    }

    unsafe extern "C" fn mock_name_free(name: *mut u8) {
        NAME_FREE_CALLS += 1;
        LAST_NAME_FREE = name;
    }

    unsafe extern "C" fn mock_heap_factory(
        _name: *const u8,
        flags: u32,
        out_desc: *mut *mut HeapDescriptor,
    ) -> u32 {
        FACTORY_CALLS += 1;
        assert_eq!(flags, 0, "factory flags argument is always 0");
        *out_desc = FACTORY_DESC;
        FACTORY_STATUS
    }

    unsafe extern "C" fn mock_heap_release(desc: *mut HeapDescriptor) {
        RELEASE_CALLS += 1;
        LAST_RELEASED = desc;
    }

    const MOCK_HOOKS: HeapCoreHooks = HeapCoreHooks {
        dispatch: mock_dispatch,
        kernel_running: mock_kernel_running,
        mutex_create: mock_mutex_create,
        mutex_wait: mock_mutex_wait,
        mutex_signal: mock_mutex_signal,
        node_new: mock_node_new,
        node_delete: mock_node_delete,
        name_dup: mock_name_dup,
        name_free: mock_name_free,
        heap_factory: mock_heap_factory,
        heap_release: mock_heap_release,
    };

    /// Resets all mock state, installs the mock table, returns the guard.
    fn mock_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            DISPATCH_CALLS = 0;
            LAST_DESC = core::ptr::null_mut();
            LAST_SIZE = 0;
            LAST_ZEROFILL = 0;
            LAST_TAG = 0;
            LAST_OLDPTR = core::ptr::null_mut();
            LAST_COPY = 0;
            LAST_OOM = 0;
            DISPATCH_RET = RESULT_A as *mut u8;
            KERNEL_UP = 0;
            EVENTS = Vec::new();
            CREATE_STATE2_DURING = 0xff;
            CURRENT_DESC = core::ptr::null_mut();
            NEW_CALLS = 0;
            NEW_RET_NULL = false;
            DELETE_CALLS = 0;
            LAST_DELETE = core::ptr::null_mut();
            FACTORY_CALLS = 0;
            FACTORY_STATUS = 0;
            FACTORY_DESC = core::ptr::null_mut();
            RELEASE_CALLS = 0;
            LAST_RELEASED = core::ptr::null_mut();
            NAME_FREE_CALLS = 0;
            LAST_NAME_FREE = core::ptr::null_mut();
            NODE_POOL_NEXT = 0;
            NAME_POOL_NEXT = 0;
            *core::ptr::addr_of_mut!(HEAP_CORE_HOOKS) = MOCK_HOOKS;
            *core::ptr::addr_of_mut!(NAMED_HEAP_TABLE) =
                [core::ptr::null_mut(); NAMED_HEAP_SLOTS];
        }
        guard
    }

    fn test_desc() -> *mut HeapDescriptor {
        std::boxed::Box::leak(std::boxed::Box::new(unsafe {
            core::mem::zeroed::<HeapDescriptor>()
        }))
    }

    // --- wrapper pass-through tests ---

    #[test]
    fn heap_alloc_passes_args_and_zero_constants() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            let p = heap_alloc(desc, 0x1234, 7);
            assert_eq!(p, RESULT_A as *mut u8);
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(LAST_DESC, desc);
            assert_eq!(LAST_SIZE, 0x1234);
            assert_eq!(LAST_ZEROFILL, 0);
            assert_eq!(LAST_TAG, 7);
            assert!(LAST_OLDPTR.is_null());
            assert_eq!(LAST_COPY, 0);
            assert_eq!(LAST_OOM, 0);
        }
    }

    #[test]
    fn heap_alloc_tag1_sets_only_the_oom_flag() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            heap_alloc_tag1(desc, 64, 9);
            assert_eq!(LAST_SIZE, 64);
            assert_eq!(LAST_TAG, 9, "tag passes through like the other veneers");
            assert_eq!(LAST_ZEROFILL, 0);
            assert!(LAST_OLDPTR.is_null());
            assert_eq!(LAST_COPY, 0);
            assert_eq!(LAST_OOM, 1, "the constant 1 lands in core param 7");
        }
    }

    #[test]
    fn heap_alloc_zero_sets_zerofill() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            heap_alloc_zero(desc, 32, 3);
            assert_eq!(LAST_ZEROFILL, 1);
            assert_eq!(LAST_TAG, 3);
            assert!(LAST_OLDPTR.is_null());
            assert_eq!(LAST_COPY, 0);
            assert_eq!(LAST_OOM, 0);
        }
    }

    #[test]
    fn heap_realloc_maps_oldptr_and_copy_flag() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            let old = 0xDEAD_0000 as *mut u8;
            DISPATCH_RET = RESULT_B as *mut u8;
            let p = heap_realloc(desc, old, 0x800, 11, 1);
            assert_eq!(p, RESULT_B as *mut u8);
            assert_eq!(LAST_DESC, desc);
            assert_eq!(LAST_SIZE, 0x800, "new_size moves into the size slot");
            assert_eq!(LAST_OLDPTR, old, "oldptr moves into core param 5");
            assert_eq!(LAST_COPY, 1, "copy flag moves into core param 6");
            assert_eq!(LAST_TAG, 11);
            assert_eq!(LAST_ZEROFILL, 0);
            assert_eq!(LAST_OOM, 0);
        }
    }

    // --- lock/unlock tests ---

    #[test]
    fn lock_before_kernel_is_up_is_noop() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            CURRENT_DESC = desc;
            KERNEL_UP = 0;
            heap_lock(desc);
            assert_eq!((*desc).mutex_state, 0);
            assert_eq!((*desc).mutex_handle, 0);
            assert_eq!(EVENTS, std::vec![b'k'], "only the kernel check runs");
            heap_unlock(desc);
            assert_eq!(EVENTS, std::vec![b'k'], "unlock without state signals nothing");
        }
    }

    #[test]
    fn lock_creates_mutex_once_kernel_is_up_then_waits() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            (*desc).mutex_state = 0;
            CURRENT_DESC = desc;
            KERNEL_UP = 1;
            heap_lock(desc);
            assert_eq!((*desc).mutex_state, 1);
            assert_eq!((*desc).mutex_state2, 0, "creation flag cleared afterwards");
            assert_eq!(CREATE_STATE2_DURING, 1, "creation flag set during create");
            assert_eq!((*desc).mutex_handle, MOCK_HANDLE);
            assert_eq!(EVENTS, std::vec![b'k', b'c', b'w']);
            // Second lock on the same descriptor: no re-create, just wait.
            heap_lock(desc);
            assert_eq!(EVENTS, std::vec![b'k', b'c', b'w', b'w']);
            // Unlock pairs with each wait.
            heap_unlock(desc);
            heap_unlock(desc);
            assert_eq!(EVENTS, std::vec![b'k', b'c', b'w', b'w', b's', b's']);
        }
    }

    #[test]
    fn lock_with_state_already_set_only_waits() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            (*desc).mutex_state = 1;
            (*desc).mutex_handle = MOCK_HANDLE;
            CURRENT_DESC = desc;
            KERNEL_UP = 1;
            heap_lock(desc);
            assert_eq!(EVENTS, std::vec![b'w'], "no kernel check, no create");
        }
    }

    // --- registry tests ---

    #[test]
    fn add_creates_node_and_lookup_returns_desc() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            FACTORY_DESC = desc;
            let idx = named_heap_add(b"audio\0".as_ptr());
            assert_eq!(idx, 0);
            assert_eq!(FACTORY_CALLS, 1);
            assert_eq!(NEW_CALLS, 1);
            let node = NAMED_HEAP_TABLE[0];
            assert!(!node.is_null());
            assert_eq!((*node).refcount, 1);
            assert_eq!((*node).desc, desc);
            assert!(c_str_eq((*node).name, b"audio\0".as_ptr()));
            assert_eq!(named_heap_lookup(0), desc);
        }
    }

    #[test]
    fn add_existing_name_bumps_refcount_without_factory() {
        let _lock = mock_env();
        unsafe {
            FACTORY_DESC = test_desc();
            let first = named_heap_add(b"audio\0".as_ptr());
            let again = named_heap_add(b"audio\0".as_ptr());
            assert_eq!(first, again);
            assert_eq!(FACTORY_CALLS, 1, "no second factory call");
            assert_eq!(NEW_CALLS, 1, "no second node");
            assert_eq!((*NAMED_HEAP_TABLE[first as usize]).refcount, 2);
            // A different name misses the strcmp and takes a new slot.
            let other = named_heap_add(b"video\0".as_ptr());
            assert_ne!(other, first);
            assert_eq!(FACTORY_CALLS, 2);
        }
    }

    #[test]
    fn add_fills_three_slots_then_fails() {
        let _lock = mock_env();
        unsafe {
            FACTORY_DESC = test_desc();
            assert_eq!(named_heap_add(b"a\0".as_ptr()), 0);
            assert_eq!(named_heap_add(b"b\0".as_ptr()), 1);
            assert_eq!(named_heap_add(b"c\0".as_ptr()), 2);
            assert_eq!(named_heap_add(b"d\0".as_ptr()), -1, "table full");
            // ...but an existing name still bumps its refcount.
            assert_eq!(named_heap_add(b"a\0".as_ptr()), 0);
            assert_eq!((*NAMED_HEAP_TABLE[0]).refcount, 2);
        }
    }

    #[test]
    fn add_factory_failure_deletes_node_and_fails() {
        let _lock = mock_env();
        unsafe {
            FACTORY_STATUS = 1; // failure -> refcount 0
            assert_eq!(named_heap_add(b"audio\0".as_ptr()), -1);
            assert_eq!(FACTORY_CALLS, 1);
            assert_eq!(DELETE_CALLS, 1, "failed node is deleted");
            assert!(!LAST_DELETE.is_null());
            assert!(NAMED_HEAP_TABLE[0].is_null(), "slot stays empty");
        }
    }

    #[test]
    fn add_new_failure_returns_minus_one() {
        let _lock = mock_env();
        unsafe {
            NEW_RET_NULL = true;
            assert_eq!(named_heap_add(b"audio\0".as_ptr()), -1);
            assert_eq!(FACTORY_CALLS, 0, "factory not reached");
        }
    }

    #[test]
    fn release_decrements_and_destroys_at_zero() {
        let _lock = mock_env();
        unsafe {
            let desc = test_desc();
            FACTORY_DESC = desc;
            let idx = named_heap_add(b"audio\0".as_ptr()) as usize;
            named_heap_add(b"audio\0".as_ptr());
            let node = NAMED_HEAP_TABLE[idx];
            let name = (*node).name;

            named_heap_release(idx); // 2 -> 1: nothing destroyed
            assert_eq!((*node).refcount, 1);
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(DELETE_CALLS, 0);
            assert!(!NAMED_HEAP_TABLE[idx].is_null());

            named_heap_release(idx); // 1 -> 0: full teardown
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(LAST_RELEASED, desc);
            assert_eq!(NAME_FREE_CALLS, 1);
            assert_eq!(LAST_NAME_FREE, name);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(LAST_DELETE, node);
            assert!(NAMED_HEAP_TABLE[idx].is_null(), "slot cleared");

            // The freed slot can be reused.
            FACTORY_CALLS = 0;
            assert_eq!(named_heap_add(b"video\0".as_ptr()), idx as i32);
            assert_eq!(FACTORY_CALLS, 1);
        }
    }
}
