//! Ports of the malloc-family veneers that sit between the C/C++ runtime
//! and the retailOS heap core (cluster 0x0819cd5c..0x0819d9d8), plus the
//! lazy default-heap init and the C++ `operator new`/`operator delete`
//! front-ends:
//!
//! - `malloc_wrapper` — original: `FUN_080eb67c` @ 0x080eb67c (40 bytes,
//!   96 call sites). Saves (size, tag), runs the lazy init, loads the
//!   default-heap handle from the global @ 0x089ca638 and tail-branches to
//!   `heap_alloc` @ 0x0819d67c with (heap, size, tag).
//! - `free_wrapper` — original: `FUN_080e7970` @ 0x080e7970 (40 bytes,
//!   62 call sites). Same prologue, tail-branches to `heap_free` @
//!   0x0819d4dc with (heap, ptr, tag). No NULL guard here — `heap_free`
//!   itself ignores NULL (and panics via `heap_panic` on a zero/free
//!   header word).
//! - `calloc_wrapper` — original: `FUN_0807b254` @ 0x0807b254 (44 bytes:
//!   40 code + literal; 14 bl call sites, among them the name-node
//!   allocator @ 0x0809388c). malloc_wrapper's zerofill sibling: lazy
//!   init, then tail-branches to `heap_alloc_zero` @ 0x0819ce00 with
//!   (heap, size, tag) — the calloc-style veneer that sets the core's
//!   zerofill argument. No size*count multiply: callers pass a byte
//!   count, like malloc.
//! - `realloc_wrapper` — original: `FUN_080edbf0` @ 0x080edbf0 (56 bytes,
//!   6 call sites). Lazy init, then calls (not tail-branches — a fourth
//!   argument goes on the stack) `heap_realloc` @ 0x0819d6a0 with
//!   (heap, ptr, size, a3, a4).
//! - `lazy_init_default_heap` — original: `FUN_08077250` @ 0x08077250
//!   (44 bytes). If the global @ 0x089ca638 is still NULL, creates the
//!   default heap: `heap_create(desc = 0x08a1a710,
//!   start = 0x08a1a710 - 0x8000 = 0x08a12710, size = 0x8000)` — a 32 KB
//!   region sitting *immediately below* the 0x398-byte descriptor — and
//!   stores the returned handle (the descriptor pointer; `heap_create` @
//!   0x0819d7b4 returns its first argument) into the global.
//! - `operator_new` / `operator_delete` — originals @ 0x082aadd4 (8 bytes,
//!   1797 call sites — the dominant allocator in osos) and 0x082aad24
//!   (16 bytes, 665 call sites). Tag-2 pair: new is a pure tail veneer
//!   (`mov r1, #2; b 0x080eb67c`), delete is NULL-guarded
//!   (`cmp r0, #0; movne r1, #2; bne 0x080e7970; bx lr`).
//! - `operator_new_tag3` / `operator_delete_tag3` — originals `FUN_082aad74`
//!   @ 0x082aad74 (8 bytes, 111 `bl` call sites) and `FUN_082aad14` @
//!   0x082aad14 (16 bytes, 155 `bl` + 3 `b` call sites). Structurally
//!   identical pair with tag 3; 0x082aad14 is the neighbour immediately
//!   below the tag-2 delete @ 0x082aad24, not the same function.
//! - `free_tag4` — original: `FUN_0805d070` @ 0x0805d070 (8 bytes;
//!   58 `bl`-form + 13 tail-branch call sites). The tag-4 deallocation
//!   entry of the "MemH" managed-buffer family @ 0x0805d028..0x0805d1e4:
//!   `mov r1, #4; b 0x080e7970`, with no NULL guard of its own.
//! - `calloc_tag4` — original: `FUN_0805d1dc` @ 0x0805d1dc (8 bytes;
//!   23 `bl` call sites). The family's zerofill-alloc entry:
//!   `mov r1, #4; b 0x0807b254` (tail call `calloc_wrapper`).
//! - `malloc_tag4` — original: `FUN_0805d1d4` @ 0x0805d1d4 (8 bytes;
//!   23 `bl` call sites). The family's plain-alloc entry:
//!   `mov r1, #4; b 0x080eb67c` (tail call `malloc_wrapper`).
//! - `cxx_vec_delete` — original: `FUN_0803170c` @ 0x0803170c (16 bytes).
//!   C++ `delete[]` with destructors: cookie-driven `__cpp_finalise` walk
//!   via the null-guard veneer @ 0x082ab254, then the tag-3 delete.
//! - `cxx_array_dealloc` — original: `FUN_08266f2c` @ 0x08266f2c
//!   (4 bytes; 276 call sites). C++ array deallocation for elements
//!   without destructors: a bare `b 0x082aad24` into the tag-2
//!   `operator delete`, so its `count`/`elem` arguments are dead.
//! - `cpp_finalise_null_guard` — original @ 0x082ab254 (16 bytes:
//!   `cmp r0, #0; ldmdbne r0, {r2, r3}; bne __cpp_finalise; mov pc, lr`).
//!   NULL-guarded cookie-loading front-end of `__cpp_finalise`
//!   @ 0x080336d8 (runtime/atexit): loads the array cookie (elem size @
//!   -8, count @ -4) and tail-calls the destructor walk, which returns
//!   the true block start (`array - 8`); a NULL array skips the walk and
//!   returns NULL (r0 unchanged). Sole osos caller: `cxx_vec_delete`.
//! - `operator_new_checked` — original: `FUN_08266c70` @ 0x08266c70
//!   (48 bytes, 223 call sites). `p = operator_new(size)`; on NULL it
//!   invokes the C++ new-handler dispatch @ 0x08266abc with code 3,
//!   then returns `p` (still NULL if no handler freed anything — the
//!   original does not retry at this level). The port lives in
//!   heap/new_handler.rs next to the dispatch it calls; re-exported
//!   here so existing `heap::veneers::operator_new_checked` callers
//!   (cxx/string.rs, the string maps) keep their paths.
//! - `heap_panic` — original: `FUN_08030f44` @ 0x08030f44 (32 bytes,
//!   fatal, does not return). `__rt_raise(1, 0)` @ 0x080320a8, then the
//!   exit path @ 0x08035878 (`_rt_exit`-ish: runs atexit handlers and
//!   flushes stdio), then tail-branches to the final terminate stub @
//!   0x082b20a0 with r0 = 1 (a semihosting SWI 0x123456 + spin).
//!
//! Heap-dispatch design (deviation, by necessity): instead of the
//! originals' tail branches, these veneers dispatch indirectly through
//! the `HEAP_OPS` function-pointer table (same pattern as
//! src/runtime/malloc_rt.rs) so host tests can swap in a mock heap. The
//! defaults are wired to the real ports wherever one exists:
//! `alloc`/`alloc_zero`/`free`/`realloc`/`create` reach the heap core
//! veneers `heap_alloc` @ 0x0819d67c / `heap_alloc_zero` @ 0x0819ce00 /
//! `heap_free` @ 0x0819d4dc / `heap_realloc`
//! @ 0x0819d6a0 (wrappers.rs, free_path.rs) and `heap_create` @
//! 0x0819d7b4 (init.rs) through thin handle-cast shims (the heap handle
//! *is* the descriptor pointer — `heap_create` returns its first
//! argument), `new_handler` is the real C++ new-handler dispatch @
//! 0x08266abc (new_handler.rs, through the one-argument shim — the
//! checked path's code-3 call never carries the variadic tail), and
//! `raise` is `__rt_raise` @ 0x080320a8 (runtime/raise.rs)
//! directly. The remaining slots keep behavior-faithful stubs:
//! `exit` is a no-op, matching the 0x08035878
//! stdio cleanup which runtime/exit.rs ports as dead semihost code; and
//! `terminate` spins, matching the 0x082b20a0 semihosting-SWI + spin
//! stub in runtime/exit.rs.
//!
//! Simplifications:
//! - The default-heap region and descriptor are modeled as one
//!   `static mut` storage block (`region` immediately followed by `desc`,
//!   mirroring the original 0x08a12710..0x08a1a710 + 0x08a1a710 layout)
//!   instead of living at the original load addresses; the original
//!   addresses are documented above.
//! - `heap_panic` keeps the original's raise -> exit -> terminate call
//!   sequence through the ops table, with a final `loop {}` safety net in
//!   case a swapped-in `terminate` hook returns (the original target
//!   0x082b20a0 never does).

use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};

/// Size of the default heap region: 32 KB (original `mov r2, #0x8000`).
const DEFAULT_HEAP_SIZE: usize = 0x8000;

/// Caller tag used by the dominant `operator new`/`operator delete` pair
/// (0x082aadd4 / 0x082aad24).
const TAG_OPERATOR_NEW: usize = 2;

/// Caller tag used by the second new/delete pair (0x082aad74 / 0x082aad14).
const TAG_OPERATOR_NEW_TAG3: usize = 3;

/// Caller tag used by the "MemH" managed-buffer family @ 0x0805d028..
/// 0x0805d1e4 and its free veneer [`free_tag4`] @ 0x0805d070.
const TAG_MEM_BUFFER: usize = 4;

/// Default-heap backing storage. Original layout: a 32 KB region @
/// 0x08a12710 immediately followed by the 0x398-byte descriptor @
/// 0x08a1a710 (`heap_create` is called with `start = desc - 0x8000`).
/// Kept as raw byte storage so it can be const-initialized; `heap_create`
/// lays the descriptor out in place.
#[repr(C, align(8))]
struct DefaultHeapStorage {
    /// Original: 0x08a12710..0x08a1a710.
    region: [u8; DEFAULT_HEAP_SIZE],
    /// Original: 0x08a1a710..0x08a1aaa8 (0x398 bytes on target).
    desc: [u8; core::mem::size_of::<HeapDescriptor>()],
}

static mut DEFAULT_HEAP_STORAGE: DefaultHeapStorage = DefaultHeapStorage {
    region: [0; DEFAULT_HEAP_SIZE],
    desc: [0; core::mem::size_of::<HeapDescriptor>()],
};

/// Indirect dispatch table for the heap core + new-handler + fatal path
/// (see the module header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct HeapVeneerOps {
    /// `heap_alloc` @ 0x0819d67c: (heap handle, size, caller tag).
    pub alloc: unsafe extern "C" fn(
        heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8,
    /// `heap_alloc_zero` @ 0x0819ce00: same contract, zerofilled block.
    pub alloc_zero: unsafe extern "C" fn(
        heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8,
    /// `heap_free` @ 0x0819d4dc: (heap handle, ptr, caller tag).
    pub free: unsafe extern "C" fn(heap: *mut HeapDescriptorDescriptor, ptr: *mut u8, tag: usize),
    /// `heap_realloc` @ 0x0819d6a0: (heap handle, ptr, size, a3, a4);
    /// a3/a4 are the original's r2/stack-in arguments (observed: 1, 1 from
    /// the ADS `realloc` veneer).
    pub realloc: unsafe extern "C" fn(
        heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        size: usize,
        a3: usize,
        a4: usize,
    ) -> *mut u8,
    /// `heap_create` @ 0x0819d7b4: initializes `desc` in place over the
    /// region [start, start + size) and returns the heap handle (the
    /// original returns its first argument).
    pub create: unsafe extern "C" fn(
        desc: *mut HeapDescriptor,
        start: *mut u8,
        size: usize,
    ) -> *mut HeapDescriptorDescriptor,
    /// C++ new-handler dispatch @ 0x08266abc (code 3 = plain `operator
    /// new` failure). The default is the real port's one-argument form
    /// (new_handler.rs), which returns immediately when no handler is
    /// registered — the only state stock retailOS ever reaches.
    pub new_handler: unsafe extern "C" fn(code: usize),
    /// `__rt_raise` @ 0x080320a8 (runtime/raise.rs; the default is the
    /// real port).
    pub raise: unsafe extern "C" fn(sig: i32, code: i32) -> i32,
    /// Exit path @ 0x08035878 (atexit handlers + stdio flush).
    pub exit: unsafe extern "C" fn(),
    /// Final terminate stub @ 0x082b20a0 (semihosting SWI + spin; never
    /// returns in the original).
    pub terminate: unsafe extern "C" fn(code: i32),
}

/// `alloc` slot shim over `heap_alloc` @ 0x0819d67c (wrappers.rs): the
/// handle value is the descriptor pointer (see the module header); the
/// tag narrows to the u32 the callee truncates to a byte anyway.
unsafe extern "C" fn alloc_ported(
    heap: *mut HeapDescriptorDescriptor,
    size: usize,
    tag: usize,
) -> *mut u8 {
    crate::heap::wrappers::heap_alloc(heap as *mut HeapDescriptor, size, tag as u32)
}

/// `alloc_zero` slot shim over `heap_alloc_zero` @ 0x0819ce00
/// (wrappers.rs) — same handle/tag conventions as `alloc_ported`.
unsafe extern "C" fn alloc_zero_ported(
    heap: *mut HeapDescriptorDescriptor,
    size: usize,
    tag: usize,
) -> *mut u8 {
    crate::heap::wrappers::heap_alloc_zero(heap as *mut HeapDescriptor, size, tag as u32)
}

/// `free` slot shim over `heap_free` @ 0x0819d4dc (free_path.rs).
unsafe extern "C" fn free_ported(heap: *mut HeapDescriptorDescriptor, ptr: *mut u8, tag: usize) {
    crate::heap::free_path::heap_free(heap as *mut HeapDescriptor, ptr, tag)
}

/// `realloc` slot shim over `heap_realloc` @ 0x0819d6a0 (wrappers.rs):
/// a3/a4 are the tag and copy-on-move flag of the callee's contract.
unsafe extern "C" fn realloc_ported(
    heap: *mut HeapDescriptorDescriptor,
    ptr: *mut u8,
    size: usize,
    a3: usize,
    a4: usize,
) -> *mut u8 {
    crate::heap::wrappers::heap_realloc(heap as *mut HeapDescriptor, ptr, size, a3 as u32, a4 as u32)
}

/// `create` slot shim over `heap_create` @ 0x0819d7b4 (init.rs): returns
/// the descriptor pointer as the heap handle, exactly like the original
/// (`heap_create` returns its first argument).
unsafe extern "C" fn create_ported(
    desc: *mut HeapDescriptor,
    start: *mut u8,
    size: usize,
) -> *mut HeapDescriptorDescriptor {
    crate::heap::init::heap_create(desc, start as usize, size) as *mut HeapDescriptorDescriptor
}

/// Default stub: the original exit path @ 0x08035878 is the stdio cleanup
/// that runtime/exit.rs ports as a no-op (dead semihost code) — no-op.
unsafe extern "C" fn missing_exit() {}

/// Default stub: the original @ 0x082b20a0 spins via semihosting SWI
/// (runtime/exit.rs stubs it the same way) — spin here too.
unsafe extern "C" fn missing_terminate(_code: i32) {
    loop {}
}

/// Wired defaults (see the module header). Host tests swap in a mock heap
/// and restore this afterwards.
pub(crate) const DEFAULT_HEAP_OPS: HeapVeneerOps = HeapVeneerOps {
    alloc: alloc_ported,
    alloc_zero: alloc_zero_ported,
    free: free_ported,
    realloc: realloc_ported,
    create: create_ported,
    new_handler: crate::heap::new_handler::cxx_new_handler_report,
    raise: crate::runtime::raise::__rt_raise,
    exit: missing_exit,
    terminate: missing_terminate,
};

/// The active heap-core implementation. Defaults to the real ports plus
/// the documented stubs above; replaced by host tests (mock heap).
/// Written once at init on target; tests serialize access.
pub static mut HEAP_OPS: HeapVeneerOps = DEFAULT_HEAP_OPS;

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime (heap installer, host tests), and in a build where
/// nothing writes it yet, LLVM would otherwise constant-fold the loads to
/// the default stubs and inline their `loop {}` bodies.
#[inline(always)]
fn heap_ops() -> HeapVeneerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS)) }
}

/// Reads the default-heap handle (original global word @ 0x089ca638).
#[inline(always)]
fn default_heap() -> *mut HeapDescriptorDescriptor {
    unsafe { core::ptr::addr_of!(DEFAULT_HEAP).read() }
}

/// lazy_init_default_heap — original: `FUN_08077250` @ 0x08077250
/// (44 bytes).
///
/// Creates the 32 KB default heap on first use: `heap_create(desc, start,
/// 0x8000)` with `start = desc - 0x8000`, storing the returned handle into
/// the global @ 0x089ca638. Subsequent calls return immediately.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_init_default_heap() {
    if !default_heap().is_null() {
        return;
    }
    let storage = core::ptr::addr_of_mut!(DEFAULT_HEAP_STORAGE);
    let desc = core::ptr::addr_of_mut!((*storage).desc) as *mut HeapDescriptor;
    let start = core::ptr::addr_of_mut!((*storage).region) as *mut u8;
    let handle = (heap_ops().create)(desc, start, DEFAULT_HEAP_SIZE);
    core::ptr::addr_of_mut!(DEFAULT_HEAP).write(handle);
}

/// malloc_wrapper — original: `FUN_080eb67c` @ 0x080eb67c (40 bytes).
///
/// Ensures the default heap exists, then allocates `size` bytes from it
/// with caller tag `tag` (telemetry only; see `BlockHeader::link_or_tag`).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn malloc_wrapper(size: usize, tag: usize) -> *mut u8 {
    lazy_init_default_heap();
    (heap_ops().alloc)(default_heap(), size, tag)
}

/// calloc_wrapper — original: `FUN_0807b254` @ 0x0807b254 (44 bytes;
/// 14 bl call sites).
///
/// Ensures the default heap exists, then allocates `size` zerofilled
/// bytes from it with caller tag `tag` (via `heap_alloc_zero` @
/// 0x0819ce00 — the original's tail branch).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calloc_wrapper(size: usize, tag: usize) -> *mut u8 {
    lazy_init_default_heap();
    (heap_ops().alloc_zero)(default_heap(), size, tag)
}

/// free_wrapper — original: `FUN_080e7970` @ 0x080e7970 (40 bytes).
///
/// Frees `ptr` back to the default heap with caller tag `tag`. No NULL
/// guard at this level: `heap_free` @ 0x0819d4dc ignores NULL itself.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn free_wrapper(ptr: *mut u8, tag: usize) {
    lazy_init_default_heap();
    (heap_ops().free)(default_heap(), ptr, tag)
}

/// realloc_wrapper — original: `FUN_080edbf0` @ 0x080edbf0 (56 bytes).
///
/// `a3`/`a4` mirror the original's r2 / stacked fourth argument (both
/// observed as 1 from the ADS `realloc` veneer; semantics live in
/// `heap_realloc` @ 0x0819d6a0).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn realloc_wrapper(
    ptr: *mut u8,
    size: usize,
    a3: usize,
    a4: usize,
) -> *mut u8 {
    lazy_init_default_heap();
    (heap_ops().realloc)(default_heap(), ptr, size, a3, a4)
}

/// operator new (tag 2) — original @ 0x082aadd4 (8 bytes, 1797 call
/// sites — the dominant allocator in osos): `mov r1, #2; b 0x080eb67c`.
///
/// `inline(never)`: on device this is a real function every caller
/// reaches with `bl`. Letting LLVM inline the whole lazy-heap-init path
/// into a caller turns an 11-instruction caller into 38 and destroys
/// the match (see app/singletons.rs).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operator_new(size: usize) -> *mut u8 {
    malloc_wrapper(size, TAG_OPERATOR_NEW)
}

/// operator delete (tag 2) — original @ 0x082aad24 (16 bytes, 665 call
/// sites): NULL-guarded `free_wrapper` with tag 2.
///
/// `inline(never)` for the same reason as `operator_new`: on device
/// this is a real function every caller reaches with `bl`/`b`, and
/// letting LLVM inline the lazy-init + free path into a caller destroys
/// that caller's match (notably `cxx_array_dealloc`, whose whole body
/// is one tail branch here).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operator_delete(ptr: *mut u8) {
    if !ptr.is_null() {
        free_wrapper(ptr, TAG_OPERATOR_NEW);
    }
}

/// operator new (tag 3) — original: `FUN_082aad74` @ 0x082aad74 (8 bytes,
/// 111 `bl` call sites; binary-verified against osos.dec, of which 101 sit
/// inside a function extent Ghidra knows about). Whole body:
///
/// ```text
/// 082aad74:  mov r1, #3        ; caller tag
/// 082aad78:  b   0x080eb67c    ; tail call malloc_wrapper(size, 3)
/// ```
///
/// The tag-2 `operator_new`'s sibling for a second allocation tag: pins
/// the caller tag to 3 and hands `size` straight to `malloc_wrapper`,
/// returning whatever it returns (NULL included — there is no
/// out-of-memory check here; that lives in `operator_new_checked`).
///
/// Note the asymmetry with `operator_delete_tag3`: the alloc side has **no
/// NULL guard** — `size == 0` is passed through to the heap core
/// untouched, exactly like the original's unconditional tail branch.
///
/// Deviations: the original's tail branch is a plain call here (Rust has
/// no guaranteed tail calls), and `malloc_wrapper` dispatches through
/// `HEAP_OPS` rather than branching to 0x080eb67c directly.
/// `inline(never)` for the same reason as the tag-2 pair: on device this
/// is a real `bl` target for 111 call sites, and an 8-byte body is exactly
/// what LLVM would otherwise inline away, dragging the whole lazy-heap-init
/// path into every caller and destroying those callers' matches.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operator_new_tag3(size: usize) -> *mut u8 {
    malloc_wrapper(size, TAG_OPERATOR_NEW_TAG3)
}

/// operator delete (tag 3) — original: `FUN_082aad14` @ 0x082aad14
/// (16 bytes, 155 `bl` call sites + 3 tail `b`; binary-verified against
/// osos.dec, of which 145 `bl` sit inside a function extent Ghidra knows
/// about). The immediate neighbour *below* the tag-2 `operator_delete`
/// @ 0x082aad24, not the same function. Whole body:
///
/// ```text
/// 082aad14:  cmp   r0, #0
/// 082aad18:  movne r1, #3      ; caller tag
/// 082aad1c:  bne   0x080e7970  ; tail call free_wrapper(ptr, 3)
/// 082aad20:  bx    lr          ; NULL: return without touching the heap
/// ```
///
/// The tag-3 half of the pair: `delete NULL` is a no-op that never reaches
/// the heap at all, while a non-NULL pointer is released with caller tag 3.
/// That NULL guard is genuinely absent from `operator_new_tag3` — the C++
/// standard requires it on delete and not on new, and the original encodes
/// exactly that.
///
/// Deviations: the original's conditional tail branch is a plain guarded
/// call here, and `free_wrapper` dispatches through `HEAP_OPS`.
/// `inline(never)`: 155 call sites reach this with `bl` on device.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operator_delete_tag3(ptr: *mut u8) {
    if !ptr.is_null() {
        free_wrapper(ptr, TAG_OPERATOR_NEW_TAG3);
    }
}

/// free_tag4 — original: `FUN_0805d070` @ 0x0805d070 (8 bytes; 46 `bl`
/// + 12 `blne` = 58 `bl`-form call sites, plus 9 `b` + 4 `bne` tail
/// branches = 71 total, all binary-verified by decoding every B/BL word
/// in osos.dec). Whole body:
///
/// ```text
/// 0805d070:  mov r1, #4        ; caller tag
/// 0805d074:  b   0x080e7970    ; tail call free_wrapper(ptr, 4)
/// ```
///
/// The tag-4 deallocation entry. It is *not* an `operator delete`: there
/// is no NULL guard at all, so `free_tag4(NULL)` reaches `free_wrapper`
/// and the heap core (which ignores NULL) — which is why 12 of the 58
/// `bl`-form sites are `blne`, guarding on the caller's side. That makes
/// it the exact structural twin of the tag-2/tag-3 `operator new`
/// veneers rather than of their deletes.
///
/// Tag 4 belongs to the "MemH" managed-buffer family that surrounds this
/// veneer: the handle constructor @ 0x0805d10c allocates its 16-byte
/// header and payload with tag 4 and stamps the header's second word
/// with the magic 0x4d656d48 ("MemH"), the destructor @ 0x0805d028
/// validates that magic and releases both with tag 4, and the family's
/// alloc twins sit immediately below the memset/memcmp block at
/// 0x0805d1d4 (`mov r1, #4; b malloc_wrapper`, ported as
/// [`malloc_tag4`] below) and 0x0805d1dc (`mov r1, #4; b calloc_wrapper`,
/// ported as [`calloc_tag4`] below).
///
/// Deviations: the original's tail branch is a plain call here (Rust has
/// no guaranteed tail calls), and `free_wrapper` dispatches through
/// `HEAP_OPS` instead of branching to 0x080e7970 directly.
/// `inline(never)`: on device 58 call sites reach this with `bl`, and an
/// 8-byte body is exactly what LLVM would otherwise inline away, dragging
/// the whole lazy-heap-init path into every caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn free_tag4(ptr: *mut u8) {
    free_wrapper(ptr, TAG_MEM_BUFFER);
}

/// calloc_tag4 — original: `FUN_0805d1dc` @ 0x0805d1dc (8 bytes; 23 `bl`
/// call sites, binary-verified by decoding every B/BL word in osos.dec —
/// none predicated, no tail `b`). Ghidra's 8-byte extent is exactly
/// right: the word below @ 0x0805d1e4 is a `push {r4-r8, lr}` starting
/// the MemH handle resize/realloc function. Whole body:
///
/// ```text
/// 0805d1dc:  mov r1, #4        ; caller tag
/// 0805d1e0:  b   0x0807b254    ; tail call calloc_wrapper(size, 4)
/// ```
///
/// The zerofill-alloc entry of the "MemH" managed-buffer family @
/// 0x0805d028..0x0805d1e4 (the free half is [`free_tag4`]): pins the
/// caller tag to 4 and hands `size` straight to `calloc_wrapper`,
/// returning whatever it returns (NULL included — no out-of-memory
/// check here, mirroring the original's unconditional tail branch).
/// Structural twin of the malloc veneer [`malloc_tag4`] @ 0x0805d1d4
/// (`mov r1, #4; b malloc_wrapper`). The 23 call sites cluster in two
/// regions: five at 0x080585a0..0x080588c0 and seven at
/// 0x0805df44..0x0805e580 (immediately above the MemH family), the rest
/// scattered (0x08044638, 0x080478d0, 0x08047c10, 0x0805b778,
/// 0x08063a08, 0x08068a54, 0x08068a6c, 0x0807f350, 0x0807fb04,
/// 0x0809ea6c, 0x080e35c0).
///
/// Deviations: the original's tail branch is a plain call here (Rust has
/// no guaranteed tail calls), and `calloc_wrapper` dispatches through
/// the `HEAP_OPS.alloc_zero` slot instead of branching to 0x0807b254
/// directly. `inline(never)`: on device 23 call sites reach this with
/// `bl`, and an 8-byte body is exactly what LLVM would otherwise inline
/// away, dragging the whole lazy-heap-init path into every caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calloc_tag4(size: usize) -> *mut u8 {
    calloc_wrapper(size, TAG_MEM_BUFFER)
}

/// malloc_tag4 — original: `FUN_0805d1d4` @ 0x0805d1d4 (8 bytes; 23 `bl`
/// call sites, binary-verified by decoding every B/BL word in osos.dec —
/// none predicated, no tail `b`, matching Ghidra's count). Ghidra's
/// 8-byte extent is exactly right: the word below @ 0x0805d1dc is the
/// `mov r1, #4` starting [`calloc_tag4`]. Whole body:
///
/// ```text
/// 0805d1d4:  mov r1, #4        ; caller tag
/// 0805d1d8:  b   0x080eb67c    ; tail call malloc_wrapper(size, 4)
/// ```
///
/// The plain-alloc entry of the "MemH" managed-buffer family @
/// 0x0805d028..0x0805d1e4 (the free half is [`free_tag4`], the zerofill
/// half [`calloc_tag4`]): pins the caller tag to 4 and hands `size`
/// straight to `malloc_wrapper`, returning whatever it returns (NULL
/// included — no out-of-memory check here, mirroring the original's
/// unconditional tail branch). Unlike `calloc_tag4`'s clustered sites,
/// the 23 `bl` sites are scattered across the image: 0x0803c148,
/// 0x08057ce0, 0x0805de68, 0x0805e52c, 0x0805f600, 0x080680d4,
/// 0x080681f0, 0x0806e4f8, 0x080866fc, 0x0808d0c4, 0x0808d0ec,
/// 0x0809d9b8, 0x0809ea84, 0x080be6f0, 0x080be874, 0x080ca020,
/// 0x080ca790, 0x080ce588, 0x080ce5c0, 0x080d1b50, 0x080d8cc0,
/// 0x080da6b0, 0x080f0758.
///
/// Deviations: the original's tail branch is a plain call here (Rust has
/// no guaranteed tail calls), and `malloc_wrapper` dispatches through
/// the `HEAP_OPS.alloc` slot instead of branching to 0x080eb67c
/// directly. `inline(never)`: on device 23 call sites reach this with
/// `bl`, and an 8-byte body is exactly what LLVM would otherwise inline
/// away, dragging the whole lazy-heap-init path into every caller.
/// `malloc_wrapper` is reached through its symbol, not a builtin —
/// LLVM cannot swap the call for a libc `malloc` here because the
/// callee carries the tag argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn malloc_tag4(size: usize) -> *mut u8 {
    malloc_wrapper(size, TAG_MEM_BUFFER)
}

/// cpp_finalise_null_guard — original @ 0x082ab254 (16 bytes:
/// `cmp r0, #0; ldmdbne r0, {r2, r3}; bne __cpp_finalise; mov pc, lr`).
///
/// NULL-guarded cookie-loading front-end of `__cpp_finalise` @ 0x080336d8
/// (runtime/atexit): reads the array cookie at `array - 8` (two 32-bit
/// words: element size @ -8, element count @ -4 — the original's single
/// `ldmdb r0, {r2, r3}`) and tail-calls the destructor walk, whose return
/// value is the true block start (`array - 8`). A NULL `array` skips the
/// walk and returns NULL (the original falls through with r0 unchanged).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cpp_finalise_null_guard(
    array: *mut u8,
    dtor: extern "C" fn(*mut u8),
) -> *mut u8 {
    if array.is_null() {
        return array;
    }
    // Cookie words are 32-bit on device; kept u32 so the -8/-4 offsets
    // stay byte-faithful on 64-bit test hosts too. Aligned loads, like
    // the original's `ldmdb` (allocations are always word-aligned).
    let elem_size = *(array.sub(8) as *const u32) as usize;
    let count = *(array.sub(4) as *const u32) as usize;
    crate::runtime::atexit::__cpp_finalise(array, dtor, elem_size, count)
}

/// cxx_vec_delete — original: `FUN_0803170c` @ 0x0803170c (16 bytes;
/// 4 call sites: 0x08267070, 0x082a7164, 0x082a8bec, 0x083b6c10).
///
/// The ADS C++ `delete[]` helper for arrays of objects with destructors:
/// runs `dtor` over every element (via the null-guarded `__cpp_finalise`
/// front-end @ 0x082ab254, LAST element first), then releases the
/// allocation with the tag-3 `operator delete`. A NULL array pointer
/// flows NULL through the guard into the null-guarded
/// `operator_delete_tag3`, making the whole call a no-op.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_vec_delete(ptr: *mut u8, dtor: extern "C" fn(*mut u8)) {
    let block = cpp_finalise_null_guard(ptr, dtor);
    operator_delete_tag3(block);
}

/// cxx_array_dealloc — original: `FUN_08266f2c` @ 0x08266f2c (4 bytes:
/// a single `b 0x082aad24`; 274 `bl` + 2 `b` = 276 call sites,
/// binary-verified — the busiest deallocation entry after `operator
/// delete` itself).
///
/// The ADS C++ array deallocation entry (`operator delete[]`'s
/// cookie-free form, emitted for arrays of trivially destructible
/// elements): a pure tail branch to the tag-2 `operator_delete`. The
/// `count`/`elem` arguments never survive the branch — the callee's
/// first instructions overwrite r1 with the tag and never read r2 — so
/// they are inert here too. Every ported call site passes 0 for `elem`,
/// like the original deque machinery does.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_array_dealloc(ptr: *mut u8, _count: usize, _elem: usize) {
    operator_delete(ptr);
}

/// operator_new_checked — original: `FUN_08266c70` @ 0x08266c70
/// (48 bytes, 223 call sites). The port lives in heap/new_handler.rs
/// alongside the new-handler dispatch it calls with code 3; re-exported
/// here so the cxx/string and string-map callers keep their
/// `heap::veneers::operator_new_checked` paths.
pub use crate::heap::new_handler::operator_new_checked;

/// heap_panic — original: `FUN_08030f44` @ 0x08030f44 (32 bytes). Fatal,
/// does not return.
///
/// Called from the heap core on a corrupt free (zero header word or a
/// header with the free bit already set — double free). Runs the
/// original's rundown path: `__rt_raise(1, 0)` @ 0x080320a8, the exit
/// path @ 0x08035878, then the final terminate stub @ 0x082b20a0 with
/// code 1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_panic() -> ! {
    let ops = heap_ops();
    (ops.raise)(1, 0);
    (ops.exit)();
    (ops.terminate)(1);
    // Safety net: the original's terminate target never returns; if a
    // swapped-in hook does, spin rather than fall off a noreturn fn.
    loop {}
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that swap the global ops table / DEFAULT_HEAP.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Fake heap handle returned by the mock `heap_create`.
    static mut FAKE_HANDLE: HeapDescriptorDescriptor = HeapDescriptorDescriptor {
        desc: core::ptr::null_mut(),
    };

    // Mock heap call log.
    static mut CREATE_CALLS: usize = 0;
    static mut LAST_CREATE_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    static mut LAST_CREATE_START: *mut u8 = core::ptr::null_mut();
    static mut LAST_CREATE_SIZE: usize = 0;
    static mut ALLOC_CALLS: usize = 0;
    static mut LAST_ALLOC_HEAP: *mut HeapDescriptorDescriptor = core::ptr::null_mut();
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut LAST_ALLOC_TAG: usize = 0;
    static mut ALLOC_RET: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_ZERO_CALLS: usize = 0;
    static mut LAST_ALLOC_ZERO_HEAP: *mut HeapDescriptorDescriptor = core::ptr::null_mut();
    static mut LAST_ALLOC_ZERO_SIZE: usize = 0;
    static mut LAST_ALLOC_ZERO_TAG: usize = 0;
    static mut FREE_CALLS: usize = 0;
    static mut LAST_FREE_HEAP: *mut HeapDescriptorDescriptor = core::ptr::null_mut();
    static mut LAST_FREE_PTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_FREE_TAG: usize = 0;
    static mut REALLOC_CALLS: usize = 0;
    static mut LAST_REALLOC_HEAP: *mut HeapDescriptorDescriptor = core::ptr::null_mut();
    static mut LAST_REALLOC_PTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_REALLOC_SIZE: usize = 0;
    static mut LAST_REALLOC_A3: usize = 0;
    static mut LAST_REALLOC_A4: usize = 0;
    static mut NEW_HANDLER_CALLS: usize = 0;
    static mut LAST_NEW_HANDLER_CODE: usize = 0;

    const BLOCK_A: usize = 0xA110_0000;

    unsafe extern "C" fn mock_create(
        desc: *mut HeapDescriptor,
        start: *mut u8,
        size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        CREATE_CALLS += 1;
        LAST_CREATE_DESC = desc;
        LAST_CREATE_START = start;
        LAST_CREATE_SIZE = size;
        core::ptr::addr_of_mut!(FAKE_HANDLE)
    }

    unsafe extern "C" fn mock_alloc(
        heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_CALLS += 1;
        LAST_ALLOC_HEAP = heap;
        LAST_ALLOC_SIZE = size;
        LAST_ALLOC_TAG = tag;
        ALLOC_RET
    }

    unsafe extern "C" fn mock_alloc_zero(
        heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_ZERO_CALLS += 1;
        LAST_ALLOC_ZERO_HEAP = heap;
        LAST_ALLOC_ZERO_SIZE = size;
        LAST_ALLOC_ZERO_TAG = tag;
        ALLOC_RET
    }

    unsafe extern "C" fn mock_free(
        heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        FREE_CALLS += 1;
        LAST_FREE_HEAP = heap;
        LAST_FREE_PTR = ptr;
        LAST_FREE_TAG = tag;
    }

    unsafe extern "C" fn mock_realloc(
        heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        size: usize,
        a3: usize,
        a4: usize,
    ) -> *mut u8 {
        REALLOC_CALLS += 1;
        LAST_REALLOC_HEAP = heap;
        LAST_REALLOC_PTR = ptr;
        LAST_REALLOC_SIZE = size;
        LAST_REALLOC_A3 = a3;
        LAST_REALLOC_A4 = a4;
        ALLOC_RET
    }

    unsafe extern "C" fn mock_new_handler(code: usize) {
        NEW_HANDLER_CALLS += 1;
        LAST_NEW_HANDLER_CODE = code;
    }

    const MOCK_OPS: HeapVeneerOps = HeapVeneerOps {
        alloc: mock_alloc,
        alloc_zero: mock_alloc_zero,
        free: mock_free,
        realloc: mock_realloc,
        create: mock_create,
        new_handler: mock_new_handler,
        // Never reached by these tests (heap_panic is not exercised).
        raise: DEFAULT_HEAP_OPS.raise,
        exit: missing_exit,
        terminate: missing_terminate,
    };

    /// Resets the mock log + DEFAULT_HEAP, installs the mock table,
    /// returns the lock guard. pub(crate): malloc_rt.rs's default-shim
    /// tests route the ADS chain through this mock too.
    pub(crate) fn mock_heap() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            CREATE_CALLS = 0;
            LAST_CREATE_DESC = core::ptr::null_mut();
            LAST_CREATE_START = core::ptr::null_mut();
            LAST_CREATE_SIZE = 0;
            ALLOC_CALLS = 0;
            LAST_ALLOC_HEAP = core::ptr::null_mut();
            LAST_ALLOC_SIZE = 0;
            LAST_ALLOC_TAG = 0;
            ALLOC_RET = BLOCK_A as *mut u8;
            ALLOC_ZERO_CALLS = 0;
            LAST_ALLOC_ZERO_HEAP = core::ptr::null_mut();
            LAST_ALLOC_ZERO_SIZE = 0;
            LAST_ALLOC_ZERO_TAG = 0;
            FREE_CALLS = 0;
            LAST_FREE_HEAP = core::ptr::null_mut();
            LAST_FREE_PTR = core::ptr::null_mut();
            LAST_FREE_TAG = 0;
            REALLOC_CALLS = 0;
            LAST_REALLOC_HEAP = core::ptr::null_mut();
            LAST_REALLOC_PTR = core::ptr::null_mut();
            LAST_REALLOC_SIZE = 0;
            LAST_REALLOC_A3 = 0;
            LAST_REALLOC_A4 = 0;
            NEW_HANDLER_CALLS = 0;
            LAST_NEW_HANDLER_CODE = 0;
            core::ptr::addr_of_mut!(DEFAULT_HEAP).write(core::ptr::null_mut());
            *core::ptr::addr_of_mut!(HEAP_OPS) = MOCK_OPS;
        }
        guard
    }

    /// Mock-log accessors for tests outside this module (malloc_rt.rs).
    /// (calls, size, tag) of the last mock alloc.
    pub(crate) fn alloc_log() -> (usize, usize, usize) {
        unsafe { (ALLOC_CALLS, LAST_ALLOC_SIZE, LAST_ALLOC_TAG) }
    }

    /// Overrides the pointer the mock alloc returns (new_handler.rs's
    /// operator_new_checked tests force allocation failure this way).
    pub(crate) fn set_alloc_ret(ptr: *mut u8) {
        unsafe { ALLOC_RET = ptr }
    }

    /// (calls, ptr, tag) of the last mock free.
    pub(crate) fn free_log() -> (usize, *mut u8, usize) {
        unsafe { (FREE_CALLS, LAST_FREE_PTR, LAST_FREE_TAG) }
    }

    /// (calls, ptr, size, a3, a4) of the last mock realloc.
    pub(crate) fn realloc_log() -> (usize, *mut u8, usize, usize, usize) {
        unsafe {
            (
                REALLOC_CALLS,
                LAST_REALLOC_PTR,
                LAST_REALLOC_SIZE,
                LAST_REALLOC_A3,
                LAST_REALLOC_A4,
            )
        }
    }

    /// The block pointer the mock alloc/realloc return.
    pub(crate) fn mock_block() -> *mut u8 {
        BLOCK_A as *mut u8
    }

    #[test]
    fn lazy_init_creates_default_heap_once() {
        let _lock = mock_heap();
        unsafe {
            lazy_init_default_heap();
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(DEFAULT_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            lazy_init_default_heap();
            lazy_init_default_heap();
            assert_eq!(CREATE_CALLS, 1, "init must run exactly once");
        }
    }

    #[test]
    fn lazy_init_wires_descriptor_and_region_like_the_original() {
        let _lock = mock_heap();
        unsafe {
            lazy_init_default_heap();
            assert_eq!(CREATE_CALLS, 1);
            // Original: heap_create(desc = 0x08a1a710,
            // start = 0x08a1a710 - 0x8000 = 0x08a12710, size = 0x8000) —
            // a 32 KB region immediately below the descriptor.
            assert_eq!(LAST_CREATE_SIZE, 0x8000);
            let storage = core::ptr::addr_of_mut!(DEFAULT_HEAP_STORAGE);
            assert_eq!(
                LAST_CREATE_DESC,
                core::ptr::addr_of_mut!((*storage).desc) as *mut HeapDescriptor
            );
            assert_eq!(
                LAST_CREATE_START,
                core::ptr::addr_of_mut!((*storage).region) as *mut u8
            );
            assert_eq!(
                LAST_CREATE_DESC as usize - LAST_CREATE_START as usize,
                0x8000,
                "region must end where the descriptor begins (desc = start + 0x8000)"
            );
        }
    }

    #[test]
    fn malloc_wrapper_inits_and_passes_tag_through() {
        let _lock = mock_heap();
        unsafe {
            let p = malloc_wrapper(0x120, 7);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(CREATE_CALLS, 1, "wrapper must run the lazy init");
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(LAST_ALLOC_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_ALLOC_SIZE, 0x120);
            assert_eq!(LAST_ALLOC_TAG, 7);
            malloc_wrapper(0x40, 9);
            assert_eq!(CREATE_CALLS, 1, "second call must not re-init");
            assert_eq!(LAST_ALLOC_TAG, 9);
        }
    }

    #[test]
    fn calloc_wrapper_inits_and_routes_to_the_zerofill_veneer() {
        let _lock = mock_heap();
        unsafe {
            let p = calloc_wrapper(0x54, 8);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(CREATE_CALLS, 1, "wrapper must run the lazy init");
            assert_eq!(ALLOC_ZERO_CALLS, 1);
            assert_eq!(LAST_ALLOC_ZERO_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_ALLOC_ZERO_SIZE, 0x54);
            assert_eq!(LAST_ALLOC_ZERO_TAG, 8);
            assert_eq!(ALLOC_CALLS, 0, "never the plain-alloc slot");
            calloc_wrapper(0x18, 5);
            assert_eq!(CREATE_CALLS, 1, "second call must not re-init");
            assert_eq!(LAST_ALLOC_ZERO_TAG, 5);
        }
    }

    #[test]
    fn calloc_wrapper_default_slot_is_the_zerofill_shim() {
        assert_eq!(
            DEFAULT_HEAP_OPS.alloc_zero as usize,
            alloc_zero_ported as usize
        );
    }

    #[test]
    fn free_wrapper_passes_tag_through_without_null_guard() {
        let _lock = mock_heap();
        unsafe {
            free_wrapper(BLOCK_A as *mut u8, 5);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 5);
            // The original has no NULL guard here (heap_free ignores NULL).
            free_wrapper(core::ptr::null_mut(), 5);
            assert_eq!(FREE_CALLS, 2);
            assert!(LAST_FREE_PTR.is_null());
        }
    }

    #[test]
    fn realloc_wrapper_forwards_all_args() {
        let _lock = mock_heap();
        unsafe {
            let p = realloc_wrapper(BLOCK_A as *mut u8, 0x200, 1, 1);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(REALLOC_CALLS, 1);
            assert_eq!(LAST_REALLOC_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_REALLOC_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_REALLOC_SIZE, 0x200);
            assert_eq!(LAST_REALLOC_A3, 1);
            assert_eq!(LAST_REALLOC_A4, 1);
        }
    }

    #[test]
    fn cxx_array_dealloc_is_the_tag_2_delete_with_dead_arguments() {
        let _lock = mock_heap();
        unsafe {
            // NULL flows into the guarded delete: nothing reaches the heap.
            cxx_array_dealloc(core::ptr::null_mut(), 0x20, 0);
            assert_eq!(FREE_CALLS, 0);
            // Same block freed with wildly different count/elem values must
            // produce identical heap traffic — both arguments die at the
            // original's tail branch.
            cxx_array_dealloc(BLOCK_A as *mut u8, 0x20, 0);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 2, "the tag-2 delete, not tag 3");
            cxx_array_dealloc(BLOCK_A as *mut u8, 0, usize::MAX);
            assert_eq!(FREE_CALLS, 2);
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 2);
        }
    }

    #[test]
    fn operator_new_uses_tag_2() {
        let _lock = mock_heap();
        unsafe {
            let p = operator_new(24);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(LAST_ALLOC_SIZE, 24);
            assert_eq!(LAST_ALLOC_TAG, 2);
        }
    }

    #[test]
    fn operator_delete_uses_tag_2_and_guards_null() {
        let _lock = mock_heap();
        unsafe {
            operator_delete(core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 0, "delete(NULL) must not reach the heap");
            operator_delete(BLOCK_A as *mut u8);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 2);
        }
    }

    #[test]
    fn tag3_pair_uses_tag_3() {
        let _lock = mock_heap();
        unsafe {
            let p = operator_new_tag3(48);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(LAST_ALLOC_TAG, 3);
            operator_delete_tag3(core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 0, "tag-3 delete must NULL-guard too");
            operator_delete_tag3(BLOCK_A as *mut u8);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_TAG, 3);
        }
    }

    #[test]
    fn tag3_new_forwards_size_unguarded_and_returns_the_block_verbatim() {
        let _lock = mock_heap();
        unsafe {
            // The original is an unconditional tail branch: every size,
            // including 0, reaches the heap core with tag 3.
            for size in [0usize, 1, 48, 0x1000] {
                let before = ALLOC_CALLS;
                assert_eq!(operator_new_tag3(size), BLOCK_A as *mut u8);
                assert_eq!(ALLOC_CALLS, before + 1, "no guard on the alloc side");
                assert_eq!(LAST_ALLOC_SIZE, size);
                assert_eq!(LAST_ALLOC_TAG, 3);
            }
            assert_eq!(FREE_CALLS, 0, "new must never touch the free path");
            // The heap's return value flows back untouched — a failed
            // allocation surfaces as NULL, not as a retry (that is
            // operator_new_checked's job).
            set_alloc_ret(core::ptr::null_mut());
            assert!(operator_new_tag3(64).is_null());
        }
    }

    #[test]
    fn tag3_delete_null_takes_the_no_op_path() {
        let _lock = mock_heap();
        unsafe {
            // `cmp r0,#0; ... bx lr`: NULL returns without a heap call,
            // and without even running the lazy heap init.
            operator_delete_tag3(core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 0, "delete(NULL) must not reach the heap");
            assert_eq!(CREATE_CALLS, 0, "NULL returns before free_wrapper");
            // Non-NULL forwards the pointer verbatim with tag 3.
            operator_delete_tag3(BLOCK_A as *mut u8);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 3, "tag 3, not the tag-2 delete");
        }
    }

    #[test]
    fn free_tag4_releases_with_tag_4_and_runs_the_lazy_init() {
        let _lock = mock_heap();
        unsafe {
            free_tag4(BLOCK_A as *mut u8);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(CREATE_CALLS, 1, "the veneer runs the lazy heap init");
            assert_eq!(LAST_FREE_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_FREE_TAG, 4, "tag 4, not the operator-delete tags");
            assert_eq!(ALLOC_CALLS, 0, "free must never touch the alloc path");
        }
    }

    #[test]
    fn free_tag4_has_no_null_guard() {
        let _lock = mock_heap();
        unsafe {
            // `mov r1,#4; b free_wrapper` — unconditional. Unlike the two
            // operator deletes, NULL reaches the heap core (which ignores
            // it); the 12 `blne` call sites guard on their own side.
            free_tag4(core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 1, "NULL still reaches the heap");
            assert!(LAST_FREE_PTR.is_null());
            assert_eq!(LAST_FREE_TAG, 4);
        }
    }

    #[test]
    fn calloc_tag4_allocates_zerofilled_with_tag_4_and_runs_the_lazy_init() {
        let _lock = mock_heap();
        unsafe {
            assert_eq!(calloc_tag4(0x120), BLOCK_A as *mut u8);
            assert_eq!(ALLOC_ZERO_CALLS, 1, "routes to the zerofill slot");
            assert_eq!(CREATE_CALLS, 1, "the veneer runs the lazy heap init");
            assert_eq!(LAST_ALLOC_ZERO_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_ALLOC_ZERO_SIZE, 0x120, "size passes through verbatim");
            assert_eq!(LAST_ALLOC_ZERO_TAG, 4, "tag 4, not the operator-new tags");
            assert_eq!(ALLOC_CALLS, 0, "calloc must never touch the plain alloc path");
            assert_eq!(FREE_CALLS, 0, "alloc must never touch the free path");
        }
    }

    #[test]
    fn calloc_tag4_has_no_size_guard_and_passes_failure_through() {
        let _lock = mock_heap();
        unsafe {
            // `mov r1,#4; b calloc_wrapper` — unconditional, like the
            // operator_new veneers: size 0 reaches the heap core
            // untouched.
            for size in [0usize, 1, 48, 0x628] {
                let before = ALLOC_ZERO_CALLS;
                assert_eq!(calloc_tag4(size), BLOCK_A as *mut u8);
                assert_eq!(ALLOC_ZERO_CALLS, before + 1, "no guard on the alloc side");
                assert_eq!(LAST_ALLOC_ZERO_SIZE, size);
                assert_eq!(LAST_ALLOC_ZERO_TAG, 4);
            }
            // The heap's return value flows back untouched — a failed
            // allocation surfaces as NULL, not as a retry.
            set_alloc_ret(core::ptr::null_mut());
            assert!(calloc_tag4(64).is_null());
        }
    }

    #[test]
    fn malloc_tag4_allocates_with_tag_4_and_runs_the_lazy_init() {
        let _lock = mock_heap();
        unsafe {
            assert_eq!(malloc_tag4(0x120), BLOCK_A as *mut u8);
            assert_eq!(ALLOC_CALLS, 1, "routes to the plain-alloc slot");
            assert_eq!(CREATE_CALLS, 1, "the veneer runs the lazy heap init");
            assert_eq!(LAST_ALLOC_HEAP, core::ptr::addr_of_mut!(FAKE_HANDLE));
            assert_eq!(LAST_ALLOC_SIZE, 0x120, "size passes through verbatim");
            assert_eq!(LAST_ALLOC_TAG, 4, "tag 4, not the operator-new tags");
            assert_eq!(ALLOC_ZERO_CALLS, 0, "malloc must never touch the zerofill path");
            assert_eq!(FREE_CALLS, 0, "alloc must never touch the free path");
        }
    }

    #[test]
    fn malloc_tag4_has_no_size_guard_and_passes_failure_through() {
        let _lock = mock_heap();
        unsafe {
            // `mov r1,#4; b malloc_wrapper` — unconditional, like the
            // operator_new veneers: size 0 reaches the heap core
            // untouched.
            for size in [0usize, 1, 48, 0x628] {
                let before = ALLOC_CALLS;
                assert_eq!(malloc_tag4(size), BLOCK_A as *mut u8);
                assert_eq!(ALLOC_CALLS, before + 1, "no guard on the alloc side");
                assert_eq!(LAST_ALLOC_SIZE, size);
                assert_eq!(LAST_ALLOC_TAG, 4);
            }
            // The heap's return value flows back untouched — a failed
            // allocation surfaces as NULL, not as a retry.
            set_alloc_ret(core::ptr::null_mut());
            assert!(malloc_tag4(64).is_null());
        }
    }

    // --- cxx_vec_delete ---

    /// Destructor call log for the vec-delete tests.
    static mut DTOR_CALLS: usize = 0;
    static mut DTOR_SEEN: [usize; 8] = [0; 8];

    extern "C" fn logging_dtor(elem: *mut u8) {
        unsafe {
            DTOR_SEEN[DTOR_CALLS] = elem as usize;
            DTOR_CALLS += 1;
        }
    }

    #[test]
    fn vec_delete_runs_dtors_in_reverse_then_frees_the_cookie_block() {
        let _lock = mock_heap();
        unsafe {
            DTOR_CALLS = 0;
            // Block layout: 8-byte cookie (elem_size, count) + 3 elements
            // of 4 bytes. Word storage keeps the cookie reads aligned.
            let mut block = [0u32; 2 + 3];
            block[0] = 4; // elem_size @ -8
            block[1] = 3; // count @ -4
            let base = block.as_mut_ptr() as *mut u8;
            let array = base.add(8);
            cxx_vec_delete(array, logging_dtor);
            assert_eq!(DTOR_CALLS, 3);
            // Last element first, exactly like __cpp_finalise.
            assert_eq!(DTOR_SEEN[0], array as usize + 8);
            assert_eq!(DTOR_SEEN[1], array as usize + 4);
            assert_eq!(DTOR_SEEN[2], array as usize);
            // The freed pointer is the cookie start (base - 8), tag 3.
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, base);
            assert_eq!(LAST_FREE_TAG, 3);
        }
    }

    #[test]
    fn vec_delete_zero_count_frees_without_dtor_calls() {
        let _lock = mock_heap();
        unsafe {
            DTOR_CALLS = 0;
            let mut block = [0u32; 2];
            block[0] = 4;
            block[1] = 0; // empty array
            let base = block.as_mut_ptr() as *mut u8;
            cxx_vec_delete(base.add(8), logging_dtor);
            assert_eq!(DTOR_CALLS, 0, "no elements, no destructor calls");
            assert_eq!(FREE_CALLS, 1, "the cookie block is still freed");
            assert_eq!(LAST_FREE_PTR, base);
        }
    }

    #[test]
    fn finalise_null_guard_returns_cookie_start_or_null() {
        let _lock = mock_heap();
        unsafe {
            DTOR_CALLS = 0;
            // NULL passes through untouched, no destructor calls.
            assert!(cpp_finalise_null_guard(core::ptr::null_mut(), logging_dtor).is_null());
            assert_eq!(DTOR_CALLS, 0);
            // Non-NULL: walks the cookie-described array (last first) and
            // returns the cookie start (array - 8), like __cpp_finalise.
            let mut block = [0u32; 2 + 2];
            block[0] = 4; // elem_size @ -8
            block[1] = 2; // count @ -4
            let base = block.as_mut_ptr() as *mut u8;
            let array = base.add(8);
            assert_eq!(cpp_finalise_null_guard(array, logging_dtor), base);
            assert_eq!(DTOR_CALLS, 2);
            assert_eq!(DTOR_SEEN[0], array as usize + 4);
            assert_eq!(DTOR_SEEN[1], array as usize);
            assert_eq!(FREE_CALLS, 0, "the guard itself must not free");
        }
    }

    #[test]
    fn vec_delete_null_is_a_complete_no_op() {
        let _lock = mock_heap();
        unsafe {
            DTOR_CALLS = 0;
            cxx_vec_delete(core::ptr::null_mut(), logging_dtor);
            assert_eq!(DTOR_CALLS, 0);
            assert_eq!(FREE_CALLS, 0, "NULL flows into the guarded delete");
        }
    }
}
