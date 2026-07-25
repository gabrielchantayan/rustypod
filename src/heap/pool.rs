//! Port of the retailOS aligned-block pool allocator (cluster
//! 0x0826f560..0x0826f804): a C++ object that owns a private heap (the
//! 0x398-byte app-level heap descriptor embedded at +0x7c of a 0x418-byte
//! control struct) and carves arbitrarily-aligned sub-blocks out of heap
//! allocations. Six create sites (0x080d397c, 0x081246f8, 0x081b5488,
//! 0x081bba48, 0x081bba70, 0x081bba80) call it with a byte size
//! (0x100000 / 0x180000 / 0x500000 / table_value << 19) and a name string.
//!
//! - `pool_create` — original: `FUN_0826f658` @ 0x0826f658 (68 bytes).
//!   `operator new(0x418)` @ 0x082aadd4, then `pool_init`; if the init left
//!   the ready flag clear it runs `pool_destroy` + `operator delete` @
//!   0x082aad24 and returns NULL.
//! - `pool_init` — original: `FUN_0826f79c` @ 0x0826f79c (72 bytes).
//!   Base-subobject ctor @ 0x082141bc (vtable + block deque, arg 1), empty
//!   heap create @ 0x0819d7c8 on the embedded descriptor, clears the ready
//!   flag (+0x414), seeds regions; seed success sets the flag.
//! - `pool_seed_regions` — original: `FUN_0826f560` @ 0x0826f560 (248
//!   bytes; starts 0x18 bytes before the nominal cluster boundary). Fills
//!   the base-class deque with block descriptors covering `size` bytes
//!   (hook @ 0x08213fc4, cap 2000 blocks), then walks it with two 16-byte
//!   deque iterators (element stride 0x28, segment stride 0x500) and adds
//!   every block to the embedded heap via `heap_add_region` @ 0x0819cf68.
//!   Each block is `region_block_size()` bytes (block-manager global
//!   [0x089cb1b4]+0x30, hook @ 0x0818a364) starting at the address the
//!   descriptor maps to (hook @ 0x08280430). Returns 0 on success (and
//!   sets the ready flag itself), 1 on failure.
//! - `pool_alloc` — original: `FUN_0826f6a0` @ 0x0826f6a0 (152 bytes).
//!   The core of the module. Looks up (pad, mask) in the alignment table
//!   (see below), allocates `size + pad` from the embedded heap with
//!   caller tag 0x2b, then aligns: `ptr = (raw + pad) & mask`. The delta
//!   `ptr - raw` (1..=pad, never 0 in practice because heap blocks are
//!   8-aligned and pad >= 4) is stored at `ptr - 4` so `pool_free` can
//!   recover the heap block. If `uncached == 1` (exactly 1) it first
//!   clean+invalidates the D-cache lines covering `[ptr - 4, ptr + size)`
//!   (hook @ 0x08044c10, an `mcr p15,0,rX,c7,c14,1` loop — NOT a memset)
//!   and returns the pointer with bit 31 set: the S5L8702 uncached DRAM
//!   alias, so DMA masters see the buffer coherently. A delta of 0 fails
//!   the allocation (original quirk, dead code with this table).
//! - `pool_alloc_v0` / `pool_alloc_v1` — originals @ 0x0826f73c and
//!   0x0826f780 (28 bytes each). Thin veneers over `pool_alloc` passing
//!   variant 0 / 1 as the stack argument. Variant 0 routes to the
//!   move-preserving heap entry @ 0x0819d2f0 (heap core last-arg 1 =
//!   copy contents when the block moves; inert here because the core's
//!   move hint pointer is always 0), variant 1 to the plain tagged entry
//!   @ 0x0819d67c (the same entry `malloc_wrapper` uses).
//! - `pool_free` — original: `FUN_0826f758` @ 0x0826f758 (40 bytes).
//!   Guards (ready flag, NULL), reloads the delta word, strips the
//!   uncached bit, and tail-branches to `heap_free` @ 0x0819d4dc with
//!   tag 2 (yes — alloc tags 0x2b, free tags 2).
//! - `pool_destroy` — original: `FUN_0826f7e4` @ 0x0826f7e4 (28 bytes).
//!   Clears the ready flag, runs `heap_destroy` @ 0x0819d7e4 on the
//!   embedded descriptor (frees its RTXC mutex), then tail-branches to
//!   the non-deleting base-subobject dtor chain @ 0x08214224. (Ghidra's
//!   `FUN_0826f7e4` decompile is bogus — it inlined that whole chain.)
//!
//! Not ported (outside the assigned cluster, documented for callers): the
//! argument-swapping C++ wrappers @ 0x082aad34 (NULL/flag-guarded
//! `pool_free`) and @ 0x082aad7c (`pool_alloc_v1` with swapped r0/r1).
//!
//! Alignment table (original runtime base @ 0x089cb1bc, 8-byte
//! {pad, mask} entries indexed by class): the decrypted image holds UI
//! layout strings at that vaddr — the whole 0x089cb1xx page is
//! re-initialized at runtime (0x089cb1b4 e.g. becomes the
//! "AMBlockManagerThread" object global), so the table content is not in
//! the image there. It was recovered from a serialized copy @ 0x089d6094
//! (0xdd marker followed by the four pairs) and cross-checked against the
//! class indices passed by every alloc call site (0, 1, 2, 3 only):
//!
//! ```text
//! class 0: pad    4, mask 0xffff_fffc  (word)
//! class 1: pad   16, mask 0xffff_fff0
//! class 2: pad   32, mask 0xffff_ffe0  (cache line)
//! class 3: pad 1024, mask 0xffff_fc00  (DMA page)
//! ```
//!
//! The `mask` constants below are written full-width (`!3` & co.): they
//! equal the binary's 32-bit masks on target, and keep host 64-bit test
//! pointers from being truncated.
//!
//! Heap-dispatch design (deviation, by necessity — the HEAP_OPS pattern
//! of the other heap modules): external callees dispatch indirectly
//! through `POOL_OPS` so host tests can swap in mocks. The heap-facing
//! slots default to the real ports: `operator new`/`delete` @
//! 0x082aadd4/0x082aad24 (veneers.rs), `heap_create_empty` @ 0x0819d7c8 /
//! `heap_destroy` @ 0x0819d7e4 / `heap_add_region` @ 0x0819cf68
//! (init.rs), the alloc entries @ 0x0819d2f0 / 0x0819d67c (wrappers.rs)
//! and `heap_free` @ 0x0819d4dc (free_path.rs). Still stubbed (C++/
//! driver machinery outside the heap): `base_construct` spins,
//! `base_destroy` returns its argument, `deque_fill` reports failure
//! (create then cleanly returns NULL), the block-manager queries return
//! 0/NULL, and `dcache_flush` is a no-op (memory contents unaffected,
//! like the real cache op). The heap "handle" passed around is the
//! embedded `HeapDescriptor*` itself (the `HeapDescriptorDescriptor` of
//! types.rs is a same-layout wrapper used only for the default-heap
//! global).
//!
//! Further simplifications (no observable behavior change):
//! - The deque-node accessor @ 0x08214150 (`add r0, r0, #0x4c; bx lr`)
//!   and the 16-byte iterator copy @ 0x083dd9e4 are pure pointer ops —
//!   inlined instead of routed through hooks.
//! - The delta-word store in `pool_alloc` and load in `pool_free` go
//!   through the *unmarked* address; the original uses the bit-31-set
//!   uncached alias, which is the same DRAM cell on target but
//!   undereferenceable on host.
//! - `heap`/`ready` offsets use `offset_of!` (statically asserted to be
//!   0x7c / 0x414 on 32-bit targets); on 64-bit hosts the widened
//!   `HeapDescriptor` shifts them, which is harmless because the
//!   desc -> pool roundtrip uses the same constant both ways.
//! - Like the original, `pool_alloc` does not bounds-check the alignment
//!   class (`get_unchecked`); classes 0..=3 are the only ones in the
//!   table and the only ones used in osos.

use crate::heap::types::HeapDescriptor;

/// Size of the pool control struct (original: `ldr r0, =0x418`).
const POOL_CONTROL_SIZE: usize = 0x418;

/// Byte offset of the embedded heap descriptor (0x7c on target).
const HEAP_OFFSET: usize = core::mem::offset_of!(PoolControl, heap);

/// Byte offset of the base-subobject block deque (original: 0x4c; the
/// accessor @ 0x08214150 is `this + 0x4c`).
const DEQUE_OFFSET: usize = 0x4c;

/// Caller tag stamped on pool heap allocations (original: `mov r2, #0x2b`).
const TAG_POOL_ALLOC: usize = 0x2b;

/// Caller tag the pool passes to `heap_free` (original: `mov r2, #2`).
const TAG_POOL_FREE: usize = 2;

/// Bit set on returned pointers for uncached (DMA-coherent) allocations:
/// the S5L8702 uncached DRAM alias.
const UNCACHED_MARK: usize = 0x8000_0000;

/// Deque element stride (0x28) and segment stride (0x500) used by the
/// seed walk.
const ELEM_SIZE: usize = 0x28;
const SEGMENT_SIZE: usize = 0x500;

/// Cap on seeded blocks (original: `mov r2, #2000`).
const MAX_SEED_BLOCKS: usize = 2000;

/// The 0x418-byte pool control struct: C++ base subobject (vtable,
/// block deque at +0x4c, ...) up to +0x7c, then the embedded heap
/// descriptor, then the ready flag at +0x414.
#[repr(C)]
pub struct PoolControl {
    /// Base subobject @ +0x000..+0x07c (opaque here; owned by the
    /// ctor/dtor/deque hooks).
    pub base: [u8; 0x7c],
    /// Embedded heap descriptor @ +0x07c.
    pub heap: HeapDescriptor,
    /// Ready flag @ +0x414: set once the heap has been seeded.
    pub ready: u8,
    pub _pad: [u8; 3],
}

// Exact 0x418 layout with the descriptor at 0x7c and the flag at 0x414
// holds on 32-bit targets; on 64-bit hosts the widened HeapDescriptor
// shifts them (harmless — see the module header).
#[cfg(target_pointer_width = "32")]
const _HEAP_OFFSET_CHECK: [u8; 0x7c] = [0; HEAP_OFFSET];
#[cfg(target_pointer_width = "32")]
const _READY_OFFSET_CHECK: [u8; 0x414] = [0; core::mem::offset_of!(PoolControl, ready)];
#[cfg(target_pointer_width = "32")]
const _CONTROL_SIZE_CHECK: [u8; 0x418] = [0; core::mem::size_of::<PoolControl>()];

/// Alignment table entry (original: 8 bytes @ 0x089cb1bc + class * 8).
/// `mask` is the full-width form of the binary's 32-bit mask (see the
/// module header for provenance).
#[derive(Clone, Copy)]
struct AlignClass {
    pad: usize,
    mask: usize,
}

/// The four alignment classes (recovered table, see the module header).
static ALIGN_TABLE: [AlignClass; 4] = [
    AlignClass { pad: 4, mask: !3 },      // 0: word
    AlignClass { pad: 16, mask: !15 },    // 1: 16-byte
    AlignClass { pad: 32, mask: !31 },    // 2: cache line
    AlignClass { pad: 1024, mask: !1023 },// 3: DMA page
];

/// 16-byte deque iterator (copied verbatim by 0x083dd9e4). The deque
/// head at `this + 0x4c` holds the begin iterator, +0x10 the end.
#[repr(C)]
#[derive(Clone, Copy)]
struct DequeIter {
    cur: *mut u8,
    seg_base: *mut u8,
    seg_end: *mut u8,
    seg_slot: *mut *mut u8,
}

/// Indirect dispatch table for the not-yet-ported callees (see the module
/// header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct PoolOps {
    /// C++ `operator new` @ 0x082aadd4 (tag-2 malloc of the control
    /// struct).
    pub new_control: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// C++ `operator delete` @ 0x082aad24 (NULL-guarded tag-2 free).
    pub delete_control: unsafe extern "C" fn(ptr: *mut u8),
    /// Base-subobject ctor @ 0x082141bc (vtable, block deque; `flag` is
    /// always 1 from `pool_init`). Returns `this`.
    pub base_construct: unsafe extern "C" fn(
        this: *mut PoolControl,
        name: *const u8,
        flag: usize,
    ) -> *mut PoolControl,
    /// Non-deleting base-subobject dtor chain @ 0x08214224.
    pub base_destroy: unsafe extern "C" fn(this: *mut PoolControl) -> *mut PoolControl,
    /// Block-deque fill @ 0x08213fc4: populate the deque with block
    /// descriptors covering `size` bytes, at most `max` entries.
    /// Returns nonzero on success, 0 on failure.
    pub deque_fill: unsafe extern "C" fn(
        this: *mut PoolControl,
        size: usize,
        max: usize,
    ) -> i32,
    /// Block-manager region size @ 0x0818a364 (0 when no block manager).
    pub region_block_size: unsafe extern "C" fn() -> u32,
    /// Map a block deque element to its region start @ 0x08280430.
    pub region_start: unsafe extern "C" fn(elem: *const u8) -> *mut u8,
    /// Empty-heap create @ 0x0819d7c8 (no initial region). Returns the
    /// descriptor.
    pub heap_create: unsafe extern "C" fn(desc: *mut HeapDescriptor) -> *mut HeapDescriptor,
    /// Heap destroy @ 0x0819d7e4 (frees the RTXC mutex). Returns the
    /// descriptor.
    pub heap_destroy: unsafe extern "C" fn(desc: *mut HeapDescriptor) -> *mut HeapDescriptor,
    /// Move-preserving tagged heap alloc @ 0x0819d2f0 (heap core last
    /// stack arg = 1).
    pub heap_alloc_alt: unsafe extern "C" fn(
        heap: *mut HeapDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8,
    /// Plain tagged heap alloc @ 0x0819d67c (heap core last stack arg =
    /// 0; the entry `malloc_wrapper` uses).
    pub heap_alloc: unsafe extern "C" fn(
        heap: *mut HeapDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8,
    /// Heap free @ 0x0819d4dc.
    pub heap_free: unsafe extern "C" fn(heap: *mut HeapDescriptor, ptr: *mut u8, tag: usize),
    /// Heap region add @ 0x0819cf68.
    pub heap_add_region: unsafe extern "C" fn(
        heap: *mut HeapDescriptor,
        start: *mut u8,
        size: usize,
    ),
    /// D-cache clean+invalidate of the lines covering [addr, addr+len)
    /// @ 0x08044c10 (`mcr p15,0,rX,c7,c14,1` loop; returns early when
    /// `addr` already has the uncached bit set).
    pub dcache_flush: unsafe extern "C" fn(addr: *mut u8, len: usize),
}

/// Default stub: cannot construct the base subobject — spin.
unsafe extern "C" fn missing_base_construct(
    _this: *mut PoolControl,
    _name: *const u8,
    _flag: usize,
) -> *mut PoolControl {
    loop {}
}

/// Default stub: the non-deleting dtor has nothing to tear down — return
/// the argument, mirroring the original's `this`-returning chain.
unsafe extern "C" fn missing_base_destroy(this: *mut PoolControl) -> *mut PoolControl {
    this
}

/// Default stub: no block source — report failure (0), so `pool_create`
/// cleanly fails instead of seeding an empty heap.
unsafe extern "C" fn missing_deque_fill(
    _this: *mut PoolControl,
    _size: usize,
    _max: usize,
) -> i32 {
    0
}

/// Default stub: no block manager — size 0.
unsafe extern "C" fn missing_region_block_size() -> u32 {
    0
}

/// Default stub: no block manager — NULL.
unsafe extern "C" fn missing_region_start(_elem: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// `heap_alloc_alt` slot shim over `heap_alloc_tag1` @ 0x0819d2f0
/// (wrappers.rs): narrows the tag to the callee's u32.
unsafe extern "C" fn heap_alloc_alt_ported(
    heap: *mut HeapDescriptor,
    size: usize,
    tag: usize,
) -> *mut u8 {
    crate::heap::wrappers::heap_alloc_tag1(heap, size, tag as u32)
}

/// `heap_alloc` slot shim over `heap_alloc` @ 0x0819d67c (wrappers.rs).
unsafe extern "C" fn heap_alloc_ported(
    heap: *mut HeapDescriptor,
    size: usize,
    tag: usize,
) -> *mut u8 {
    crate::heap::wrappers::heap_alloc(heap, size, tag as u32)
}

/// `heap_free` slot shim over `heap_free` @ 0x0819d4dc (free_path.rs;
/// the callee is `C-unwind` for its host tests, hence the shim).
unsafe extern "C" fn heap_free_ported(heap: *mut HeapDescriptor, ptr: *mut u8, tag: usize) {
    crate::heap::free_path::heap_free(heap, ptr, tag);
}

/// `heap_add_region` slot shim over `heap_add_region` @ 0x0819cf68
/// (init.rs): passes the start address as the callee's integer argument
/// and drops the returned descriptor, like the original call site.
unsafe extern "C" fn heap_add_region_ported(
    heap: *mut HeapDescriptor,
    start: *mut u8,
    size: usize,
) {
    crate::heap::init::heap_add_region(heap, start as usize, size);
}

/// Default stub: no cache runtime — no-op (memory contents unaffected,
/// exactly like the real cache maintenance op).
unsafe extern "C" fn missing_dcache_flush(_addr: *mut u8, _len: usize) {}

/// Wired defaults (see the module header): real ports for the heap-facing
/// slots, documented stubs for the unported C++/driver machinery. Host
/// tests swap in mocks and restore this afterwards.
pub(crate) const DEFAULT_POOL_OPS: PoolOps = PoolOps {
    new_control: crate::heap::veneers::operator_new,
    delete_control: crate::heap::veneers::operator_delete,
    base_construct: missing_base_construct,
    base_destroy: missing_base_destroy,
    deque_fill: missing_deque_fill,
    region_block_size: missing_region_block_size,
    region_start: missing_region_start,
    heap_create: crate::heap::init::heap_create_empty,
    heap_destroy: crate::heap::init::heap_destroy,
    heap_alloc_alt: heap_alloc_alt_ported,
    heap_alloc: heap_alloc_ported,
    heap_free: heap_free_ported,
    heap_add_region: heap_add_region_ported,
    dcache_flush: missing_dcache_flush,
};

/// The active pool-machinery implementation. Defaults to the wired table
/// above; replaced by host tests (mocks). Written once at init on
/// target; tests serialize access.
pub static mut POOL_OPS: PoolOps = DEFAULT_POOL_OPS;

/// Reads one op from the table. Volatile so LLVM cannot constant-fold
/// the loads to the default stubs and inline their `loop {}` bodies in
/// builds where nothing writes the table yet (see malloc_rt.rs /
/// veneers.rs). Per-field reads (rather than a whole-table copy) keep
/// the generated code close to the originals' single literal loads.
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(POOL_OPS.$field)) }
    };
}

#[inline(always)]
fn heap_desc(pool: *mut PoolControl) -> *mut HeapDescriptor {
    unsafe { core::ptr::addr_of_mut!((*pool).heap) }
}

#[inline(always)]
fn ready_flag(pool: *mut PoolControl) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*pool).ready) }
}

/// pool_create — original: `FUN_0826f658` @ 0x0826f658 (68 bytes).
///
/// Allocates the 0x418-byte control struct and initializes it. Returns
/// the pool on success; on init failure destroys and deletes it and
/// returns NULL. `name` is the pool name string handed to the base
/// subobject.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_create(size: usize, name: *const u8) -> *mut PoolControl {
    let mem = (op!(new_control))(POOL_CONTROL_SIZE) as *mut PoolControl;
    let pool = pool_init(mem, size, name);
    // Original reads the flag before the NULL check (a NULL `mem` has
    // already faulted inside the ctor chain on target).
    if ready_flag(pool).read() != 0 {
        return pool;
    }
    if !pool.is_null() {
        pool_destroy(pool);
        (op!(delete_control))(pool as *mut u8);
    }
    core::ptr::null_mut()
}

/// pool_init — original: `FUN_0826f79c` @ 0x0826f79c (72 bytes).
///
/// Constructs the base subobject, creates the empty embedded heap,
/// clears the ready flag and seeds the regions; seed success sets the
/// flag. Always returns the control struct.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_init(
    mem: *mut PoolControl,
    size: usize,
    name: *const u8,
) -> *mut PoolControl {
    let this = (op!(base_construct))(mem, name, 1);
    let desc = (op!(heap_create))(heap_desc(this));
    let pool = (desc as *mut u8).sub(HEAP_OFFSET) as *mut PoolControl;
    ready_flag(pool).write(0);
    if pool_seed_regions(pool, size) == 0 {
        ready_flag(pool).write(1);
    }
    pool
}

/// pool_seed_regions — original: `FUN_0826f560` @ 0x0826f560 (248 bytes).
///
/// Fills the block deque (cap 2000 blocks) and walks it with begin/end
/// iterators, adding every block to the embedded heap. Returns 0 on
/// success (setting the ready flag), 1 on failure.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_seed_regions(pool: *mut PoolControl, size: usize) -> i32 {
    if ready_flag(pool).read() != 0 {
        return 1;
    }
    if (op!(deque_fill))(pool, size, MAX_SEED_BLOCKS) == 0 {
        return 1;
    }
    // Original: deque node accessor 0x08214150 (this + 0x4c) and the
    // 16-byte iterator copy 0x083dd9e4 — pure pointer ops, inlined.
    let deque = (pool as *mut u8).add(DEQUE_OFFSET) as *const DequeIter;
    let mut it = deque.read();
    loop {
        let end = deque.add(1).read();
        // Continue while (seg_slot < end.seg_slot), or (== and cur <
        // end.cur) — the original's unsigned `bcc` pairs.
        if it.seg_slot == end.seg_slot {
            if (it.cur as usize) >= (end.cur as usize) {
                break;
            }
        } else if (it.seg_slot as usize) >= (end.seg_slot as usize) {
            break;
        }
        let block_size = (op!(region_block_size))();
        let start = (op!(region_start))(it.cur);
        (op!(heap_add_region))(heap_desc(pool), start, block_size as usize);
        it.cur = it.cur.add(ELEM_SIZE);
        if it.cur == it.seg_end {
            it.seg_slot = it.seg_slot.add(1);
            it.cur = it.seg_slot.read();
            it.seg_base = it.cur;
            it.seg_end = it.cur.add(SEGMENT_SIZE);
        }
    }
    ready_flag(pool).write(1);
    0
}

/// pool_alloc — original: `FUN_0826f6a0` @ 0x0826f6a0 (152 bytes).
///
/// Allocates `size` bytes aligned to `align_class`'s alignment (see the
/// table in the module header). `uncached == 1` flushes the block's cache
/// lines and returns the uncached-alias (bit 31) pointer. `variant`
/// selects the heap entry: 0 = move-preserving @ 0x0819d2f0, anything
/// else = plain @ 0x0819d67c. Returns NULL when the pool is not ready or
/// the heap is exhausted (and, as an original quirk, when the alignment
/// delta would be 0 — dead with this table).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_alloc(
    pool: *mut PoolControl,
    size: usize,
    align_class: usize,
    uncached: usize,
    variant: usize,
) -> *mut u8 {
    if ready_flag(pool).read() == 0 {
        return core::ptr::null_mut();
    }
    let ops_heap = heap_desc(pool);
    // No bounds check in the original — the table is indexed raw.
    let class = ALIGN_TABLE.get_unchecked(align_class);
    let alloc_size = class.pad.wrapping_add(size);
    let raw = if variant == 0 {
        (op!(heap_alloc_alt))(ops_heap, alloc_size, TAG_POOL_ALLOC)
    } else {
        (op!(heap_alloc))(ops_heap, alloc_size, TAG_POOL_ALLOC)
    };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let mut ptr = (raw as usize).wrapping_add(class.pad) & class.mask;
    if uncached == 1 {
        (op!(dcache_flush))((ptr - 4) as *mut u8, size + 4);
        ptr |= UNCACHED_MARK;
    }
    let delta = (ptr & !UNCACHED_MARK).wrapping_sub(raw as usize);
    if delta != 0 {
        // Original stores through the (possibly marked) uncached alias —
        // the same DRAM cell; host tests cannot dereference bit-31
        // addresses, so the store uses the unmarked address.
        (((ptr & !UNCACHED_MARK) - 4) as *mut u32).write(delta as u32);
        return ptr as *mut u8;
    }
    core::ptr::null_mut()
}

/// pool_alloc_v0 veneer — original @ 0x0826f73c (28 bytes): `pool_alloc`
/// with variant 0 (move-preserving heap entry @ 0x0819d2f0).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_alloc_v0(
    pool: *mut PoolControl,
    size: usize,
    align_class: usize,
    uncached: usize,
) -> *mut u8 {
    pool_alloc(pool, size, align_class, uncached, 0)
}

/// pool_alloc_v1 veneer — original @ 0x0826f780 (28 bytes): `pool_alloc`
/// with variant 1 (plain heap entry @ 0x0819d67c).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_alloc_v1(
    pool: *mut PoolControl,
    size: usize,
    align_class: usize,
    uncached: usize,
) -> *mut u8 {
    pool_alloc(pool, size, align_class, uncached, 1)
}

/// pool_free — original: `FUN_0826f758` @ 0x0826f758 (40 bytes).
///
/// Recovers the heap block from the delta word at `ptr - 4` and frees it
/// with tag 2. No-op when the pool is not ready or `ptr` is NULL.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_free(pool: *mut PoolControl, ptr: *mut u8) {
    if ready_flag(pool).read() == 0 || ptr.is_null() {
        return;
    }
    // Original loads the delta through the (possibly marked) uncached
    // alias — same DRAM cell; use the unmarked address (see pool_alloc).
    let unmarked = (ptr as usize) & !UNCACHED_MARK;
    let delta = ((unmarked - 4) as *const u32).read() as usize;
    let raw = unmarked.wrapping_sub(delta);
    (op!(heap_free))(heap_desc(pool), raw as *mut u8, TAG_POOL_FREE);
}

/// pool_destroy — original: `FUN_0826f7e4` @ 0x0826f7e4 (28 bytes).
///
/// Clears the ready flag, destroys the embedded heap, and tail-branches
/// to the non-deleting base-subobject dtor chain (whose result it
/// returns). Does NOT free the control struct — callers do that with
/// `operator delete` (see `pool_create`'s failure path).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_destroy(pool: *mut PoolControl) -> *mut PoolControl {
    ready_flag(pool).write(0);
    let desc = (op!(heap_destroy))(heap_desc(pool));
    let pool = (desc as *mut u8).sub(HEAP_OFFSET) as *mut PoolControl;
    (op!(base_destroy))(pool)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // ---- mock state ----------------------------------------------------

    static mut NEW_CALLS: usize = 0;
    static mut LAST_NEW_SIZE: usize = 0;
    static mut DELETE_CALLS: usize = 0;
    static mut LAST_DELETE_PTR: *mut u8 = core::ptr::null_mut();
    static mut CTOR_CALLS: usize = 0;
    static mut LAST_CTOR_NAME: *const u8 = core::ptr::null();
    static mut LAST_CTOR_FLAG: usize = 0;
    static mut DTOR_CALLS: usize = 0;
    static mut LAST_DTOR_THIS: *mut PoolControl = core::ptr::null_mut();
    static mut FILL_CALLS: usize = 0;
    static mut LAST_FILL_SIZE: usize = 0;
    static mut LAST_FILL_MAX: usize = 0;
    static mut FILL_RET: i32 = 1;
    static mut FILL_SETUP: bool = false;
    static mut CREATE_CALLS: usize = 0;
    static mut LAST_CREATE_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    static mut HEAP_DESTROY_CALLS: usize = 0;
    static mut LAST_HEAP_DESTROY_DESC: *mut HeapDescriptor = core::ptr::null_mut();
    static mut ALLOC_CALLS: usize = 0;
    static mut ALLOC_ALT_CALLS: usize = 0;
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut LAST_ALLOC_TAG: usize = 0;
    static mut ALLOC_RET_NULL: bool = false;
    static mut BUMP: usize = 0;
    static mut FREE_CALLS: usize = 0;
    static mut LAST_FREE_HEAP: *mut HeapDescriptor = core::ptr::null_mut();
    static mut LAST_FREE_PTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_FREE_TAG: usize = 0;
    static mut ADD_REGION_CALLS: usize = 0;
    static mut ADD_REGION_STARTS: [usize; 64] = [0; 64];
    static mut ADD_REGION_SIZES: [usize; 64] = [0; 64];
    static mut FLUSH_CALLS: usize = 0;
    static mut LAST_FLUSH_ADDR: usize = 0;
    static mut LAST_FLUSH_LEN: usize = 0;

    const BLOCK_SIZE: u32 = 0x800;

    #[repr(align(8))]
    struct ControlBuf([u8; 0x800]);
    static mut CONTROL_BUF: ControlBuf = ControlBuf([0; 0x800]);

    /// Deque backing store: two segments, 32 + 8 elements of 0x28 bytes.
    static mut SEG0: [[u8; ELEM_SIZE]; 32] = [[0; ELEM_SIZE]; 32];
    static mut SEG1: [[u8; ELEM_SIZE]; 8] = [[0; ELEM_SIZE]; 8];
    static mut SEG_TAB: [*mut u8; 2] = [core::ptr::null_mut(); 2];

    fn control_ptr() -> *mut PoolControl {
        unsafe { core::ptr::addr_of_mut!(CONTROL_BUF) as *mut PoolControl }
    }

    /// The pool marks uncached allocations by setting pointer bit 31
    /// (`UNCACHED_MARK`) — fine on the 32-bit target, but an ASLR'd host
    /// static can land with bit 31 set, and unmarking then corrupts the
    /// address. Map the arena at a low hint instead, as on the device
    /// (page alignment covers the 1024-byte alignment tests carve at).
    fn arena_ptr() -> *mut u8 {
        use std::sync::OnceLock;
        static ARENA: OnceLock<usize> = OnceLock::new();
        *ARENA.get_or_init(|| {
            extern "C" {
                fn mmap(
                    addr: usize,
                    len: usize,
                    prot: i32,
                    flags: i32,
                    fd: i32,
                    offset: i64,
                ) -> usize;
            }
            #[cfg(target_os = "macos")]
            const MAP_PRIVATE_ANON: i32 = 0x1002;
            #[cfg(target_os = "linux")]
            const MAP_PRIVATE_ANON: i32 = 0x22;
            const PROT_READ_WRITE: i32 = 3;
            let p = unsafe {
                mmap(0x0800_0000, 0x8000, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0)
            };
            assert!(
                p != usize::MAX && p & UNCACHED_MARK == 0,
                "test arena must map below bit 31 (got {p:#x})"
            );
            p
        }) as *mut u8
    }

    /// Writes the begin/end deque iterators into the pool's deque nodes
    /// (pool + 0x4c, pool + 0x5c), covering all 40 mock elements.
    unsafe fn setup_deque(pool: *mut PoolControl) {
        let seg0 = core::ptr::addr_of_mut!(SEG0) as *mut u8;
        let seg1 = core::ptr::addr_of_mut!(SEG1) as *mut u8;
        SEG_TAB[0] = seg0;
        SEG_TAB[1] = seg1;
        let deque = (pool as *mut u8).add(DEQUE_OFFSET) as *mut DequeIter;
        deque.write(DequeIter {
            cur: seg0,
            seg_base: seg0,
            seg_end: seg0.add(SEGMENT_SIZE),
            seg_slot: core::ptr::addr_of_mut!(SEG_TAB[0]),
        });
        deque.add(1).write(DequeIter {
            cur: seg1.add(8 * ELEM_SIZE),
            seg_base: seg1,
            seg_end: seg1.add(SEGMENT_SIZE),
            seg_slot: core::ptr::addr_of_mut!(SEG_TAB[1]),
        });
    }

    // ---- mock ops -------------------------------------------------------

    unsafe extern "C" fn mock_new(size: usize) -> *mut u8 {
        NEW_CALLS += 1;
        LAST_NEW_SIZE = size;
        control_ptr() as *mut u8
    }

    unsafe extern "C" fn mock_delete(ptr: *mut u8) {
        DELETE_CALLS += 1;
        LAST_DELETE_PTR = ptr;
    }

    unsafe extern "C" fn mock_ctor(
        this: *mut PoolControl,
        name: *const u8,
        flag: usize,
    ) -> *mut PoolControl {
        CTOR_CALLS += 1;
        LAST_CTOR_NAME = name;
        LAST_CTOR_FLAG = flag;
        this
    }

    unsafe extern "C" fn mock_dtor(this: *mut PoolControl) -> *mut PoolControl {
        DTOR_CALLS += 1;
        LAST_DTOR_THIS = this;
        this
    }

    unsafe extern "C" fn mock_fill(this: *mut PoolControl, size: usize, max: usize) -> i32 {
        FILL_CALLS += 1;
        LAST_FILL_SIZE = size;
        LAST_FILL_MAX = max;
        if FILL_SETUP {
            setup_deque(this);
        }
        FILL_RET
    }

    unsafe extern "C" fn mock_block_size() -> u32 {
        BLOCK_SIZE
    }

    unsafe extern "C" fn mock_region_start(elem: *const u8) -> *mut u8 {
        // Deterministic distinct start per element.
        (elem as usize + 0x1_0000) as *mut u8
    }

    unsafe extern "C" fn mock_heap_create(desc: *mut HeapDescriptor) -> *mut HeapDescriptor {
        CREATE_CALLS += 1;
        LAST_CREATE_DESC = desc;
        desc
    }

    unsafe extern "C" fn mock_heap_destroy(desc: *mut HeapDescriptor) -> *mut HeapDescriptor {
        HEAP_DESTROY_CALLS += 1;
        LAST_HEAP_DESTROY_DESC = desc;
        desc
    }

    unsafe fn bump_alloc(size: usize, tag: usize) -> *mut u8 {
        LAST_ALLOC_SIZE = size;
        LAST_ALLOC_TAG = tag;
        if ALLOC_RET_NULL {
            return core::ptr::null_mut();
        }
        let p = arena_ptr().add(BUMP);
        BUMP += 0x2000;
        p
    }

    unsafe extern "C" fn mock_heap_alloc(
        _heap: *mut HeapDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_CALLS += 1;
        bump_alloc(size, tag)
    }

    unsafe extern "C" fn mock_heap_alloc_alt(
        _heap: *mut HeapDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_ALT_CALLS += 1;
        bump_alloc(size, tag)
    }

    unsafe extern "C" fn mock_heap_free(
        heap: *mut HeapDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        FREE_CALLS += 1;
        LAST_FREE_HEAP = heap;
        LAST_FREE_PTR = ptr;
        LAST_FREE_TAG = tag;
    }

    unsafe extern "C" fn mock_add_region(
        _heap: *mut HeapDescriptor,
        start: *mut u8,
        size: usize,
    ) {
        if ADD_REGION_CALLS < 64 {
            ADD_REGION_STARTS[ADD_REGION_CALLS] = start as usize;
            ADD_REGION_SIZES[ADD_REGION_CALLS] = size;
        }
        ADD_REGION_CALLS += 1;
    }

    unsafe extern "C" fn mock_flush(addr: *mut u8, len: usize) {
        FLUSH_CALLS += 1;
        LAST_FLUSH_ADDR = addr as usize;
        LAST_FLUSH_LEN = len;
    }

    const MOCK_OPS: PoolOps = PoolOps {
        new_control: mock_new,
        delete_control: mock_delete,
        base_construct: mock_ctor,
        base_destroy: mock_dtor,
        deque_fill: mock_fill,
        region_block_size: mock_block_size,
        region_start: mock_region_start,
        heap_create: mock_heap_create,
        heap_destroy: mock_heap_destroy,
        heap_alloc_alt: mock_heap_alloc_alt,
        heap_alloc: mock_heap_alloc,
        heap_free: mock_heap_free,
        heap_add_region: mock_add_region,
        dcache_flush: mock_flush,
    };

    /// Resets the mock log, installs the mock table, returns the lock
    /// guard.
    fn mock_pool() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            NEW_CALLS = 0;
            LAST_NEW_SIZE = 0;
            DELETE_CALLS = 0;
            LAST_DELETE_PTR = core::ptr::null_mut();
            CTOR_CALLS = 0;
            LAST_CTOR_NAME = core::ptr::null();
            LAST_CTOR_FLAG = 0;
            DTOR_CALLS = 0;
            LAST_DTOR_THIS = core::ptr::null_mut();
            FILL_CALLS = 0;
            LAST_FILL_SIZE = 0;
            LAST_FILL_MAX = 0;
            FILL_RET = 1;
            FILL_SETUP = false;
            CREATE_CALLS = 0;
            LAST_CREATE_DESC = core::ptr::null_mut();
            HEAP_DESTROY_CALLS = 0;
            LAST_HEAP_DESTROY_DESC = core::ptr::null_mut();
            ALLOC_CALLS = 0;
            ALLOC_ALT_CALLS = 0;
            LAST_ALLOC_SIZE = 0;
            LAST_ALLOC_TAG = 0;
            ALLOC_RET_NULL = false;
            BUMP = 0;
            FREE_CALLS = 0;
            LAST_FREE_HEAP = core::ptr::null_mut();
            LAST_FREE_PTR = core::ptr::null_mut();
            LAST_FREE_TAG = 0;
            ADD_REGION_CALLS = 0;
            FLUSH_CALLS = 0;
            LAST_FLUSH_ADDR = 0;
            LAST_FLUSH_LEN = 0;
            core::ptr::write_bytes(control_ptr() as *mut u8, 0, 0x800);
            *core::ptr::addr_of_mut!(POOL_OPS) = MOCK_OPS;
        }
        guard
    }

    /// Fabricates a ready pool without running create.
    unsafe fn ready_pool() -> *mut PoolControl {
        let pool = control_ptr();
        ready_flag(pool).write(1);
        pool
    }

    static POOL_NAME: &[u8] = b"test_pool\0";

    // ---- create / destroy ----------------------------------------------

    #[test]
    fn create_initializes_and_seeds_pool() {
        let _lock = mock_pool();
        unsafe {
            FILL_SETUP = true;
            let pool = pool_create(0x100000, POOL_NAME.as_ptr());
            assert!(!pool.is_null());
            assert_eq!(pool, control_ptr());
            assert_eq!(NEW_CALLS, 1);
            assert_eq!(LAST_NEW_SIZE, 0x418, "control struct is 0x418 bytes");
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(LAST_CTOR_NAME, POOL_NAME.as_ptr());
            assert_eq!(LAST_CTOR_FLAG, 1);
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(LAST_CREATE_DESC, heap_desc(pool));
            assert_eq!(FILL_CALLS, 1);
            assert_eq!(LAST_FILL_SIZE, 0x100000);
            assert_eq!(LAST_FILL_MAX, 2000, "seed caps at 2000 blocks");
            // 40 mock blocks (32 + 8 across the segment boundary).
            assert_eq!(ADD_REGION_CALLS, 40);
            assert!(ready_flag(pool).read() != 0);
            let starts: Vec<usize> = ADD_REGION_STARTS[..40].to_vec();
            for size in &ADD_REGION_SIZES[..40] {
                assert_eq!(*size, BLOCK_SIZE as usize);
            }
            let mut dedup = starts.clone();
            dedup.sort_unstable();
            dedup.dedup();
            assert_eq!(dedup.len(), 40, "region starts must be distinct");
        }
    }

    #[test]
    fn create_failure_destroys_and_deletes() {
        let _lock = mock_pool();
        unsafe {
            FILL_RET = 0; // deque fill fails
            let pool = pool_create(0x100000, POOL_NAME.as_ptr());
            assert!(pool.is_null());
            assert_eq!(ADD_REGION_CALLS, 0, "no regions on failed seed");
            assert_eq!(HEAP_DESTROY_CALLS, 1);
            assert_eq!(LAST_HEAP_DESTROY_DESC, heap_desc(control_ptr()));
            assert_eq!(DTOR_CALLS, 1);
            assert_eq!(LAST_DTOR_THIS, control_ptr());
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(LAST_DELETE_PTR, control_ptr() as *mut u8);
            assert_eq!(ready_flag(control_ptr()).read(), 0);
        }
    }

    #[test]
    fn destroy_clears_flag_and_tears_down() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            let ret = pool_destroy(pool);
            assert_eq!(ready_flag(pool).read(), 0);
            assert_eq!(HEAP_DESTROY_CALLS, 1);
            assert_eq!(LAST_HEAP_DESTROY_DESC, heap_desc(pool));
            assert_eq!(DTOR_CALLS, 1);
            assert_eq!(LAST_DTOR_THIS, pool);
            assert_eq!(ret, pool, "returns the base-dtor chain result");
            assert_eq!(DELETE_CALLS, 0, "destroy does not free the struct");
        }
    }

    // ---- alloc ----------------------------------------------------------

    /// Classes 0..=3 with their alignments; the bump allocator returns
    /// arena+8 (8-aligned only), so every class must carve forward.
    #[test]
    fn alloc_carves_each_alignment_class() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            for (class, align) in [(0usize, 4usize), (1, 16), (2, 32), (3, 1024)] {
                BUMP = 8;
                let raw = arena_ptr().add(8);
                let size = 0x100;
                let ptr = pool_alloc(pool, size, class, 0, 1);
                assert!(!ptr.is_null(), "class {class}");
                assert_eq!(ALLOC_CALLS, class + 1);
                assert_eq!(ALLOC_ALT_CALLS, 0);
                assert_eq!(LAST_ALLOC_SIZE, size + align, "size + pad");
                assert_eq!(LAST_ALLOC_TAG, 0x2b, "allocs tagged 0x2b");
                let unmarked = ptr as usize;
                assert_eq!(unmarked & (align - 1), 0, "class {class} alignment");
                let delta = unmarked - raw as usize;
                assert!(delta > 0 && delta <= align, "delta in 1..=pad");
                assert_eq!(
                    ((unmarked - 4) as *const u32).read() as usize,
                    delta,
                    "delta word at ptr-4"
                );
                assert_eq!(FLUSH_CALLS, 0, "no flush without uncached");
            }
        }
    }

    #[test]
    fn alloc_uncached_flushes_and_marks() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let raw = arena_ptr().add(8);
            let ptr = pool_alloc(pool, 0x100, 2, 1, 1);
            assert_eq!(ptr as usize & UNCACHED_MARK, UNCACHED_MARK);
            let unmarked = ptr as usize & !UNCACHED_MARK;
            assert_eq!(unmarked & 31, 0, "class 2 = 32-byte alignment");
            assert_eq!(FLUSH_CALLS, 1);
            assert_eq!(LAST_FLUSH_ADDR, unmarked - 4);
            assert_eq!(LAST_FLUSH_LEN, 0x100 + 4, "flush covers delta word + body");
            let delta = unmarked - raw as usize;
            assert_eq!(((unmarked - 4) as *const u32).read() as usize, delta);
        }
    }

    #[test]
    fn alloc_uncached_only_when_exactly_one() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let ptr = pool_alloc(pool, 0x40, 1, 2, 1); // uncached = 2
            assert_eq!(ptr as usize & UNCACHED_MARK, 0);
            assert_eq!(FLUSH_CALLS, 0, "original compares uncached == 1");
        }
    }

    #[test]
    fn alloc_v0_uses_alt_heap_entry() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let ptr = pool_alloc_v0(pool, 0x40, 1, 0);
            assert!(!ptr.is_null());
            assert_eq!(ALLOC_ALT_CALLS, 1);
            assert_eq!(ALLOC_CALLS, 0);
        }
    }

    #[test]
    fn alloc_v1_uses_plain_heap_entry() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let ptr = pool_alloc_v1(pool, 0x40, 1, 0);
            assert!(!ptr.is_null());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_ALT_CALLS, 0);
        }
    }

    #[test]
    fn alloc_exhaustion_returns_null() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            ALLOC_RET_NULL = true;
            assert!(pool_alloc(pool, 0x100, 0, 0, 1).is_null());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(FLUSH_CALLS, 0);
        }
    }

    #[test]
    fn alloc_on_unready_pool_returns_null() {
        let _lock = mock_pool();
        unsafe {
            let pool = control_ptr(); // ready = 0 from the wiped buffer
            assert!(pool_alloc(pool, 0x100, 0, 0, 1).is_null());
            assert_eq!(ALLOC_CALLS, 0, "heap untouched when not ready");
        }
    }

    // ---- free -----------------------------------------------------------

    #[test]
    fn free_recovers_block_from_delta_word() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let ptr = pool_alloc(pool, 0x100, 2, 0, 1); // 32-aligned carve
            let raw = arena_ptr().add(8);
            pool_free(pool, ptr);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_HEAP, heap_desc(pool));
            assert_eq!(LAST_FREE_PTR, raw, "free must recover the heap block");
            assert_eq!(LAST_FREE_TAG, 2, "free passes tag 2");
        }
    }

    #[test]
    fn free_strips_uncached_mark() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            BUMP = 8;
            let ptr = pool_alloc(pool, 0x100, 2, 1, 1); // marked pointer
            assert_eq!(ptr as usize & UNCACHED_MARK, UNCACHED_MARK);
            let raw = arena_ptr().add(8);
            pool_free(pool, ptr);
            assert_eq!(LAST_FREE_PTR, raw);
        }
    }

    #[test]
    fn free_guards_null_and_unready() {
        let _lock = mock_pool();
        unsafe {
            let pool = ready_pool();
            pool_free(pool, core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 0, "free(NULL) is a no-op");
            ready_flag(pool).write(0);
            pool_free(pool, arena_ptr());
            assert_eq!(FREE_CALLS, 0, "free on unready pool is a no-op");
        }
    }
}
