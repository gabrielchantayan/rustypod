//! Port of the C++ block-deque container machinery behind the aligned-
//! block pool allocator (heap/pool.rs) — the base subobject of the pool
//! control struct (a "block-manager client with a deque of block
//! descriptors") and the deque primitives it is built on:
//!
//! - `deque_node_accessor` — original: `FUN_08214150` @ 0x08214150
//!   (8 bytes: `add r0, r0, #0x4c; bx lr`; 1 bl call site @ 0x0826f59c
//!   in `pool_seed_regions`, binary-verified). Returns the address of
//!   the base subobject's block deque (+0x4c).
//! - `deque_iter_copy` — original: `FUN_083dd9e4` @ 0x083dd9e4
//!   (36 bytes; 2 bl call sites @ 0x0826f5b0 / 0x0826f61c, both in
//!   `pool_seed_regions`, binary-verified). Copies a 16-byte deque
//!   iterator word by word. ABI quirk kept: dst in r0, src in **r2** —
//!   r1 is scratch the callee never reads (both stock call sites happen
//!   to leave the deque pointer there), so the export keeps the
//!   three-argument shape.
//! - `deque_seg_capacity` — original: `FUN_083d9ec0` @ 0x083d9ec0
//!   (8 bytes: `mov r0, #0x20; bx lr`; 7 bl call sites, binary-
//!   verified). Elements per deque segment: 0x20 elements of 0x28 bytes
//!   = the 0x500-byte segment stride of the seed walk.
//! - `deque_iter_init` — original: `FUN_083d9eec` @ 0x083d9eec
//!   (68 bytes; 9 bl call sites, binary-verified). Builds an iterator:
//!   `cur` as given; `seg_base`/`seg_end` from the segment-map slot
//!   (`*slot` and `*slot + 0x20 * 0x28`, the latter via a real
//!   `deque_seg_capacity` call) or NULL when `slot` is NULL.
//! - `deque_pop_front` — original: `FUN_083ddbdc` @ 0x083ddbdc
//!   (204 bytes; 4 bl call sites @ 0x0814c724, 0x081fc0c8, 0x08214250,
//!   0x083ddcbc, binary-verified). Pops the front element: advances
//!   `begin.cur` by 0x28, decrements the count, virtual-calls the
//!   element's destructor (vtable slot 0 — elements are polymorphic
//!   block descriptors), and when the segment is spent (or the deque is
//!   now empty) retires it: frees the old segment through the
//!   deallocator, advances the segment-map slot, and either re-anchors
//!   `begin` on the next segment or (empty) resets both iterators to
//!   NULL and frees the segment map itself. The stale `map`/`map_cap`
//!   words are deliberately not cleared — the original leaves them
//!   dangling too.
//! - `client_handle_get` — original: `FUN_083d64f4` @ 0x083d64f4
//!   (16 bytes). `*slot ? **slot : NULL` — reads the block-manager
//!   client handle out of the base object's two-level client ref
//!   (+0x4). Every user re-derefs before each call, and so do the
//!   ported callers.
//! - `pool_base_construct` — original: `FUN_082141bc` @ 0x082141bc
//!   (100 bytes; 1 bl call site @ 0x0826f7ac in `pool_init`, binary-
//!   verified). Parent-class ctor (0x081f0050, ops slot), installs the
//!   class vtable, zeroes the deque (both iterators NULL via a real
//!   `deque_iter_init(_, 0, 0)` call, count/map/map_cap 0), creates the
//!   +0x78 mailbox via `mailbox_slot_create` @ 0x0808e294
//!   (kernel/kobj.rs, real port). Returns `this`.
//! - `pool_base_release_blocks` — original: `FUN_08214158` @ 0x08214158
//!   (100 bytes; 1 bl call site @ 0x08214238 in the dtor, binary-
//!   verified). Under the base mutex: when the deque is non-empty and a
//!   client is attached, hands the block descriptors back to the block
//!   manager (erase @ 0x081fc080 + commit @ 0x081fc884, ops slots; the
//!   client handle is re-read before every call, faithfully), then
//!   zeroes the fill counters (+0x44/+0x48). The original tail-branches
//!   through the mutex unlock and returns its status; the only caller
//!   ignores it, so the port returns ().
//! - `pool_base_destroy` — original @ 0x08214224 (76 bytes incl. the
//!   vtable literal; NOT in Ghidra's function list — it decompiled the
//!   chain inlined into `pool_destroy`, whose tail `b 0x0826f800 ->
//!   0x08214224` is binary-verified, the sole call site). Non-deleting
//!   dtor: re-installs the class vtable, `pool_base_release_blocks`,
//!   deletes the +0x78 mailbox via `mailbox_slot_delete` @ 0x080a6bec
//!   (real port), drains the deque with real `deque_pop_front` calls
//!   while the count is nonzero, then tail-calls the parent dtor
//!   (0x081f00a0, ops slot) whose result (`this`) it returns.
//! - `block_deque_fill` — original: `FUN_08213fc4` @ 0x08213fc4
//!   (280 bytes; 1 bl call site @ 0x0826f580 in `pool_seed_regions`,
//!   binary-verified). Under the base mutex, populates the deque with
//!   block descriptors covering `size` bytes (at most `max`, stored at
//!   +0x48 and doubling as the wait timeout): computes the block count
//!   `ceil(size / region_block_size())` via a real `__rt_udiv` call
//!   (block size read twice, faithfully), stores it at +0x44, attaches
//!   the block-manager client (0x081efc8c, ops slot — gate), reserves
//!   `count * block_size` bytes (0x081fbe4c, 32-bit product like the
//!   original `mul`), waits up to one `queue_wait` (0x080b4adc, ops
//!   slot, on the +0x78 mailbox) for 0x40000 bytes of client headroom
//!   (0x081fc3f4), then asks the client to populate the deque
//!   (0x081fc298) and returns its result. Both post-reserve failure
//!   paths (no headroom / populate returned 0) virtual-call the
//!   object's `fill_failed` vtable slot (+0x10) before returning 0;
//!   pre-reserve failures (bad args, attach or reserve refused) do not.
//!   `size` is compared signed (`ble`), kept as-is.
//!
//! # Base subobject layout ([`PoolBase`], 0x7c bytes on target)
//!
//! Recovered from the ctor/dtor/fill/parent-ctor machine code; offsets
//! statically asserted on 32-bit targets:
//!
//! ```text
//! +0x00 vtable            (class vtable @ 0x08993120, see below)
//! +0x04 client_ref        (two-level block-manager client ref)
//! +0x08 mutex             (0x1c-byte C++ recursive mutex, opaque here)
//! +0x24 parent_mailbox    (parent-class mailbox slot)
//! +0x28 parent_flags      (+0x28 zeroed, +0x29 = ctor flag byte)
//! +0x2c name_state        (0x18-byte name object, opaque here)
//! +0x44 fill_block_count  (deque_fill's computed block count)
//! +0x48 fill_cap          (deque_fill's max/timeout argument)
//! +0x4c deque             (BlockDeque: begin/end iters, count, map)
//! +0x78 mailbox           (fill's wait channel, mailbox_slot_* pair)
//! ```
//!
//! # Deviations
//!
//! - **Vtable**: both the ctor and dtor install the literal vtable
//!   pointer 0x08993120, but that page is ADS runtime-initialized RW
//!   data — the decrypted image holds stale bytes there (its "slots"
//!   point mid-function), and no serialized copy exists in the image
//!   (scanned), so the real slot contents are unrecoverable. The port
//!   models the one slot the ported cluster dispatches (+0x10,
//!   `fill_failed`) as [`POOL_BASE_VTABLE`], with a documented no-op
//!   default; the virtual dispatch itself is faithful (through the
//!   object's vtable pointer, so subclass/test vtables are honored).
//! - **Ops table** ([`POOL_BASE_OPS`], house pattern): the unported
//!   callees dispatch indirectly. Parent ctor/dtor @ 0x081f0050 /
//!   0x081f00a0 default to faithful-subset stubs (the ctor stub zeroes
//!   `client_ref` — the one parent field this cluster reads — and both
//!   return `this`); the block-manager client calls (0x081efc8c,
//!   0x081fbe4c, 0x081fc3f4, 0x081fc298, 0x081fc080, 0x081fc884)
//!   default to failure/no-op stubs matching the no-manager state;
//!   `queue_wait` @ 0x080b4adc defaults to a no-op (its result is
//!   discarded by the only ported caller); `seg_dealloc` @ 0x08266f2c
//!   (the C++ array deallocator: NULL-guarded lazy-init free to the
//!   default heap with stats, 276 call sites — identified, not ported)
//!   defaults to a behaviorally equivalent shim over the real
//!   `free_wrapper` (heap_free ignores the tag, and the original
//!   ignores its count argument). The mailbox slot pair defaults to the
//!   real kernel/kobj.rs ports.
//! - **Mutex**: the base mutex at +0x8 is locked/unlocked through the
//!   same unported C++ recursive-mutex pair @ 0x082e8390 / 0x082e83d8
//!   as the region mutexes, so this module dispatches through
//!   block_region.rs's `REGION_MUTEX_OPS` (one boundary for one
//!   original pair; defaults are documented no-ops).
//! - Field access is by typed struct field, never literal byte offset,
//!   so the 32-bit target layout is exact while 64-bit host tests get
//!   disjoint (wider) fields — the block_region.rs lesson.
//! - `block_deque_fill` with no block manager divides by zero in
//!   `__rt_udiv` (block size 0) exactly like the original would; on
//!   device the manager exists before any pool is created.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::kernel::kobj::Mailbox;

/// Deque element stride in bytes (block descriptor objects).
pub const DEQUE_ELEM_SIZE: usize = 0x28;

/// Deque segment size in bytes: `deque_seg_capacity() * DEQUE_ELEM_SIZE`.
pub const DEQUE_SEG_BYTES: usize = 0x500;

/// Byte-count threshold `block_deque_fill` requires from the client
/// before populating (original: `mov r1, #0x40000`).
const FILL_HEADROOM: usize = 0x40000;

/// 16-byte deque iterator (target layout; copied verbatim by
/// `deque_iter_copy`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DequeIter {
    /// Current element.
    pub cur: *mut u8,
    /// Start of the current segment.
    pub seg_base: *mut u8,
    /// End of the current segment (`seg_base + 0x500`).
    pub seg_end: *mut u8,
    /// Slot in the segment map holding the current segment.
    pub seg_slot: *mut *mut u8,
}

impl DequeIter {
    /// All-NULL iterator (the empty deque's begin/end value).
    pub const NULL: DequeIter = DequeIter {
        cur: core::ptr::null_mut(),
        seg_base: core::ptr::null_mut(),
        seg_end: core::ptr::null_mut(),
        seg_slot: core::ptr::null_mut(),
    };
}

/// The block deque (0x2c bytes at +0x4c of the base subobject).
#[repr(C)]
pub struct BlockDeque {
    /// Begin iterator (+0x00 of the node, +0x4c of the base).
    pub begin: DequeIter,
    /// End iterator (+0x10).
    pub end: DequeIter,
    /// Element count (+0x20).
    pub count: u32,
    /// Segment-pointer map (+0x24).
    pub map: *mut *mut u8,
    /// Map capacity handed to the deallocator when the deque empties
    /// (+0x28).
    pub map_cap: u32,
}

/// The class vtable, modeled down to the one slot the ported cluster
/// dispatches (see the module-header vtable deviation).
#[repr(C)]
pub struct PoolBaseVtable {
    /// Slots +0x00..+0x10: contents unrecoverable (stale RW init data).
    pub unresolved: [usize; 4],
    /// Slot +0x10: fill-failure callback, virtual-called by
    /// `block_deque_fill` on both post-reserve failure paths.
    pub fill_failed: unsafe extern "C" fn(this: *mut PoolBase),
}

/// Default `fill_failed`: the original target is unrecoverable (see the
/// module header) — documented no-op.
unsafe extern "C" fn missing_fill_failed(_this: *mut PoolBase) {}

/// The class vtable instance installed by ctor and dtor (original
/// literal pointer: 0x08993120).
pub static POOL_BASE_VTABLE: PoolBaseVtable = PoolBaseVtable {
    unresolved: [0; 4],
    fill_failed: missing_fill_failed,
};

/// The pool base subobject (0x7c bytes on target — the module header
/// maps every field to its recovered offset).
#[repr(C)]
pub struct PoolBase {
    pub vtable: *const PoolBaseVtable,
    pub client_ref: *const *mut u8,
    /// C++ recursive mutex storage (opaque; locked by address through
    /// the REGION_MUTEX_OPS boundary).
    pub mutex: [u32; 7],
    pub parent_mailbox: *mut Mailbox,
    pub parent_flags: [u8; 4],
    /// Parent-class name object (opaque).
    pub name_state: [u32; 6],
    pub fill_block_count: u32,
    pub fill_cap: u32,
    pub deque: BlockDeque,
    pub mailbox: *mut Mailbox,
}

// Target-exact layout (asserted only where the original offsets exist).
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x04] = [0; core::mem::offset_of!(PoolBase, client_ref)];
    const _: [u8; 0x08] = [0; core::mem::offset_of!(PoolBase, mutex)];
    const _: [u8; 0x24] = [0; core::mem::offset_of!(PoolBase, parent_mailbox)];
    const _: [u8; 0x28] = [0; core::mem::offset_of!(PoolBase, parent_flags)];
    const _: [u8; 0x2c] = [0; core::mem::offset_of!(PoolBase, name_state)];
    const _: [u8; 0x44] = [0; core::mem::offset_of!(PoolBase, fill_block_count)];
    const _: [u8; 0x48] = [0; core::mem::offset_of!(PoolBase, fill_cap)];
    const _: [u8; 0x4c] = [0; core::mem::offset_of!(PoolBase, deque)];
    const _: [u8; 0x78] = [0; core::mem::offset_of!(PoolBase, mailbox)];
    const _: [u8; 0x7c] = [0; core::mem::size_of::<PoolBase>()];
    const _: [u8; 0x2c] = [0; core::mem::size_of::<BlockDeque>()];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(PoolBaseVtable, fill_failed)];
}

/// Signature of a deque element's virtual destructor (element vtable
/// slot 0, dispatched by `deque_pop_front`).
type ElemDtor = unsafe extern "C" fn(elem: *mut u8);

/// Indirect dispatch table for the unported callees (see the module
/// header for each default's contract).
#[derive(Clone, Copy)]
pub struct PoolBaseOps {
    /// Parent-class ctor @ 0x081f0050 (vtable, mutex init, +0x24
    /// mailbox, flag byte, name). Returns `this`.
    pub parent_construct: unsafe extern "C" fn(
        this: *mut PoolBase,
        name: *const u8,
        flag: usize,
    ) -> *mut PoolBase,
    /// Parent-class non-deleting dtor @ 0x081f00a0. Returns `this`.
    pub parent_destroy: unsafe extern "C" fn(this: *mut PoolBase) -> *mut PoolBase,
    /// Mailbox slot pair @ 0x0808e294 / 0x080a6bec (kernel/kobj.rs —
    /// defaults are the real ports).
    pub mailbox_slot_create: unsafe extern "C" fn(slot: *mut *mut Mailbox),
    pub mailbox_slot_delete: unsafe extern "C" fn(slot: *mut *mut Mailbox),
    /// Block-manager client attach @ 0x081efc8c: creates/joins the
    /// shared client object and installs the client ref. Nonzero on
    /// success — the fill gate.
    pub client_attach: unsafe extern "C" fn(this: *mut PoolBase) -> i32,
    /// Client byte reservation @ 0x081fbe4c `(client, bytes, 0)`.
    /// Nonzero on success.
    pub client_reserve:
        unsafe extern "C" fn(client: *mut u8, bytes: usize, zero: usize) -> i32,
    /// Client headroom check @ 0x081fc3f4 `(client, bytes)`. Nonzero
    /// when at least `bytes` are available.
    pub client_avail: unsafe extern "C" fn(client: *mut u8, bytes: usize) -> i32,
    /// Client deque populate @ 0x081fc298 `(client, count, deque)`.
    /// Nonzero on success — `block_deque_fill`'s return value.
    pub client_populate:
        unsafe extern "C" fn(client: *mut u8, count: usize, deque: *mut BlockDeque) -> i32,
    /// Block hand-back pair @ 0x081fc080 `(client, deque)` /
    /// 0x081fc884 `(client)`.
    pub client_erase: unsafe extern "C" fn(client: *mut u8, deque: *mut BlockDeque),
    pub client_erase_commit: unsafe extern "C" fn(client: *mut u8),
    /// Mailbox queue-get wait @ 0x080b4adc `(slot, timeout)`; result
    /// discarded by the fill loop.
    pub queue_wait: unsafe extern "C" fn(slot: *mut *mut Mailbox, timeout: u32) -> u32,
    /// Segment/map deallocator @ 0x08266f2c `(ptr, count)` — the count
    /// is ignored by the original too.
    pub seg_dealloc: unsafe extern "C" fn(ptr: *mut u8, count: usize),
}

/// Default parent ctor stub: faithful subset — zeroes `client_ref` (the
/// one parent field this cluster reads; the real ctor zeroes it too)
/// and returns `this`.
unsafe extern "C" fn stub_parent_construct(
    this: *mut PoolBase,
    _name: *const u8,
    _flag: usize,
) -> *mut PoolBase {
    (*this).client_ref = core::ptr::null();
    this
}

/// Default parent dtor stub: nothing of the parent is modeled — return
/// `this` like the original chain.
unsafe extern "C" fn stub_parent_destroy(this: *mut PoolBase) -> *mut PoolBase {
    this
}

/// Default client stubs: no block manager — attach/reserve/avail/
/// populate report failure, the hand-back pair is a no-op.
unsafe extern "C" fn stub_client_attach(_this: *mut PoolBase) -> i32 {
    0
}

unsafe extern "C" fn stub_client_reserve(_client: *mut u8, _bytes: usize, _zero: usize) -> i32 {
    0
}

unsafe extern "C" fn stub_client_avail(_client: *mut u8, _bytes: usize) -> i32 {
    0
}

unsafe extern "C" fn stub_client_populate(
    _client: *mut u8,
    _count: usize,
    _deque: *mut BlockDeque,
) -> i32 {
    0
}

unsafe extern "C" fn stub_client_erase(_client: *mut u8, _deque: *mut BlockDeque) {}

unsafe extern "C" fn stub_client_erase_commit(_client: *mut u8) {}

/// Default queue wait stub: nothing to wait on without the kernel
/// queue machinery; the caller discards the result.
unsafe extern "C" fn stub_queue_wait(_slot: *mut *mut Mailbox, _timeout: u32) -> u32 {
    0
}

/// Default `seg_dealloc`: behaviorally equivalent shim over the real
/// default-heap free path (see the module-header ops deviation).
unsafe extern "C" fn seg_dealloc_shim(ptr: *mut u8, _count: usize) {
    if !ptr.is_null() {
        crate::heap::veneers::free_wrapper(ptr, 0);
    }
}

/// Wired defaults (real ports where they exist, documented stubs for
/// the unported block-manager client and parent class).
pub(crate) const DEFAULT_POOL_BASE_OPS: PoolBaseOps = PoolBaseOps {
    parent_construct: stub_parent_construct,
    parent_destroy: stub_parent_destroy,
    mailbox_slot_create: crate::kernel::kobj::mailbox_slot_create,
    mailbox_slot_delete: crate::kernel::kobj::mailbox_slot_delete,
    client_attach: stub_client_attach,
    client_reserve: stub_client_reserve,
    client_avail: stub_client_avail,
    client_populate: stub_client_populate,
    client_erase: stub_client_erase,
    client_erase_commit: stub_client_erase_commit,
    queue_wait: stub_queue_wait,
    seg_dealloc: seg_dealloc_shim,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the defaults.
pub static mut POOL_BASE_OPS: PoolBaseOps = DEFAULT_POOL_BASE_OPS;

/// Reads one op (volatile — same rationale as every dispatch table).
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(POOL_BASE_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// The base mutex address (this + 0x8), as passed to the lock pair.
#[inline(always)]
unsafe fn base_mutex(this: *mut PoolBase) -> *mut u8 {
    core::ptr::addr_of_mut!((*this).mutex) as *mut u8
}

/// deque_node_accessor — original: `FUN_08214150` @ 0x08214150
/// (8 bytes).
///
/// The base subobject's block deque (+0x4c on target).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_node_accessor(this: *mut PoolBase) -> *mut BlockDeque {
    core::ptr::addr_of_mut!((*this).deque)
}

/// deque_iter_copy — original: `FUN_083dd9e4` @ 0x083dd9e4 (36 bytes).
///
/// Word-by-word 16-byte iterator copy. `_r1` preserves the original ABI
/// (src travels in r2; r1 is never read — see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_iter_copy(dst: *mut DequeIter, _r1: usize, src: *const DequeIter) {
    dst.write(src.read());
}

/// deque_seg_capacity — original: `FUN_083d9ec0` @ 0x083d9ec0
/// (8 bytes).
///
/// Elements per deque segment (0x20).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_seg_capacity() -> usize {
    0x20
}

/// deque_iter_init — original: `FUN_083d9eec` @ 0x083d9eec (68 bytes).
///
/// Anchors an iterator at `cur` inside the segment held by `slot`
/// (NULL slot: NULL segment bounds). Returns `iter`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_iter_init(
    iter: *mut DequeIter,
    cur: *mut u8,
    slot: *mut *mut u8,
) -> *mut DequeIter {
    (*iter).cur = cur;
    if slot.is_null() {
        (*iter).seg_base = core::ptr::null_mut();
        (*iter).seg_end = core::ptr::null_mut();
    } else {
        let base = slot.read();
        (*iter).seg_base = base;
        (*iter).seg_end = base.add(deque_seg_capacity() * DEQUE_ELEM_SIZE);
    }
    (*iter).seg_slot = slot;
    iter
}

/// client_handle_get — original: `FUN_083d64f4` @ 0x083d64f4
/// (16 bytes).
///
/// Reads the block-manager client handle through the base object's
/// two-level client ref: `*slot ? **slot : NULL`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn client_handle_get(ref_slot: *const *const *mut u8) -> *mut u8 {
    let client_ref = ref_slot.read();
    if client_ref.is_null() {
        return core::ptr::null_mut();
    }
    client_ref.read()
}

/// The base object's client handle (`client_handle_get(this + 0x4)`,
/// the shape every original call site uses).
#[inline(always)]
unsafe fn base_client(this: *mut PoolBase) -> *mut u8 {
    client_handle_get(core::ptr::addr_of!((*this).client_ref) as *const *const *mut u8)
}

/// deque_pop_front — original: `FUN_083ddbdc` @ 0x083ddbdc (204 bytes).
///
/// Destroys and removes the front element; retires spent segments and,
/// on the last element, the segment map (see the module header). The
/// original returns a meaningless r0/r1 pair every caller ignores.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_pop_front(dq: *mut BlockDeque) {
    let d = &mut *dq;
    let elem = d.begin.cur;
    d.begin.cur = elem.add(DEQUE_ELEM_SIZE);
    d.count = d.count.wrapping_sub(1);
    // Element vtable slot 0: the descriptor's virtual destructor.
    let vtable = (elem as *const *const ElemDtor).read();
    (vtable.read())(elem);
    if d.count != 0 && d.begin.cur != d.begin.seg_end {
        return;
    }
    // Segment spent (or deque empty): retire it and advance the map.
    let slot = d.begin.seg_slot;
    d.begin.seg_slot = slot.add(1);
    let old_seg = slot.read();
    (op!(seg_dealloc))(old_seg, deque_seg_capacity());
    if d.count != 0 {
        let next_slot = d.begin.seg_slot;
        let mut it = DequeIter::NULL;
        deque_iter_init(&mut it, next_slot.read(), next_slot);
        d.begin = it;
    } else {
        let mut it = DequeIter::NULL;
        deque_iter_init(&mut it, core::ptr::null_mut(), core::ptr::null_mut());
        d.end = it;
        d.begin = d.end;
        (op!(seg_dealloc))(d.map as *mut u8, d.map_cap as usize);
    }
}

/// pool_base_construct — original: `FUN_082141bc` @ 0x082141bc
/// (100 bytes).
///
/// Constructs the base subobject: parent ctor, class vtable, empty
/// deque, +0x78 mailbox. Returns `this`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_base_construct(
    this: *mut PoolBase,
    name: *const u8,
    flag: usize,
) -> *mut PoolBase {
    let this = (op!(parent_construct))(this, name, flag);
    (*this).vtable = &POOL_BASE_VTABLE;
    (*this).deque.map_cap = 0;
    let mut it = DequeIter::NULL;
    deque_iter_init(&mut it, core::ptr::null_mut(), core::ptr::null_mut());
    (*this).deque.end = it;
    (*this).deque.begin = (*this).deque.end;
    (*this).deque.count = 0;
    (*this).deque.map = core::ptr::null_mut();
    (op!(mailbox_slot_create))(core::ptr::addr_of_mut!((*this).mailbox));
    this
}

/// pool_base_release_blocks — original: `FUN_08214158` @ 0x08214158
/// (100 bytes).
///
/// Hands the deque's block descriptors back to the attached client (if
/// any) and zeroes the fill counters, under the base mutex.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_base_release_blocks(this: *mut PoolBase) {
    let mutex = base_mutex(this);
    (mutex_op!(lock))(mutex);
    if (*this).deque.count != 0 && !base_client(this).is_null() {
        (op!(client_erase))(base_client(this), core::ptr::addr_of_mut!((*this).deque));
        (op!(client_erase_commit))(base_client(this));
    }
    (*this).fill_block_count = 0;
    (*this).fill_cap = 0;
    (mutex_op!(unlock))(mutex);
}

/// pool_base_destroy — original @ 0x08214224 (76 bytes; the
/// `pool_destroy` tail-branch target).
///
/// Non-deleting destructor chain: release blocks, delete the mailbox,
/// drain the deque, parent dtor. Returns `this` (the parent chain's
/// result).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_base_destroy(this: *mut PoolBase) -> *mut PoolBase {
    (*this).vtable = &POOL_BASE_VTABLE;
    pool_base_release_blocks(this);
    (op!(mailbox_slot_delete))(core::ptr::addr_of_mut!((*this).mailbox));
    let dq = core::ptr::addr_of_mut!((*this).deque);
    while (*dq).count != 0 {
        deque_pop_front(dq);
    }
    (op!(parent_destroy))(this)
}

/// block_deque_fill — original: `FUN_08213fc4` @ 0x08213fc4
/// (280 bytes).
///
/// Populates the deque with block descriptors covering `size` bytes
/// (at most `max`), through the block-manager client (see the module
/// header for the full protocol). Nonzero on success.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_deque_fill(this: *mut PoolBase, size: usize, max: usize) -> i32 {
    let mutex = base_mutex(this);
    (mutex_op!(lock))(mutex);
    let mut result: i32 = 0;
    'fill: {
        // Original: `cmp r7, #0; ble` — size is compared signed.
        if size as isize <= 0 || max == 0 {
            break 'fill;
        }
        // The manager pointer load whose result the original discards.
        crate::heap::block_mgr::block_manager_get();
        let block_size = crate::heap::block_mgr::region_block_size();
        // ceil(size / block_size); the block size is read twice,
        // faithfully. No manager -> block size 0 -> division by zero,
        // exactly like the original.
        let dividend = crate::heap::block_mgr::region_block_size()
            .wrapping_add(size as u32)
            .wrapping_sub(1);
        let count = crate::runtime::rt_div::__rt_udiv(dividend, block_size);
        (*this).fill_block_count = count;
        (*this).fill_cap = max as u32;
        if (op!(client_attach))(this) == 0 {
            break 'fill;
        }
        let bytes = count.wrapping_mul(crate::heap::block_mgr::region_block_size());
        if (op!(client_reserve))(base_client(this), bytes as usize, 0) == 0 {
            break 'fill;
        }
        // Wait (once) for the client to have 0x40000 bytes of headroom.
        let mut waited = false;
        loop {
            if (op!(client_avail))(base_client(this), FILL_HEADROOM) != 0 || waited {
                break;
            }
            waited = true;
            (op!(queue_wait))(
                core::ptr::addr_of_mut!((*this).mailbox),
                (*this).fill_cap,
            );
        }
        if (op!(client_avail))(base_client(this), FILL_HEADROOM) == 0 {
            result = 0;
        } else {
            result = (op!(client_populate))(
                base_client(this),
                (*this).fill_block_count as usize,
                core::ptr::addr_of_mut!((*this).deque),
            );
            if result != 0 {
                break 'fill;
            }
        }
        // Both remaining paths: virtual fill-failure callback.
        let vtable = (*this).vtable;
        ((*vtable).fill_failed)(this);
    }
    (mutex_op!(unlock))(mutex);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global ops tables.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// One shared, ordered event log across every mocked boundary.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Unlock(usize),
        ParentCtor { this: usize, name: usize, flag: usize },
        ParentDtor(usize),
        MboxCreate(usize),
        MboxDelete(usize),
        Attach(usize),
        Reserve { client: usize, bytes: usize, zero: usize },
        Avail { client: usize, bytes: usize },
        Populate { client: usize, count: usize, deque: usize },
        Erase { client: usize, deque: usize },
        EraseCommit(usize),
        QueueWait { slot: usize, timeout: u32 },
        SegFree { ptr: usize, count: usize },
        ElemDtor(usize),
        FillFailed(usize),
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    fn push(ev: Ev) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(ev) }
    }

    fn events() -> Vec<Ev> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    // ---- configurable mock behavior ------------------------------------

    static mut ATTACH_RET: i32 = 1;
    static mut RESERVE_RET: i32 = 1;
    static mut AVAIL_RETS: [i32; 4] = [1; 4];
    static mut AVAIL_CALLS: usize = 0;
    static mut POPULATE_RET: i32 = 7;

    /// Fake client object: first word is the handle every call receives.
    static mut CLIENT_OBJ: [*mut u8; 1] = [0x0c11_e000 as *mut u8];
    /// Marker block the mock mailbox create installs.
    const MBOX_MARKER: usize = 0x0b0e_0000;

    unsafe extern "C" fn mock_lock(m: *mut u8) -> u32 {
        push(Ev::Lock(m as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(m: *mut u8) -> u32 {
        push(Ev::Unlock(m as usize));
        0
    }

    unsafe extern "C" fn mock_parent_ctor(
        this: *mut PoolBase,
        name: *const u8,
        flag: usize,
    ) -> *mut PoolBase {
        push(Ev::ParentCtor {
            this: this as usize,
            name: name as usize,
            flag,
        });
        // Faithful subset, like the wired default stub.
        (*this).client_ref = core::ptr::null();
        this
    }

    unsafe extern "C" fn mock_parent_dtor(this: *mut PoolBase) -> *mut PoolBase {
        push(Ev::ParentDtor(this as usize));
        this
    }

    unsafe extern "C" fn mock_mbox_create(slot: *mut *mut Mailbox) {
        push(Ev::MboxCreate(slot as usize));
        *slot = MBOX_MARKER as *mut Mailbox;
    }

    unsafe extern "C" fn mock_mbox_delete(slot: *mut *mut Mailbox) {
        push(Ev::MboxDelete(slot as usize));
        *slot = core::ptr::null_mut();
    }

    unsafe extern "C" fn mock_attach(this: *mut PoolBase) -> i32 {
        push(Ev::Attach(this as usize));
        if ATTACH_RET != 0 {
            // The real attach installs the client ref (this + 0x4).
            (*this).client_ref = core::ptr::addr_of!(CLIENT_OBJ) as *const *mut u8;
        }
        ATTACH_RET
    }

    unsafe extern "C" fn mock_reserve(client: *mut u8, bytes: usize, zero: usize) -> i32 {
        push(Ev::Reserve {
            client: client as usize,
            bytes,
            zero,
        });
        RESERVE_RET
    }

    unsafe extern "C" fn mock_avail(client: *mut u8, bytes: usize) -> i32 {
        push(Ev::Avail {
            client: client as usize,
            bytes,
        });
        let i = AVAIL_CALLS;
        AVAIL_CALLS += 1;
        AVAIL_RETS[i.min(3)]
    }

    unsafe extern "C" fn mock_populate(client: *mut u8, count: usize, deque: *mut BlockDeque) -> i32 {
        push(Ev::Populate {
            client: client as usize,
            count,
            deque: deque as usize,
        });
        POPULATE_RET
    }

    unsafe extern "C" fn mock_erase(client: *mut u8, deque: *mut BlockDeque) {
        push(Ev::Erase {
            client: client as usize,
            deque: deque as usize,
        });
    }

    unsafe extern "C" fn mock_erase_commit(client: *mut u8) {
        push(Ev::EraseCommit(client as usize));
    }

    unsafe extern "C" fn mock_queue_wait(slot: *mut *mut Mailbox, timeout: u32) -> u32 {
        push(Ev::QueueWait {
            slot: slot as usize,
            timeout,
        });
        0
    }

    unsafe extern "C" fn mock_seg_free(ptr: *mut u8, count: usize) {
        push(Ev::SegFree {
            ptr: ptr as usize,
            count,
        });
    }

    const MOCK_OPS: PoolBaseOps = PoolBaseOps {
        parent_construct: mock_parent_ctor,
        parent_destroy: mock_parent_dtor,
        mailbox_slot_create: mock_mbox_create,
        mailbox_slot_delete: mock_mbox_delete,
        client_attach: mock_attach,
        client_reserve: mock_reserve,
        client_avail: mock_avail,
        client_populate: mock_populate,
        client_erase: mock_erase,
        client_erase_commit: mock_erase_commit,
        queue_wait: mock_queue_wait,
        seg_dealloc: mock_seg_free,
    };

    /// Installs the recorders (ops + shared mutex boundary), resets the
    /// log and knobs, returns the serialization guard.
    fn mock_all() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            ATTACH_RET = 1;
            RESERVE_RET = 1;
            AVAIL_RETS = [1; 4];
            AVAIL_CALLS = 0;
            POPULATE_RET = 7;
            CLIENT_OBJ = [0x0c11_e000 as *mut u8];
            *core::ptr::addr_of_mut!(POOL_BASE_OPS) = MOCK_OPS;
            *core::ptr::addr_of_mut!(REGION_MUTEX_OPS) = RegionMutexOps {
                lock: mock_lock,
                unlock: mock_unlock,
            };
        }
        guard
    }

    /// Restores every wired default this module dispatches through.
    fn restore() {
        unsafe {
            *core::ptr::addr_of_mut!(POOL_BASE_OPS) = DEFAULT_POOL_BASE_OPS;
            *core::ptr::addr_of_mut!(REGION_MUTEX_OPS) = DEFAULT_REGION_MUTEX_OPS;
        }
    }

    /// A garbage-filled base object, so initialization is observable.
    fn garbage_base() -> std::boxed::Box<PoolBase> {
        let mut b = std::boxed::Box::new(unsafe { core::mem::zeroed::<PoolBase>() });
        unsafe {
            core::ptr::write_bytes(
                &mut *b as *mut PoolBase as *mut u8,
                0xAA,
                core::mem::size_of::<PoolBase>(),
            );
        }
        b
    }

    fn client_handle() -> usize {
        unsafe { CLIENT_OBJ[0] as usize }
    }

    // ---- deque primitives ----------------------------------------------

    #[test]
    fn seg_capacity_is_32_elements() {
        unsafe {
            assert_eq!(deque_seg_capacity(), 0x20);
            assert_eq!(deque_seg_capacity() * DEQUE_ELEM_SIZE, DEQUE_SEG_BYTES);
        }
    }

    #[test]
    fn iter_init_anchors_on_the_slot_segment() {
        let mut seg = [0u8; DEQUE_SEG_BYTES];
        let mut slot: *mut u8 = seg.as_mut_ptr();
        let mut it = DequeIter::NULL;
        unsafe {
            let ret = deque_iter_init(&mut it, seg.as_mut_ptr().add(0x28), &mut slot);
            assert_eq!(ret, &mut it as *mut DequeIter);
            assert_eq!(it.cur, seg.as_mut_ptr().add(0x28));
            assert_eq!(it.seg_base, seg.as_mut_ptr());
            assert_eq!(it.seg_end, seg.as_mut_ptr().add(DEQUE_SEG_BYTES));
            assert_eq!(it.seg_slot, &mut slot as *mut *mut u8);
        }
    }

    #[test]
    fn iter_init_null_slot_zeroes_the_bounds() {
        let mut it = DequeIter {
            cur: 0x1 as *mut u8,
            seg_base: 0x2 as *mut u8,
            seg_end: 0x3 as *mut u8,
            seg_slot: 0x4 as *mut *mut u8,
        };
        unsafe {
            deque_iter_init(&mut it, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(it.cur.is_null());
            assert!(it.seg_base.is_null());
            assert!(it.seg_end.is_null());
            assert!(it.seg_slot.is_null());
        }
    }

    #[test]
    fn iter_copy_copies_all_four_fields_and_ignores_r1() {
        let src = DequeIter {
            cur: 0x10 as *mut u8,
            seg_base: 0x20 as *mut u8,
            seg_end: 0x30 as *mut u8,
            seg_slot: 0x40 as *mut *mut u8,
        };
        let mut dst = DequeIter::NULL;
        unsafe {
            deque_iter_copy(&mut dst, 0xdead_beef, &src);
            assert_eq!(dst.cur, src.cur);
            assert_eq!(dst.seg_base, src.seg_base);
            assert_eq!(dst.seg_end, src.seg_end);
            assert_eq!(dst.seg_slot, src.seg_slot);
        }
    }

    #[test]
    fn node_accessor_returns_the_deque_field() {
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            assert_eq!(
                deque_node_accessor(this),
                core::ptr::addr_of_mut!((*this).deque)
            );
        }
    }

    #[test]
    fn client_handle_get_walks_the_two_level_ref() {
        unsafe {
            let word: *mut u8 = 0x5555 as *mut u8;
            let obj: [*mut u8; 1] = [word];
            let mut ref_slot: *const *mut u8 = obj.as_ptr();
            assert_eq!(
                client_handle_get(&mut ref_slot as *mut _ as *const *const *mut u8),
                word
            );
            ref_slot = core::ptr::null();
            assert!(
                client_handle_get(&mut ref_slot as *mut _ as *const *const *mut u8).is_null()
            );
        }
    }

    // ---- pop_front ------------------------------------------------------

    /// Element vtable whose slot 0 records the destroyed element.
    unsafe extern "C" fn recording_elem_dtor(elem: *mut u8) {
        push(Ev::ElemDtor(elem as usize));
    }

    static ELEM_VTABLE: [ElemDtor; 1] = [recording_elem_dtor];

    /// Writes the recording vtable pointer into an element's word 0.
    unsafe fn init_elem(elem: *mut u8) {
        (elem as *mut *const ElemDtor).write(ELEM_VTABLE.as_ptr());
    }

    #[test]
    fn pop_front_mid_segment_only_advances() {
        let _guard = mock_all();
        let mut seg = [0u8; DEQUE_SEG_BYTES];
        let mut map = [seg.as_mut_ptr()];
        unsafe {
            init_elem(seg.as_mut_ptr());
            let mut dq = BlockDeque {
                begin: DequeIter::NULL,
                end: DequeIter::NULL,
                count: 2,
                map: map.as_mut_ptr(),
                map_cap: 1,
            };
            deque_iter_init(&mut dq.begin, seg.as_mut_ptr(), map.as_mut_ptr());
            deque_pop_front(&mut dq);
            assert_eq!(dq.count, 1);
            assert_eq!(dq.begin.cur, seg.as_mut_ptr().add(DEQUE_ELEM_SIZE));
            assert_eq!(events(), std::vec![Ev::ElemDtor(seg.as_mut_ptr() as usize)]);
        }
        restore();
    }

    #[test]
    fn pop_front_retires_a_spent_segment_and_reanchors() {
        let _guard = mock_all();
        let mut seg0 = [0u8; DEQUE_SEG_BYTES];
        let mut seg1 = [0u8; DEQUE_SEG_BYTES];
        let mut map = [seg0.as_mut_ptr(), seg1.as_mut_ptr()];
        unsafe {
            // Last element of seg0 + one element in seg1.
            let last = seg0.as_mut_ptr().add(DEQUE_SEG_BYTES - DEQUE_ELEM_SIZE);
            init_elem(last);
            init_elem(seg1.as_mut_ptr());
            let mut dq = BlockDeque {
                begin: DequeIter::NULL,
                end: DequeIter::NULL,
                count: 2,
                map: map.as_mut_ptr(),
                map_cap: 2,
            };
            deque_iter_init(&mut dq.begin, last, map.as_mut_ptr());
            deque_pop_front(&mut dq);
            assert_eq!(dq.count, 1);
            // Re-anchored on seg1 through the next map slot.
            assert_eq!(dq.begin.cur, seg1.as_mut_ptr());
            assert_eq!(dq.begin.seg_base, seg1.as_mut_ptr());
            assert_eq!(dq.begin.seg_end, seg1.as_mut_ptr().add(DEQUE_SEG_BYTES));
            assert_eq!(dq.begin.seg_slot, map.as_mut_ptr().add(1));
            assert_eq!(
                events(),
                std::vec![
                    Ev::ElemDtor(last as usize),
                    Ev::SegFree {
                        ptr: seg0.as_mut_ptr() as usize,
                        count: 0x20
                    },
                ]
            );
        }
        restore();
    }

    #[test]
    fn pop_front_last_element_frees_segment_and_map() {
        let _guard = mock_all();
        let mut seg = [0u8; DEQUE_SEG_BYTES];
        let mut map = [seg.as_mut_ptr()];
        unsafe {
            init_elem(seg.as_mut_ptr());
            let mut dq = BlockDeque {
                begin: DequeIter::NULL,
                end: DequeIter::NULL,
                count: 1,
                map: map.as_mut_ptr(),
                map_cap: 1,
            };
            deque_iter_init(&mut dq.begin, seg.as_mut_ptr(), map.as_mut_ptr());
            deque_pop_front(&mut dq);
            assert_eq!(dq.count, 0);
            assert!(dq.begin.cur.is_null(), "empty deque: NULL iterators");
            assert!(dq.end.cur.is_null());
            assert_eq!(
                events(),
                std::vec![
                    Ev::ElemDtor(seg.as_mut_ptr() as usize),
                    Ev::SegFree {
                        ptr: seg.as_mut_ptr() as usize,
                        count: 0x20
                    },
                    Ev::SegFree {
                        ptr: map.as_mut_ptr() as usize,
                        count: 1
                    },
                ]
            );
        }
        restore();
    }

    // ---- ctor / release / dtor ------------------------------------------

    static BASE_NAME: &[u8] = b"deque_base\0";

    #[test]
    fn construct_builds_an_empty_deque_and_mailbox() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            let ret = pool_base_construct(this, BASE_NAME.as_ptr(), 1);
            assert_eq!(ret, this);
            assert_eq!((*this).vtable, &POOL_BASE_VTABLE as *const PoolBaseVtable);
            assert!((*this).client_ref.is_null(), "parent ctor zeroes the ref");
            assert!((*this).deque.begin.cur.is_null());
            assert!((*this).deque.end.cur.is_null());
            assert_eq!((*this).deque.count, 0);
            assert!((*this).deque.map.is_null());
            assert_eq!((*this).deque.map_cap, 0);
            assert_eq!((*this).mailbox as usize, MBOX_MARKER);
            assert_eq!(
                events(),
                std::vec![
                    Ev::ParentCtor {
                        this: this as usize,
                        name: BASE_NAME.as_ptr() as usize,
                        flag: 1
                    },
                    Ev::MboxCreate(core::ptr::addr_of_mut!((*this).mailbox) as usize),
                ]
            );
        }
        restore();
    }

    #[test]
    fn release_blocks_empty_deque_skips_the_client() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            pool_base_construct(this, BASE_NAME.as_ptr(), 1);
            (*this).fill_block_count = 5;
            (*this).fill_cap = 2000;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            pool_base_release_blocks(this);
            assert_eq!((*this).fill_block_count, 0);
            assert_eq!((*this).fill_cap, 0);
            let m = base_mutex(this) as usize;
            assert_eq!(events(), std::vec![Ev::Lock(m), Ev::Unlock(m)]);
        }
        restore();
    }

    #[test]
    fn release_blocks_hands_blocks_back_rereading_the_handle() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            pool_base_construct(this, BASE_NAME.as_ptr(), 1);
            (*this).deque.count = 3;
            (*this).client_ref = core::ptr::addr_of!(CLIENT_OBJ) as *const *mut u8;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            pool_base_release_blocks(this);
            let m = base_mutex(this) as usize;
            let dq = core::ptr::addr_of_mut!((*this).deque) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(m),
                    Ev::Erase {
                        client: client_handle(),
                        deque: dq
                    },
                    Ev::EraseCommit(client_handle()),
                    Ev::Unlock(m),
                ]
            );
        }
        restore();
    }

    #[test]
    fn release_blocks_nonempty_without_client_only_clears_counters() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            pool_base_construct(this, BASE_NAME.as_ptr(), 1);
            (*this).deque.count = 3;
            (*this).fill_block_count = 3;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            pool_base_release_blocks(this);
            assert_eq!((*this).fill_block_count, 0);
            let m = base_mutex(this) as usize;
            assert_eq!(events(), std::vec![Ev::Lock(m), Ev::Unlock(m)]);
        }
        restore();
    }

    #[test]
    fn destroy_releases_deletes_drains_and_chains_to_the_parent() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        let mut seg = [0u8; DEQUE_SEG_BYTES];
        let mut map = [seg.as_mut_ptr()];
        unsafe {
            pool_base_construct(this, BASE_NAME.as_ptr(), 1);
            // One live element so the drain loop runs the real pop_front.
            init_elem(seg.as_mut_ptr());
            (*this).deque.count = 1;
            (*this).deque.map = map.as_mut_ptr();
            (*this).deque.map_cap = 1;
            deque_iter_init(
                core::ptr::addr_of_mut!((*this).deque.begin),
                seg.as_mut_ptr(),
                map.as_mut_ptr(),
            );
            (*this).vtable = core::ptr::null(); // prove the dtor reinstalls it
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            let ret = pool_base_destroy(this);
            assert_eq!(ret, this);
            assert_eq!((*this).vtable, &POOL_BASE_VTABLE as *const PoolBaseVtable);
            assert_eq!((*this).deque.count, 0);
            assert!((*this).mailbox.is_null());
            let m = base_mutex(this) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(m),
                    Ev::Unlock(m),
                    Ev::MboxDelete(core::ptr::addr_of_mut!((*this).mailbox) as usize),
                    Ev::ElemDtor(seg.as_mut_ptr() as usize),
                    Ev::SegFree {
                        ptr: seg.as_mut_ptr() as usize,
                        count: 0x20
                    },
                    Ev::SegFree {
                        ptr: map.as_mut_ptr() as usize,
                        count: 1
                    },
                    Ev::ParentDtor(this as usize),
                ]
            );
        }
        restore();
    }

    // ---- fill ------------------------------------------------------------

    /// Installs a fake block manager with the given block size; returns
    /// a closure-free "uninstall before drop" duty to the caller.
    #[repr(align(4))]
    struct FakeManager([u8; 0x40]);
    static mut FAKE_MGR: FakeManager = FakeManager([0; 0x40]);

    unsafe fn install_manager(block_size: u32) {
        let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
        (mgr.add(crate::heap::block_mgr::BLOCK_SIZE_OFFSET) as *mut u32).write(block_size);
        crate::heap::block_mgr::BLOCK_MANAGER = mgr;
    }

    unsafe fn uninstall_manager() {
        crate::heap::block_mgr::BLOCK_MANAGER = core::ptr::null_mut();
    }

    /// A constructed base with the recorders installed and the event log
    /// cleared, ready for a fill call.
    unsafe fn fresh_base(base: *mut PoolBase) {
        pool_base_construct(base, BASE_NAME.as_ptr(), 1);
        (*core::ptr::addr_of_mut!(EVENTS)).clear();
    }

    #[test]
    fn fill_rejects_zero_or_negative_size_and_zero_max() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            fresh_base(this);
            let m = base_mutex(this) as usize;
            assert_eq!(block_deque_fill(this, 0, 2000), 0);
            assert_eq!(block_deque_fill(this, usize::MAX, 2000), 0, "signed ble");
            assert_eq!(block_deque_fill(this, 0x1000, 0), 0);
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(m),
                    Ev::Unlock(m),
                    Ev::Lock(m),
                    Ev::Unlock(m),
                    Ev::Lock(m),
                    Ev::Unlock(m)
                ],
                "gate failures touch nothing but the mutex"
            );
        }
        restore();
    }

    #[test]
    fn fill_attach_failure_stores_counts_but_goes_no_further() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            ATTACH_RET = 0;
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 0);
            // ceil((0x800 + 0x1000 - 1) / 0x800) as the original computes it.
            assert_eq!((*this).fill_block_count, 2);
            assert_eq!((*this).fill_cap, 2000);
            let m = base_mutex(this) as usize;
            assert_eq!(
                events(),
                std::vec![Ev::Lock(m), Ev::Attach(this as usize), Ev::Unlock(m)]
            );
            uninstall_manager();
        }
        restore();
    }

    #[test]
    fn fill_reserve_failure_returns_zero_without_the_virtual_callback() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            RESERVE_RET = 0;
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 0);
            let m = base_mutex(this) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(m),
                    Ev::Attach(this as usize),
                    Ev::Reserve {
                        client: client_handle(),
                        bytes: 0x1000, // 2 blocks * 0x800
                        zero: 0
                    },
                    Ev::Unlock(m)
                ]
            );
            uninstall_manager();
        }
        restore();
    }

    #[test]
    fn fill_success_populates_the_deque_and_forwards_the_result() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            POPULATE_RET = 7;
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 7);
            let m = base_mutex(this) as usize;
            let dq = core::ptr::addr_of_mut!((*this).deque) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(m),
                    Ev::Attach(this as usize),
                    Ev::Reserve {
                        client: client_handle(),
                        bytes: 0x1000,
                        zero: 0
                    },
                    Ev::Avail {
                        client: client_handle(),
                        bytes: 0x40000
                    },
                    Ev::Avail {
                        client: client_handle(),
                        bytes: 0x40000
                    },
                    Ev::Populate {
                        client: client_handle(),
                        count: 2,
                        deque: dq
                    },
                    Ev::Unlock(m)
                ],
                "instant headroom: no wait, loop check + post check"
            );
            uninstall_manager();
        }
        restore();
    }

    #[test]
    fn fill_waits_once_on_the_mailbox_when_headroom_lags() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            AVAIL_RETS = [0, 1, 1, 1];
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 7);
            let evs = events();
            let wait = Ev::QueueWait {
                slot: core::ptr::addr_of_mut!((*this).mailbox) as usize,
                timeout: 2000,
            };
            assert_eq!(
                evs.iter().filter(|e| **e == wait).count(),
                1,
                "exactly one wait, on the +0x78 mailbox with timeout = max"
            );
            // wait sits between the first (failed) and second avail check.
            let first_avail = evs
                .iter()
                .position(|e| matches!(e, Ev::Avail { .. }))
                .unwrap();
            assert_eq!(evs[first_avail + 1], wait);
            uninstall_manager();
        }
        restore();
    }

    /// A test vtable proving the virtual dispatch goes through the
    /// object's vtable pointer.
    static TEST_VTABLE: PoolBaseVtable = PoolBaseVtable {
        unresolved: [0; 4],
        fill_failed: recording_fill_failed,
    };

    unsafe extern "C" fn recording_fill_failed(this: *mut PoolBase) {
        push(Ev::FillFailed(this as usize));
    }

    #[test]
    fn fill_no_headroom_after_wait_virtual_calls_fill_failed() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            (*this).vtable = &TEST_VTABLE;
            AVAIL_RETS = [0, 0, 0, 0];
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 0);
            let evs = events();
            assert_eq!(
                evs.iter()
                    .filter(|e| matches!(e, Ev::FillFailed(t) if *t == this as usize))
                    .count(),
                1
            );
            assert!(
                !evs.iter().any(|e| matches!(e, Ev::Populate { .. })),
                "no populate without headroom"
            );
            uninstall_manager();
        }
        restore();
    }

    #[test]
    fn fill_populate_failure_virtual_calls_fill_failed() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            (*this).vtable = &TEST_VTABLE;
            POPULATE_RET = 0;
            assert_eq!(block_deque_fill(this, 0x1000, 2000), 0);
            let evs = events();
            let populate_at = evs
                .iter()
                .position(|e| matches!(e, Ev::Populate { .. }))
                .expect("populate ran");
            assert_eq!(evs[populate_at + 1], Ev::FillFailed(this as usize));
            uninstall_manager();
        }
        restore();
    }

    #[test]
    fn fill_block_count_rounds_up_partial_blocks() {
        let _guard = mock_all();
        let mut base = garbage_base();
        let this = &mut *base as *mut PoolBase;
        unsafe {
            install_manager(0x800);
            fresh_base(this);
            block_deque_fill(this, 0x801, 2000);
            assert_eq!((*this).fill_block_count, 2, "0x801 bytes need 2 blocks");
            fresh_base(this);
            block_deque_fill(this, 0x800, 2000);
            assert_eq!((*this).fill_block_count, 1);
            uninstall_manager();
        }
        restore();
    }
}
