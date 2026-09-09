//! `"crts"` string-pool entry release — `FUN_080c5efc` @ 0x080c5efc
//! (176 bytes; **21 direct `bl` call sites** — 18 plain `bl`, 3 `blne` —
//! plus 2 tail branches, all binary-scanned).
//!
//! # Extent
//!
//! Decoded from raw `osos.dec` bytes: the body runs 0x080c5efc
//! (`push {r4,r5,r6,lr}`) through the `pop {r4,r5,r6,pc}` at 0x080c5fa8,
//! and the next separately linked function's `push {r3,r4,r5,lr}` sits at
//! 0x080c5fac. There is no trailing literal pool — the function loads no
//! constants from memory — so Ghidra's 176 bytes is exact for once. `r6`
//! is pushed and never used: the original saves it purely to keep the
//! stack eight-byte aligned.
//!
//! # The object
//!
//! `pool` is the same 0x58-byte `"crts"`-tagged object that
//! [`crate::util::crts_object::crts_object_destroy`] tears down and whose
//! +0x30 counter [`crate::util::tagged_counter`] moves. Cross-reading the
//! two interning allocators that share this header — 0x080b4e60 (raw byte
//! blob) and 0x080be81c (a `u16`-length-prefixed UTF-16 string, hence the
//! tag literal `'strc'`, in-memory bytes `"crts"`) — pins down every field
//! this function touches:
//!
//! ```text
//! +0x00  tag = 0x73747263            +0x1c  entry_count (capacity)
//! +0x04  flags                       +0x20  free-list head (1-based id)
//! +0x08  Handle -> PoolEntry[]       +0x24  unused bytes left in the blob
//! +0x0c  Handle -> refcount i32[]    +0x28  blob growth step
//! +0x10  Handle -> byte blob         +0x2c  entry-array growth step
//! +0x14  hash index                  +0x30  lock_depth (busy counter)
//! +0x18  hash index                  +0x34  reclaimable_bytes
//! ```
//!
//! Both handle fields are Mac-Memory-Manager handles — a pointer to a
//! relocatable master pointer — which is why the original dereferences
//! them twice (`ldr r0,[r4,#8]; ldr r0,[r0]`). The failure status -50 is
//! classic Mac OS `paramErr`, matching that lineage.
//!
//! A [`PoolEntry`] is two words: the blob offset of the payload and its
//! byte length. Bit 31 of the first word marks a non-live entry — the
//! allocator writes 0x80000000 when it grows the array and threads the
//! free list through the second word, while this function writes
//! [`ENTRY_RECLAIMABLE`] (0x80000001) and leaves the length in place, so
//! the two states are distinguishable. A released entry is therefore not
//! returned to the free list here; its bytes are added to the
//! `reclaimable_bytes` running total at +0x34 for the compaction pass the
//! allocator runs (0x080a64bc) before its next allocation.
//!
//! # Algorithm
//!
//! ```text
//! if pool == NULL or pool->tag != 'strc':  return -50   // 0x080a7714
//! if pool->lock_depth != 0:                return -50
//! if pool->flags & 0x40:                   return -50
//! if id == 0:                              return 0     // no-op
//! if id < 0 or id > pool->entry_count:     return -50
//! if pool->flags & 0x01:                                // refcounted
//!     if --(*pool->refcounts)[id - 1] != 0:  return 0
//! entry = &(*pool->entries)[id - 1]
//! pool->reclaimable_bytes += entry.length
//! entry.blob_offset = 0x80000001
//! return 0
//! ```
//!
//! The `id == 0` early success is what lets every caller release an
//! optional slot unconditionally: 0x080ca934 releases fourteen stored ids
//! back to back without a single NULL/zero test of its own, and
//! 0x080b4e60 / 0x080be81c open by releasing the caller's old id before
//! interning the replacement.
//!
//! # Call census
//!
//! Decoding every ARM B/BL word in `osos.dec` finds exactly 21 direct call
//! sites: 18 unconditional `bl` and 3 `blne` (0x08048fa8, 0x08048fb8,
//! 0x08095e3c), plus 2 tail branches — `b` at 0x080caa24 (the last release
//! of the 0x080ca934 sequence) and `bne` at 0x080da8a0. The predicated
//! forms are all caller-side gates on an unrelated condition, not NULL
//! guards: this function guards its own `pool` argument. The address
//! occurs in no data word, so it is never dispatched virtually.
//!
//! # Deliberate deviations
//!
//! - The four-instruction tag guard at 0x080a7714 (returns one iff `pool`
//!   is non-NULL and its first word is [`CRTS_TAG`]) is inlined rather
//!   than given a dispatch seam, following `util/tagged_counter.rs` and
//!   `util/crts_object.rs`; that callee has no port and no identity is
//!   invented for it.
//! - The two handle fields are typed as native double pointers instead of
//!   the `u32` words `util/crts_object.rs` uses. That module only compares
//!   and forwards them; this one dereferences them, and a native pointer
//!   keeps the 4-byte target spacing exactly (verified by the
//!   32-bit-only [`offset_of!`](core::mem::offset_of) assertions below)
//!   while letting host tests exercise every path instead of skipping on
//!   hosts that cannot map a fixture below 4 GiB.
//! - The refcount decrement and the `reclaimable_bytes` accumulation use
//!   wrapping arithmetic, as the original's `subs`/`add` do.

use core::mem::{offset_of, MaybeUninit};
use core::ptr;

/// First word required of a pool, checked by the inlined 0x080a7714 guard.
/// The ARM literal is the character constant `'strc'`; in memory its bytes
/// read `"crts"`.
pub const CRTS_TAG: u32 = 0x7374_7263;

/// Failure status of every rejected release (`mvn r0, #0x31`). This is
/// classic Mac OS `paramErr`.
pub const PARAM_ERR: i32 = -50;

/// `flags & 0x01` — the pool keeps a parallel reference count per entry at
/// the +0x0c handle. When clear, one release frees the entry outright.
pub const FLAG_REFCOUNTED: u32 = 0x01;

/// `flags & 0x40` — the pool refuses mutation. Both interning allocators
/// (0x080b4e60, 0x080be81c) and this release reject it with
/// [`PARAM_ERR`].
pub const FLAG_IMMUTABLE: u32 = 0x40;

/// Value written over a released entry's blob offset. Bit 31 marks the
/// entry non-live; bit 0 distinguishes it from the allocator's 0x80000000
/// "never used, on the free list" marker, because a released entry's bytes
/// are still occupied by stale payload and counted in
/// [`StringPool::reclaimable_bytes`].
pub const ENTRY_RECLAIMABLE: u32 = 0x8000_0001;

/// One slot of the pool's entry array: eight bytes, one per interned
/// payload, addressed by a 1-based id.
#[repr(C)]
pub struct PoolEntry {
    /// +0x00 — byte offset of the payload inside the pool's blob while the
    /// entry is live, or a bit-31 marker ([`ENTRY_RECLAIMABLE`], or the
    /// allocator's 0x80000000) while it is not.
    pub blob_offset: u32,
    /// +0x04 — payload length in bytes. Doubles as the free-list link on
    /// entries the allocator has never handed out.
    pub length: i32,
}

/// The prefix of the `"crts"` pool header that `string_pool_release`
/// reads. Fields past +0x34 belong to the allocator and are not modelled.
#[repr(C)]
pub struct StringPool {
    /// +0x00 — must equal [`CRTS_TAG`].
    pub tag: u32,
    /// +0x04 — [`FLAG_REFCOUNTED`] / [`FLAG_IMMUTABLE`] and the allocator's
    /// own bits.
    pub flags: u32,
    /// +0x08 — handle to the entry array, indexed by `id - 1`.
    pub entries: *mut *mut PoolEntry,
    /// +0x0c — handle to the parallel `i32` refcount array. Read only when
    /// [`FLAG_REFCOUNTED`] is set.
    pub refcounts: *mut *mut i32,
    /// +0x10..+0x1c — blob handle and the two hash-index arrays.
    payload_and_index: [u32; 3],
    /// +0x1c — number of entries the arrays hold; the largest valid id.
    pub entry_count: i32,
    /// +0x20..+0x30 — free-list head, blob accounting and growth steps.
    allocator_state: [u32; 4],
    /// +0x30 — non-zero while a scan holds the pool; releases are refused.
    pub lock_depth: i32,
    /// +0x34 — bytes of blob occupied by released entries, awaiting
    /// compaction.
    pub reclaimable_bytes: i32,
}

/// The whole point of using native pointers above is that the 32-bit
/// target layout stays byte-exact; assert it where it is checkable.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(offset_of!(StringPool, entries) == 0x08);
    assert!(offset_of!(StringPool, refcounts) == 0x0c);
    assert!(offset_of!(StringPool, entry_count) == 0x1c);
    assert!(offset_of!(StringPool, lock_depth) == 0x30);
    assert!(offset_of!(StringPool, reclaimable_bytes) == 0x34);
    assert!(core::mem::size_of::<PoolEntry>() == 8);
};

/// string_pool_release — original: `FUN_080c5efc` @ 0x080c5efc (176 bytes).
///
/// Drops one reference to the pool entry named by the 1-based `id`. On a
/// refcounted pool the entry survives until its count reaches zero; the
/// last reference (or any reference on a pool without counts) marks the
/// entry reclaimable and adds its payload length to the pool's
/// `reclaimable_bytes`. Releasing id 0 is a documented no-op returning 0.
///
/// Returns [`PARAM_ERR`] without touching anything for a NULL or
/// foreign-tagged pool, a pool that is locked ([`StringPool::lock_depth`])
/// or immutable ([`FLAG_IMMUTABLE`]), and a negative or out-of-range `id`.
///
/// # Safety
///
/// A valid, unlocked, mutable pool must carry live handles: the entry
/// array for any accepted `id`, and the refcount array as well when
/// [`FLAG_REFCOUNTED`] is set. The original has no guard on either, and
/// neither does this port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_release(pool: *mut StringPool, id: i32) -> i32 {
    if pool.is_null() || (*pool).tag != CRTS_TAG {
        return PARAM_ERR;
    }
    if (*pool).lock_depth != 0 {
        return PARAM_ERR;
    }

    let flags = (*pool).flags;
    if flags & FLAG_IMMUTABLE != 0 {
        return PARAM_ERR;
    }
    if id == 0 {
        return 0;
    }
    if id < 0 || (*pool).entry_count < id {
        return PARAM_ERR;
    }

    let slot = (id - 1) as usize;
    if flags & FLAG_REFCOUNTED != 0 {
        let refcount = (*(*pool).refcounts).add(slot);
        let remaining = refcount.read().wrapping_sub(1);
        refcount.write(remaining);
        if remaining != 0 {
            return 0;
        }
    }

    let entry = (*(*pool).entries).add(slot);
    (*pool).reclaimable_bytes = (*pool).reclaimable_bytes.wrapping_add((*entry).length);
    (*entry).blob_offset = ENTRY_RECLAIMABLE;
    0
}

/// Failure status of a failed scratch-buffer allocation in
/// [`string_pool_copy_entry`] (`mvneq r0, #107` in the original — the ARM
/// immediate is the bitwise inverse, so the value is !107). This is
/// classic Mac OS `memFullErr`, matching the pool family's lineage.
pub const MEM_FULL_ERR: i32 = -108;

/// Payloads up to this many bytes are staged through the 512-byte stack
/// buffer of [`string_pool_copy_entry`]; anything larger is staged
/// through a tag-4 heap allocation. The original's compare is unsigned
/// (`cmp r0, #0x200; addls` / `bls`), so exactly 512 bytes stays on the
/// stack.
pub const STACK_BLOB_CAPACITY: usize = 512;

/// `max_len` of the size-query read [`string_pool_copy_entry`] opens
/// with: the original passes 0x7fffffff, i.e. "report the true payload
/// length, there is no buffer to clip to".
pub const QUERY_MAX_LEN: u32 = 0x7fff_ffff;

/// RetailOS load address of the unported pool blob reader (204 bytes).
pub const STRING_POOL_READ_ADDRESS: usize = 0x080b_4318;

/// RetailOS load address of the unported pool interning writer
/// (824 bytes).
pub const STRING_POOL_INTERN_ADDRESS: usize = 0x080c_5a94;

/// RetailOS load address of the unported replace-and-intern wrapper
/// [`string_pool_store_counted`] tail-branches into (76 bytes; the
/// `bx lr` at 0x080b4eb0 is inter-function alignment padding, not body).
pub const STRING_POOL_STORE_ADDRESS: usize = 0x080b_4e60;

/// ABI of the pool blob reader @ 0x080b4318, decoded from raw bytes.
/// With `dst` NULL it reports the payload length of entry `id` through
/// `len_out` without copying; otherwise it copies
/// `min(entry_len, max_len)` bytes (signed compare) into `dst`, re-locks
/// the pool's +0x30 counter around the read, and stores the copied length
/// to `len_out`. Returns 0 on success (id 0 is an immediate success
/// no-op), [`PARAM_ERR`] (-50) for a NULL or foreign-tagged pool, a
/// negative or out-of-range id, or a non-live entry. A NULL `len_out`
/// is tolerated.
pub type StringPoolRead = unsafe extern "C" fn(
    pool: *mut StringPool,
    id: i32,
    dst: *mut u8,
    len_out: *mut u32,
    max_len: u32,
) -> i32;

/// ABI of the pool interning writer @ 0x080c5a94. Stores `len` bytes
/// from `data` as a pool entry — first searching live entries for an
/// identical payload to share (bumping its refcount) — and writes the
/// 1-based entry id to `id_out`. `id_out` may be NULL and is zeroed on
/// entry otherwise; a zero `len` is a no-op returning 0. Returns
/// [`PARAM_ERR`] for a NULL, foreign-tagged, locked or immutable pool.
pub type StringPoolIntern = unsafe extern "C" fn(
    pool: *mut StringPool,
    data: *const u8,
    len: u32,
    id_out: *mut i32,
) -> i32;

/// The replace-and-intern wrapper @ 0x080b4e60 shares the
/// [`StringPoolIntern`] ABI exactly (`(pool, data, len, id_out)` in
/// r0-r3). Decoded from raw bytes: it runs the 0x080a7714 tag guard,
/// releases the id currently stored at `*id_out`
/// ([`string_pool_release`] — the `ldr r1, [r4]` is unconditional, so a
/// NULL `id_out` faults and callers never pass one), and on a successful
/// release tail-branches into the interning writer 0x080c5a94 with the
/// same four arguments, propagating its status. A failed release
/// short-circuits: its status is returned and nothing is interned.
pub type StringPoolStore = StringPoolIntern;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_string_pool_read(
    pool: *mut StringPool,
    id: i32,
    dst: *mut u8,
    len_out: *mut u32,
    max_len: u32,
) -> i32 {
    let body: StringPoolRead = core::mem::transmute(STRING_POOL_READ_ADDRESS);
    body(pool, id, dst, len_out, max_len)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_pool_read(
    _pool: *mut StringPool,
    _id: i32,
    _dst: *mut u8,
    _len_out: *mut u32,
    _max_len: u32,
) -> i32 {
    panic!("string_pool_copy_entry requires pool reader 0x080b4318")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_string_pool_intern(
    pool: *mut StringPool,
    data: *const u8,
    len: u32,
    id_out: *mut i32,
) -> i32 {
    let body: StringPoolIntern = core::mem::transmute(STRING_POOL_INTERN_ADDRESS);
    body(pool, data, len, id_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_pool_intern(
    _pool: *mut StringPool,
    _data: *const u8,
    _len: u32,
    _id_out: *mut i32,
) -> i32 {
    panic!("string_pool_copy_entry requires pool intern 0x080c5a94")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_string_pool_store(
    pool: *mut StringPool,
    data: *const u8,
    len: u32,
    id_out: *mut i32,
) -> i32 {
    let body: StringPoolStore = core::mem::transmute(STRING_POOL_STORE_ADDRESS);
    body(pool, data, len, id_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_pool_store(
    _pool: *mut StringPool,
    _data: *const u8,
    _len: u32,
    _id_out: *mut i32,
) -> i32 {
    panic!("string_pool_store_counted requires replace-and-intern wrapper 0x080b4e60")
}

/// Active boundary for the unported pool blob reader. On the target it
/// calls directly into retailOS @ 0x080b4318; host tests replace it with
/// a recording implementation.
#[cfg(target_os = "none")]
pub static mut STRING_POOL_READ: StringPoolRead = retail_string_pool_read;

/// Active host boundary for the unported pool blob reader.
#[cfg(not(target_os = "none"))]
pub static mut STRING_POOL_READ: StringPoolRead = missing_string_pool_read;

/// Active boundary for the unported pool interning writer, same policy
/// as [`STRING_POOL_READ`]; retail target 0x080c5a94.
#[cfg(target_os = "none")]
pub static mut STRING_POOL_INTERN: StringPoolIntern = retail_string_pool_intern;

/// Active host boundary for the unported pool interning writer.
#[cfg(not(target_os = "none"))]
pub static mut STRING_POOL_INTERN: StringPoolIntern = missing_string_pool_intern;

#[inline(always)]
unsafe fn string_pool_read_seam() -> StringPoolRead {
    ptr::read_volatile(ptr::addr_of!(STRING_POOL_READ))
}

#[inline(always)]
unsafe fn string_pool_intern_seam() -> StringPoolIntern {
    ptr::read_volatile(ptr::addr_of!(STRING_POOL_INTERN))
}

/// Active boundary for the unported replace-and-intern wrapper, same
/// policy as [`STRING_POOL_READ`]; retail target 0x080b4e60.
#[cfg(target_os = "none")]
pub static mut STRING_POOL_STORE: StringPoolStore = retail_string_pool_store;

/// Active host boundary for the unported replace-and-intern wrapper.
#[cfg(not(target_os = "none"))]
pub static mut STRING_POOL_STORE: StringPoolStore = missing_string_pool_store;

#[inline(always)]
unsafe fn string_pool_store_seam() -> StringPoolStore {
    ptr::read_volatile(ptr::addr_of!(STRING_POOL_STORE))
}

/// string_pool_copy_entry — original: `FUN_080be830` @ 0x080be830
/// (176 bytes; **15 direct `bl` call sites, all unconditional, plus one
/// tail `b`** at 0x0806b03c — binary-verified by decoding every B/BL
/// word in osos.dec).
///
/// Copies one entry between two `"crts"` pools: reads the payload of
/// entry `src_id` from `src` and interns it into `dst`, whose new 1-based
/// id lands in `dst_id_out`. The payload is staged through a scratch
/// buffer because the reader and writer are separate halves of the pool
/// API:
///
/// ```text
/// status = pool_read(src, src_id, NULL, &len, 0x7fffffff)   // size query
/// if status != 0:                    return status
/// blob = len <= 512 ? stack_blob : malloc_tag4(len)          // unsigned cmp
/// if blob == NULL:                   return -108             // memFullErr
/// status = pool_read(src, src_id, blob, &len, len)           // real copy
/// if status == 0:
///     status = pool_intern(dst, blob, len, dst_id_out)
/// if blob != stack_blob: free_tag4(blob)
/// return status
/// ```
///
/// # Extent and call census
///
/// Decoded from raw `osos.dec` bytes: the body runs 0x080be830
/// (`push {r4-r8,lr}`) through the `pop {r4-r8,pc}` at 0x080be8dc, and
/// the next separately linked function's `push {r4,r5,lr}` (an in-place
/// word byte-swap loop) sits at 0x080be8e0. There is no trailing literal
/// pool — 0x80000000 and 0x7fffffff are `mvn` immediates — so Ghidra's
/// 176 bytes is exact. Fourteen of the `bl` sites sit back to back in
/// the slot-copy chain of 0x0806ad74 (whose final slot at +0x8a8
/// open-codes this exact sequence inline, confirming the semantics) and
/// one in 0x080d189c; the address occurs in no data word, so the
/// function is never dispatched virtually.
///
/// # Deliberate deviations
///
/// - The two unported pool callees dispatch through the volatile seams
///   [`STRING_POOL_READ`] and [`STRING_POOL_INTERN`]; their target
///   defaults transmute the retail addresses 0x080b4318 / 0x080c5a94, so
///   the port is hook-ready on device, while host tests install
///   recording mocks (the `util/crts_object.rs` precedent). No identity
///   beyond the verified behaviour documented on the ABI types is
///   invented for either.
/// - `malloc_tag4` / `free_tag4` are already ported
///   (`crate::heap::veneers`); they are called directly, matching
///   `util/inner_state.rs`.
/// - The original's scratch buffer is 512 uninitialised stack bytes at
///   sp+4 (its sp+0x204 slot holds `len`); the port uses
///   [`MaybeUninit`] so no memset call appears where the original has
///   none. The free condition `blob != stack_blob` is computed from the
///   allocation choice, which is equivalent: a heap block can never
///   alias the stack frame.
///
/// # Safety
///
/// `src` and `dst` must be valid `"crts"` pools and `dst_id_out` a
/// writable id slot or NULL — every check is the callees', exactly as in
/// the original, which dereferences nothing itself.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_copy_entry(
    src: *mut StringPool,
    src_id: i32,
    dst: *mut StringPool,
    dst_id_out: *mut i32,
) -> i32 {
    let mut len: u32 = 0;
    let status = string_pool_read_seam()(src, src_id, ptr::null_mut(), &mut len, QUERY_MAX_LEN);
    if status != 0 {
        return status;
    }
    let mut stack_blob = MaybeUninit::<[u8; STACK_BLOB_CAPACITY]>::uninit();
    let heap_backed = len as usize > STACK_BLOB_CAPACITY;
    let blob = if heap_backed {
        crate::heap::veneers::malloc_tag4(len as usize)
    } else {
        stack_blob.as_mut_ptr() as *mut u8
    };
    if blob.is_null() {
        return MEM_FULL_ERR;
    }
    let mut status = string_pool_read_seam()(src, src_id, blob, &mut len, len);
    if status == 0 {
        status = string_pool_intern_seam()(dst, blob, len, dst_id_out);
    }
    if heap_backed {
        crate::heap::veneers::free_tag4(blob);
    }
    status
}

/// string_pool_store_counted — original: `FUN_080be81c` @ 0x080be81c
/// (20 bytes; **15 direct `bl` call sites, all unconditional; no tail
/// branches and no data-word references** — binary-verified by decoding
/// every B/BL word and every word equal to the address in osos.dec).
///
/// Stores a counted UTF-16 string into the pool, replacing the id the
/// caller holds in `*id_out`. The whole body is a five-instruction
/// argument-mangling thunk — Ghidra's 20 bytes is exact, and its C
/// silently inlines the bodies of both the tail target 0x080b4e60 and
/// that function's own tail target 0x080c5a94:
///
/// ```text
/// mov     r3, r2              ; id_out
/// movs    r2, r1              ; counted, setting Z on NULL
/// ldrhne  r2, [r1], #2        ; len = *counted, data = counted + 1
/// lslne   r2, r2, #1          ; len in bytes = u16 unit count * 2
/// b       0x080b4e60          ; tail: store(pool, data, len, id_out)
/// ```
///
/// A non-NULL `counted` yields `data = counted + 1` (the payload
/// directly follows the length word) and `len = *counted * 2` — the
/// prefix counts 16-bit units, the pool stores bytes. A NULL `counted`
/// leaves both zero (`movs` copies the NULL into the length register
/// and the predicated halfword load is skipped), so storing NULL is how
/// a caller clears a slot: the wrapper releases the old id, and the
/// interning writer's zero-length path zeroes `*id_out` and returns 0.
/// The thunk itself guards and dereferences nothing — every check
/// (pool tag, NULL `id_out`) is the tail target's, exactly as in the
/// original.
///
/// The fifteen call sites (0x08046388, 0x0804644c, 0x0804650c,
/// 0x08046570, 0x080465d4, 0x080671e8, 0x080672a0, 0x08067bd8,
/// 0x08067c04, 0x08067c30, 0x08067c84, 0x08094d24, 0x080cb24c,
/// 0x080cb298, 0x080dcb2c) are all plain `bl`; the address occurs in
/// no data word, so the function is never dispatched virtually.
///
/// # Deliberate deviations
///
/// - The unported tail target dispatches through the volatile seam
///   [`STRING_POOL_STORE`], whose default transmutes the retail address
///   0x080b4e60 so the port is hook-ready on device, while host tests
///   install a recording mock (the `util/crts_object.rs` precedent). No
///   identity beyond the raw-byte-verified behaviour documented on
///   [`StringPoolStore`] is invented for it.
/// - The length is widened to `u32` before doubling, as the original's
///   `ldrh` + `lsl` on a 32-bit register do: a count of 0x8000 yields
///   0x10000 bytes, not 0.
///
/// # Safety
///
/// `counted` must be NULL or point to a readable `u16` length followed
/// by that many `u16` units; `pool` and `id_out` are forwarded
/// unchecked to the retail wrapper, which requires a valid `"crts"`
/// pool and a writable id slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_store_counted(
    pool: *mut StringPool,
    counted: *const u16,
    id_out: *mut i32,
) -> i32 {
    let mut data = counted as *const u8;
    let mut len = 0u32;
    if !counted.is_null() {
        len = (counted.read() as u32) << 1;
        data = counted.add(1) as *const u8;
    }
    string_pool_store_seam()(pool, data, len, id_out)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    /// A pool whose two handles resolve to owned arrays. The cells hold the
    /// master pointers, so the fixture must not move once wired — hence the
    /// `Box`.
    struct Fixture {
        entries: Vec<PoolEntry>,
        refcounts: Vec<i32>,
        entries_cell: *mut PoolEntry,
        refcounts_cell: *mut i32,
        pool: StringPool,
    }

    /// Builds a pool of `entries.len()` slots whose refcounts start at
    /// `refcounts` (pass an empty vector for a pool without counts).
    fn fixture(flags: u32, entries: Vec<PoolEntry>, refcounts: Vec<i32>) -> Box<Fixture> {
        let entry_count = entries.len() as i32;
        let mut fixture = Box::new(Fixture {
            entries,
            refcounts,
            entries_cell: core::ptr::null_mut(),
            refcounts_cell: core::ptr::null_mut(),
            pool: StringPool {
                tag: CRTS_TAG,
                flags,
                entries: core::ptr::null_mut(),
                refcounts: core::ptr::null_mut(),
                payload_and_index: [0; 3],
                entry_count,
                allocator_state: [0; 4],
                lock_depth: 0,
                reclaimable_bytes: 0,
            },
        });
        fixture.entries_cell = fixture.entries.as_mut_ptr();
        fixture.refcounts_cell = fixture.refcounts.as_mut_ptr();
        fixture.pool.entries = core::ptr::addr_of_mut!(fixture.entries_cell);
        fixture.pool.refcounts = core::ptr::addr_of_mut!(fixture.refcounts_cell);
        fixture
    }

    /// Three live entries of 10, 20 and 30 bytes.
    fn live_entries() -> Vec<PoolEntry> {
        std::vec![
            PoolEntry { blob_offset: 0, length: 10 },
            PoolEntry { blob_offset: 16, length: 20 },
            PoolEntry { blob_offset: 48, length: 30 },
        ]
    }

    #[test]
    fn null_pool_is_param_err() {
        unsafe {
            assert_eq!(string_pool_release(core::ptr::null_mut(), 1), PARAM_ERR);
            assert_eq!(string_pool_release(core::ptr::null_mut(), 0), PARAM_ERR);
        }
    }

    #[test]
    fn foreign_tag_is_param_err_and_changes_nothing() {
        let mut f = fixture(0, live_entries(), Vec::new());
        f.pool.tag = 0x7374_7264; // "drts"
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), PARAM_ERR);
        }
        assert_eq!(f.entries[0].blob_offset, 0);
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn a_locked_pool_refuses_even_a_zero_id() {
        let mut f = fixture(0, live_entries(), Vec::new());
        f.pool.lock_depth = 1;
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), PARAM_ERR);
            assert_eq!(
                string_pool_release(&mut f.pool, 0),
                PARAM_ERR,
                "the lock is checked before the id-0 shortcut"
            );
        }
        assert_eq!(f.entries[0].blob_offset, 0);
    }

    #[test]
    fn an_immutable_pool_refuses_every_release() {
        let mut f = fixture(FLAG_IMMUTABLE, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 2), PARAM_ERR);
            assert_eq!(string_pool_release(&mut f.pool, 0), PARAM_ERR);
        }
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn id_zero_succeeds_without_touching_the_pool() {
        let mut f = fixture(0, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 0), 0);
        }
        assert!(f.entries.iter().all(|e| e.blob_offset != ENTRY_RECLAIMABLE));
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn negative_and_out_of_range_ids_are_param_err() {
        let mut f = fixture(0, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, -1), PARAM_ERR);
            assert_eq!(string_pool_release(&mut f.pool, i32::MIN), PARAM_ERR);
            assert_eq!(string_pool_release(&mut f.pool, 4), PARAM_ERR);
            assert_eq!(string_pool_release(&mut f.pool, i32::MAX), PARAM_ERR);
        }
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn the_last_id_is_in_range() {
        let mut f = fixture(0, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 3), 0);
        }
        assert_eq!(f.entries[2].blob_offset, ENTRY_RECLAIMABLE);
        assert_eq!(f.pool.reclaimable_bytes, 30);
    }

    #[test]
    fn an_empty_pool_rejects_id_one_but_still_accepts_id_zero() {
        let mut f = fixture(0, Vec::new(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), PARAM_ERR);
            assert_eq!(string_pool_release(&mut f.pool, 0), 0);
        }
    }

    #[test]
    fn an_uncounted_release_marks_the_entry_and_banks_its_length() {
        let mut f = fixture(0, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 2), 0);
        }
        assert_eq!(f.entries[1].blob_offset, ENTRY_RECLAIMABLE);
        assert_eq!(f.entries[1].length, 20, "the length survives for compaction");
        assert_eq!(f.entries[0].blob_offset, 0, "neighbours are untouched");
        assert_eq!(f.entries[2].blob_offset, 48);
        assert_eq!(f.pool.reclaimable_bytes, 20);
    }

    #[test]
    fn reclaimable_bytes_accumulate_across_releases() {
        let mut f = fixture(0, live_entries(), Vec::new());
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), 0);
            assert_eq!(string_pool_release(&mut f.pool, 3), 0);
        }
        assert_eq!(f.pool.reclaimable_bytes, 40);
    }

    #[test]
    fn reclaimable_bytes_wrap_like_the_originals_add() {
        let mut f = fixture(0, live_entries(), Vec::new());
        f.pool.reclaimable_bytes = i32::MAX;
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), 0);
        }
        assert_eq!(f.pool.reclaimable_bytes, i32::MIN + 9);
    }

    #[test]
    fn a_counted_release_only_decrements_while_references_remain() {
        let mut f = fixture(FLAG_REFCOUNTED, live_entries(), std::vec![1, 3, 1]);
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 2), 0);
        }
        assert_eq!(f.refcounts[1], 2);
        assert_eq!(f.entries[1].blob_offset, 16, "still live");
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn a_counted_release_frees_when_the_last_reference_drops() {
        let mut f = fixture(FLAG_REFCOUNTED, live_entries(), std::vec![1, 2, 1]);
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 2), 0);
            assert_eq!(string_pool_release(&mut f.pool, 2), 0);
        }
        assert_eq!(f.refcounts[1], 0);
        assert_eq!(f.entries[1].blob_offset, ENTRY_RECLAIMABLE);
        assert_eq!(f.pool.reclaimable_bytes, 20);
    }

    #[test]
    fn a_counted_release_of_an_already_zero_entry_underflows_and_does_not_free() {
        let mut f = fixture(FLAG_REFCOUNTED, live_entries(), std::vec![0, 0, 0]);
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), 0);
        }
        assert_eq!(f.refcounts[0], -1, "the original decrements unconditionally");
        assert_eq!(f.entries[0].blob_offset, 0, "only a zero result frees");
        assert_eq!(f.pool.reclaimable_bytes, 0);
    }

    #[test]
    fn an_uncounted_pool_never_reads_the_refcount_handle() {
        let mut f = fixture(0, live_entries(), Vec::new());
        f.pool.refcounts = core::ptr::null_mut();
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), 0);
        }
        assert_eq!(f.entries[0].blob_offset, ENTRY_RECLAIMABLE);
    }

    #[test]
    fn handles_are_read_through_the_master_pointer_at_call_time() {
        let mut f = fixture(0, live_entries(), Vec::new());
        let mut relocated = live_entries();
        f.entries_cell = relocated.as_mut_ptr();
        unsafe {
            assert_eq!(string_pool_release(&mut f.pool, 1), 0);
        }
        assert_eq!(relocated[0].blob_offset, ENTRY_RECLAIMABLE);
        assert_eq!(f.entries[0].blob_offset, 0, "the old block is not touched");
    }

    // --- string_pool_copy_entry seam-mock scaffolding ---

    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes the tests that swap the pool reader/intern seams and the
    /// heap ops table (the crts_object.rs `DESTROY_LOCK` precedent).
    static COPY_LOCK: Mutex<()> = Mutex::new(());

    /// Sentinel pool pointers; the copy function never dereferences them
    /// and the recording mocks only compare them.
    const SRC_POOL: usize = 0x5000_0000;
    const DST_POOL: usize = 0x5000_0100;

    /// One observed reader call. `dst == 0` marks the size query.
    #[derive(Clone, PartialEq, Debug)]
    struct ReadCall {
        pool: usize,
        id: i32,
        dst: usize,
        max_len: u32,
    }

    /// One observed intern call, with the payload bytes captured at call
    /// time (the scratch buffer is dead by assert time).
    #[derive(Clone, PartialEq, Debug)]
    struct InternCall {
        pool: usize,
        bytes: Vec<u8>,
        id_out: usize,
    }

    static mut READ_CALLS: Vec<ReadCall> = Vec::new();
    static mut READ_QUERY_STATUS: i32 = 0;
    static mut READ_COPY_STATUS: i32 = 0;
    /// Payload the mock reader reports and copies.
    static mut PAYLOAD: Vec<u8> = Vec::new();

    static mut INTERN_CALLS: Vec<InternCall> = Vec::new();
    static mut INTERN_STATUS: i32 = 0;
    /// Id the mock intern writes through `id_out`.
    static mut INTERN_NEW_ID: i32 = 0;

    unsafe extern "C" fn recording_pool_read(
        pool: *mut StringPool,
        id: i32,
        dst: *mut u8,
        len_out: *mut u32,
        max_len: u32,
    ) -> i32 {
        READ_CALLS.push(ReadCall { pool: pool as usize, id, dst: dst as usize, max_len });
        if dst.is_null() {
            if READ_QUERY_STATUS == 0 && !len_out.is_null() {
                *len_out = PAYLOAD.len() as u32;
            }
            READ_QUERY_STATUS
        } else {
            if READ_COPY_STATUS != 0 {
                return READ_COPY_STATUS;
            }
            let n = core::cmp::min(PAYLOAD.len(), max_len as usize);
            ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), dst, n);
            if !len_out.is_null() {
                *len_out = n as u32;
            }
            0
        }
    }

    unsafe extern "C" fn recording_pool_intern(
        pool: *mut StringPool,
        data: *const u8,
        len: u32,
        id_out: *mut i32,
    ) -> i32 {
        let bytes = std::slice::from_raw_parts(data, len as usize).to_vec();
        INTERN_CALLS.push(InternCall { pool: pool as usize, bytes, id_out: id_out as usize });
        if !id_out.is_null() {
            *id_out = INTERN_NEW_ID;
        }
        INTERN_STATUS
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                STRING_POOL_READ = missing_string_pool_read;
                STRING_POOL_INTERN = missing_string_pool_intern;
                STRING_POOL_STORE = missing_string_pool_store;
                core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS)
                    .write(crate::heap::veneers::DEFAULT_HEAP_OPS);
                READ_CALLS = Vec::new();
                READ_QUERY_STATUS = 0;
                READ_COPY_STATUS = 0;
                PAYLOAD = Vec::new();
                INTERN_CALLS = Vec::new();
                INTERN_STATUS = 0;
                INTERN_NEW_ID = 0;
                STORE_CALLS = Vec::new();
                STORE_STATUS = 0;
            }
        }
    }

    /// Installs the recording seams and the mock heap; returns the locks
    /// (copy lock first, heap lock second — the inner_state.rs order) and
    /// the reset guard.
    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, Reset) {
        let copy_guard = COPY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            STRING_POOL_READ = recording_pool_read;
            STRING_POOL_INTERN = recording_pool_intern;
        }
        (copy_guard, heap_guard, Reset)
    }

    #[test]
    fn query_failure_returns_status_and_calls_nothing_else() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        unsafe {
            READ_QUERY_STATUS = PARAM_ERR;
            let mut out_id = -1i32;
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                3,
                DST_POOL as *mut StringPool,
                &mut out_id,
            );
            assert_eq!(status, PARAM_ERR);
            assert_eq!(out_id, -1, "the intern never ran");
            assert_eq!(
                READ_CALLS,
                std::vec![ReadCall { pool: SRC_POOL, id: 3, dst: 0, max_len: QUERY_MAX_LEN }],
                "one size query with a NULL buffer"
            );
            assert!(INTERN_CALLS.is_empty());
        }
        assert_eq!(alloc_log().0, 0, "no scratch allocation on query failure");
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn small_blob_copies_through_the_stack_buffer() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        unsafe {
            PAYLOAD = b"hello".to_vec();
            INTERN_NEW_ID = 7;
            let mut out_id = -1i32;
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                3,
                DST_POOL as *mut StringPool,
                &mut out_id,
            );
            assert_eq!(status, 0);
            assert_eq!(out_id, 7);
            assert_eq!(READ_CALLS.len(), 2, "query then copy");
            assert_eq!(READ_CALLS[0].dst, 0);
            assert_eq!(READ_CALLS[0].max_len, QUERY_MAX_LEN);
            assert_ne!(READ_CALLS[1].dst, 0, "the copy read gets a real buffer");
            assert_eq!(READ_CALLS[1].max_len, 5, "clipped to the queried length");
            assert_eq!(
                INTERN_CALLS,
                std::vec![InternCall {
                    pool: DST_POOL,
                    bytes: b"hello".to_vec(),
                    id_out: &mut out_id as *mut i32 as usize,
                }]
            );
        }
        assert_eq!(alloc_log().0, 0, "512 bytes and under stay on the stack");
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn exactly_512_bytes_stays_on_the_stack() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        unsafe {
            PAYLOAD = std::vec![0xab; STACK_BLOB_CAPACITY];
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                1,
                DST_POOL as *mut StringPool,
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(INTERN_CALLS.len(), 1);
            assert_eq!(INTERN_CALLS[0].bytes.len(), STACK_BLOB_CAPACITY);
            assert_eq!(INTERN_CALLS[0].id_out, 0, "a NULL id_out passes through");
        }
        assert_eq!(alloc_log().0, 0, "the original's compare is unsigned ls");
    }

    #[test]
    fn larger_blob_round_trips_through_the_tag4_heap() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        let mut backing = std::vec![0u8; STACK_BLOB_CAPACITY + 1];
        unsafe {
            PAYLOAD = (0..=STACK_BLOB_CAPACITY).map(|i| (i & 0xff) as u8).collect();
            set_alloc_ret(backing.as_mut_ptr());
            let mut out_id = 0i32;
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                2,
                DST_POOL as *mut StringPool,
                &mut out_id,
            );
            assert_eq!(status, 0);
            assert_eq!(INTERN_CALLS.len(), 1);
            assert_eq!(INTERN_CALLS[0].bytes, PAYLOAD);
        }
        assert_eq!(alloc_log(), (1, (STACK_BLOB_CAPACITY + 1) as usize, 4));
        assert_eq!(free_log(), (1, backing.as_mut_ptr(), 4), "scratch freed");
    }

    #[test]
    fn allocation_failure_is_mem_full_err() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        unsafe {
            PAYLOAD = std::vec![0xcd; STACK_BLOB_CAPACITY + 88];
            set_alloc_ret(ptr::null_mut());
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                2,
                DST_POOL as *mut StringPool,
                ptr::null_mut(),
            );
            assert_eq!(status, MEM_FULL_ERR);
            assert_eq!(READ_CALLS.len(), 1, "no copy read without a buffer");
            assert!(INTERN_CALLS.is_empty());
        }
        assert_eq!(alloc_log().0, 1);
        assert_eq!(free_log().0, 0, "nothing to free");
    }

    #[test]
    fn copy_read_failure_propagates_and_frees_the_heap_buffer() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        let mut backing = std::vec![0u8; STACK_BLOB_CAPACITY + 88];
        unsafe {
            PAYLOAD = std::vec![0xcd; STACK_BLOB_CAPACITY + 88];
            READ_COPY_STATUS = PARAM_ERR;
            set_alloc_ret(backing.as_mut_ptr());
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                2,
                DST_POOL as *mut StringPool,
                ptr::null_mut(),
            );
            assert_eq!(status, PARAM_ERR);
            assert_eq!(READ_CALLS.len(), 2);
            assert!(INTERN_CALLS.is_empty(), "no intern after a failed read");
        }
        assert_eq!(free_log(), (1, backing.as_mut_ptr(), 4), "freed on the way out");
    }

    #[test]
    fn intern_failure_propagates_and_still_frees() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        let mut backing = std::vec![0u8; STACK_BLOB_CAPACITY + 88];
        unsafe {
            PAYLOAD = std::vec![0xcd; STACK_BLOB_CAPACITY + 88];
            INTERN_STATUS = PARAM_ERR;
            set_alloc_ret(backing.as_mut_ptr());
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                2,
                DST_POOL as *mut StringPool,
                ptr::null_mut(),
            );
            assert_eq!(status, PARAM_ERR);
            assert_eq!(INTERN_CALLS.len(), 1);
        }
        assert_eq!(free_log(), (1, backing.as_mut_ptr(), 4));
    }

    #[test]
    fn zero_length_blob_interns_zero_bytes_from_the_stack() {
        let (_copy_guard, _heap_guard, _reset) = mock();
        unsafe {
            PAYLOAD = Vec::new();
            let status = string_pool_copy_entry(
                SRC_POOL as *mut StringPool,
                9,
                DST_POOL as *mut StringPool,
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(INTERN_CALLS.len(), 1);
            assert!(INTERN_CALLS[0].bytes.is_empty());
        }
        assert_eq!(alloc_log().0, 0);
    }

    // --- string_pool_store_counted seam-mock scaffolding ---

    /// One observed replace-and-intern call, with the payload bytes
    /// captured at call time (the caller's string may be dead by assert
    /// time). `data` keeps the raw pointer so the NULL/empty distinction
    /// stays visible.
    #[derive(Clone, PartialEq, Debug)]
    struct StoreCall {
        pool: usize,
        data: usize,
        bytes: Vec<u8>,
        id_out: usize,
    }

    static mut STORE_CALLS: Vec<StoreCall> = Vec::new();
    static mut STORE_STATUS: i32 = 0;

    unsafe extern "C" fn recording_pool_store(
        pool: *mut StringPool,
        data: *const u8,
        len: u32,
        id_out: *mut i32,
    ) -> i32 {
        let bytes = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len as usize).to_vec()
        };
        STORE_CALLS.push(StoreCall { pool: pool as usize, data: data as usize, bytes, id_out: id_out as usize });
        STORE_STATUS
    }

    /// Installs the recording store seam. Takes the same COPY_LOCK so a
    /// store test can never run beside a copy test while the shared
    /// seam statics are swapped; the heap lock is not needed (the thunk
    /// allocates nothing).
    fn store_mock() -> (MutexGuard<'static, ()>, Reset) {
        let copy_guard = COPY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            STRING_POOL_STORE = recording_pool_store;
        }
        (copy_guard, Reset)
    }

    /// The little-endian byte image of a u16 slice, as the pool's byte
    /// blob would hold it.
    fn utf16_bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn null_string_stores_len_zero_from_a_null_data_pointer() {
        let (_copy_guard, _reset) = store_mock();
        unsafe {
            STORE_STATUS = 42;
            let mut slot = 9i32;
            let status = string_pool_store_counted(
                SRC_POOL as *mut StringPool,
                ptr::null(),
                &mut slot,
            );
            assert_eq!(status, 42, "the wrapper's status passes through");
            assert_eq!(slot, 9, "the thunk never writes id_out itself");
            assert_eq!(
                STORE_CALLS,
                std::vec![StoreCall {
                    pool: SRC_POOL,
                    data: 0,
                    bytes: Vec::new(),
                    id_out: &mut slot as *mut i32 as usize,
                }],
                "movs r2, r1 leaves data and length both zero"
            );
        }
    }

    #[test]
    fn empty_string_stores_zero_bytes_past_the_length_word() {
        let (_copy_guard, _reset) = store_mock();
        let counted = [0u16];
        unsafe {
            let mut slot = 0i32;
            let status = string_pool_store_counted(
                SRC_POOL as *mut StringPool,
                counted.as_ptr(),
                &mut slot,
            );
            assert_eq!(status, 0);
            assert_eq!(STORE_CALLS.len(), 1);
            let call = &STORE_CALLS[0];
            assert_eq!(call.data, counted.as_ptr() as usize + 2);
            assert!(call.bytes.is_empty(), "a zero count doubles to zero bytes");
        }
    }

    #[test]
    fn counted_payload_passes_through_as_bytes() {
        let (_copy_guard, _reset) = store_mock();
        let counted = [3u16, 0x0061, 0x0062, 0x0063]; // "abc"
        unsafe {
            let status = string_pool_store_counted(
                SRC_POOL as *mut StringPool,
                counted.as_ptr(),
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(
                STORE_CALLS,
                std::vec![StoreCall {
                    pool: SRC_POOL,
                    data: counted.as_ptr() as usize + 2,
                    bytes: utf16_bytes(&counted[1..]),
                    id_out: 0, // a NULL id_out is forwarded unchecked
                }]
            );
        }
    }

    #[test]
    fn the_count_widens_to_u32_before_doubling() {
        let (_copy_guard, _reset) = store_mock();
        // 0x8000 units: a u16 shift would wrap to a zero length, the
        // original's 32-bit lsl gives 0x10000 bytes.
        let mut counted = std::vec![0u16; 0x8001];
        counted[0] = 0x8000;
        unsafe {
            let status = string_pool_store_counted(
                SRC_POOL as *mut StringPool,
                counted.as_ptr(),
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(STORE_CALLS.len(), 1);
            assert_eq!(STORE_CALLS[0].bytes.len(), 0x10000);
            assert_eq!(STORE_CALLS[0].data, counted.as_ptr() as usize + 2);
        }
    }

    #[test]
    fn pool_and_failure_status_pass_through_unchecked() {
        let (_copy_guard, _reset) = store_mock();
        let counted = [1u16, 0x0078];
        unsafe {
            STORE_STATUS = PARAM_ERR;
            let status = string_pool_store_counted(
                ptr::null_mut(),
                counted.as_ptr(),
                ptr::null_mut(),
            );
            assert_eq!(status, PARAM_ERR);
            assert_eq!(STORE_CALLS.len(), 1, "the thunk guards nothing itself");
            assert_eq!(STORE_CALLS[0].pool, 0, "even a NULL pool is forwarded");
            assert_eq!(STORE_CALLS[0].bytes, utf16_bytes(&counted[1..]));
        }
    }
}
