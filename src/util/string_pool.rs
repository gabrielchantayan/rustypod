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
//! - The separately linked 0x080a7714 tag guard is ported as
//!   [`crate::util::crts_tag::crts_has_tag`] and called directly, without a
//!   replaceable dispatch seam.
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
use crate::util::crts_tag::crts_has_tag;
use crate::util::pool_entry_is_live::pool_entry_is_live;
#[cfg(target_pointer_width = "32")]
use crate::util::tagged_counter::{tagged_counter_try_decrement, tagged_counter_try_increment};

type BcopyPort = unsafe extern "C" fn(*const u8, *mut u8, usize);

/// A volatile load prevents LLVM from recognizing bcopy's memmove tail and
/// replacing the call with an AEABI builtin.
static BCOPY_PORT: BcopyPort = crate::libc::bcopy::bcopy;
#[cfg(test)]
use crate::util::crts_tag::CRTS_TAG;
#[cfg(test)]
extern crate std;


/// Serializes host tests that replace the shared pool-store boundary.
///
/// Ports that call [`string_pool_store_counted`] directly use this same lock
/// before installing their recorder, so they cannot race this module's own
/// seam tests.
#[cfg(test)]
pub(crate) static STRING_POOL_SEAM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());


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
    /// +0x10 — handle to the byte blob. The reader dereferences this
    /// master pointer only when copying payload bytes.
    pub payload: *mut *mut u8,
    /// +0x14..+0x1c — the two hash-index arrays and entry count.
    hash_indices: [u32; 2],
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
    assert!(offset_of!(StringPool, payload) == 0x10);
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
    if crts_has_tag(pool.cast()) == 0 {
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

/// string_pool_read — original: `FUN_080b4318` @ 0x080b4318 (204 bytes;
/// **6 direct `bl` call sites, all unconditional**, binary-scanned).
///
/// Raw ARM establishes the exact extent: `push {r4-r9,sl,lr}` begins at
/// 0x080b4318, `pop {r4-r9,sl,pc}` returns at 0x080b43e0, and the next
/// separately linked function begins with `b 0x082841c8` at 0x080b43e4.
/// It first clears non-NULL `len_out`, then validates the `"crts"` tag and
/// a positive 1-based `id` in range. It increments the pool's +0x30 counter,
/// accepts an entry only when both signed words are positive/non-negative,
/// copies `min(entry.length, max_len as i32)` bytes only for non-NULL `dst`,
/// writes that length, and decrements the counter on both entry outcomes.
///
/// The separately linked 0x080ac160 entry-live predicate is ported as
/// [`crate::util::pool_entry_is_live::pool_entry_is_live`] and called
/// directly. Existing 0x080a7714 / 0x0808e16c / 0x0809f744 ports are called
/// directly. The bcopy function pointer is read volatile to prevent LLVM
/// replacing its memmove tail with an AEABI builtin; there is no seam.
///
/// On 64-bit hosts, `StringPool` uses native handle pointers, so its
/// `lock_depth` is not at the target's +0x30. The host build updates that
/// modeled field directly; 32-bit firmware calls the two counter ports.
///
/// # Safety
///
/// A tag-valid pool with an accepted id must carry live entry and payload
/// handles. `dst`, when non-NULL, must have room for the signed-clamped
/// length; retailOS deliberately has no guard for a negative `max_len`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_read(
    pool: *mut StringPool,
    id: i32,
    dst: *mut u8,
    len_out: *mut u32,
    max_len: u32,
) -> i32 {
    if !len_out.is_null() {
        len_out.write(0);
    }
    if crts_has_tag(pool.cast()) == 0 {
        return PARAM_ERR;
    }
    if id == 0 {
        return 0;
    }
    if id < 0 || id > (*pool).entry_count {
        return PARAM_ERR;
    }

    #[cfg(target_pointer_width = "32")]
    let _ = tagged_counter_try_increment(pool.cast());
    #[cfg(not(target_pointer_width = "32"))]
    {
        (*pool).lock_depth = (*pool).lock_depth.wrapping_add(1);
    }
    let entry = (*(*pool).entries).add((id - 1) as usize);
    let status = if pool_entry_is_live(entry.cast()) == 0 {
        PARAM_ERR
    } else {
        let copied_len = (*entry).length.min(max_len as i32);
        if !dst.is_null() {
            let payload = *(*pool).payload;
            ptr::read_volatile(ptr::addr_of!(BCOPY_PORT))(
                payload.add((*entry).blob_offset as usize),
                dst,
                copied_len as usize,
            );
        }
        if !len_out.is_null() {
            len_out.write(copied_len as u32);
        }
        0
    };
    #[cfg(target_pointer_width = "32")]
    let _ = tagged_counter_try_decrement(pool.cast());
    #[cfg(not(target_pointer_width = "32"))]
    if (*pool).lock_depth > 0 {
        (*pool).lock_depth -= 1;
    }
    status
}

/// RetailOS load address of the unported pool interning writer
/// (824 bytes).
pub const STRING_POOL_INTERN_ADDRESS: usize = 0x080c_5a94;

/// RetailOS load address of the unported replace-and-intern wrapper
/// [`string_pool_store_counted`] tail-branches into (76 bytes; the
/// `bx lr` at 0x080b4eb0 is inter-function alignment padding, not body).
pub const STRING_POOL_STORE_ADDRESS: usize = 0x080b_4e60;

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

/// Active boundary for the unported pool interning writer; host tests replace
/// it with a recording implementation.
#[cfg(target_os = "none")]
pub static mut STRING_POOL_INTERN: StringPoolIntern = retail_string_pool_intern;

/// Active host boundary for the unported pool interning writer.
#[cfg(not(target_os = "none"))]
pub static mut STRING_POOL_INTERN: StringPoolIntern = missing_string_pool_intern;


#[inline(always)]
unsafe fn string_pool_intern_seam() -> StringPoolIntern {
    ptr::read_volatile(ptr::addr_of!(STRING_POOL_INTERN))
}

/// Active boundary for the unported replace-and-intern wrapper; retail target
/// 0x080b4e60.
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
/// - The reader @ 0x080b4318 is now ported as [`string_pool_read`] and is
///   called directly. The unported interning writer continues to use
///   [`STRING_POOL_INTERN`] so host tests can record its ABI.
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
    let status = string_pool_read(src, src_id, ptr::null_mut(), &mut len, QUERY_MAX_LEN);
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
    let mut status = string_pool_read(src, src_id, blob, &mut len, len);
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

/// string_pool_intern_counted — original: `FUN_080c9ff8` @ 0x080c9ff8
/// (20 bytes; **7 direct `bl` call sites, all unconditional, plus one tail
/// `b`; no data-word references** — binary-verified by decoding every ARM
/// B/BL word and every word equal to the address in `osos.dec`).
///
/// Interns a u16-length-prefixed UTF-16 string without releasing the id
/// already held in `id_out`. The entire body is a five-instruction
/// argument-mangling thunk. The next separately linked function begins at
/// 0x080ca00c (`push {r4,r5,r6,lr}`), so the five words from 0x080c9ff8
/// through 0x080ca008 are the complete extent; Ghidra instead attaches the
/// 0x080c5a94 interning body to this address:
///
/// ```text
/// mov     r3, r2              ; id_out
/// movs    r2, r1              ; counted, setting Z on NULL
/// ldrhne  r2, [r1], #2        ; len = *counted, data = counted + 1
/// lslne   r2, r2, #1          ; len in bytes = u16 unit count * 2
/// b       0x080c5a94          ; tail: intern(pool, data, len, id_out)
/// ```
///
/// A non-NULL `counted` forwards the bytes after its length prefix and a
/// byte length of `*counted * 2`. A NULL `counted` forwards NULL and zero,
/// leaving the interning writer to apply its documented zero-length
/// behavior. The thunk performs no validation or writes of its own.
///
/// The seven direct callers are 0x08068584, 0x0809604c, 0x080960b8,
/// 0x0809611c, 0x08096190, 0x080be520, and 0x080be688; all are plain `bl`.
///
/// # Deliberate deviation
///
/// The unported tail target dispatches through the volatile
/// [`STRING_POOL_INTERN`] seam, whose target default is retailOS
/// 0x080c5a94. This makes the thunk hook-ready on-device and lets host tests
/// observe the exact forwarded ABI without assigning an unverified identity
/// to the interning writer beyond [`StringPoolIntern`].
///
/// # Safety
///
/// `counted` must be NULL or point to a readable `u16` length followed by
/// that many `u16` units. `pool` and `id_out` are forwarded unchecked to the
/// retail interning writer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_intern_counted(
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
    string_pool_intern_seam()(pool, data, len, id_out)
}
/// string_pool_read_counted — original: `FUN_080bd8bc` @ 0x080bd8bc
/// (52 bytes including its trailing literal-pool word; **6 direct `bl` call
/// sites, all unconditional** — binary-verified by decoding every ARM B/BL
/// word in `osos.dec`).
///
/// Reads one pool entry as a u16-length-prefixed byte payload. The blob reader
/// writes at `counted + 1` with its fixed 510-byte cap, then the wrapper
/// stores the copied byte count divided by two in `*counted`, and returns the
/// reader status left in `r0`. The fourth ABI argument initializes the stack
/// length local before the reader call, but the reader unconditionally clears
/// its non-NULL length output before any validation; it therefore has no
/// observable effect.
///
/// Raw ARM establishes the true extent: `push {r2,r3,r4,lr}` starts at
/// 0x080bd8bc, the return `pop {r2,r3,r4,pc}` is at 0x080bd8e8, its
/// `0x000001fe` literal pool word is at 0x080bd8ec, and the separately linked
/// next function begins with `ldr r2,[pc,#92]` at 0x080bd8f0. Ghidra's
/// reported 48-byte body excludes the literal pool. The six direct callers
/// are 0x080530fc, 0x080537e0, 0x08095da8, 0x0809603c, 0x080dcafc, and
/// 0x0813db6c; none is predicated. No deviation: it calls the ported
/// [`string_pool_read`] directly.
///
/// # Safety
///
/// `pool`, `counted`, and `entry_id` are forwarded unchecked to the pool
/// reader. `counted` must have writable space for its leading count and up to
/// 510 payload bytes; the original dereferences it unconditionally.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_read_counted(
    pool: *mut StringPool,
    entry_id: i32,
    counted: *mut u16,
    initial_byte_len: u32,
) -> i32 {
    let mut byte_len = initial_byte_len;
    let status = string_pool_read(pool, entry_id, counted.add(1).cast(), &mut byte_len, 0x1fe);
    counted.write((byte_len >> 1) as u16);
    status
}

/// string_pool_read_counted_from_context — original: `FUN_080556cc` @
/// `0x080556cc` (20 bytes; **7 direct `bl` call sites** — five plain `bl`,
/// two `blne`; no tail branches or data-word references).
///
/// Raw ARM establishes the complete five-word tail wrapper: it runs from
/// `0x080556cc` through `b 0x080bd8bc` at `0x080556dc`; the separately linked
/// sibling begins with `push {r4,lr}` at `0x080556e0`. The tail target reads a
/// UTF-16 payload from a `"crts"` pool with a fixed 510-byte limit, writes its
/// byte count to a stack local, then stores half that count into the output's
/// leading `u16`.
///
/// `context[0]` is a target-width pointer to an owner whose `"crts"` pool is
/// at `+0x1c8`; `context + 0x34` is the signed pool entry id. The wrapper
/// writes bytes beginning at `counted + 1`, then replaces `*counted` with the
/// copied byte length divided by two. It deliberately ignores the reader
/// status, as does retailOS. The reader zeros its non-NULL length output
/// before any failure path, so the initialized local below is equivalent to
/// the raw stack path.
///
/// The seven inbound calls are `bl` at 0x080463b8, 0x08047924, 0x0817b1e4,
/// 0x0817b844, and 0x082a3908, plus `blne` at 0x0817b0a8 and 0x0817b754.
/// Those conditional calls are caller-side gates, not NULL guards: this
/// wrapper dereferences both arguments unconditionally.
///
/// # Safety
///
/// `context` must be 4-byte aligned and point to readable target-layout
/// words at `+0x00` and `+0x34`; its first word must name an owner with a
/// valid pool at `+0x1c8`. `counted` must point to writable storage for one
/// leading `u16` plus 255 UTF-16 units; [`string_pool_read`] validates the
/// pool/id inputs but is otherwise called unchecked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_pool_read_counted_from_context(
    context: *const u8,
    counted: *mut u16,
) {
    let owner = context.cast::<u32>().read() as usize as *mut u8;
    let pool = owner.add(0x1c8).cast::<StringPool>();
    let entry_id = context.add(0x34).cast::<i32>().read();
    let mut byte_len = 0u32;
    let _ = string_pool_read(pool, entry_id, counted.add(1).cast(), &mut byte_len, 0x1fe);
    counted.write((byte_len >> 1) as u16);
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
        payload: Vec<u8>,
        entries_cell: *mut PoolEntry,
        refcounts_cell: *mut i32,
        payload_cell: *mut u8,
        pool: StringPool,
    }

    /// Builds a pool of `entries.len()` slots whose refcounts start at
    /// `refcounts` (pass an empty vector for a pool without counts).
    fn fixture(flags: u32, entries: Vec<PoolEntry>, refcounts: Vec<i32>) -> Box<Fixture> {
        let entry_count = entries.len() as i32;
        let mut fixture = Box::new(Fixture {
            entries,
            refcounts,
            payload: Vec::new(),
            entries_cell: core::ptr::null_mut(),
            refcounts_cell: core::ptr::null_mut(),
            payload_cell: core::ptr::null_mut(),
            pool: StringPool {
                tag: CRTS_TAG,
                flags,
                entries: core::ptr::null_mut(),
                refcounts: core::ptr::null_mut(),
                payload: core::ptr::null_mut(),
                hash_indices: [0; 2],
                entry_count,
                allocator_state: [0; 4],
                lock_depth: 0,
                reclaimable_bytes: 0,
            },
        });
        fixture.entries_cell = fixture.entries.as_mut_ptr();
        fixture.refcounts_cell = fixture.refcounts.as_mut_ptr();
        fixture.payload_cell = fixture.payload.as_mut_ptr();
        fixture.pool.entries = core::ptr::addr_of_mut!(fixture.entries_cell);
        fixture.pool.refcounts = core::ptr::addr_of_mut!(fixture.refcounts_cell);
        fixture.pool.payload = core::ptr::addr_of_mut!(fixture.payload_cell);
        fixture
    }

    fn payload_fixture(payload: Vec<u8>) -> Box<Fixture> {
        let mut fixture = fixture(0, std::vec![PoolEntry {
            blob_offset: 0,
            length: payload.len() as i32,
        }], Vec::new());
        fixture.payload = payload;
        fixture.payload_cell = fixture.payload.as_mut_ptr();
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

    use std::sync::MutexGuard;

    const SRC_POOL: usize = 0x5000_0000;
    const DST_POOL: usize = 0x5000_0100;

    #[derive(Clone, PartialEq, Debug)]
    struct InternCall {
        pool: usize,
        data: usize,
        bytes: Vec<u8>,
        id_out: usize,
    }

    static mut INTERN_CALLS: Vec<InternCall> = Vec::new();
    static mut INTERN_STATUS: i32 = 0;
    static mut INTERN_NEW_ID: i32 = 0;

    unsafe extern "C" fn recording_pool_intern(
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
        INTERN_CALLS.push(InternCall { pool: pool as usize, data: data as usize, bytes, id_out: id_out as usize });
        if !id_out.is_null() {
            *id_out = INTERN_NEW_ID;
        }
        INTERN_STATUS
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                STRING_POOL_INTERN = missing_string_pool_intern;
                STRING_POOL_STORE = missing_string_pool_store;
                INTERN_CALLS = Vec::new();
                INTERN_STATUS = 0;
                INTERN_NEW_ID = 0;
                STORE_CALLS = Vec::new();
                STORE_STATUS = 0;
            }
        }
    }

    #[test]
    fn reader_clears_length_before_tag_validation() {
        let mut len = 0xdead_beefu32;
        unsafe {
            assert_eq!(string_pool_read(core::ptr::null_mut(), 1, ptr::null_mut(), &mut len, 1), PARAM_ERR);
        }
        assert_eq!(len, 0);
    }

    #[test]
    fn reader_zero_id_is_a_tagged_no_op() {
        let mut fixture = payload_fixture(b"payload".to_vec());
        let mut len = 9u32;
        let mut dst = [0xa5u8; 2];
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 0, dst.as_mut_ptr(), &mut len, 2), 0);
        }
        assert_eq!(len, 0);
        assert_eq!(dst, [0xa5; 2]);
        assert_eq!(fixture.pool.lock_depth, 0);
    }

    #[test]
    fn reader_rejects_negative_offset_or_nonpositive_length_without_locking() {
        let mut fixture = payload_fixture(b"payload".to_vec());
        let mut len = 7u32;
        fixture.pool.lock_depth = 11;
        fixture.entries[0].blob_offset = 0x8000_0000;
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 1, ptr::null_mut(), &mut len, 6), PARAM_ERR);
        }
        assert_eq!(len, 0);
        assert_eq!(fixture.pool.lock_depth, 11);
        fixture.entries[0].blob_offset = 0;
        fixture.entries[0].length = 0;
        len = 7;
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 1, ptr::null_mut(), &mut len, 6), PARAM_ERR);
        }
        assert_eq!(len, 0);
        assert_eq!(fixture.pool.lock_depth, 11);
    }

    #[test]
    fn reader_copies_signed_clamped_payload_and_restores_lock_depth() {
        let mut fixture = payload_fixture(b"_hello!".to_vec());
        fixture.entries[0].blob_offset = 1;
        fixture.entries[0].length = 5;
        fixture.pool.lock_depth = 7;
        let mut len = 0u32;
        let mut dst = [0u8; 3];
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 1, dst.as_mut_ptr(), &mut len, 3), 0);
        }
        assert_eq!(dst, *b"hel");
        assert_eq!(len, 3);
        assert_eq!(fixture.pool.lock_depth, 7);
    }

    #[test]
    fn reader_applies_signed_maximum_to_null_destination_query() {
        let mut fixture = payload_fixture(b"payload".to_vec());
        let mut len = 0u32;
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 1, ptr::null_mut(), &mut len, u32::MAX), 0);
        }
        assert_eq!(len, u32::MAX, "cmp/movgt treats max_len as signed");
        assert_eq!(fixture.pool.lock_depth, 0);
    }

    #[test]
    fn reader_tolerates_a_null_length_output() {
        let mut fixture = payload_fixture(b"payload".to_vec());
        let mut dst = [0u8; 7];
        unsafe {
            assert_eq!(string_pool_read(&mut fixture.pool, 1, dst.as_mut_ptr(), ptr::null_mut(), 7), 0);
        }
        assert_eq!(&dst, b"payload");
    }
    /// Installs the recording interning seam for
    /// [`string_pool_intern_counted`]. The shared lock prevents concurrent
    /// replacement of the global function-pointer seam.
    fn intern_mock() -> (MutexGuard<'static, ()>, Reset) {
        let intern_guard = STRING_POOL_SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            STRING_POOL_INTERN = recording_pool_intern;
        }
        (intern_guard, Reset)
    }

    #[test]
    fn intern_counted_null_forwards_null_data_and_zero_length() {
        let (_intern_guard, _reset) = intern_mock();
        unsafe {
            INTERN_STATUS = PARAM_ERR;
            INTERN_NEW_ID = 23;
            let mut slot = -1i32;
            let status = string_pool_intern_counted(
                SRC_POOL as *mut StringPool,
                ptr::null(),
                &mut slot,
            );
            assert_eq!(status, PARAM_ERR, "the interning status passes through");
            assert_eq!(slot, 23, "the thunk never owns the output slot");
            assert_eq!(
                INTERN_CALLS,
                std::vec![InternCall {
                    pool: SRC_POOL,
                    data: 0,
                    bytes: Vec::new(),
                    id_out: &mut slot as *mut i32 as usize,
                }]
            );
        }
    }

    #[test]
    fn intern_counted_empty_string_starts_after_the_length_word() {
        let (_intern_guard, _reset) = intern_mock();
        let counted = [0u16];
        unsafe {
            let status = string_pool_intern_counted(
                DST_POOL as *mut StringPool,
                counted.as_ptr(),
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(
                INTERN_CALLS,
                std::vec![InternCall {
                    pool: DST_POOL,
                    data: counted.as_ptr() as usize + 2,
                    bytes: Vec::new(),
                    id_out: 0,
                }]
            );
        }
    }

    #[test]
    fn intern_counted_forwards_utf16_bytes_and_widens_the_count() {
        let (_intern_guard, _reset) = intern_mock();
        let mut counted = std::vec![0u16; 0x8001];
        counted[0] = 0x8000;
        counted[1] = 0x0061;
        counted[2] = 0x20ac;
        unsafe {
            let status = string_pool_intern_counted(
                ptr::null_mut(),
                counted.as_ptr(),
                ptr::null_mut(),
            );
            assert_eq!(status, 0);
            assert_eq!(INTERN_CALLS.len(), 1);
            assert_eq!(INTERN_CALLS[0].pool, 0, "the thunk does not guard pool");
            assert_eq!(INTERN_CALLS[0].data, counted.as_ptr() as usize + 2);
            assert_eq!(INTERN_CALLS[0].bytes.len(), 0x10000);
            assert_eq!(&INTERN_CALLS[0].bytes[..4], &[0x61, 0, 0xac, 0x20]);
        }
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

    /// Installs the recording store seam. Takes the shared store lock so a
    /// store test can never run beside a copy test while the shared seam
    /// statics are swapped; the heap lock is not needed (the thunk allocates
    /// nothing).
    fn store_mock() -> (MutexGuard<'static, ()>, Reset) {
        let copy_guard = STRING_POOL_SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
