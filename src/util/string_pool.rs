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

use core::mem::offset_of;

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
}
