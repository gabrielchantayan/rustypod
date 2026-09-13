//! The MOV playback manager's **chained slot table** — a fixed table of
//! 128 twenty-byte entries chained together by index, and its one-word
//! link accessor.
//!
//! Port:
//! - [`mov_chain_table_next`] — original: `FUN_0820c8a0` @ 0x0820c8a0
//!   (**56 bytes**, 0x0820c8a0..0x0820c8d8, 14 instructions, no literal
//!   pool; the separately linked sibling setter opens at 0x0820c8d8 with
//!   `cmp r1, #128` / `addcc`, so Ghidra's 56 is exact — byte-decoded
//!   from osos.dec). **16 `bl` call sites, 0 predicated, 0 tail
//!   branches**, verified by decoding every B/BL word in osos.dec:
//!   0x081e39cc, 0x081e3b28, 0x081e4004, 0x081e4ad0, 0x081e4c04,
//!   0x081e4f50, 0x081e4fbc, 0x081e5358, 0x0820c838, 0x0820c928,
//!   0x0820ca10, 0x0820cb54, 0x0829e3e8, 0x0829e458, 0x0829e468,
//!   0x0829e480. No DATA word references the address, so it is only ever
//!   direct-called.
//! - [`mov_chain_table_set_next`] — original: `FUN_0820c8d8` @ 0x0820c8d8
//!   (**28 bytes**, 0x0820c8d8..0x0820c8f4, 7 instructions, no literal
//!   pool). **8 direct call sites, all unconditional `bl`; 0 predicated
//!   forms**, verified by decoding every ARM B/BL word in `osos.dec`:
//!   0x081e451c, 0x081e4748, 0x081e4ce4, 0x081e4cfc, 0x081e4fd4,
//!   0x081e4fec, 0x081e51e8, and 0x081e5378.
//! - [`mov_chain_table_lookup_tagged_value`] — original: `FUN_0820ccc0` @
//!   0x0820ccc0 (136 bytes; **7 call sites, all unconditional `bl`**).
//!
//! # What it is
//!
//! The table lives inside the MOV demuxer's playback manager object:
//! the 0x0820cxxx cluster passes the manager `this` itself as the table
//! base and guards the table with a mutex at `this + 0xa00` — exactly
//! `128 * 20` bytes in — with the lock-service pointer at `this + 0xa08`
//! (see `lock_service_lock`'s ledger notes). The 0x081e3xxx..0x081e5cxx
//! and 0x0829e3xx callers reach the same table through `*(obj + 0x1060)`.
//! The atom-path string `"moov"/"udta"/"meta"/"ilst"` sits at 0x0820c7e8
//! directly above the cluster, tying the region to MOV metadata item
//! playback.
//!
//! Each 20-byte entry carries a tag byte at +0x08 (the scan loop @
//! 0x0820c86c finds an entry by it) and a **next-slot link** at +0x0c:
//!
//! ```text
//! +0x00  u32  (unidentified)
//! +0x04  u32  (unidentified)
//! +0x08  u8   tag — compared by the scan @ 0x0820c86c
//! +0x0c  u32  next slot index: < 0x80 = chain continues,
//!               0xffffffff = chain end, anything else = corrupt
//! +0x10  u32  (unidentified)
//! ```
//!
//! The chain walkers @ 0x0820c8f4 and 0x0820c9ec call this accessor in
//! a loop, feeding each returned link back in as the next index, so the
//! 0xffffffff end marker and the < 0x80 validity window are observable
//! contract, not guesswork. The predicated twin @ 0x0820c8d8
//! (`strcc r2, [r0, #12]`) is the matching setter.
//!
//! # Algorithm
//!
//! ```text
//! 0820c8a0  e3510080  cmp  r1, #128
//! 0820c8a4  2a000009  bcs  0x820c8d0        @ index >= 128 -> return 2
//! 0820c8a8  e0811101  add  r1, r1, r1, lsl #2   @ index * 5
//! 0820c8ac  e0800101  add  r0, r0, r1, lsl #2   @ base + index * 20
//! 0820c8b0  e590000c  ldr  r0, [r0, #12]    @ next = entry->link
//! 0820c8b4  e3500080  cmp  r0, #128
//! 0820c8b8  e5820000  str  r0, [r2]         @ *out = next (UNCONDITIONAL)
//! 0820c8b8  3a000001  bcc  0x820c8c8        @ next < 128    -> ok
//! 0820c8c0  e3700001  cmn  r0, #1
//! 0820c8c4  1a000001  bne  0x820c8d0        @ next != -1    -> return 2
//! 0820c8c8  e3a00000  mov  r0, #0
//! 0820c8cc  e12fff1e  bx   lr
//! 0820c8d0  e3a00002  mov  r0, #2
//! 0820c8d4  e12fff1e  bx   lr
//! ```
//!
//! # Observable contract
//!
//! - The bounds check is on the INDEX only; `table` and `out` are never
//!   NULL-checked (stock faults on the `ldr`/`str`).
//! - `*out` is written BEFORE the link validity tests, so a corrupt link
//!   still lands in `*out` alongside the error return — the callers that
//!   chain (`bl` then loop on success) never observe it, but the store is
//!   real and is preserved here.
//! - An out-of-range index stores nothing; `*out` is left untouched.
//! - Zero predicated call sites: no caller NULL-guards the table or
//!   pre-checks the index; every caller relies on this function's own
//!   bounds check.
//!
//! # Deviations
//!
//! None. The port mirrors the exact branch structure, including the
//! unconditional `*out` store. No NULL guards added. Status codes are
//! bare `0`/`2` as in the original (the walkers compare against 0; the
//! error propagates as 2 up through the cluster).

use core::ffi::c_void;

use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::kernel::sync_mutex::Mutex;

/// Number of slots in the fixed table: the bound tested at 0x0820c8a0
/// and the scan limit at 0x0820c890 both use 128.
pub const MOV_CHAIN_TABLE_SLOTS: usize = 128;

/// One 20-byte table entry. Only the tag byte (+0x08) and the next-slot
/// link (+0x0c) are identified; the remaining words are used by the
/// unported rest of the cluster and are modeled as opaque words so the
/// layout stays exact.
#[repr(C)]
pub struct MovChainEntry {
    pub field_00: u32,
    pub field_04: u32,
    /// Compared by the scan loop @ 0x0820c86c (`ldrb [entry, #8]`).
    pub tag: u8,
    pub pad_09: [u8; 3],
    /// Next slot index in the chain: `< 0x80` continues the chain,
    /// `0xffffffff` ends it, anything else is rejected as corrupt.
    pub next: u32,
    pub field_10: u32,
}

const _: () = assert!(core::mem::size_of::<MovChainEntry>() == 20);

/// The 128-entry chained slot table at the head of the MOV playback
/// manager object (mutex follows immediately at +0xa00).
#[repr(C)]
pub struct MovChainTable {
    pub entries: [MovChainEntry; MOV_CHAIN_TABLE_SLOTS],
}

/// The table-bearing prefix of the MOV playback manager as accessed by
/// `mov_chain_table_lookup_tagged_value`. On target, `mutex` and
/// `lock_service` are at `this + 0xa00` and `this + 0xa08`, respectively.
#[repr(C)]
pub struct MovChainTableManager {
    pub table: MovChainTable,
    pub mutex: Mutex,
    pub lock_service: *mut c_void,
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::size_of::<MovChainTableManager>() == 0xa0c);


/// Status: link read and valid (chain continues or ends cleanly).
pub const MOV_CHAIN_TABLE_OK: i32 = 0;
/// Status: index out of range, or link value corrupt.
pub const MOV_CHAIN_TABLE_ERR: i32 = 2;

/// mov_chain_table_next — original: `FUN_0820c8a0` @ 0x0820c8a0 (56 bytes,
/// 0x0820c8a0..0x0820c8d8; **16 call sites, all unconditional `bl`** —
/// counted by decoding every B/BL word in `osos.dec`).
///
/// Reads the next-slot link (+0x0c) of table entry `index` into `*out`.
/// Returns [`MOV_CHAIN_TABLE_OK`] when the link continues the chain
/// (`< 0x80`) or ends it (`0xffffffff`), [`MOV_CHAIN_TABLE_ERR`] when the
/// index is out of range (nothing stored) or the link is any other value
/// (still stored).
///
/// # Safety
///
/// `table` must point to a readable [`MovChainTable`] and `out` to one
/// writable `u32`; neither is NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_next")]
pub unsafe extern "C" fn mov_chain_table_next(
    table: *const MovChainTable,
    index: u32,
    out: *mut u32,
) -> i32 {
    if index >= MOV_CHAIN_TABLE_SLOTS as u32 {
        return MOV_CHAIN_TABLE_ERR;
    }
    let next = unsafe { core::ptr::read(core::ptr::addr_of!((*table).entries[index as usize].next)) };
    unsafe { core::ptr::write(out, next) };
    if next < MOV_CHAIN_TABLE_SLOTS as u32 || next == 0xffff_ffff {
        MOV_CHAIN_TABLE_OK
    } else {
        MOV_CHAIN_TABLE_ERR
    }
}
/// mov_chain_table_set_next — original: `FUN_0820c8d8` @ 0x0820c8d8
/// (28 bytes, 0x0820c8d8..0x0820c8f4; **8 call sites, all unconditional
/// `bl`, 0 predicated forms** — counted by decoding every B/BL word in
/// `osos.dec`).
///
/// Writes `next` into the +0x0c next-slot link of table entry `index`.
/// The `cmp r1, #128` makes the address calculation and store conditional:
/// indexes 0..127 update their own entry and return
/// [`MOV_CHAIN_TABLE_OK`]; every other `u32` leaves the table untouched
/// and returns [`MOV_CHAIN_TABLE_ERR`]. Unlike
/// [`mov_chain_table_next`], this setter does not validate the link value.
///
/// # Deviations
///
/// None. The function has no NULL guard; stock faults when a valid index
/// reaches the store. The zero predicated-call count means callers rely on
/// this bounds check rather than pre-checking the index.
///
/// # Safety
///
/// `table` must point to a writable [`MovChainTable`] when `index < 128`;
/// it is not NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_set_next")]
pub unsafe extern "C" fn mov_chain_table_set_next(
    table: *mut MovChainTable,
    index: u32,
    next: u32,
) -> i32 {
    if index < MOV_CHAIN_TABLE_SLOTS as u32 {
        unsafe { core::ptr::write(core::ptr::addr_of_mut!((*table).entries[index as usize].next), next) };
        MOV_CHAIN_TABLE_OK
    } else {
        MOV_CHAIN_TABLE_ERR
    }
}

/// mov_chain_table_lookup_tagged_value — original: `FUN_0820ccc0` @
/// 0x0820ccc0 (136 bytes, 0x0820ccc0..0x0820cd48; **7 call sites, all
/// unconditional `bl`, 0 predicated forms and no tail `b`** — counted by
/// decoding every ARM B/BL word in `osos.dec`: 0x081e32c8, 0x081e3338,
/// 0x081e3454, 0x081e3704, 0x081e3864, 0x081e3a9c, and 0x081e48dc).
///
/// Locks the manager's table, then examines the entry at `manager + index`
/// when signed `index < 128` and `index != -1`. Therefore stock admits
/// negative indexes other than -1; ordinary callers use table indexes or
/// the -1 sentinel. A matching entry has `tag == 3` and its +0x10 word equal
/// to `match_value`. Its +0x00 word is always stored in `*out`; a nonzero
/// stored value returns [`MOV_CHAIN_TABLE_OK`], while zero returns
/// [`MOV_CHAIN_TABLE_ERR`]. All nonmatches, rejected indexes, lock failures,
/// and unlock failures return [`MOV_CHAIN_TABLE_ERR`] and leave `*out`
/// untouched.
///
/// No behavioral deviations. `lock_service` is read volatile so the device
/// binary keeps stock's load at `this + 0xa08` even though the already-ported
/// lock adapters deliberately ignore their `service` argument.
///
/// # Safety
///
/// `manager` must point to a live [`MovChainTableManager`]. If `index < 128`
/// and `index != -1`, the `MovChainEntry` at `manager + index` must be
/// readable; `out` must be writable if that entry matches. Neither pointer
/// is NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_lookup_tagged_value")]
pub unsafe extern "C" fn mov_chain_table_lookup_tagged_value(
    manager: *mut MovChainTableManager,
    out: *mut u32,
    index: i32,
    match_value: u32,
) -> i32 {
    let mutex = unsafe { core::ptr::addr_of_mut!((*manager).mutex) };
    let lock_service = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*manager).lock_service)) };
    if unsafe { lock_service_lock(lock_service, mutex) } != MOV_CHAIN_TABLE_OK {
        return MOV_CHAIN_TABLE_ERR;
    }

    let mut status = MOV_CHAIN_TABLE_ERR;
    if index < MOV_CHAIN_TABLE_SLOTS as i32 && index != -1 {
        let entries = unsafe { core::ptr::addr_of!((*manager).table.entries).cast::<MovChainEntry>() };
        let entry = entries.wrapping_offset(index as isize);
        let tag = unsafe { core::ptr::read(core::ptr::addr_of!((*entry).tag)) };
        let entry_match_value = unsafe { core::ptr::read(core::ptr::addr_of!((*entry).field_10)) };
        if tag == 3 && entry_match_value == match_value {
            let value = unsafe { core::ptr::read(core::ptr::addr_of!((*entry).field_00)) };
            unsafe { core::ptr::write(out, value) };
            if value != 0 {
                status = MOV_CHAIN_TABLE_OK;
            }
        }
    }

    if unsafe { lock_service_unlock(lock_service, mutex) } != MOV_CHAIN_TABLE_OK {
        MOV_CHAIN_TABLE_ERR
    } else {
        status
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    const POISON: u32 = 0xdead_beef;

    fn fresh_table() -> MovChainTable {
        MovChainTable {
            entries: [const {
                MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0 }
            }; MOV_CHAIN_TABLE_SLOTS],
        }
    }

    fn fresh_manager() -> MovChainTableManager {
        MovChainTableManager {
            table: fresh_table(),
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            lock_service: core::ptr::null_mut(),
        }
    }

    #[repr(C)]
    struct ManagerWithPrefix {
        prefix: [MovChainEntry; 2],
        manager: MovChainTableManager,
    }

    fn fresh_manager_with_prefix() -> ManagerWithPrefix {
        ManagerWithPrefix {
            prefix: [const {
                MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0 }
            }; 2],
            manager: fresh_manager(),
        }
    }

    /// A valid chain link lands in `*out` and reports success.
    #[test]
    fn reads_link_of_valid_entry() {
        let mut table = fresh_table();
        table.entries[5].next = 7;
        let mut out = POISON;

        let rc = unsafe { mov_chain_table_next(&table, 5, &mut out) };

        assert_eq!(rc, MOV_CHAIN_TABLE_OK);
        assert_eq!(out, 7);
    }

    /// Every index reads ITS OWN entry's +0x0c word: fill all five words
    /// of each entry with distinct values and prove the link word is the
    /// one returned, not a neighbor field or a neighbor entry.
    #[test]
    fn reads_correct_entry_and_field() {
        let mut table = fresh_table();
        for (i, e) in table.entries.iter_mut().enumerate() {
            let i = i as u32;
            e.field_00 = 0x1000 + i;
            e.field_04 = 0x2000 + i;
            e.tag = (i & 0xff) as u8;
            e.next = (i * 3 + 1) % 128; // always a valid link
            e.field_10 = 0x5000 + i;
        }
        let snapshot_next: [u32; MOV_CHAIN_TABLE_SLOTS] =
            core::array::from_fn(|i| table.entries[i].next);

        for i in 0..MOV_CHAIN_TABLE_SLOTS as u32 {
            let mut out = POISON;
            let rc = unsafe { mov_chain_table_next(&table, i, &mut out) };
            assert_eq!(rc, MOV_CHAIN_TABLE_OK, "index {i}");
            assert_eq!(out, snapshot_next[i as usize], "index {i} link");
        }
        // The table itself is not modified by a read.
        for (i, e) in table.entries.iter().enumerate() {
            assert_eq!(e.next, snapshot_next[i]);
        }
    }

    /// The chain-end marker is a clean success and is stored verbatim.
    #[test]
    fn end_of_chain_marker_succeeds() {
        let mut table = fresh_table();
        table.entries[0].next = 0xffff_ffff;
        table.entries[127].next = 0xffff_ffff;
        for index in [0u32, 127] {
            let mut out = POISON;
            let rc = unsafe { mov_chain_table_next(&table, index, &mut out) };
            assert_eq!(rc, MOV_CHAIN_TABLE_OK, "index {index}");
            assert_eq!(out, 0xffff_ffff);
        }
    }

    /// Boundary: 0x7f is the last valid link, 0x80 is the first corrupt
    /// one — and the corrupt value is STILL written to `*out` because the
    /// stock `str r0, [r2]` precedes the validity branches.
    #[test]
    fn link_boundary_and_corrupt_still_stored() {
        let mut table = fresh_table();
        table.entries[1].next = 0x7f;
        table.entries[2].next = 0x80;
        table.entries[3].next = 0xffff_fffe;

        let mut out = POISON;
        assert_eq!(unsafe { mov_chain_table_next(&table, 1, &mut out) }, MOV_CHAIN_TABLE_OK);
        assert_eq!(out, 0x7f);

        let mut out = POISON;
        assert_eq!(unsafe { mov_chain_table_next(&table, 2, &mut out) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, 0x80, "error path still stores the raw link");

        let mut out = POISON;
        assert_eq!(unsafe { mov_chain_table_next(&table, 3, &mut out) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, 0xffff_fffe);
    }

    /// Out-of-range indexes return the error and leave `*out` untouched —
    /// the `bcs` at 0x0820c8a4 skips the `str` entirely.
    #[test]
    fn out_of_range_index_stores_nothing() {
        let mut table = fresh_table();
        table.entries[0].next = 42;
        for index in [128u32, 129, 0xffff_ffff, 0x8000_0000] {
            let mut out = POISON;
            let rc = unsafe { mov_chain_table_next(&table, index, &mut out) };
            assert_eq!(rc, MOV_CHAIN_TABLE_ERR, "index {index:#x}");
            assert_eq!(out, POISON, "index {index:#x} must not store");
        }
    }

    /// A full walk as the 0x0820c9ec caller performs it: chase links from
    /// a head until the end marker, counting hops.
    #[test]
    fn chain_walk_terminates_at_end_marker() {
        let mut table = fresh_table();
        let chain = [10u32, 20, 30, 40];
        for w in chain.windows(2) {
            table.entries[w[0] as usize].next = w[1];
        }
        table.entries[chain[chain.len() - 1] as usize].next = 0xffff_ffff;

        let mut hops = 0u32;
        let mut cursor = chain[0];
        loop {
            let mut next = POISON;
            let rc = unsafe { mov_chain_table_next(&table, cursor, &mut next) };
            assert_eq!(rc, MOV_CHAIN_TABLE_OK);
            if next == 0xffff_ffff {
                break;
            }
            cursor = next;
            hops += 1;
            assert!(hops < 128, "walk must terminate");
        }
        assert_eq!((hops, cursor), (3, 40), "10 -> 20 -> 30 -> 40 -> end");
    }
    /// The setter accepts every link bit-pattern unchanged, including
    /// values the accessor later treats as corrupt, and changes only the
    /// selected entry's +0x0c word.
    #[test]
    fn setter_writes_selected_entry_without_validating_link() {
        let mut table = fresh_table();
        for (i, entry) in table.entries.iter_mut().enumerate() {
            let i = i as u32;
            entry.field_00 = 0x1000 + i;
            entry.field_04 = 0x2000 + i;
            entry.tag = i as u8;
            entry.next = 0x2000 + i;
            entry.field_10 = 0x5000 + i;
        }

        assert_eq!(unsafe { mov_chain_table_set_next(&mut table, 0, 0xffff_fffe) }, MOV_CHAIN_TABLE_OK);
        assert_eq!(unsafe { mov_chain_table_set_next(&mut table, 127, 0x80) }, MOV_CHAIN_TABLE_OK);

        assert_eq!(table.entries[0].next, 0xffff_fffe);
        assert_eq!(table.entries[127].next, 0x80);
        assert_eq!(table.entries[1].next, 0x2001);
        assert_eq!(table.entries[0].field_00, 0x1000);
        assert_eq!(table.entries[127].field_10, 0x507f);
    }

    /// The conditional `strcc` skips all stores at and above the 128-slot
    /// boundary, including high-bit indexes.
    #[test]
    fn setter_out_of_range_indexes_leave_table_unchanged() {
        let mut table = fresh_table();
        table.entries[0].next = 10;
        table.entries[127].next = 20;

        for index in [128u32, 129, 0x8000_0000, 0xffff_ffff] {
            assert_eq!(
                unsafe { mov_chain_table_set_next(&mut table, index, 0xdead_beef) },
                MOV_CHAIN_TABLE_ERR,
                "index {index:#x}",
            );
        }

        assert_eq!(table.entries[0].next, 10);
        assert_eq!(table.entries[127].next, 20);
    }

    /// The +0x00 value is returned only for a tag-3 entry whose +0x10 word
    /// matches, and the lookup preserves the other entries.
    #[test]
    fn lookup_tagged_value_returns_matching_nonzero_entry() {
        let mut manager = fresh_manager();
        manager.table.entries[17].field_00 = 0x1234_5678;
        manager.table.entries[17].tag = 3;
        manager.table.entries[17].field_10 = 0xa5a5_5a5a;
        manager.table.entries[18].field_00 = 0xfeed_face;
        manager.table.entries[18].tag = 3;
        manager.table.entries[18].field_10 = 0xa5a5_5a5a;
        let mut out = POISON;

        let rc = unsafe {
            mov_chain_table_lookup_tagged_value(&mut manager, &mut out, 17, 0xa5a5_5a5a)
        };

        assert_eq!(rc, MOV_CHAIN_TABLE_OK);
        assert_eq!(out, 0x1234_5678);
        assert_eq!(manager.table.entries[18].field_00, 0xfeed_face);
    }

    /// A tag mismatch, value mismatch, the -1 sentinel, and high indexes
    /// all skip the +0x00 store.
    #[test]
    fn lookup_tagged_value_nonmatches_and_boundaries_store_nothing() {
        let mut manager = fresh_manager();
        manager.table.entries[0].field_00 = 1;
        manager.table.entries[0].tag = 2;
        manager.table.entries[0].field_10 = 0x55;
        manager.table.entries[127].field_00 = 2;
        manager.table.entries[127].tag = 3;
        manager.table.entries[127].field_10 = 0x66;

        for (index, match_value) in [(0, 0x55), (127, 0x77), (-1, 0), (128, 0), (i32::MAX, 0)] {
            let mut out = POISON;
            let rc = unsafe {
                mov_chain_table_lookup_tagged_value(&mut manager, &mut out, index, match_value)
            };
            assert_eq!(rc, MOV_CHAIN_TABLE_ERR, "index {index}");
            assert_eq!(out, POISON, "index {index} must not store");
        }
    }

    /// The signed `bge` rejects only indexes >= 128; the separate `cmn`
    /// rejects -1 alone, so -2 addresses the second preceding entry.
    #[test]
    fn lookup_tagged_value_accepts_negative_index_except_minus_one() {
        let mut fixture = fresh_manager_with_prefix();
        fixture.prefix[0].field_00 = 0x2468_ace0;
        fixture.prefix[0].tag = 3;
        fixture.prefix[0].field_10 = 0x77;
        let mut out = POISON;

        let rc = unsafe {
            mov_chain_table_lookup_tagged_value(&mut fixture.manager, &mut out, -2, 0x77)
        };

        assert_eq!(rc, MOV_CHAIN_TABLE_OK);
        assert_eq!(out, 0x2468_ace0);
    }

    /// A matching null +0x00 word is still stored before the status remains
    /// 2, exactly as `str r0, [r7]` precedes `movne r6, #0` in stock.
    #[test]
    fn lookup_tagged_value_stores_zero_but_reports_error() {
        let mut manager = fresh_manager();
        manager.table.entries[4].tag = 3;
        manager.table.entries[4].field_10 = 0x99;
        let mut out = POISON;

        let rc = unsafe { mov_chain_table_lookup_tagged_value(&mut manager, &mut out, 4, 0x99) };

        assert_eq!(rc, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, 0);
    }
}
