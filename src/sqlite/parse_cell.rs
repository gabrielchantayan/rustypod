//! The b-tree cell parser — SQLite 3.5.x's `sqlite3BtreeParseCellPtr`,
//! the routine every b-tree walk runs to decode one cell's on-page
//! header into the 0x20-byte `CellInfo` whose layout is documented in
//! `sqlite/cell_size.rs`'s module header.
//!
//! `btree_parse_cell_ptr` — original: `FUN_083727ec` @ 0x083727ec (296
//! bytes; 9 `bl` call sites: 0x082b6624, 0x082b6914, 0x082c0a5c [the
//! ported `cell_size_ptr`], 0x082c2ad8, 0x082c3468, 0x082cdfe0,
//! 0x082d6924, 0x082d98c4, 0x082e87b0).
//!
//! ```c
//! void sqlite3BtreeParseCellPtr(MemPage *pPage, u8 *pCell, CellInfo *pInfo);
//! ```
//!
//! Algorithm (verified against osos.asm — Ghidra's decompile obscures
//! the `__rt_udiv` remainder and the signed halfword compares):
//!
//! 1. `info.pCell = cell`; the header cursor starts at `childPtrSize`
//!    (MemPage +0x09 — 4 on internal pages, skipping the child pointer).
//! 2. Leaf pages (MemPage +0x07): decode the payload varint at
//!    `cell + cursor`. A first byte below 0x80 is the whole varint —
//!    the original inlines that fast path and only calls
//!    `sqlite3GetVarint` @ 0x0837ac30 for multi-byte values. Internal
//!    pages have no payload varint (0).
//! 3. Table pages (intKey, MemPage +0x03): the rowid varint is decoded
//!    by `sqlite3GetVarint32` @ 0x0837aab0 — always through the call,
//!    no inline fast path — straight into `info` +0x08 (nKey). +0x0c is
//!    never written on this path.
//!    Index pages: the nData varint goes through the same inline fast
//!    path / `sqlite3GetVarint` pair as step 2, lands at +0x08, +0x0c
//!    is zeroed, and nData is added to the payload total.
//! 4. `info` +0x14 = total payload, +0x18 = header length (u16).
//! 5. If the payload fits (`nPayload <= maxLocal`, MemPage +0x0a u16):
//!    nLocal = nPayload, iOverflow = 0, nSize = max(nPayload + header,
//!    4) — the original clamps with a signed `movlt`.
//!    Otherwise the surplus-splitting rule of upstream 3.5.x:
//!    `surplus = minLocal + (nPayload - minLocal) % (usableSize - 4)`
//!    (minLocal at MemPage +0x0c u16; usableSize at pBt +0x1e u16, pBt
//!    at MemPage +0x40), `nLocal = min(surplus, maxLocal)` except that a
//!    surplus over maxLocal collapses to minLocal; iOverflow =
//!    nLocal + header and nSize = iOverflow + 4 (the overflow page
//!    number's 4 bytes).
//!
//! Deviations:
//!
//! - The 0x0837ac30 varint reader (`sqlite3GetVarint`) is ported
//!   (`sqlite/get_varint.rs`) and is the shipped default of its
//!   [`BTREE_CELL_OPS`] slot; the 0x0837aab0 reader
//!   (`sqlite3GetVarint32`) is identified but not yet ported and rides
//!   the seam as a zero-writing stand-in — the same house static
//!   `cell_size_ptr` already dispatches through (one seam per
//!   cluster). The ported `__rt_udiv` @ 0x08036f14 is called as
//!   [`__rt_udivmod`] because the original consumes the r1 remainder,
//!   not the r0 quotient.
//! - `info.pCell` stores the 32-bit pointer value exactly like the
//!   original's `str r1,[r2,#0x0]`; on 64-bit hosts that is the low
//!   word of the address, which the host fixtures round-trip by living
//!   below 4 GiB.

use crate::runtime::rt_div::__rt_udivmod;
use crate::sqlite::cell_size::{get_varint32_op, get_varint_op};

/// `MemPage` byte offsets the original reads.
const MP_INT_KEY: usize = 0x03;
const MP_LEAF: usize = 0x07;
const MP_CHILD_PTR_SIZE: usize = 0x09;
const MP_MAX_LOCAL: usize = 0x0a;
const MP_MIN_LOCAL: usize = 0x0c;
const MP_P_BT: usize = 0x40;

/// `BtShared.usableSize` — the divisor base of the overflow split.
const BT_USABLE_SIZE: usize = 0x1e;

/// `CellInfo` byte offsets the original writes (see `sqlite/cell_size.rs`).
const CI_P_CELL: usize = 0x00;
const CI_N_KEY: usize = 0x08;
const CI_N_KEY_HI: usize = 0x0c;
const CI_PAYLOAD_VARINT: usize = 0x10;
const CI_N_PAYLOAD: usize = 0x14;
const CI_N_HEADER: usize = 0x18;
const CI_N_LOCAL: usize = 0x1a;
const CI_I_OVERFLOW: usize = 0x1c;
const CI_N_SIZE: usize = 0x1e;

#[inline(always)]
unsafe fn rd_u8(base: *const u8, off: usize) -> u8 {
    *base.add(off)
}

#[inline(always)]
unsafe fn rd_u16(base: *const u8, off: usize) -> u16 {
    u16::from_le(base.add(off).cast::<u16>().read_unaligned())
}

#[inline(always)]
unsafe fn rd_u32(base: *const u8, off: usize) -> u32 {
    u32::from_le(base.add(off).cast::<u32>().read_unaligned())
}

#[inline(always)]
unsafe fn wr_u16(base: *mut u8, off: usize, v: u16) {
    base.add(off).cast::<u16>().write_unaligned(v.to_le());
}

#[inline(always)]
unsafe fn wr_u32(base: *mut u8, off: usize, v: u32) {
    base.add(off).cast::<u32>().write_unaligned(v.to_le());
}

/// The original's inline single-byte fast path (shared by the leaf
/// payload varint and the index nData varint): a first byte below 0x80
/// IS the varint — value = byte, length 1 — and `sqlite3GetVarint` is
/// skipped entirely. Only multi-byte varints go through the seam slot,
/// whose 64-bit decode the original truncates to the low word.
#[inline(always)]
unsafe fn read_varint_fast(p: *const u8) -> (u32, u32) {
    let first = *p;
    if first < 0x80 {
        (first as u32, 1)
    } else {
        let mut value = 0u64;
        let len = get_varint_op()(p, &mut value);
        (value as u32, len)
    }
}

/// btree_parse_cell_ptr — original: `FUN_083727ec` @ 0x083727ec (296
/// bytes; 9 `bl` call sites).
///
/// SQLite's `sqlite3BtreeParseCellPtr`: parse the b-tree cell at `cell`
/// on page `page` and fill the 0x20-byte `CellInfo` at `info` (offsets
/// in the module header and in `sqlite/cell_size.rs`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_parse_cell_ptr(page: *const u8, cell: *const u8, info: *mut u8) {
    wr_u32(info, CI_P_CELL, cell as usize as u32);

    // Header cursor (r5 in the original): starts past the child
    // pointer on internal pages, at the cell start on leaf pages.
    let mut header = rd_u8(page, MP_CHILD_PTR_SIZE) as u32;

    // The payload varint ([sp,#4] in the original): read on leaf
    // pages, 0 on internal pages; becomes the total payload once index
    // pages add nData.
    let mut payload = 0u32;
    if rd_u8(page, MP_LEAF) != 0 {
        let (value, len) = read_varint_fast(cell.add(header as usize));
        payload = value;
        header += len;
    }
    wr_u32(info, CI_PAYLOAD_VARINT, payload);

    if rd_u8(page, MP_INT_KEY) != 0 {
        // Table b-tree: the rowid varint, always decoded through
        // sqlite3GetVarint32 straight into +0x08 (nKey). +0x0c keeps
        // whatever the caller's CellInfo held.
        let mut rowid = 0u32;
        header += get_varint32_op()(cell.add(header as usize), &mut rowid);
        wr_u32(info, CI_N_KEY, rowid);
    } else {
        // Index b-tree: the nData varint (sqlite3GetVarint, low word)
        // at +0x08, +0x0c zeroed, and it counts toward the payload.
        let (n_data, len) = read_varint_fast(cell.add(header as usize));
        header += len;
        wr_u32(info, CI_N_KEY, n_data);
        wr_u32(info, CI_N_KEY_HI, 0);
        payload = payload.wrapping_add(n_data);
    }

    wr_u32(info, CI_N_PAYLOAD, payload);
    wr_u16(info, CI_N_HEADER, header as u16);

    let max_local = rd_u16(page, MP_MAX_LOCAL) as u32;
    if payload <= max_local {
        // Common case: the whole payload is local, no overflow page.
        wr_u16(info, CI_N_LOCAL, payload as u16);
        let mut n_size = payload + header;
        if n_size < 4 {
            n_size = 4;
        }
        wr_u16(info, CI_I_OVERFLOW, 0);
        wr_u16(info, CI_N_SIZE, n_size as u16);
    } else {
        // The payload spills: hold between minLocal and maxLocal bytes
        // locally so overflow pages stay packed; the overflow page
        // number sits right after the local payload.
        let min_local = rd_u16(page, MP_MIN_LOCAL) as u32;
        let p_bt = rd_u32(page, MP_P_BT) as *const u8;
        let usable = rd_u16(p_bt, BT_USABLE_SIZE) as u32;
        let mut remainder = 0u32;
        __rt_udivmod(payload - min_local, usable - 4, &mut remainder);
        let mut n_local = remainder + min_local;
        if n_local > max_local {
            n_local = min_local;
        }
        wr_u16(info, CI_N_LOCAL, n_local as u16);
        let i_overflow = (n_local + header) as u16;
        wr_u16(info, CI_I_OVERFLOW, i_overflow);
        wr_u16(info, CI_N_SIZE, i_overflow.wrapping_add(4));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::cell_size::{cell_size_ptr, BTREE_CELL_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{LazyLock, MutexGuard};

    /// The fixture slab: one low mapping holding the fake BtShared,
    /// MemPage, cell bytes and CellInfo, all round-tripping through u32.
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_PARSE_CELL, SLAB_LEN).map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    const SLAB_LEN: usize = 0x10000;
    const OFF_BT: usize = 0x0000; // 0x40 — fake BtShared (usableSize @ +0x1e)
    const OFF_PAGE: usize = 0x1000; // 0x60 — fake MemPage
    const OFF_CELL: usize = 0x2000; // 0x40 — cell bytes
    const OFF_INFO: usize = 0x3000; // 0x20 CellInfo + 8 guard bytes
    const GUARD_LEN: usize = 8;

    /// Seam call counters, for the inline-fast-path fidelity checks.
    static GET_VARINT_CALLS: AtomicU32 = AtomicU32::new(0);
    static GET_VARINT32_CALLS: AtomicU32 = AtomicU32::new(0);

    /// Real SQLite varint decode (big-endian base-128, 9 bytes max) so
    /// the seam mocks behave like the identified originals.
    unsafe fn decode_varint(p: *const u8) -> (u64, u32) {
        let mut v = 0u64;
        for i in 0..8 {
            let b = *p.add(i);
            if b < 0x80 {
                return ((v << 7) | b as u64, i as u32 + 1);
            }
            v = (v << 7) | (b & 0x7f) as u64;
        }
        ((v << 8) | *p.add(8) as u64, 9)
    }

    unsafe extern "C" fn real_get_varint(p: *const u8, out: *mut u64) -> u32 {
        GET_VARINT_CALLS.fetch_add(1, Ordering::Relaxed);
        let (v, n) = decode_varint(p);
        *out = v;
        n
    }

    unsafe extern "C" fn real_get_varint32(p: *const u8, out: *mut u32) -> u32 {
        GET_VARINT32_CALLS.fetch_add(1, Ordering::Relaxed);
        let (v, n) = decode_varint(p);
        *out = v as u32;
        n
    }

    /// Maps the slab, installs the real-decoding varint mocks, and
    /// restores the shipped defaults on drop. `None` (test skips) when
    /// this host cannot place the fixture below 4 GiB.
    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        base: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let base = match try_slab() {
                Some(b) => b,
                None => {
                    note_missing_u32_fixture("sqlite::parse_cell_tests");
                    return None;
                }
            };
            GET_VARINT_CALLS.store(0, Ordering::Relaxed);
            GET_VARINT32_CALLS.store(0, Ordering::Relaxed);
            unsafe {
                let ops = &mut *core::ptr::addr_of_mut!(BTREE_CELL_OPS);
                ops.parse_cell = btree_parse_cell_ptr;
                ops.get_varint = real_get_varint;
                ops.get_varint32 = real_get_varint32;
                core::ptr::write_bytes(base, 0, SLAB_LEN);
                // CellInfo + guard bytes: poison so unwritten fields and
                // out-of-bounds writes are visible.
                core::ptr::write_bytes(
                    base.add(OFF_INFO),
                    0xaa,
                    CELL_INFO_LEN + GUARD_LEN,
                );
            }
            Some(Fixture { _guard: guard, base })
        }

        fn page(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_PAGE) }
        }

        fn cell(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_CELL) }
        }

        fn info(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_INFO) }
        }

        /// Fills the fake MemPage/BtShared with the given field values.
        fn page_fields(
            &self,
            int_key: u8,
            leaf: u8,
            child_ptr_size: u8,
            max_local: u16,
            min_local: u16,
            usable_size: u16,
        ) {
            unsafe {
                let page = self.page();
                *page.add(MP_INT_KEY) = int_key;
                *page.add(MP_LEAF) = leaf;
                *page.add(MP_CHILD_PTR_SIZE) = child_ptr_size;
                wr_u16(page, MP_MAX_LOCAL, max_local);
                wr_u16(page, MP_MIN_LOCAL, min_local);
                wr_u32(page, MP_P_BT, self.base.add(OFF_BT) as usize as u32);
                wr_u16(self.base.add(OFF_BT), BT_USABLE_SIZE, usable_size);
            }
        }

        fn set_cell(&self, bytes: &[u8]) {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.cell(), bytes.len());
            }
        }

        fn run(&self) {
            unsafe { btree_parse_cell_ptr(self.page(), self.cell(), self.info()) }
        }

        fn info_u32(&self, off: usize) -> u32 {
            unsafe { rd_u32(self.info(), off) }
        }

        fn info_u16(&self, off: usize) -> u16 {
            unsafe { rd_u16(self.info(), off) }
        }

        /// +0x04..+0x08 is alignment padding the original never writes.
        fn assert_pad_untouched(&self) {
            for i in 0x04..0x08 {
                assert_eq!(unsafe { *self.info().add(i) }, 0xaa, "CellInfo pad byte +{i:#x}");
            }
        }

        /// Bytes past the 0x20-byte CellInfo must survive.
        fn assert_guard_untouched(&self) {
            for i in 0..GUARD_LEN {
                assert_eq!(
                    unsafe { *self.info().add(CELL_INFO_LEN + i) },
                    0xaa,
                    "guard byte +{i:#x}"
                );
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                let ops = &mut *core::ptr::addr_of_mut!(BTREE_CELL_OPS);
                ops.parse_cell = crate::sqlite::cell_size::DEFAULT_BTREE_CELL_OPS.parse_cell;
                ops.get_varint = crate::sqlite::cell_size::DEFAULT_BTREE_CELL_OPS.get_varint;
                ops.get_varint32 = crate::sqlite::cell_size::DEFAULT_BTREE_CELL_OPS.get_varint32;
            }
        }
    }

    const CELL_INFO_LEN: usize = 0x20;

    fn get_varint_calls() -> u32 {
        GET_VARINT_CALLS.load(Ordering::Relaxed)
    }

    fn get_varint32_calls() -> u32 {
        GET_VARINT32_CALLS.load(Ordering::Relaxed)
    }

    /// SQLite table-page constants for a 1024-byte usable page, as the
    /// firmware's page init computes them.
    const MAX_LOCAL: u16 = 489; // usableSize - 35
    const MIN_LOCAL: u16 = 103; // (usableSize - 12) * 32 / 255 - 23
    const USABLE: u16 = 1024;

    #[test]
    fn int_key_internal_cell_is_rowid_varint_only() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 0, 4, MAX_LOCAL, MIN_LOCAL, USABLE);
        // 4-byte child pointer, then rowid varint [0x81,0x34] = 180.
        f.set_cell(&[0x00, 0x00, 0x00, 0x2a, 0x81, 0x34]);
        f.run();
        assert_eq!(f.info_u32(CI_P_CELL), f.cell() as usize as u32);
        assert_eq!(f.info_u32(CI_N_KEY), 180, "rowid from get_varint32");
        assert_eq!(get_varint32_calls(), 1);
        assert_eq!(get_varint_calls(), 0, "internal page reads no payload varint");
        // +0x0c is never written on table pages.
        for i in 0x0c..0x10 {
            assert_eq!(unsafe { *f.info().add(i) }, 0xaa, "byte +{i:#x}");
        }
        assert_eq!(f.info_u32(CI_PAYLOAD_VARINT), 0);
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 0);
        assert_eq!(f.info_u16(CI_N_HEADER), 6, "child pointer + 2 varint bytes");
        assert_eq!(f.info_u16(CI_N_LOCAL), 0);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0);
        assert_eq!(f.info_u16(CI_N_SIZE), 6);
        f.assert_pad_untouched();
        f.assert_guard_untouched();
    }

    #[test]
    fn table_leaf_cell_single_byte_varints_skip_the_seam() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint 0x40 (64), rowid varint 0x07.
        f.set_cell(&[0x40, 0x07]);
        f.run();
        assert_eq!(f.info_u32(CI_PAYLOAD_VARINT), 64);
        assert_eq!(f.info_u32(CI_N_KEY), 7);
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 64);
        assert_eq!(f.info_u16(CI_N_HEADER), 2);
        assert_eq!(f.info_u16(CI_N_LOCAL), 64);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0);
        assert_eq!(f.info_u16(CI_N_SIZE), 66);
        // The single-byte payload varint used the inline fast path; the
        // rowid still went through get_varint32 (the original has no
        // fast path on that read).
        assert_eq!(get_varint_calls(), 0);
        assert_eq!(get_varint32_calls(), 1);
        f.assert_pad_untouched();
        f.assert_guard_untouched();
    }

    #[test]
    fn table_leaf_multi_byte_payload_varint_calls_get_varint() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint [0x81,0x00] = 128, rowid varint 0x01.
        f.set_cell(&[0x81, 0x00, 0x01]);
        f.run();
        assert_eq!(get_varint_calls(), 1);
        assert_eq!(get_varint32_calls(), 1);
        assert_eq!(f.info_u32(CI_PAYLOAD_VARINT), 128);
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 128);
        assert_eq!(f.info_u16(CI_N_HEADER), 3);
        assert_eq!(f.info_u16(CI_N_LOCAL), 128);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0);
        assert_eq!(f.info_u16(CI_N_SIZE), 131);
        f.assert_pad_untouched();
        f.assert_guard_untouched();
    }

    #[test]
    fn index_leaf_cell_adds_n_data_to_the_payload() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(0, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint 0x0a (10), nData varint 0x05.
        f.set_cell(&[0x0a, 0x05]);
        f.run();
        assert_eq!(f.info_u32(CI_N_KEY), 5, "nData at +0x08");
        assert_eq!(f.info_u32(CI_N_KEY_HI), 0, "+0x0c zeroed on index pages");
        assert_eq!(f.info_u32(CI_PAYLOAD_VARINT), 10);
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 15, "nData counts toward the payload");
        assert_eq!(f.info_u16(CI_N_HEADER), 2);
        assert_eq!(f.info_u16(CI_N_LOCAL), 15);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0);
        assert_eq!(f.info_u16(CI_N_SIZE), 17);
        f.assert_pad_untouched();
        f.assert_guard_untouched();
    }

    #[test]
    fn index_internal_cell_skips_the_payload_varint() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(0, 0, 4, MAX_LOCAL, MIN_LOCAL, USABLE);
        // 4-byte child pointer, then nData varint 0x64 (100).
        f.set_cell(&[0x00, 0x00, 0x00, 0x07, 0x64]);
        f.run();
        assert_eq!(f.info_u32(CI_PAYLOAD_VARINT), 0);
        assert_eq!(f.info_u32(CI_N_KEY), 100);
        assert_eq!(f.info_u32(CI_N_KEY_HI), 0);
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 100);
        assert_eq!(f.info_u16(CI_N_HEADER), 5);
        assert_eq!(f.info_u16(CI_N_LOCAL), 100);
        assert_eq!(f.info_u16(CI_N_SIZE), 105);
        f.assert_pad_untouched();
        f.assert_guard_untouched();
    }

    #[test]
    fn payload_at_max_local_stays_local() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint [0x83,0x69] = 489 == maxLocal, rowid 0x01.
        f.set_cell(&[0x83, 0x69, 0x01]);
        f.run();
        assert_eq!(f.info_u32(CI_N_PAYLOAD), MAX_LOCAL as u32);
        assert_eq!(f.info_u16(CI_N_LOCAL), MAX_LOCAL);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0, "boundary: bcc is strict");
        assert_eq!(f.info_u16(CI_N_SIZE), 489 + 3);
        f.assert_guard_untouched();
    }

    #[test]
    fn overflow_collapses_to_min_local_when_surplus_exceeds_max_local() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint [0x83,0x6a] = 490 = maxLocal + 1, rowid 0x01.
        // (490 - 103) % 1020 = 387; 387 + 103 = 490 > 489 -> minLocal.
        f.set_cell(&[0x83, 0x6a, 0x01]);
        f.run();
        assert_eq!(f.info_u16(CI_N_LOCAL), MIN_LOCAL);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 103 + 3);
        assert_eq!(f.info_u16(CI_N_SIZE), 103 + 3 + 4);
        f.assert_guard_untouched();
    }

    #[test]
    fn overflow_keeps_the_surplus_when_it_fits_max_local() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint [0x8b,0x0f] = 1423, rowid 0x01.
        // (1423 - 103) % 1020 = 300; 300 + 103 = 403 <= 489 -> surplus.
        f.set_cell(&[0x8b, 0x0f, 0x01]);
        f.run();
        assert_eq!(f.info_u16(CI_N_LOCAL), 403);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 403 + 3);
        assert_eq!(f.info_u16(CI_N_SIZE), 403 + 3 + 4);

        // Boundary: surplus == maxLocal takes the surplus (strhle).
        // payload varint [0x8b,0x65] = 1509; (1509 - 103) % 1020 = 386;
        // 386 + 103 = 489 == maxLocal.
        f.set_cell(&[0x8b, 0x65, 0x01]);
        f.run();
        assert_eq!(f.info_u16(CI_N_LOCAL), MAX_LOCAL);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 489 + 3);
        assert_eq!(f.info_u16(CI_N_SIZE), 489 + 3 + 4);
        f.assert_guard_untouched();
    }

    #[test]
    fn n_size_is_clamped_to_four() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        // payload varint 0x00, rowid varint 0x01: nSize would be 2.
        f.set_cell(&[0x00, 0x01]);
        f.run();
        assert_eq!(f.info_u32(CI_N_PAYLOAD), 0);
        assert_eq!(f.info_u16(CI_N_LOCAL), 0);
        assert_eq!(f.info_u16(CI_I_OVERFLOW), 0);
        assert_eq!(f.info_u16(CI_N_SIZE), 4, "the original's signed movlt floor");
        f.assert_guard_untouched();
    }

    #[test]
    fn n_size_lands_at_0x1e_where_cell_size_ptr_reads() {
        let Some(f) = Fixture::new() else { return };
        f.page_fields(1, 1, 0, MAX_LOCAL, MIN_LOCAL, USABLE);
        f.set_cell(&[0x40, 0x07]);
        // The ported parser is the BTREE_CELL_OPS default the wrapper
        // dispatches through; this exercises the seam end to end.
        let got = unsafe { cell_size_ptr(f.page(), f.cell()) };
        assert_eq!(got, 66, "cell_size_ptr returns CellInfo +0x1e");
    }
}
