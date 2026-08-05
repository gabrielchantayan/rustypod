//! The b-tree cell size query — SQLite 3.5.x's `cellSizePtr`, the small
//! wrapper every b-tree maintenance routine (page defragmentation, cell
//! insert/drop, free-space accounting) measures a cell through.
//!
//! `cell_size_ptr` — original: `FUN_082c0a50` @ 0x082c0a50 (28 bytes;
//! 11 `bl` call sites, binary-scanned: 0x082b6090, 0x082b6128,
//! 0x082b6698, 0x082b68a0, 0x082b6af4, 0x082c2dcc, 0x082c5ec0,
//! 0x08371064, 0x083710ac, 0x08371154, 0x08371768).
//!
//! ```c
//! static u16 cellSizePtr(MemPage *pPage, u8 *pCell){
//!   CellInfo info;
//!   sqlite3BtreeParseCellPtr(pPage, pCell, &info);
//!   return info.nSize;
//! }
//! ```
//!
//! The whole body is one call and one halfword load: build a `CellInfo`
//! on the stack, hand it to `sqlite3BtreeParseCellPtr` @ 0x083727ec
//! (ported in `sqlite/parse_cell.rs`), and return the `u16` at info
//! +0x1e —
//! `nSize`, the total number of bytes the cell occupies on the b-tree
//! page. The +0x1e offset is from the disassembly (`ldrh r0,[sp,#0x1e]`
//! @ 0x082c0a60), not Ghidra's `local_a` bookkeeping.
//!
//! `CellInfo` in this build is 0x20 bytes, written by 0x083727ec as:
//!
//! ```text
//! +0x00  pCell     (u32)   start of the cell, i.e. the `cell` argument
//! +0x04  (pad — never written; the i64 at +0x08 is 8-aligned)
//! +0x08  nKey/nData pair (2 x u32)  intKey pages: rowid varint (the
//!        0x0837aab0 callee writes the full u64, hi word at +0x0c);
//!        index pages: nData at +0x08, +0x0c zeroed
//! +0x10  u32       payload varint read on leaf pages
//! +0x14  u32       total payload (nPayload)
//! +0x18  nHeader   (u16)   bytes consumed by the cell header
//! +0x1a  nLocal    (u16)   payload held locally on the page
//! +0x1c  iOverflow (u16)   offset of the overflow page number, 0 if none
//! +0x1e  nSize     (u16)   total on-page cell size — the value returned
//! ```
//!
//! Only +0x1e is consumed here; the rest is the callee's business.
//! `MemPage` fields the callee reads (for the record): leaf +0x07,
//! intKey +0x03, childPtrSize +0x09, maxLocal +0x0a, minLocal +0x0c,
//! pBt +0x40 (whose +0x1e is the usable page size). Its varint readers
//! are 0x0837ac30 (`sqlite3GetVarint`) and 0x0837aab0 (the u64
//! decoder — upstream's `sqlite3GetVarint` role despite the repo's
//! inverted naming, see `sqlite/get_varint64.rs`); the overflow-branch
//! divisor goes through `__rt_udiv` @ 0x08036f14.
//!
//! Deviations:
//!
//! - The parse call goes through the [`BTREE_CELL_OPS`] dispatch
//!   boundary (house pattern — see `sqlite/blob_to_hex.rs`). The shipped
//!   default is now the ported parser in `sqlite/parse_cell.rs`, whose
//!   varint readers ride sibling slots on the same static: 0x0837ac30
//!   is ported (`sqlite/get_varint.rs`) and 0x0837aab0 is ported
//!   (`sqlite/get_varint64.rs`); each is its slot's shipped default.
//!   The zero-fill parser stand-in (`missing_parse_cell`) remains for
//!   tests. Nothing
//!   in the shipped firmware consumes this port yet (no
//!   hooks.yaml entry).
//! - The original's stack frame is 0x24 bytes (0x20 of `CellInfo` plus
//!   alignment slop) and is NOT initialized; the port zero-initializes
//!   its 0x20-byte buffer so the default slot's `nSize` is defined
//!   behavior in Rust.

/// Byte size of the `CellInfo` the callee fills (original frame is
/// 0x24; the top 4 bytes are alignment slop the callee never touches).
const CELL_INFO_SIZE: usize = 0x20;

/// Byte offset of `CellInfo.nSize` (original: `ldrh r0,[sp,#0x1e]`).
const N_SIZE_OFFSET: usize = 0x1e;

/// The unported services the b-tree cell cluster reaches: the parser
/// itself (ported — that slot's default is the real thing), plus the
/// two varint readers the parser calls, plus the cursor-state
/// validator the cursor accessors call. The varint readers are ported
/// and ship as their slots' defaults: 0x0837ac30 in
/// `sqlite/get_varint.rs`, 0x0837aab0 in `sqlite/get_varint64.rs`. The
/// validator (`sqlite3BtreeRestoreOrClearCursorPosition` @ 0x08372ae0)
/// is still unported; its slot ships the success stand-in.
#[derive(Clone, Copy)]
pub struct BtreeCellOps {
    /// `sqlite3BtreeParseCellPtr` @ 0x083727ec: parse the cell at
    /// `cell` on `page` and fill the 0x20-byte `CellInfo` at `info`.
    pub parse_cell: unsafe extern "C" fn(page: *const u8, cell: *const u8, info: *mut u8),
    /// `sqlite3GetVarint` @ 0x0837ac30 (ported —
    /// `sqlite::get_varint::get_varint` is the shipped default):
    /// decode the varint at `p` into `out`, return the byte count.
    /// Like the original, the slot is only reached once the caller
    /// has seen p[0]'s continuation bit set (the 1-byte case is the
    /// caller's inline fast path); the original's out-param is the
    /// low u32 word of this slot's u64.
    pub get_varint: unsafe extern "C" fn(p: *const u8, out: *mut u64) -> u32,
    /// `sqlite3GetVarint32` @ 0x0837aab0 (ported —
    /// `sqlite::get_varint64::get_varint64` is the shipped default):
    /// decode the varint at `p` into `out`, return the byte count.
    /// Naming inversion caveat: despite the slot's upstream-derived
    /// name, the original's out-param is a u64 (paired lo/hi stores —
    /// upstream's `sqlite3GetVarint` role), so the slot is `*mut u64`;
    /// see `sqlite/get_varint64.rs`. Unlike the `get_varint` slot this
    /// one is also called for single-byte varints (the rowid read has
    /// no inline fast path).
    pub get_varint32: unsafe extern "C" fn(p: *const u8, out: *mut u64) -> u32,
    /// `sqlite3BtreeRestoreOrClearCursorPosition` @ 0x08372ae0
    /// (UNPORTED — [`missing_restore_cursor_position`] is the shipped
    /// default): the cursor-state validator every cursor accessor
    /// (`sqlite3BtreeDataSize` @ 0x08370e6c, its i64 key-size sibling @
    /// 0x08371cc4, ...) runs when `BtCursor.eState` (+0x43) reaches
    /// CURSOR_REQUIRESEEK (2). Returns a SQLite result code: the saved
    /// error at cursor +0x50 when eState is CURSOR_FAULT (3),
    /// SQLITE_ABORT (4) when cursor +0x54 (isIncrblobHandle) is set,
    /// otherwise it seeks back to the saved position and returns the
    /// seek's code (0 on success). See
    /// `decomp/c/033/08372ae0_FUN_08372ae0.c`.
    pub restore_cursor_position: unsafe extern "C" fn(cursor: *mut u8) -> i32,
}

/// Default boundary while 0x083727ec is unported. Zero-filling is the
/// only honest stand-in for a parser that does not exist yet: the
/// wrapper then returns `nSize == 0` for every cell instead of whatever
/// the stack happened to hold.
unsafe extern "C" fn missing_parse_cell(_page: *const u8, _cell: *const u8, info: *mut u8) {
    core::ptr::write_bytes(info, 0, CELL_INFO_SIZE);
}

/// Stand-in kept for tests after the 0x0837ac30 port landed: a
/// single zero byte is a complete varint (value 0, length 1). The
/// shipped default is now the ported `sqlite::get_varint::get_varint`.
unsafe extern "C" fn missing_get_varint(_p: *const u8, out: *mut u64) -> u32 {
    *out = 0;
    1
}

/// Stand-in kept for tests after the 0x0837aab0 port landed, same
/// reasoning as [`missing_get_varint`]. The shipped default is now
/// the ported `sqlite::get_varint64::get_varint64`.
unsafe extern "C" fn missing_get_varint32(_p: *const u8, out: *mut u64) -> u32 {
    *out = 0;
    1
}

/// Stand-in kept for tests while 0x08372ae0 is unported: report
/// SQLITE_OK and touch nothing. With the save/restore machinery
/// unmodeled there is no saved position to seek back to — the cursor
/// is already where the caller left it — so success is the only
/// honest answer a validator that does not exist yet can give.
unsafe extern "C" fn missing_restore_cursor_position(_cursor: *mut u8) -> i32 {
    0
}

/// Wired default for [`BTREE_CELL_OPS`]: the ported parser, both
/// ported varint readers (0x0837ac30 and 0x0837aab0) and the
/// success stand-in for the unported cursor validator @ 0x08372ae0.
pub const DEFAULT_BTREE_CELL_OPS: BtreeCellOps = BtreeCellOps {
    parse_cell: crate::sqlite::parse_cell::btree_parse_cell_ptr,
    get_varint: crate::sqlite::get_varint::get_varint,
    get_varint32: crate::sqlite::get_varint64::get_varint64,
    restore_cursor_position: missing_restore_cursor_position,
};

/// Active model of the parser call in [`cell_size_ptr`] and of the
/// varint reads in `sqlite::parse_cell`. Host tests replace slots to
/// observe the exact arguments.
pub static mut BTREE_CELL_OPS: BtreeCellOps = DEFAULT_BTREE_CELL_OPS;

/// Reads the hook slot. Volatile so LLVM cannot constant-fold the load
/// to the zero-fill default (the house pattern — `sqlite/blob_to_hex.rs`).
#[inline(always)]
unsafe fn parse_cell_op() -> unsafe extern "C" fn(*const u8, *const u8, *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.parse_cell))
}

/// Reads the `sqlite3GetVarint` slot. Volatile, same rationale as
/// `parse_cell_op` above.
#[inline(always)]
pub(crate) unsafe fn get_varint_op() -> unsafe extern "C" fn(*const u8, *mut u64) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.get_varint))
}

/// Reads the `sqlite3GetVarint32` slot. Volatile, same rationale as
/// `parse_cell_op` above.
#[inline(always)]
pub(crate) unsafe fn get_varint32_op() -> unsafe extern "C" fn(*const u8, *mut u64) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.get_varint32))
}

/// Reads the `sqlite3BtreeRestoreOrClearCursorPosition` slot.
/// Volatile, same rationale as `parse_cell_op` above.
#[inline(always)]
pub(crate) unsafe fn restore_cursor_position_op() -> unsafe extern "C" fn(*mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.restore_cursor_position))
}

/// cell_size_ptr — original: `FUN_082c0a50` @ 0x082c0a50 (28 bytes;
/// 11 `bl` call sites).
///
/// SQLite's `cellSizePtr`: parse the b-tree cell at `cell` on page
/// `page` and return its total on-page size in bytes (`CellInfo.nSize`,
/// the `u16` at info +0x1e).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cell_size_ptr(page: *const u8, cell: *const u8) -> u16 {
    let mut info = [0u8; CELL_INFO_SIZE];
    parse_cell_op()(page, cell, info.as_mut_ptr());
    u16::from_le_bytes([info[N_SIZE_OFFSET], info[N_SIZE_OFFSET + 1]])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::BTREE_CELL_TEST_LOCK;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Arguments the mock parser saw, as raw pointer values.
    static SEEN: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

    /// Distinctive halfwords the mock plants at each `CellInfo` u16
    /// field, so a wrong offset can only pass by reading exactly +0x1e.
    const N_HEADER: u16 = 0x1111;
    const N_LOCAL: u16 = 0x2222;
    const I_OVERFLOW: u16 = 0x3333;
    const N_SIZE: u16 = 0x4444;

    /// `nSize` the `sized_parse_cell` mock plants, for the sweep test.
    static N_SIZE_OVERRIDE: AtomicU16 = AtomicU16::new(0);

    /// Mock that fills the `CellInfo` with noise and a chosen `nSize`.
    unsafe extern "C" fn sized_parse_cell(_p: *const u8, _c: *const u8, info: *mut u8) {
        core::ptr::write_bytes(info, 0x5a, CELL_INFO_SIZE);
        info.add(N_SIZE_OFFSET)
            .cast::<u16>()
            .write_unaligned(N_SIZE_OVERRIDE.load(Ordering::Relaxed).to_le());
    }

    /// Fills the whole 0x20-byte `CellInfo` with a position-dependent
    /// pattern, then stamps the four u16 fields — every byte the
    /// wrapper could read is both defined and distinguishable.
    unsafe extern "C" fn mock_parse_cell(page: *const u8, cell: *const u8, info: *mut u8) {
        SEEN.lock().unwrap().push((page as usize, cell as usize));
        for i in 0..CELL_INFO_SIZE {
            info.add(i).write(0xa0 + i as u8);
        }
        for (off, val) in [
            (0x18usize, N_HEADER),
            (0x1a, N_LOCAL),
            (0x1c, I_OVERFLOW),
            (N_SIZE_OFFSET, N_SIZE),
        ] {
            info.add(off).cast::<u16>().write_unaligned(val.to_le());
        }
    }

    /// Installs the mock parser and restores the shipped default (the
    /// ported parser in `sqlite::parse_cell`) on drop.
    struct Fixture {
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new() -> Self {
            let guard = BTREE_CELL_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            SEEN.lock().unwrap().clear();
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).parse_cell = mock_parse_cell;
            }
            Fixture { _guard: guard }
        }

        fn seen(&self) -> Vec<(usize, usize)> {
            SEEN.lock().unwrap().clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).parse_cell =
                    DEFAULT_BTREE_CELL_OPS.parse_cell;
            }
        }
    }

    /// Sentinel page/cell objects; only their addresses matter.
    static PAGE: [u8; 4] = [0x50, 0x0a, 0x2c, 0x08];
    static CELL: [u8; 4] = [0xec, 0x27, 0x37, 0x08];

    #[test]
    fn returns_the_n_size_halfword_at_0x1e() {
        let _f = Fixture::new();
        let got = unsafe { cell_size_ptr(PAGE.as_ptr(), CELL.as_ptr()) };
        assert_eq!(got, N_SIZE);
        assert_ne!(got, N_HEADER);
        assert_ne!(got, N_LOCAL);
        assert_ne!(got, I_OVERFLOW);
    }

    #[test]
    fn passes_page_and_cell_through_verbatim() {
        let f = Fixture::new();
        let got = unsafe { cell_size_ptr(PAGE.as_ptr(), CELL.as_ptr()) };
        assert_eq!(got, N_SIZE);
        assert_eq!(
            f.seen(),
            vec![(PAGE.as_ptr() as usize, CELL.as_ptr() as usize)],
            "the parser must be called exactly once with the caller's arguments"
        );
    }

    #[test]
    fn result_tracks_only_the_0x1e_field() {
        let _f = Fixture::new();
        unsafe {
            (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).parse_cell = sized_parse_cell;
        }
        for n_size in [0u16, 4, 0x7fff, 0xffff] {
            N_SIZE_OVERRIDE.store(n_size, Ordering::Relaxed);
            assert_eq!(
                unsafe { cell_size_ptr(PAGE.as_ptr(), CELL.as_ptr()) },
                n_size
            );
        }
    }

    #[test]
    fn zero_fill_stand_in_reports_zero() {
        let _guard = BTREE_CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).parse_cell = missing_parse_cell;
        }
        assert_eq!(unsafe { cell_size_ptr(PAGE.as_ptr(), CELL.as_ptr()) }, 0);
    }

    #[test]
    fn missing_get_varint_stand_in_reports_zero_len_one() {
        let _guard = BTREE_CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut value = u64::MAX;
        let len = unsafe { missing_get_varint(PAGE.as_ptr(), &mut value) };
        assert_eq!((value, len), (0, 1));
    }

    #[test]
    fn missing_get_varint32_stand_in_reports_zero_len_one() {
        let _guard = BTREE_CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut value = u64::MAX;
        let len = unsafe { missing_get_varint32(PAGE.as_ptr(), &mut value) };
        assert_eq!((value, len), (0, 1));
    }

    #[test]
    fn missing_restore_cursor_position_stand_in_reports_ok() {
        let mut cursor = [0x5au8; 0x60];
        let snapshot = cursor;
        let rc = unsafe { missing_restore_cursor_position(cursor.as_mut_ptr()) };
        assert_eq!(rc, 0, "SQLITE_OK — nothing to restore");
        assert_eq!(cursor, snapshot, "the stand-in must not touch the cursor");
    }

    #[test]
    fn shipped_default_is_the_ported_parser() {
        let _guard = BTREE_CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.parse_cell)) as usize,
                crate::sqlite::parse_cell::btree_parse_cell_ptr as *const () as usize,
                "the shipped parse_cell slot is the ported sqlite3BtreeParseCellPtr"
            );
        }
    }
}
