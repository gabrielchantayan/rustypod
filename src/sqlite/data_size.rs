//! The b-tree cursor payload-size accessors — SQLite 3.5.x's
//! `sqlite3BtreeDataSize` and `sqlite3BtreeKeySize`. `OP_Column` and
//! `OP_RowData` use the former for table payloads; `OP_Column` uses the
//! latter for index keys.
//!
//! `btree_data_size` — original: `FUN_08370e6c` @ 0x08370e6c (104
//! bytes; 2 `bl` call sites, binary-scanned: 0x083881e4, 0x08389a20).
//! `btree_key_size` — original: `FUN_08371cc4` @ 0x08371cc4 (112
//! bytes; binary-scanned).
//!
//! ```c
//! int sqlite3BtreeDataSize(BtCursor *pCur, u32 *pSize);
//! int sqlite3BtreeKeySize(BtCursor *pCur, i64 *pSize);
//! ```
//!
//! IDENTIFICATION NOTE — `sqlite3BtreeDataSize` stores ONE word
//! (`str r0,[r5]`) read from cursor +0x30 = `CellInfo` +0x10 =
//! `nData` (the leaf payload varint — see `sqlite/cell_size.rs`'s
//! layout), while the i64 `sqlite3BtreeKeySize` sibling at 0x08371cc4
//! reads `ldrd r0,r1,[r4,#0x28]` (`CellInfo` +0x08, nKey) and stores
//! both words (`strd`). The callers agree: 0x083881e4 sits in
//! `vdbeExec`'s `OP_Column` exactly where upstream calls
//! `sqlite3BtreeDataSize` for non-index cursors (the `isIndex` branch
//! beside it calls 0x08371cc4), and 0x08389a20 is `OP_RowData`'s
//! `sqlite3BtreeDataSize` + length-limit check (upstream 3.5.9 vdbe.c
//! lines 1938 and 3531).
//!
//! Algorithm (verified instruction-by-instruction against osos.asm;
//! Ghidra's `decomp/c/033/08370e6c_FUN_08370e6c.c` matches it
//! exactly):
//!
//! 1. `ldrb r0,[r0,#0x43]` — the cursor state byte `eState` (BtCursor
//!    +0x43: 0 = CURSOR_INVALID, 1 = CURSOR_VALID, 2 =
//!    CURSOR_REQUIRESEEK, 3 = CURSOR_FAULT). Below CURSOR_REQUIRESEEK
//!    (`cmp r0,#2; movcc r0,#0; bcc`) the restore is skipped and rc =
//!    0; otherwise the cursor goes through the cursor-state validator
//!    `sqlite3BtreeRestoreOrClearCursorPosition` @ 0x08372ae0
//!    (UNPORTED — dispatched through the [`BTREE_CELL_OPS`]
//!    `restore_cursor_position` slot, whose shipped default is the
//!    documented success stand-in in `sqlite/cell_size.rs`).
//! 2. rc != 0 (`movs r6,r0; bne`) — return the validator's code
//!    immediately; `*out` is NOT written.
//! 3. The state byte is RE-READ (the validator may have moved the
//!    cursor): CURSOR_INVALID means the cursor points at no entry —
//!    `*out = 0` (the `beq` target stores the just-loaded zero byte).
//! 4. Otherwise the cached `CellInfo` at cursor +0x20 is consulted:
//!    `ldrh r0,[r4,#0x3e]` reads `info.nSize` (CellInfo +0x1e) as the
//!    cache flag — nonzero means the cached info is still valid
//!    (upstream's `getCellInfo` macro). On a miss the current cell is
//!    parsed lazily: `ldrd r0,r1,[r4,#0x18]` loads `pPage` (+0x18)
//!    and `idx` (+0x1c) as a pair, `add r2,r4,#0x20` passes the cached
//!    info, and the JUST-PORTED [`btree_parse_cell`]
//!    (`sqlite3BtreeParseCell` @ 0x083727c8, `sqlite/parse_cell.rs`)
//!    fills it; then `validNKey` (cursor +0x42) is set to 1.
//! 5. `ldr r0,[r4,#0x30]; str r0,[r5]` — `*out` gets the cached
//!    `info.nData` word (cursor +0x30 = CellInfo +0x10). rc (0) is
//!    returned.
//!
//! The parse call is a DIRECT call to the ported export, NOT a
//! [`BTREE_CELL_OPS`] dispatch: the house precedent is direct calls
//! for ported callees (`btree_parse_cell` → [`btree_parse_cell_ptr`],
//! `expr_new` → `db_malloc_zero`) with the seam reserved for
//! identified-but-unported ones.
//!
//! Deviations: the cursor field reads go through the module's
//! unaligned accessors (the port's `*mut u8` carries no alignment
//! promise — the same house defensiveness as `sqlite/parse_cell.rs`);
//! the `*out` store is a plain aligned word write, exactly the
//! original's `str r0,[r5,#0]` (both call sites pass word-aligned
//! stack slots). `match.py` consequently lowers the raw-layout reads
//! to byte loads on ARMv5 rather than the original's aligned
//! `ldrh`/`ldr`; the loads' little-endian values and all control flow
//! are equivalent. Nothing in the shipped firmware consumes this port
//! yet (no hooks.yaml entry).

use crate::sqlite::cell_size::restore_cursor_position_op;
use crate::sqlite::parse_cell::btree_parse_cell;

/// `BtCursor` byte offsets the original reads/writes (cross-checked
/// against the validator @ 0x08372ae0 and the key-size sibling @
/// 0x08371cc4, which share the layout).
const CUR_P_PAGE: usize = 0x18;
const CUR_IDX: usize = 0x1c;
/// The cursor's cached `CellInfo` (0x20 bytes; layout in
/// `sqlite/cell_size.rs`).
const CUR_INFO: usize = 0x20;
/// `info.nKey` (CellInfo +0x08): the signed 64-bit key-size pair.
const CUR_INFO_N_KEY: usize = 0x28;
/// `info.nData` (CellInfo +0x10): the word this accessor returns.
const CUR_INFO_N_DATA: usize = 0x30;
/// `info.nSize` (CellInfo +0x1e): the cache-valid flag — zero means
/// the cached info is stale and the cell must be (re)parsed.
const CUR_INFO_N_SIZE: usize = 0x3e;
/// `validNKey`: set once the cached info describes the current cell.
const CUR_VALID_N_KEY: usize = 0x42;
/// `eState`: 0 = CURSOR_INVALID, 1 = CURSOR_VALID, 2 =
/// CURSOR_REQUIRESEEK, 3 = CURSOR_FAULT.
const CUR_E_STATE: usize = 0x43;

/// Cursor states (upstream SQLite 3.5.x `btreeInt.h`).
const CURSOR_INVALID: u8 = 0;
const CURSOR_REQUIRESEEK: u8 = 2;

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

/// btree_data_size — original: `FUN_08370e6c` @ 0x08370e6c (104
/// bytes; 2 `bl` call sites).
///
/// SQLite's `sqlite3BtreeDataSize`: set `*out` to the number of bytes
/// of data (payload) in the entry the cursor currently points at, 0
/// when the cursor points at no entry. Returns a SQLite result code —
/// the cursor-state validator's code when the cursor needed a restore
/// and that restore failed, 0 otherwise; `*out` is only written on
/// success.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_data_size(cursor: *mut u8, out: *mut u32) -> i32 {
    // `cmp r0,#0x2; movcc r0,#0x0; bcc` — the restore only runs from
    // CURSOR_REQUIRESEEK up (upstream's restoreOrClearCursorPosition
    // macro); VALID/INVALID cursors skip it with rc = 0.
    let rc = if rd_u8(cursor, CUR_E_STATE) < CURSOR_REQUIRESEEK {
        0
    } else {
        restore_cursor_position_op()(cursor)
    };
    if rc == 0 {
        // The state byte is re-read: the validator may have moved the
        // cursor (a failed seek leaves it CURSOR_INVALID).
        let size = if rd_u8(cursor, CUR_E_STATE) == CURSOR_INVALID {
            0
        } else {
            // `ldrh r0,[r4,#0x3e]`: info.nSize as the cache flag —
            // upstream's getCellInfo(pCur).
            if rd_u16(cursor, CUR_INFO_N_SIZE) == 0 {
                // `ldrd r0,r1,[r4,#0x18]` / `add r2,r4,#0x20`:
                // parse the current cell into the cached CellInfo.
                let page = rd_u32(cursor, CUR_P_PAGE) as *const u8;
                let index = rd_u32(cursor, CUR_IDX);
                btree_parse_cell(page, index, cursor.add(CUR_INFO));
                *cursor.add(CUR_VALID_N_KEY) = 1;
            }
            // `ldr r0,[r4,#0x30]`: the cached info.nData.
            rd_u32(cursor, CUR_INFO_N_DATA)
        };
        *out = size;
    }
    rc
}

/// btree_key_size — original: `FUN_08371cc4` @ 0x08371cc4 (112
/// bytes; binary-scanned).
///
/// SQLite's `sqlite3BtreeKeySize`: set `*out` to the signed 64-bit key
/// size of the entry the cursor currently points at, or zero when it
/// points at no entry. The AAPCS ABI passes the `i64 *` out-parameter in
/// r1; the original writes its low and high words with `strd`, so this
/// port copies the two target-little-endian words separately rather than
/// introducing a host alignment assumption. As with
/// [`btree_data_size`], a nonzero cursor-state validator result is
/// returned and leaves all eight output bytes untouched.
///
/// Algorithm: validate REQUIRESEEK/FAULT cursors, re-read `eState`,
/// parse the cached `CellInfo` on an `nSize == 0` cache miss and set
/// `validNKey`, then copy `CellInfo.nKey` (+0x08) to the out-parameter.
/// The parser is the direct ported [`btree_parse_cell`] callee; the
/// unported validator uses [`restore_cursor_position_op`]'s shared
/// dispatch seam.
///
/// Deviations: raw cursor fields use the same unaligned little-endian
/// accessors as the neighboring data-size port. The two output-word
/// stores preserve the original `strd` value and order on the ARM target
/// while permitting its four-byte-aligned out-pointer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_key_size(cursor: *mut u8, out: *mut i64) -> i32 {
    let rc = if rd_u8(cursor, CUR_E_STATE) < CURSOR_REQUIRESEEK {
        0
    } else {
        restore_cursor_position_op()(cursor)
    };
    if rc == 0 {
        let out = out.cast::<u32>();
        if rd_u8(cursor, CUR_E_STATE) == CURSOR_INVALID {
            // `strd r0,r0,[r5]`, with the zeroed state byte in r0.
            out.write(0);
            out.add(1).write(0);
        } else {
            if rd_u16(cursor, CUR_INFO_N_SIZE) == 0 {
                let page = rd_u32(cursor, CUR_P_PAGE) as *const u8;
                let index = rd_u32(cursor, CUR_IDX);
                btree_parse_cell(page, index, cursor.add(CUR_INFO));
                *cursor.add(CUR_VALID_N_KEY) = 1;
            }
            // `ldrd r0,r1,[r4,#0x28]; strd r0,r1,[r5]`.
            out.write(rd_u32(cursor, CUR_INFO_N_KEY));
            out.add(1).write(rd_u32(cursor, CUR_INFO_N_KEY + 4));
        }
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::cell_size::{BtreeCellOps, BTREE_CELL_OPS, DEFAULT_BTREE_CELL_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// The fixture slab: one low mapping holding the fake BtShared,
    /// MemPage, page data block and BtCursor, all round-tripping
    /// through u32 (cursor +0x18 and MemPage +0x40/+0x44 are 32-bit
    /// pointer fields on target).
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::BTREE_DATA_SIZE, SLAB_LEN).map(|p| p as usize));

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    const SLAB_LEN: usize = 0x10000;
    const OFF_PAGE: usize = 0x0000; // 0x60 — fake MemPage
    const OFF_DATA: usize = 0x1000; // 0x100 — fake page data block (aData)
    const OFF_BT: usize = 0x2000; // 0x40 — fake BtShared (usableSize @ +0x1e)
    const OFF_CURSOR: usize = 0x3000; // 0x60 — fake BtCursor

    /// MemPage offsets (see `sqlite/parse_cell.rs`).
    const MP_INT_KEY: usize = 0x03;
    const MP_LEAF: usize = 0x07;
    const MP_CHILD_PTR_SIZE: usize = 0x09;
    const MP_MAX_LOCAL: usize = 0x0a;
    const MP_MIN_LOCAL: usize = 0x0c;
    const MP_CELL_OFFSET: usize = 0x0e;
    const MP_P_BT: usize = 0x40;
    const MP_A_DATA: usize = 0x44;
    const BT_USABLE_SIZE: usize = 0x1e;

    /// CellInfo offsets the tests inspect (see `sqlite/cell_size.rs`).
    const CI_P_CELL: usize = 0x00;
    const CI_N_KEY: usize = 0x08;
    const CI_N_PAYLOAD: usize = 0x14;

    /// Cell-pointer array's offset within the fake aData.
    const CELL_OFFSET: u16 = 0x08;
    /// Cell offsets within the fake aData (big-endian array entries).
    const CELL0_OFF: u16 = 0x20;
    const CELL1_OFF: u16 = 0x28;
    /// Cell encodings: [leaf payload varint, index nData varint] —
    /// single-byte varints, so the parser's inline fast path decodes
    /// them with no seam involvement.
    const CELL0_PAYLOAD: u8 = 0x11;
    const CELL0_NKEY: u8 = 0x05;
    const CELL1_PAYLOAD: u8 = 0x22;
    const CELL1_NKEY: u8 = 0x07;

    /// Arguments the mock validator saw, as raw cursor pointer values.
    static RESTORE_SEEN: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    /// Result code the mock validator returns.
    static RESTORE_RC: AtomicI32 = AtomicI32::new(0);
    /// eState the mock validator plants before returning (-1 = leave).
    static RESTORE_NEW_STATE: AtomicI32 = AtomicI32::new(-1);

    unsafe extern "C" fn mock_restore_cursor_position(cursor: *mut u8) -> i32 {
        RESTORE_SEEN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cursor as usize);
        let new_state = RESTORE_NEW_STATE.load(Ordering::Relaxed);
        if new_state >= 0 {
            *cursor.add(CUR_E_STATE) = new_state as u8;
        }
        RESTORE_RC.load(Ordering::Relaxed)
    }

    /// Maps the slab, installs the mock validator, and restores the
    /// shipped default on drop. `None` (test skips) when this host
    /// cannot place the fixture below 4 GiB.
    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        base: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let base = match try_slab() {
                Some(b) => b,
                None => {
                    note_missing_u32_fixture("sqlite::data_size_tests");
                    return None;
                }
            };
            RESTORE_SEEN
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            RESTORE_RC.store(0, Ordering::Relaxed);
            RESTORE_NEW_STATE.store(-1, Ordering::Relaxed);
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).restore_cursor_position =
                    mock_restore_cursor_position;
                core::ptr::write_bytes(base, 0, SLAB_LEN);
            }
            let f = Fixture {
                _guard: guard,
                base,
            };
            f.build_page();
            Some(f)
        }

        fn page(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_PAGE) }
        }

        fn data(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_DATA) }
        }

        fn cursor(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_CURSOR) }
        }

        fn restore_seen(&self) -> Vec<usize> {
            RESTORE_SEEN
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// An index leaf page (intKey = 0) holding two small cells, so
        /// the ported parser has a real target whenever the code under
        /// test (correctly or not) reaches it.
        fn build_page(&self) {
            unsafe {
                let page = self.page();
                let data = self.data();
                let bt = self.base.add(OFF_BT);
                *page.add(MP_INT_KEY) = 0;
                *page.add(MP_LEAF) = 1;
                *page.add(MP_CHILD_PTR_SIZE) = 0;
                page.add(MP_MAX_LOCAL)
                    .cast::<u16>()
                    .write_unaligned(0x100u16.to_le());
                page.add(MP_MIN_LOCAL)
                    .cast::<u16>()
                    .write_unaligned(0x20u16.to_le());
                page.add(MP_CELL_OFFSET)
                    .cast::<u16>()
                    .write_unaligned(CELL_OFFSET.to_le());
                page.add(MP_P_BT)
                    .cast::<u32>()
                    .write_unaligned((bt as usize as u32).to_le());
                page.add(MP_A_DATA)
                    .cast::<u32>()
                    .write_unaligned((data as usize as u32).to_le());
                bt.add(BT_USABLE_SIZE)
                    .cast::<u16>()
                    .write_unaligned(0x200u16.to_le());
                // Big-endian cell-pointer array, two entries.
                let array = data.add(CELL_OFFSET as usize);
                *array = (CELL0_OFF >> 8) as u8;
                *array.add(1) = CELL0_OFF as u8;
                *array.add(2) = (CELL1_OFF >> 8) as u8;
                *array.add(3) = CELL1_OFF as u8;
                // Two index-leaf cells: payload varint, nData varint,
                // then payload bytes (never read — sizes only).
                *data.add(CELL0_OFF as usize) = CELL0_PAYLOAD;
                *data.add(CELL0_OFF as usize + 1) = CELL0_NKEY;
                *data.add(CELL1_OFF as usize) = CELL1_PAYLOAD;
                *data.add(CELL1_OFF as usize + 1) = CELL1_NKEY;
            }
        }

        /// Wires the cursor's structural fields: pPage, idx, and a
        /// poisoned cached CellInfo whose `nSize` cache flag the
        /// caller then sets or clears.
        fn wire_cursor(&self, state: u8, index: u32, cache_valid: bool) {
            unsafe {
                let cursor = self.cursor();
                cursor
                    .add(CUR_P_PAGE)
                    .cast::<u32>()
                    .write_unaligned((self.page() as usize as u32).to_le());
                cursor
                    .add(CUR_IDX)
                    .cast::<u32>()
                    .write_unaligned(index.to_le());
                core::ptr::write_bytes(cursor.add(CUR_INFO), 0xa5, 0x20);
                cursor
                    .add(CUR_INFO_N_SIZE)
                    .cast::<u16>()
                    .write_unaligned(if cache_valid { 0x0040u16.to_le() } else { 0 });
                *cursor.add(CUR_VALID_N_KEY) = 0;
                *cursor.add(CUR_E_STATE) = state;
            }
        }

        /// Primes the cached CellInfo with a distinguishable word in
        /// every field the accessor could plausibly return.
        fn poison_info(&self) {
            unsafe {
                let cursor = self.cursor();
                for (off, val) in [
                    (CI_P_CELL, 0x4444_4444u32),
                    (CI_N_KEY, 0x1111_1111),
                    (CI_N_KEY + 4, 0x2222_2222),
                    (CUR_INFO_N_DATA - CUR_INFO, 0x1234_5678),
                    (CI_N_PAYLOAD, 0x3333_3333),
                ] {
                    cursor
                        .add(CUR_INFO + off)
                        .cast::<u32>()
                        .write_unaligned(val.to_le());
                }
            }
        }

        fn info_word(&self, off: usize) -> u32 {
            unsafe { rd_u32(self.cursor().cast(), CUR_INFO + off) }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).restore_cursor_position =
                    DEFAULT_BTREE_CELL_OPS.restore_cursor_position;
            }
        }
    }

    /// CURSOR_INVALID skips the validator entirely and stores 0
    /// (`movcc r0,#0x0; bcc`, then the `beq` stores the zeroed state
    /// byte). No parse either — the poisoned info must survive.
    #[test]
    fn invalid_state_skips_restore_and_writes_zero() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(0, 0, true);
        f.poison_info();
        let mut out = 0xdead_beefu32;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0);
        assert!(
            f.restore_seen().is_empty(),
            "state < 2 must not call the validator"
        );
        assert_eq!(
            f.info_word(CUR_INFO_N_DATA - CUR_INFO),
            0x1234_5678,
            "no parse may run for CURSOR_INVALID"
        );
    }

    /// CURSOR_VALID also skips the validator (`bcc` is a state < 2
    /// test, not a state == 0 test) and serves the primed cache.
    #[test]
    fn valid_state_skips_restore_too() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 0, true);
        f.poison_info();
        let mut out = 0;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0x1234_5678);
        assert!(
            f.restore_seen().is_empty(),
            "state < 2 must not call the validator"
        );
    }

    /// A failing validator propagates its code, is called with the
    /// cursor verbatim, and leaves `*out`, the cache flag and
    /// `validNKey` untouched (`movs r6,r0; bne` — straight to the
    /// epilogue).
    #[test]
    fn restore_failure_propagates_and_leaves_out_untouched() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0, true);
        f.poison_info();
        RESTORE_RC.store(6, Ordering::Relaxed);
        let mut out = 0xdead_beefu32;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 6, "the validator's code is the return value");
        assert_eq!(out, 0xdead_beef, "rc != 0 must not write *out");
        assert_eq!(
            f.restore_seen(),
            vec![f.cursor() as usize],
            "the validator gets the cursor, once"
        );
        assert_eq!(f.info_word(CUR_INFO_N_DATA - CUR_INFO), 0x1234_5678);
        assert_eq!(unsafe { *f.cursor().add(CUR_VALID_N_KEY) }, 0);
    }

    /// The state byte is re-read after the validator: a restore that
    /// leaves the cursor CURSOR_INVALID (the seek failed to find the
    /// entry) stores 0, not the stale cached size.
    #[test]
    fn restore_leaving_state_invalid_writes_zero() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0, true);
        f.poison_info();
        RESTORE_NEW_STATE.store(0, Ordering::Relaxed);
        let mut out = 0xdead_beefu32;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0);
        assert_eq!(f.restore_seen(), vec![f.cursor() as usize]);
        assert_eq!(
            f.info_word(CUR_INFO_N_DATA - CUR_INFO),
            0x1234_5678,
            "an invalid cursor after restore must not parse"
        );
    }

    /// Cache hit (info.nSize != 0): no parse, and `*out` is the
    /// CellInfo +0x10 word (nData) — not nKey (+0x08), not nPayload
    /// (+0x14), not pCell (+0x00). The page behind the cursor parses
    /// to 0x11, so any parse would be visible in the result.
    #[test]
    fn cache_hit_skips_parse_and_reads_the_n_data_word() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 0, true);
        f.poison_info();
        let mut out = 0;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(
            out, 0x1234_5678,
            "*out is the cached info.nData at cursor+0x30"
        );
        assert_eq!(
            f.info_word(CI_P_CELL),
            0x4444_4444,
            "cache hit must not parse"
        );
        assert_eq!(unsafe { *f.cursor().add(CUR_VALID_N_KEY) }, 0);
    }

    /// Cache miss (info.nSize == 0): the ported parser runs on
    /// (pPage, idx, cursor+0x20) — idx selects the SECOND cell, so a
    /// wrong index argument reads cell 0's 0x11; a wrong info pointer
    /// leaves the cached fields poisoned — `validNKey` is set, and a
    /// repeat call serves the fresh cache without reparsing (the page
    /// is corrupted between calls to prove it).
    #[test]
    fn cache_miss_parses_current_cell_caches_and_reuses() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 1, false);
        let mut out = 0;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, CELL1_PAYLOAD as u32, "*out is cell 1's payload varint");
        assert_eq!(
            unsafe { *f.cursor().add(CUR_VALID_N_KEY) },
            1,
            "parse sets validNKey"
        );
        let expected_cell = unsafe { f.data().add(CELL1_OFF as usize) };
        assert_eq!(
            f.info_word(CI_P_CELL),
            expected_cell as usize as u32,
            "idx must select cell 1 through the cell-pointer array"
        );
        assert_eq!(
            f.info_word(CI_N_KEY),
            CELL1_NKEY as u32,
            "cell 1's index nData varint lands at info+0x08"
        );
        assert_ne!(f.info_word(CI_N_PAYLOAD), 0xa5a5_a5a5);
        assert_eq!(
            unsafe { rd_u16(f.cursor(), CUR_INFO_N_SIZE) },
            (CELL1_PAYLOAD as u16 + CELL1_NKEY as u16) + 2,
            "the parse fills nSize = payload + header, flipping the cache flag"
        );

        // Second call: cache now valid — corrupt the page so a
        // reparse could only return garbage, then expect the same
        // cached answer.
        unsafe { core::ptr::write_bytes(f.data(), 0xff, 0x100) };
        let mut out2 = 0;
        let rc2 = unsafe { btree_data_size(f.cursor(), &mut out2) };
        assert_eq!(rc2, 0);
        assert_eq!(
            out2, CELL1_PAYLOAD as u32,
            "the fresh cache is served, no reparse"
        );
        assert_eq!(f.info_word(CI_P_CELL), expected_cell as usize as u32);
    }

    /// The shipped default slot (success stand-in) lets a
    /// REQUIRESEEK cursor proceed to the cache as if restored.
    #[test]
    fn default_restore_stand_in_lets_requireseek_proceed() {
        let Some(f) = Fixture::new() else { return };
        unsafe {
            (*core::ptr::addr_of_mut!(BTREE_CELL_OPS)).restore_cursor_position =
                DEFAULT_BTREE_CELL_OPS.restore_cursor_position;
        }
        f.wire_cursor(2, 0, true);
        f.poison_info();
        let mut out = 0;
        let rc = unsafe { btree_data_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0x1234_5678);
        assert!(
            f.restore_seen().is_empty(),
            "the default slot is not the mock"
        );
    }

    /// The i64 sibling has the same early INVALID path, but must clear
    /// both words of its out-parameter (`strd r0,r0,[r5]`).
    #[test]
    fn key_size_invalid_skips_restore_and_clears_both_words() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(0, 0, true);
        f.poison_info();
        let mut out = -1i64;
        let rc = unsafe { btree_key_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0);
        assert!(f.restore_seen().is_empty());
        assert_eq!(
            f.info_word(CI_N_KEY),
            0x1111_1111,
            "an invalid cursor must not parse or alter cached nKey"
        );
    }

    /// Validator failures reach the shared `BTREE_CELL_OPS` seam and
    /// return before either word of the i64 out-parameter is written.
    #[test]
    fn key_size_restore_failure_propagates_and_leaves_i64_untouched() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0, true);
        f.poison_info();
        RESTORE_RC.store(6, Ordering::Relaxed);
        let mut out = 0x7ead_beef_dead_cafeu64 as i64;
        let rc = unsafe { btree_key_size(f.cursor(), &mut out) };
        assert_eq!(rc, 6);
        assert_eq!(out as u64, 0x7ead_beef_dead_cafe);
        assert_eq!(f.restore_seen(), vec![f.cursor() as usize]);
        assert_eq!(unsafe { *f.cursor().add(CUR_VALID_N_KEY) }, 0);
    }

    /// A successful restore can leave the cursor invalid; the re-read
    /// state gate then writes an all-zero i64 without parsing stale info.
    #[test]
    fn key_size_restore_to_invalid_clears_i64_without_parsing() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0, true);
        f.poison_info();
        RESTORE_NEW_STATE.store(0, Ordering::Relaxed);
        let mut out = -1i64;
        let rc = unsafe { btree_key_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0);
        assert_eq!(f.restore_seen(), vec![f.cursor() as usize]);
        assert_eq!(f.info_word(CI_N_KEY), 0x1111_1111);
    }

    /// Cache hits copy the full nKey pair in target low-word/high-word
    /// order, preserving the signed i64 bit pattern rather than nData.
    #[test]
    fn key_size_cache_hit_reads_full_signed_n_key() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 0, true);
        f.poison_info();
        unsafe {
            f.cursor()
                .add(CUR_INFO_N_KEY + 4)
                .cast::<u32>()
                .write_unaligned(0xfedc_ba98u32.to_le());
        }
        let mut out = 0;
        let rc = unsafe { btree_key_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out as u64, 0xfedc_ba98_1111_1111);
        assert_eq!(unsafe { *f.cursor().add(CUR_VALID_N_KEY) }, 0);
    }

    /// Cache misses parse into `cursor + 0x20`, set `validNKey`, and
    /// return the parser-populated nKey rather than the payload nData.
    #[test]
    fn key_size_cache_miss_parses_and_marks_n_key_valid() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 1, false);
        let mut out = -1i64;
        let rc = unsafe { btree_key_size(f.cursor(), &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, CELL1_NKEY as i64);
        assert_eq!(unsafe { *f.cursor().add(CUR_VALID_N_KEY) }, 1);
        assert_eq!(f.info_word(CI_N_KEY), CELL1_NKEY as u32);
        assert_eq!(f.info_word(CI_N_KEY + 4), 0);
        assert_ne!(f.info_word(CI_N_PAYLOAD), 0xa5a5_a5a5);
    }

    /// The slot really is one of the shared cluster's ops (catches a
    /// parallel-static regression).
    #[test]
    fn restore_slot_lives_on_btree_cell_ops() {
        let _guard = BTREE_CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ops: BtreeCellOps =
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS)) };
        assert_eq!(
            unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!(
                    BTREE_CELL_OPS.restore_cursor_position
                )) as usize
            },
            DEFAULT_BTREE_CELL_OPS.restore_cursor_position as usize,
            "the shipped default is the documented success stand-in"
        );
    }
}
