//! Positioning a SQLite b-tree cursor at its final entry.
//!
//! `btree_last` — original: `FUN_08371d34` @ 0x08371d34 (112 bytes,
//! `0x08371d34..0x08371da0`; the next separately linked function begins at
//! 0x08371da4). Raw-word decoding finds three unconditional outbound `bl`
//! instructions (`btree_move_to_root` @ 0x082d9b00,
//! `btree_move_to_rightmost` @ 0x082d9a94, and `btree_parse_cell` @
//! 0x083727c8), no predicated outbound `bl`, and two unconditional inbound
//! `bl` call sites (0x08386ecc and 0x08386ef8).
//!
//! SQLite 3.5.x's `sqlite3BtreeLast`: move to the root; report an empty tree
//! through `*res = 1`; otherwise descend to the rightmost entry, parse the
//! current cell when its cache is stale, and set `atLast` exactly when the
//! descent succeeded. `btree_move_to_rightmost` is now a direct ported callee;
//! the target-width `pPage` field remains a u32.

use crate::sqlite::move_to_root::btree_move_to_root;
use crate::sqlite::parse_cell::btree_parse_cell;
use crate::sqlite::move_to_rightmost::btree_move_to_rightmost;

const CUR_P_PAGE: usize = 0x18;
const CUR_IDX: usize = 0x1c;
const CUR_INFO: usize = 0x20;
const CUR_INFO_N_SIZE: usize = 0x3e;
const CUR_AT_LAST: usize = 0x41;
const CUR_VALID_N_KEY: usize = 0x42;
const CUR_E_STATE: usize = 0x43;
const CURSOR_INVALID: u8 = 0;


#[inline(always)]
unsafe fn rd_u16(base: *const u8, off: usize) -> u16 {
    u16::from_le(base.add(off).cast::<u16>().read_unaligned())
}

#[inline(always)]
unsafe fn rd_u32(base: *const u8, off: usize) -> u32 {
    u32::from_le(base.add(off).cast::<u32>().read_unaligned())
}

/// `btree_last` — original: `FUN_08371d34` @ 0x08371d34 (112 bytes; two
/// unconditional direct `bl` callers, no predicated inbound call).
///
/// SQLite's `sqlite3BtreeLast`: position `cursor` on its final entry and set
/// `*res` to one only for an empty tree. A move-to-root error leaves `res`
/// untouched. After a successful rightmost descent, `atLast` is one exactly
/// for a successful descent; a VALID cursor lazily fills its cached CellInfo.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_last(cursor: *mut u8, res: *mut u32) -> i32 {
    let mut rc = btree_move_to_root(cursor);
    if rc != 0 {
        return rc;
    }
    if *cursor.add(CUR_E_STATE) == CURSOR_INVALID {
        res.write(1);
        return 0;
    }

    res.write(0);
    rc = btree_move_to_rightmost(cursor);
    if rd_u16(cursor, CUR_INFO_N_SIZE) == 0 {
        let page = rd_u32(cursor, CUR_P_PAGE) as *const u8;
        let index = rd_u32(cursor, CUR_IDX);
        btree_parse_cell(page, index, cursor.add(CUR_INFO));
        *cursor.add(CUR_VALID_N_KEY) = 1;
    }
    *cursor.add(CUR_AT_LAST) = if rc == 0 { 1 } else { 0 };
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::{LazyLock, MutexGuard};

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0x000;
    const PAGE: usize = 0x100;
    const PAGE_NUMBER: usize = 0x4c;
    const PAGE_N_CELL: usize = 0x14;
    const CUR_ROOT_PAGE: usize = 0x14;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_LAST, SLAB_LEN).map(|pointer| pointer as usize)
    });

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        cursor: *mut u8,
    }
    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let base = match *SLAB {
                Some(base) => base as *mut u8,
                None => {
                    note_missing_u32_fixture("sqlite::btree_last_tests");
                    return None;
                }
            };
            unsafe {
                core::ptr::write_bytes(base, 0, SLAB_LEN);
                let cursor = base.add(CURSOR);
                let page = base.add(PAGE);
                cursor.add(CUR_ROOT_PAGE).cast::<u32>().write(7);
                cursor.add(CUR_P_PAGE).cast::<u32>().write(page as usize as u32);
                page.add(PAGE_NUMBER).cast::<u32>().write(7);
                page.add(PAGE_N_CELL).cast::<u16>().write(1);
                page.add(4).write(1);
                cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(1);
                Some(Self { _guard: guard, cursor })
            }
        }
    }


    #[test]
    fn fault_from_move_to_root_preserves_result_and_skips_rightmost() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            *fixture.cursor.add(CUR_E_STATE) = 3;
            fixture.cursor.add(0x50).cast::<u32>().write(17);
            let mut result = 99;
            assert_eq!(btree_last(fixture.cursor, &mut result), 17);
            assert_eq!(result, 99);
        }
    }

    #[test]
    fn empty_root_reports_empty_without_rightmost_descent() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            let page = fixture.cursor.add(CUR_P_PAGE).cast::<u32>().read() as usize as *mut u8;
            page.add(PAGE_N_CELL).cast::<u16>().write(0);
            *page.add(4) = 1;
            let mut result = 99;
            assert_eq!(btree_last(fixture.cursor, &mut result), 0);
            assert_eq!(result, 1);
        }
    }

    #[test]
    fn successful_rightmost_descent_reports_entry_and_marks_at_last() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            let mut result = 99;
            assert_eq!(btree_last(fixture.cursor, &mut result), 0);
            assert_eq!(result, 0);
            assert_eq!(*fixture.cursor.add(CUR_AT_LAST), 1);
        }
    }
}

