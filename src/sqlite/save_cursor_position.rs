//! Saving the positions of b-tree cursors before a b-tree mutation.
//!
//! `btree_save_all_cursors` — original: `FUN_083684fc` @ 0x083684fc.
//! Raw `osos.dec` words establish the 216-byte extent
//! `0x083684fc..0x083685d4`; the next real function starts with
//! `ldrb r1,[r1,#0xc]` at 0x083685d4. The body has 6 plain `bl` instructions
//! and no predicated `bl`; it has 4 inbound plain-`bl` callers.
//!
//! SQLite's `saveAllCursors`: walks `btree + 8`'s cursor list, skipping the
//! supplied cursor and, when non-NULL, cursors belonging to another Btree.
//! Every valid cursor saves its index key when needed, releases its page,
//! enters REQUIRESEEK, and discards its overflow cache. The first error stops
//! the walk after discarding that cursor's overflow cache.
//!
//! Deliberate deviations: target pointer slots are read as little-endian u32
//! values so their offsets remain four bytes on hosts. The raw direct calls
//! are direct calls to their ported Rust twins; no seam is introduced.

use crate::cxx::release::release_via_field_0x48;
use crate::heap::tracked::tracked_free;
use crate::sqlite::data_size::btree_key_size;
use crate::sqlite::key::btree_key;
use crate::sqlite::mem::sqlite3_malloc;

const BTREE_CURSOR_LIST: usize = 0x08;
const CUR_NEXT: usize = 0x08;
const CUR_BTREE: usize = 0x14;
const CUR_PAGE: usize = 0x18;
const CUR_SAVED_KEY: usize = 0x44;
const CUR_SAVED_N_KEY: usize = 0x48;
const CUR_OVERFLOW_CACHE: usize = 0x58;
const CUR_E_STATE: usize = 0x43;
const PAGE_INT_KEY: usize = 0x03;

const CURSOR_VALID: u8 = 1;
const CURSOR_REQUIRESEEK: u8 = 2;
const SQLITE_NOMEM: i32 = 7;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read_unaligned())
}

#[inline(always)]
unsafe fn write_u32(base: *mut u8, offset: usize, value: u32) {
    base.add(offset).cast::<u32>().write_unaligned(value.to_le());
}

/// btree_save_all_cursors — original: `FUN_083684fc` @ 0x083684fc (216
/// bytes; 6 plain `bl`, 0 predicated `bl`; 4 inbound plain-`bl` callers).
///
/// Saves every eligible valid cursor on `btree` except `except`, optionally
/// restricted to `only_for_btree`. Returns the first SQLite error, or zero.
/// A table cursor needs no saved key; an index cursor allocates and copies its
/// current key before its page is released and its state becomes REQUIRESEEK.
///
/// # Safety
/// `btree` and each linked cursor must designate writable target-layout
/// storage. Every valid cursor's page and any index-key payload must satisfy
/// the corresponding ported callee's contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_save_all_cursors(
    btree: *mut u8,
    only_for_btree: *mut u8,
    except: *mut u8,
) -> i32 {
    let mut cursor = read_u32(btree, BTREE_CURSOR_LIST) as usize as *mut u8;
    while !cursor.is_null() {
        if cursor != except
            && (only_for_btree.is_null()
                || read_u32(cursor, CUR_BTREE) as usize as *mut u8 == only_for_btree)
            && *cursor.add(CUR_E_STATE) == CURSOR_VALID
        {
            let mut rc = btree_key_size(cursor, cursor.add(CUR_SAVED_N_KEY).cast());
            if rc == 0 {
                let page = read_u32(cursor, CUR_PAGE) as usize as *mut u8;
                if *page.add(PAGE_INT_KEY) == 0 {
                    let saved_key = sqlite3_malloc(read_u32(cursor, CUR_SAVED_N_KEY) as i32);
                    if saved_key.is_null() {
                        rc = SQLITE_NOMEM;
                    } else {
                        rc = btree_key(cursor, 0, read_u32(cursor, CUR_SAVED_N_KEY), saved_key);
                        if rc == 0 {
                            write_u32(cursor, CUR_SAVED_KEY, saved_key as usize as u32);
                        } else {
                            tracked_free(saved_key);
                        }
                    }
                }
                if rc == 0 {
                    release_via_field_0x48(page);
                    write_u32(cursor, CUR_PAGE, 0);
                    *cursor.add(CUR_E_STATE) = CURSOR_REQUIRESEEK;
                }
            }
            let overflow = read_u32(cursor, CUR_OVERFLOW_CACHE) as usize as *mut u8;
            tracked_free(overflow);
            write_u32(cursor, CUR_OVERFLOW_CACHE, 0);
            if rc != 0 {
                return rc;
            }
        }
        cursor = read_u32(cursor, CUR_NEXT) as usize as *mut u8;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::{LazyLock, MutexGuard};

    const SLAB_LEN: usize = 0x10000;
    const OFF_BTREE: usize = 0x1000;
    const OFF_FIRST: usize = 0x2000;
    const OFF_SECOND: usize = 0x3000;
    const OFF_PAGE: usize = 0x4000;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_SAVE_ALL_CURSORS, SLAB_LEN).map(|p| p as usize)
    });

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        base: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let base = match *SLAB {
                Some(base) => base as *mut u8,
                None => {
                    note_missing_u32_fixture("sqlite::save_cursor_position_tests");
                    return None;
                }
            };
            unsafe { core::ptr::write_bytes(base, 0, SLAB_LEN) };
            Some(Self { _guard: guard, base })
        }

        fn btree(&self) -> *mut u8 { unsafe { self.base.add(OFF_BTREE) } }
        fn first(&self) -> *mut u8 { unsafe { self.base.add(OFF_FIRST) } }
        fn second(&self) -> *mut u8 { unsafe { self.base.add(OFF_SECOND) } }
        fn page(&self) -> *mut u8 { unsafe { self.base.add(OFF_PAGE) } }
    }

    #[test]
    fn saves_eligible_table_cursor_and_skips_except_and_other_btree() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            write_u32(fixture.btree(), BTREE_CURSOR_LIST, fixture.first() as usize as u32);
            write_u32(fixture.first(), CUR_NEXT, fixture.second() as usize as u32);
            write_u32(fixture.first(), CUR_BTREE, fixture.btree() as usize as u32);
            write_u32(fixture.first(), CUR_PAGE, fixture.page() as usize as u32);
            *fixture.first().add(CUR_E_STATE) = CURSOR_VALID;
            *fixture.page().add(PAGE_INT_KEY) = 1;

            write_u32(fixture.second(), CUR_BTREE, 0x1234_5678);
            write_u32(fixture.second(), CUR_PAGE, fixture.page() as usize as u32);
            *fixture.second().add(CUR_E_STATE) = CURSOR_VALID;

            assert_eq!(btree_save_all_cursors(fixture.btree(), fixture.btree(), core::ptr::null_mut()), 0);
            assert_eq!(*fixture.first().add(CUR_E_STATE), CURSOR_REQUIRESEEK);
            assert_eq!(read_u32(fixture.first(), CUR_PAGE), 0);
            assert_eq!(*fixture.second().add(CUR_E_STATE), CURSOR_VALID);
        }
    }

    #[test]
    fn fault_from_key_size_stops_walk_and_clears_current_overflow_cache() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            write_u32(fixture.btree(), BTREE_CURSOR_LIST, fixture.first() as usize as u32);
            write_u32(fixture.first(), CUR_NEXT, fixture.second() as usize as u32);
            *fixture.first().add(CUR_E_STATE) = 3;
            write_u32(fixture.first(), 0x50, (-19i32) as u32);
            write_u32(fixture.first(), CUR_OVERFLOW_CACHE, 0);
            *fixture.second().add(CUR_E_STATE) = CURSOR_VALID;

            assert_eq!(btree_save_all_cursors(fixture.btree(), core::ptr::null_mut(), core::ptr::null_mut()), -19);
            assert_eq!(read_u32(fixture.first(), CUR_OVERFLOW_CACHE), 0);
            assert_eq!(*fixture.second().add(CUR_E_STATE), CURSOR_VALID);
        }
    }
}
