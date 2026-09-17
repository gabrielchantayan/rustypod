//! Move a SQLite b-tree cursor into a child page.
//!
//! `btree_move_to_child` — original: `FUN_082d99d0` @ 0x082d99d0 (100
//! bytes, `0x082d99d0..0x082d9a34`). Decoding every ARM `B`/`BL` word in
//! `osos.dec` finds six inbound direct calls, all unconditional `bl` at
//! 0x082d9a74, 0x082d9ac4, 0x082d9bd4, 0x083721d4, 0x0837232c, and
//! 0x083729bc; there are no predicated calls or incoming tail `b` branches.
//!
//! It acquires `child_page` through the cursor's BtreeShared, passes the
//! current page as the acquisition flags argument, then copies the cursor
//! index into the new page's parent-cell field. It clears byte `+1` in the
//! old page before releasing it, installs the replacement, resets the
//! cursor's per-cell cache, and returns `SQLITE_CORRUPT` (11) for an empty
//! replacement page.
//!
//! Deliberate deviation: `getAndInitPage` @ 0x082d05d0 remains unported and
//! is reached through the existing `BTREE_MOVE_TO_ROOT_OPS` volatile seam.
//! `release_via_field_0x48` @ 0x0836761c is a direct ported callee. All
//! cursor and page pointers are target-width `u32` words.

use crate::cxx::release::release_via_field_0x48;
use crate::sqlite::move_to_root::get_and_init_page;

const CUR_BTREE: usize = 0x00;
const CUR_PAGE: usize = 0x18;
const CUR_INDEX: usize = 0x1c;
const CUR_INFO_N_SIZE: usize = 0x3e;
const CUR_VALID_N_KEY: usize = 0x42;
const BTREE_SHARED: usize = 0x04;
const PAGE_PARENT_INDEX: usize = 0x10;
const PAGE_N_CELL: usize = 0x14;
const SQLITE_CORRUPT: i32 = 11;

#[inline(always)]
unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    u16::from_le(base.add(offset).cast::<u16>().read())
}

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

#[inline(always)]
unsafe fn write_u32(base: *mut u8, offset: usize, value: u32) {
    base.add(offset).cast::<u32>().write(value.to_le());
}

/// `btree_move_to_child` — original: `FUN_082d99d0` @ 0x082d99d0 (100
/// bytes; six verified inbound unconditional `bl` call sites).
///
/// Install an acquired child page in `cursor`. The retail routine has no
/// NULL checks: cursor, Btree, and current page must satisfy target-layout
/// pointer contracts. It intentionally passes the current page word as both
/// the output seed and fourth acquisition argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_move_to_child(cursor: *mut u8, child_page: u32) -> i32 {
    let btree = read_u32(cursor, CUR_BTREE) as usize as *const u8;
    let shared = read_u32(btree, BTREE_SHARED);
    let old_page_word = read_u32(cursor, CUR_PAGE);
    let mut new_page_word = old_page_word;
    let rc = get_and_init_page(shared, child_page, &mut new_page_word, old_page_word);
    if rc != 0 {
        return rc;
    }

    let new_page = new_page_word as usize as *mut u8;
    new_page.add(PAGE_PARENT_INDEX).cast::<u16>().write(read_u32(cursor, CUR_INDEX) as u16);
    let old_page = old_page_word as usize as *mut u8;
    old_page.add(1).write(0);
    release_via_field_0x48(old_page);
    write_u32(cursor, CUR_PAGE, new_page_word);
    write_u32(cursor, CUR_INDEX, 0);
    cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(0);
    cursor.add(CUR_VALID_N_KEY).write(0);

    if read_u16(new_page, PAGE_N_CELL) == 0 {
        SQLITE_CORRUPT
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::move_to_root::{BtreeMoveToRootOps, BTREE_MOVE_TO_ROOT_OPS, BTREE_MOVE_TO_ROOT_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0x000;
    const BTREE: usize = 0x100;
    const OLD_PAGE: usize = 0x200;
    const NEW_PAGE: usize = 0x400;
    const SHARED: u32 = 0x1357_9bdf;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_MOVE_TO_CHILD, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static MOCK: Mutex<Mock> = Mutex::new(Mock { events: Vec::new(), result: 0, replacement: 0 });

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct GetEvent {
        shared: u32,
        page: u32,
        flags: u32,
    }

    struct Mock {
        events: Vec<GetEvent>,
        result: i32,
        replacement: u32,
    }


    unsafe extern "C" fn mock_get_and_init_page(shared: u32, page: u32, out: *mut u32, flags: u32) -> i32 {
        let mut mock = MOCK.lock();
        mock.events.push(GetEvent { shared, page, flags });
        if mock.result == 0 {
            out.write(mock.replacement);
        }
        mock.result
    }

    struct OpsGuard(BtreeMoveToRootOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { BTREE_MOVE_TO_ROOT_OPS = self.0 };
        }
    }

    unsafe fn install_mock() -> OpsGuard {
        let old = BTREE_MOVE_TO_ROOT_OPS;
        BTREE_MOVE_TO_ROOT_OPS = BtreeMoveToRootOps {
            get_and_init_page: mock_get_and_init_page,
        };
        OpsGuard(old)
    }

    unsafe fn fixture() -> Option<*mut u8> {
        let Some(base) = *SLAB else {
            return None;
        };
        let base = base as *mut u8;
        if base.is_null() {
            return None;
        }
        base.write_bytes(0, SLAB_LEN);
        let cursor = base.add(CURSOR);
        let btree = base.add(BTREE);
        write_u32(cursor, CUR_BTREE, btree as usize as u32);
        write_u32(btree, BTREE_SHARED, SHARED);
        Some(cursor)
    }

    unsafe fn page(cursor: *mut u8, offset: usize, n_cell: u16) -> *mut u8 {
        let page = cursor.add(offset);
        page.add(PAGE_N_CELL).cast::<u16>().write(n_cell);
        page
    }

    fn reset_mock() {
        let mut mock = MOCK.lock();
        mock.events.clear();
        mock.result = 0;
        mock.replacement = 0;
    }

    #[test]
    fn lookup_failure_preserves_cursor_and_old_page() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mock() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let old = page(cursor, OLD_PAGE, 3);
            old.add(1).write(0xa5);
            write_u32(cursor, CUR_PAGE, old as usize as u32);
            write_u32(cursor, CUR_INDEX, 0xface_beef);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(19);
            cursor.add(CUR_VALID_N_KEY).write(1);
            MOCK.lock().result = 7;

            assert_eq!(btree_move_to_child(cursor, 0x1020_3040), 7);
            assert_eq!(read_u32(cursor, CUR_PAGE), old as usize as u32);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0xface_beef);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 19);
            assert_eq!(cursor.add(CUR_VALID_N_KEY).read(), 1);
            assert_eq!(old.add(1).read(), 0xa5);
        }
        assert_eq!(MOCK.lock().events, vec![GetEvent {
            shared: SHARED,
            page: 0x1020_3040,
            flags: unsafe { read_u32(cursor, CUR_PAGE) },
        }]);
    }

    #[test]
    fn successful_lookup_installs_page_and_clears_cell_cache() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mock() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let old = page(cursor, OLD_PAGE, 2);
            let new = page(cursor, NEW_PAGE, 4);
            old.add(1).write(0xa5);
            write_u32(cursor, CUR_PAGE, old as usize as u32);
            write_u32(cursor, CUR_INDEX, 0xface_beef);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(19);
            cursor.add(CUR_VALID_N_KEY).write(1);
            cursor.add(0x41).write(1);
            cursor.add(0x43).write(2);
            MOCK.lock().replacement = new as usize as u32;

            assert_eq!(btree_move_to_child(cursor, 17), 0);
            assert_eq!(read_u32(cursor, CUR_PAGE), new as usize as u32);
            assert_eq!(new.add(PAGE_PARENT_INDEX).cast::<u16>().read(), 0xbeef);
            assert_eq!(old.add(1).read(), 0);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 0);
            assert_eq!(cursor.add(CUR_VALID_N_KEY).read(), 0);
            assert_eq!(cursor.add(0x41).read(), 1);
            assert_eq!(cursor.add(0x43).read(), 2);
        }
    }

    #[test]
    fn empty_replacement_returns_sqlite_corrupt_after_installing_it() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mock() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let old = page(cursor, OLD_PAGE, 1);
            let new = page(cursor, NEW_PAGE, 0);
            write_u32(cursor, CUR_PAGE, old as usize as u32);
            MOCK.lock().replacement = new as usize as u32;

            assert_eq!(btree_move_to_child(cursor, 42), SQLITE_CORRUPT);
            assert_eq!(read_u32(cursor, CUR_PAGE), new as usize as u32);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0);
        }
    }
}
