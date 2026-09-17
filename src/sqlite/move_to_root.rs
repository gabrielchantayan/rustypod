//! Positioning a SQLite b-tree cursor at its root page.
//!
//! `btree_move_to_root` — original: `FUN_082d9b00` @ 0x082d9b00 (248
//! bytes, `0x082d9b00..0x082d9bf4`; Ghidra's 220-byte extent stops before
//! the final `pop`). Decoding every ARM `B`/`BL` word in `osos.dec` finds
//! six inbound direct calls: three unconditional `bl` at 0x08371d40,
//! 0x08371ed4, and 0x08389b84; two caller-gated `bleq` at 0x08371180 and
//! 0x083717f8; and one caller-gated `blne` at 0x082c2920. There is no
//! incoming tail `b` and no data word holding this address. The predicated
//! calls are gated by their callers' cursor state.
//!
//! This is SQLite 3.5.x's `moveToRoot`: faulted cursors return their saved
//! error, and seek-required cursors are first cleared. It then obtains the
//! cursor's root page when the current page is absent or has another page
//! number, releases the old page, clears per-cell cache state, and descends
//! through the first child of an empty page only when the raw flag at
//! `MemPage + 0x04` is zero. The final state is VALID exactly when the
//! current page's `nCell` halfword at `+0x14` is nonzero.
//!
//! Deliberate deviation: `getAndInitPage` @ 0x082d05d0 remains unported and
//! uses a volatile dispatch boundary. Existing ports
//! `btree_clear_cursor` @ 0x082c3528, `release_via_field_0x48` @ 0x0836761c,
//! `load_be32` @ 0x0837a158, and `btree_move_to_child` @ 0x082d99d0 are
//! direct calls. Cursor, Btree, and MemPage pointer fields remain target
//! `u32` words so their ARM offsets do not widen on a 64-bit host.

use crate::cxx::release::release_via_field_0x48;
use crate::util::beload::load_be32;
use crate::sqlite::move_to_child::btree_move_to_child;
use crate::sqlite::btree_clear_cursor::btree_clear_cursor;

const CUR_BTREE: usize = 0x00;
const CUR_ROOT_PAGE: usize = 0x14;
const CUR_PAGE: usize = 0x18;
const CUR_INDEX: usize = 0x1c;
const CUR_INFO_N_SIZE: usize = 0x3e;
const CUR_AT_LAST: usize = 0x41;
const CUR_VALID_N_KEY: usize = 0x42;
const CUR_E_STATE: usize = 0x43;
const CUR_SAVED_RC: usize = 0x50;
const BTREE_SHARED: usize = 0x04;
const PAGE_DESCENT_FLAG: usize = 0x04;
const PAGE_N_CELL: usize = 0x14;
const PAGE_NUMBER: usize = 0x4c;
const PAGE_DATA: usize = 0x44;
const PAGE_HEADER_OFFSET: usize = 0x08;
const CURSOR_INVALID: u8 = 0;
const CURSOR_VALID: u8 = 1;
const CURSOR_REQUIRESEEK: u8 = 2;
const CURSOR_FAULT: u8 = 3;

pub type GetAndInitPageFn = unsafe extern "C" fn(shared: u32, page_number: u32, page_out: *mut u32, flags: u32) -> i32;

/// Unported calls reached by the b-tree cursor movement ports.
#[derive(Clone, Copy)]
pub struct BtreeMoveToRootOps {
    pub get_and_init_page: GetAndInitPageFn,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_get_and_init_page(shared: u32, page_number: u32, page_out: *mut u32, flags: u32) -> i32 {
    crate::sqlite::get_and_init_page::get_and_init_page(
        shared as usize as *mut u8, page_number, page_out, flags,
    ) as i32
}


unsafe extern "C" fn missing_get_and_init_page(_shared: u32, _page_number: u32, _page_out: *mut u32, _flags: u32) -> i32 {
    panic!("btree_move_to_root requires getAndInitPage @ 0x082d05d0")
}


#[cfg(target_os = "none")]
pub const DEFAULT_BTREE_MOVE_TO_ROOT_OPS: BtreeMoveToRootOps = BtreeMoveToRootOps {
    get_and_init_page: retail_get_and_init_page,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_BTREE_MOVE_TO_ROOT_OPS: BtreeMoveToRootOps = BtreeMoveToRootOps {
    get_and_init_page: missing_get_and_init_page,
};

/// Active dispatch boundary for the still-stock page acquisition service.
pub static mut BTREE_MOVE_TO_ROOT_OPS: BtreeMoveToRootOps = DEFAULT_BTREE_MOVE_TO_ROOT_OPS;

#[inline(always)]
unsafe fn move_to_root_ops() -> BtreeMoveToRootOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_MOVE_TO_ROOT_OPS))
}

#[inline(always)]
pub(crate) unsafe fn get_and_init_page(shared: u32, page_number: u32, page_out: *mut u32, flags: u32) -> i32 {
    (move_to_root_ops().get_and_init_page)(shared, page_number, page_out, flags)
}
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

#[cfg(test)]
pub(crate) static BTREE_MOVE_TO_ROOT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// `btree_move_to_root` — original: `FUN_082d9b00` @ 0x082d9b00 (248 bytes;
/// six verified inbound direct call sites: three `bl`, two caller-gated
/// `bleq`, and one caller-gated `blne`).
///
/// SQLite's `moveToRoot`: position `cursor` at its root, or return the saved
/// fault/error result. The function has no NULL checks; `cursor`, its Btree,
/// and every selected page must satisfy the target-layout pointer contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_move_to_root(cursor: *mut u8) -> i32 {
    let state = cursor.add(CUR_E_STATE).read();
    if state >= CURSOR_REQUIRESEEK {
        if state == CURSOR_FAULT {
            return read_u32(cursor, CUR_SAVED_RC) as i32;
        }
        btree_clear_cursor(cursor);
    }

    let root_page = read_u32(cursor, CUR_ROOT_PAGE);
    let mut page = read_u32(cursor, CUR_PAGE) as usize as *mut u8;
    if page.is_null() || read_u32(page, PAGE_NUMBER) != root_page {
        let btree = read_u32(cursor, CUR_BTREE) as usize as *const u8;
        let shared = read_u32(btree, BTREE_SHARED);
        let mut replacement = page as usize as u32;
        let rc = get_and_init_page(shared, root_page, &mut replacement, 0);
        if rc != 0 {
            cursor.add(CUR_E_STATE).write(CURSOR_INVALID);
            return rc;
        }
        release_via_field_0x48(page);
        page = replacement as usize as *mut u8;
        write_u32(cursor, CUR_PAGE, replacement);
    }

    write_u32(cursor, CUR_INDEX, 0);
    cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(0);
    cursor.add(CUR_AT_LAST).write(0);
    cursor.add(CUR_VALID_N_KEY).write(0);

    let mut rc = 0;
    if read_u16(page, PAGE_N_CELL) == 0 && page.add(PAGE_DESCENT_FLAG).read() == 0 {
        let data = read_u32(page, PAGE_DATA) as usize as *const u8;
        let header_offset = page.add(PAGE_HEADER_OFFSET).read() as usize;
        let child_page = load_be32(data.add(header_offset + 8));
        cursor.add(CUR_E_STATE).write(CURSOR_VALID);
        rc = btree_move_to_child(cursor, child_page);
    }

    let current_page = read_u32(cursor, CUR_PAGE) as usize as *const u8;
    cursor.add(CUR_E_STATE).write(if read_u16(current_page, PAGE_N_CELL) != 0 {
        CURSOR_VALID
    } else {
        CURSOR_INVALID
    });
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0x000;
    const BTREE: usize = 0x100;
    const OLD_PAGE: usize = 0x200;
    const NEW_PAGE: usize = 0x300;
    const CHILD_PAGE: usize = 0x400;
    const PAGE_DATA_OFFSET: usize = 0x600;
    const SHARED: u32 = 0x2468_ace0;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_MOVE_TO_ROOT, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        events: Vec::new(),
        get_result: 0,
        replacement: 0,
        child_request: 0,
        child_replacement: 0,
    });

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Get { shared: u32, page: u32, flags: u32 },
    }

    struct Mock {
        events: Vec<Event>,
        get_result: i32,
        replacement: u32,
        child_request: u32,
        child_replacement: u32,
    }


    unsafe extern "C" fn mock_get_and_init_page(shared: u32, page: u32, out: *mut u32, flags: u32) -> i32 {
        let mut mock = MOCK.lock();
        mock.events.push(Event::Get { shared, page, flags });
        if mock.get_result == 0 {
            out.write(if page == mock.child_request {
                mock.child_replacement
            } else {
                mock.replacement
            });
        }
        mock.get_result
    }

    struct OpsGuard(BtreeMoveToRootOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { BTREE_MOVE_TO_ROOT_OPS = self.0 };
        }
    }

    unsafe fn install_mocks() -> OpsGuard {
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

    unsafe fn page(cursor: *mut u8, offset: usize, number: u32, n_cell: u16, descent_flag: u8) -> *mut u8 {
        let page = cursor.add(offset);
        write_u32(page, PAGE_NUMBER, number);
        page.add(PAGE_N_CELL).cast::<u16>().write(n_cell);
        page.add(PAGE_DESCENT_FLAG).write(descent_flag);
        page
    }

    fn reset_mock() {
        let mut mock = MOCK.lock();
        mock.events.clear();
        mock.get_result = 0;
        mock.replacement = 0;
        mock.child_request = 0;
        mock.child_replacement = 0;
    }

    fn events() -> Vec<Event> {
        MOCK.lock().events.clone()
    }

    #[test]
    fn fault_cursor_returns_saved_error_without_observing_state() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mocks() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            cursor.add(CUR_E_STATE).write(CURSOR_FAULT);
            write_u32(cursor, CUR_SAVED_RC, (-17i32) as u32);
            write_u32(cursor, CUR_INDEX, 0xfeed_beef);
            assert_eq!(btree_move_to_root(cursor), -17);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0xfeed_beef);
            assert_eq!(cursor.add(CUR_E_STATE).read(), CURSOR_FAULT);
        }
        assert!(events().is_empty());
    }

    #[test]
    fn seek_required_cursor_is_cleared_then_revalidated_on_its_root() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mocks() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let root = page(cursor, OLD_PAGE, 7, 2, 1);
            write_u32(cursor, CUR_ROOT_PAGE, 7);
            write_u32(cursor, CUR_PAGE, root as usize as u32);
            write_u32(cursor, CUR_INDEX, 3);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(12);
            cursor.add(CUR_AT_LAST).write(1);
            cursor.add(CUR_VALID_N_KEY).write(1);
            cursor.add(CUR_E_STATE).write(CURSOR_REQUIRESEEK);
            assert_eq!(btree_move_to_root(cursor), 0);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 0);
            assert_eq!(cursor.add(CUR_AT_LAST).read(), 0);
            assert_eq!(cursor.add(CUR_VALID_N_KEY).read(), 0);
            assert_eq!(cursor.add(CUR_E_STATE).read(), CURSOR_VALID);
        }
        assert!(events().is_empty());
    }

    #[test]
    fn page_acquisition_failure_invalidates_without_clearing_cell_cache() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mocks() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let old = page(cursor, OLD_PAGE, 4, 2, 1);
            write_u32(cursor, CUR_ROOT_PAGE, 9);
            write_u32(cursor, CUR_PAGE, old as usize as u32);
            write_u32(cursor, CUR_INDEX, 6);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(13);
            cursor.add(CUR_E_STATE).write(CURSOR_VALID);
            MOCK.lock().get_result = 5;
            assert_eq!(btree_move_to_root(cursor), 5);
            assert_eq!(cursor.add(CUR_E_STATE).read(), CURSOR_INVALID);
            assert_eq!(read_u32(cursor, CUR_INDEX), 6);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 13);
        }
        assert_eq!(events(), vec![Event::Get { shared: SHARED, page: 9, flags: 0 }]);
    }

    #[test]
    fn empty_root_acquisition_descends_to_its_big_endian_first_child() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mocks() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let expected_child_flags = unsafe { cursor.add(NEW_PAGE) as usize as u32 };
        unsafe {
            let old = page(cursor, OLD_PAGE, 4, 1, 1);
            let new = page(cursor, NEW_PAGE, 9, 0, 0);
            let child = page(cursor, CHILD_PAGE, 10, 3, 1);
            let data = cursor.add(PAGE_DATA_OFFSET);
            write_u32(new, PAGE_DATA, data as usize as u32);
            data.add(8).copy_from_nonoverlapping([0x12, 0x34, 0x56, 0x78].as_ptr(), 4);
            write_u32(cursor, CUR_ROOT_PAGE, 9);
            write_u32(cursor, CUR_PAGE, old as usize as u32);
            MOCK.lock().replacement = new as usize as u32;
            MOCK.lock().child_replacement = child as usize as u32;
            MOCK.lock().child_request = 0x1234_5678;
            assert_eq!(btree_move_to_root(cursor), 0);
            assert_eq!(read_u32(cursor, CUR_PAGE), child as usize as u32);
            assert_eq!(cursor.add(CUR_E_STATE).read(), CURSOR_VALID);
        }
        assert_eq!(
            events(),
            vec![
                Event::Get { shared: SHARED, page: 9, flags: 0 },
                Event::Get { shared: SHARED, page: 0x1234_5678, flags: expected_child_flags },
            ]
        );
    }

    #[test]
    fn empty_root_with_set_raw_flag_stays_invalid_without_descending() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let _ops = unsafe { install_mocks() };
        reset_mock();
        let Some(cursor) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let root = page(cursor, OLD_PAGE, 9, 0, 1);
            write_u32(cursor, CUR_ROOT_PAGE, 9);
            write_u32(cursor, CUR_PAGE, root as usize as u32);
            write_u32(cursor, CUR_INDEX, 2);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(1);
            assert_eq!(btree_move_to_root(cursor), 0);
            assert_eq!(cursor.add(CUR_E_STATE).read(), CURSOR_INVALID);
            assert_eq!(read_u32(cursor, CUR_INDEX), 0);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 0);
        }
        assert!(events().is_empty());
    }
}
