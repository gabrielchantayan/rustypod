//! Descend a SQLite b-tree cursor to its leftmost leaf.
//!
//! `btree_move_to_leftmost` — original: `FUN_082d9a34` @ 0x082d9a34 (96
//! bytes, `0x082d9a34..0x082d9a94`). Raw ARM words establish the next real
//! function boundary at 0x082d9a94. The body has two unconditional `bl`
//! instructions: `load_be32` @ 0x0837a158 and `btree_move_to_child` @
//! 0x082d99d0; there are no predicated `bl` instructions.
//!
//! Starting at `cursor.pPage`, an internal page reads its first big-endian
//! cell offset and then its child page number, descending through
//! `btree_move_to_child` until it reaches a leaf. A child-move error is
//! returned unchanged. Deliberate deviation: none; target pointer fields stay
//! `u32` words on host fixtures.

use crate::sqlite::move_to_child::btree_move_to_child;
use crate::util::beload::load_be32;

const CUR_PAGE: usize = 0x18;
const PAGE_FLAGS: usize = 0x04;
const PAGE_HEADER_OFFSET: usize = 0x08;
const PAGE_N_CELL: usize = 0x14;
const PAGE_DATA: usize = 0x44;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

/// `btree_move_to_leftmost` — original: `FUN_082d9a34` @ 0x082d9a34 (96
/// bytes; two verified unconditional outbound `bl` calls, no predicated calls).
///
/// Move `cursor` to its leftmost leaf. The retail function assumes valid
/// target-layout cursor and page pointers; an error from moving to a child is
/// returned unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_move_to_leftmost(cursor: *mut u8) -> i32 {
    loop {
        let page = read_u32(cursor, CUR_PAGE) as usize as *mut u8;
        if page.add(PAGE_FLAGS).read() != 0 {
            return 0;
        }

        let data = read_u32(page, PAGE_DATA) as usize as *const u8;
        let cell_offset = u16::from_be(data.add(page.add(PAGE_HEADER_OFFSET).read() as usize).cast::<u16>().read()) as usize;
        let child_page = load_be32(data.add(cell_offset));
        let status = btree_move_to_child(cursor, child_page);
        if status != 0 {
            return status;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::move_to_root::{BtreeMoveToRootOps, BTREE_MOVE_TO_ROOT_OPS, BTREE_MOVE_TO_ROOT_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0;
    const BTREE: usize = 0x100;
    const INTERNAL: usize = 0x200;
    const LEAF: usize = 0x400;
    const DATA: usize = 0x600;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::BTREE_MOVE_TO_LEFTMOST, SLAB_LEN).map(|p| p as usize));
    static CHILD: AtomicU32 = AtomicU32::new(0);
    static REQUESTED_PAGE: AtomicU32 = AtomicU32::new(0);
    static RESULT: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn get_page(_shared: u32, page: u32, out: *mut u32, _flags: u32) -> i32 {
        REQUESTED_PAGE.store(page, Ordering::Relaxed);
        out.write(CHILD.load(Ordering::Relaxed));
        RESULT.load(Ordering::Relaxed)
    }

    struct OpsGuard(BtreeMoveToRootOps);
    impl Drop for OpsGuard {
        fn drop(&mut self) { unsafe { BTREE_MOVE_TO_ROOT_OPS = self.0 }; }
    }

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        let cursor = base.add(CURSOR);
        let btree = base.add(BTREE);
        let internal = base.add(INTERNAL);
        let leaf = base.add(LEAF);
        cursor.add(0).cast::<u32>().write((btree as usize as u32).to_le());
        btree.add(4).cast::<u32>().write(0x1234_5678u32.to_le());
        cursor.add(CUR_PAGE).cast::<u32>().write((internal as usize as u32).to_le());
        Some((cursor, internal, leaf, base.add(DATA)))
    }

    #[test]
    fn leaf_returns_without_reading_cell_data() {
        let Some((cursor, page, _, _)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture(module_path!())); return };
        unsafe {
            page.add(PAGE_FLAGS).write(1);
            assert_eq!(btree_move_to_leftmost(cursor), 0);
            assert_eq!(read_u32(cursor, CUR_PAGE), page as usize as u32);
        }
    }

    #[test]
    fn internal_page_uses_first_cell_child_then_reaches_leaf() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let old = unsafe { BTREE_MOVE_TO_ROOT_OPS };
        let _ops = OpsGuard(old);
        unsafe { BTREE_MOVE_TO_ROOT_OPS = BtreeMoveToRootOps { get_and_init_page: get_page }; }
        let Some((cursor, internal, leaf, data)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture(module_path!())); return };
        unsafe {
            internal.add(PAGE_DATA).cast::<u32>().write((data as usize as u32).to_le());
            data.copy_from_nonoverlapping([0, 12].as_ptr(), 2);
            data.add(12).copy_from_nonoverlapping([0, 0, 0, 41].as_ptr(), 4);
            leaf.add(PAGE_FLAGS).write(1);
            leaf.add(PAGE_N_CELL).cast::<u16>().write(1);
            CHILD.store(leaf as usize as u32, Ordering::Relaxed);
            RESULT.store(0, Ordering::Relaxed);
            assert_eq!(btree_move_to_leftmost(cursor), 0);
            assert_eq!(REQUESTED_PAGE.load(Ordering::Relaxed), 41);
            assert_eq!(read_u32(cursor, CUR_PAGE), leaf as usize as u32);
        }
    }

    #[test]
    fn child_move_error_is_returned_unchanged() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let old = unsafe { BTREE_MOVE_TO_ROOT_OPS };
        let _ops = OpsGuard(old);
        unsafe { BTREE_MOVE_TO_ROOT_OPS = BtreeMoveToRootOps { get_and_init_page: get_page }; }
        let Some((cursor, internal, _, data)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture(module_path!())); return };
        unsafe {
            internal.add(PAGE_DATA).cast::<u32>().write((data as usize as u32).to_le());
            data.copy_from_nonoverlapping([0, 8].as_ptr(), 2);
            data.add(8).copy_from_nonoverlapping([0, 0, 0, 9].as_ptr(), 4);
            CHILD.store(0, Ordering::Relaxed);
            RESULT.store(-7, Ordering::Relaxed);
            assert_eq!(btree_move_to_leftmost(cursor), -7);
            assert_eq!(REQUESTED_PAGE.load(Ordering::Relaxed), 9);
            assert_eq!(read_u32(cursor, CUR_PAGE), internal as usize as u32);
        }
    }
}
