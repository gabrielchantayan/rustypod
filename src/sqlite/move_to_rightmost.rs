//! Descend a SQLite b-tree cursor to its rightmost leaf.
//!
//! `btree_move_to_rightmost` — original: `FUN_082d9a94` @ 0x082d9a94 (108
//! bytes, `0x082d9a94..0x082d9b00`). Raw ARM words establish the next real
//! function boundary at 0x082d9b00 and two outbound unconditional `bl`
//! instructions: `load_be32` @ 0x0837a158 and `btree_move_to_child` @
//! 0x082d99d0. There are no predicated `bl` instructions; raw whole-image
//! call decoding finds two unconditional inbound `bl` call sites.
//!
//! Starting at `cursor.pPage`, an internal page selects its big-endian
//! right-child page number and descends through `btree_move_to_child`. A leaf
//! selects its final cell and invalidates the cached CellInfo. Deliberate
//! deviation: none; retail discards a child-move error and returns zero, as
//! does this port. Target pointer fields remain u32 words on host fixtures.

use crate::sqlite::move_to_child::btree_move_to_child;
use crate::util::beload::load_be32;

const CUR_PAGE: usize = 0x18;
const CUR_INDEX: usize = 0x1c;
const CUR_INFO_N_SIZE: usize = 0x3e;
const CUR_VALID_N_KEY: usize = 0x42;
const PAGE_FLAGS: usize = 0x04;
const PAGE_HEADER_OFFSET: usize = 0x08;
const PAGE_N_CELL: usize = 0x14;
const PAGE_DATA: usize = 0x44;

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

/// `btree_move_to_rightmost` — original: `FUN_082d9a94` @ 0x082d9a94 (108
/// bytes; two verified unconditional inbound `bl` call sites, no predicated
/// calls).
///
/// Move `cursor` to the final cell of its rightmost leaf. The retail function
/// assumes valid target-layout cursor and page pointers. Its zero return does
/// not report an error from the attempted child move.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_move_to_rightmost(cursor: *mut u8) -> i32 {
    loop {
        let page = read_u32(cursor, CUR_PAGE) as usize as *mut u8;
        if page.add(PAGE_FLAGS).read() != 0 {
            write_u32(cursor, CUR_INDEX, read_u16(page, PAGE_N_CELL).wrapping_sub(1) as u32);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(0);
            cursor.add(CUR_VALID_N_KEY).write(0);
            return 0;
        }

        let data = read_u32(page, PAGE_DATA) as usize as *const u8;
        let child_page = load_be32(data.add(page.add(PAGE_HEADER_OFFSET).read() as usize + 8));
        write_u32(cursor, CUR_INDEX, read_u16(page, PAGE_N_CELL) as u32);
        if btree_move_to_child(cursor, child_page) != 0 {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::move_to_root::{BtreeMoveToRootOps, BTREE_MOVE_TO_ROOT_OPS, BTREE_MOVE_TO_ROOT_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CURSOR: usize = 0;
    const BTREE: usize = 0x100;
    const INTERNAL: usize = 0x200;
    const LEAF: usize = 0x400;
    const DATA: usize = 0x600;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::BTREE_MOVE_TO_RIGHTMOST, SLAB_LEN).map(|p| p as usize));
    static CHILD: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn get_page(_shared: u32, _page: u32, out: *mut u32, _flags: u32) -> i32 {
        out.write(CHILD.load(Ordering::Relaxed));
        0
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
        write_u32(cursor, 0, btree as usize as u32);
        write_u32(btree, 4, 0x1234_5678);
        write_u32(cursor, CUR_PAGE, internal as usize as u32);
        Some((cursor, internal, leaf, base.add(DATA)))
    }

    #[test]
    fn leaf_selects_last_cell_and_invalidates_cached_info() {
        let Some((cursor, page, _, _)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture(module_path!())); return };
        unsafe {
            page.add(PAGE_FLAGS).write(1);
            page.add(PAGE_N_CELL).cast::<u16>().write(3);
            cursor.add(CUR_INFO_N_SIZE).cast::<u16>().write(9);
            cursor.add(CUR_VALID_N_KEY).write(1);
            assert_eq!(btree_move_to_rightmost(cursor), 0);
            assert_eq!(read_u32(cursor, CUR_INDEX), 2);
            assert_eq!(cursor.add(CUR_INFO_N_SIZE).cast::<u16>().read(), 0);
            assert_eq!(cursor.add(CUR_VALID_N_KEY).read(), 0);
        }
    }

    #[test]
    fn internal_page_uses_right_child_then_selects_leaf_tail() {
        let _lock = BTREE_MOVE_TO_ROOT_TEST_LOCK.lock();
        let old = unsafe { BTREE_MOVE_TO_ROOT_OPS };
        let _ops = OpsGuard(old);
        unsafe { BTREE_MOVE_TO_ROOT_OPS = BtreeMoveToRootOps { get_and_init_page: get_page }; }
        let Some((cursor, internal, leaf, data)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture(module_path!())); return };
        unsafe {
            internal.add(PAGE_N_CELL).cast::<u16>().write(2);
            write_u32(internal, PAGE_DATA, data as usize as u32);
            data.add(8).copy_from_nonoverlapping([0, 0, 0, 41].as_ptr(), 4);
            leaf.add(PAGE_FLAGS).write(1);
            leaf.add(PAGE_N_CELL).cast::<u16>().write(4);
            CHILD.store(leaf as usize as u32, Ordering::Relaxed);
            assert_eq!(btree_move_to_rightmost(cursor), 0);
            assert_eq!(read_u32(cursor, CUR_PAGE), leaf as usize as u32);
            assert_eq!(read_u32(cursor, CUR_INDEX), 3);
        }
    }
}
