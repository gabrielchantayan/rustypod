//! btree_allocate_temp_space — original: `FUN_082b3b34` @ 0x082b3b34.
//!
//! True extent: 0x082b3b34..0x082b3b5c (40 bytes), ending in pop {r4,pc};
//! the next function starts with push {r4-r8,lr}. Raw-word scan verifies two
//! incoming plain BL calls (0x083710b8, 0x083716c4), no predicated BL calls.
//! The body has one plain BL to sqlite3_malloc @ 0x08390b14 and no predicated BL.
//!
//! SQLite's allocateTempSpace: retain an existing BtShared.pTmpSpace;
//! otherwise allocate pageSize - 8 bytes and store the result, including NULL.
//! Failure leaves the cache empty so a later invocation retries. The unsigned
//! halfword page size is promoted before subtraction, so sizes below eight
//! produce negative allocation requests rather than wrapping at 16 bits.
//!
//! Deliberate deviations: reuse the repr(C) BtreeShared layout, whose pointer
//! fields widen on hosts; malloc uses the existing DB_MEM_OPS dispatch seam,
//! wired to the ported sqlite3_malloc, rather than the firmware BL address.

use super::btree_set_page_size::BtreeShared;
use super::mem::db_malloc_op;

/// Lazily installs the shared B-tree's temporary cell-construction buffer.
///
/// # Safety
/// `shared` must be a valid, exclusively accessible BtreeShared. Any existing
/// temporary allocation remains owned by the caller; this function never frees it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_allocate_temp_space(shared: *mut BtreeShared) {
    if !(*shared).tmp_space.is_null() {
        return;
    }
    (*shared).tmp_space = (db_malloc_op())((*shared).page_size as i32 - 8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log, REALLOC_RESULT};

    fn shared(page_size: u16) -> BtreeShared {
        BtreeShared {
            pager: core::ptr::null_mut(),
            _reserved0: [0; 0x11],
            read_only: 0,
            _reserved1: [0; 6],
            page_size,
            usable_size: 123,
            _reserved2: [0; 0x40],
            tmp_space: core::ptr::null_mut(),
        }
    }

    #[test]
    fn caches_success_without_replacing_existing_space() {
        let mut buffer = [0xa5; 504];
        let _guard = install_recorder(buffer.as_mut_ptr());
        let mut shared = shared(512);
        unsafe { btree_allocate_temp_space(&mut shared) };
        assert_eq!(shared.tmp_space, buffer.as_mut_ptr());
        shared.page_size = 4096;
        unsafe { btree_allocate_temp_space(&mut shared) };
        assert_eq!(shared.tmp_space, buffer.as_mut_ptr());
        assert_eq!(realloc_log(), std::vec![(0, 504)]);
        assert_eq!(shared.usable_size, 123);
        assert_eq!(buffer, [0xa5; 504], "allocation is not zero-filled");
    }

    #[test]
    fn failure_leaves_null_and_next_invocation_retries() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut shared = shared(512);
        unsafe { btree_allocate_temp_space(&mut shared) };
        assert!(shared.tmp_space.is_null());
        let mut buffer = [0u8; 504];
        unsafe {
            REALLOC_RESULT = buffer.as_mut_ptr();
            btree_allocate_temp_space(&mut shared);
        }
        assert_eq!(shared.tmp_space, buffer.as_mut_ptr());
        assert_eq!(realloc_log(), std::vec![(0, 504), (0, 504)]);
    }

    #[test]
    fn halfword_page_size_is_promoted_before_subtraction() {
        let _guard = install_recorder(core::ptr::null_mut());
        for size in [0, 7, 8, 9, 0x8000, 0xffff] {
            let mut shared = shared(size);
            unsafe { btree_allocate_temp_space(&mut shared) };
            assert!(shared.tmp_space.is_null());
        }
        assert_eq!(realloc_log(), std::vec![
            (0, -8), (0, -1), (0, 0), (0, 1), (0, 32760), (0, 65527),
        ]);
    }
}
