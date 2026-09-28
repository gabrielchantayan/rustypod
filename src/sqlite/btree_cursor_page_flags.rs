//! Read the current SQLite B-tree page's type flags.
//!
//! `btree_cursor_page_flags` — original: `FUN_08371300` @ 0x08371300
//! (48 bytes, extent 0x08371300..0x08371330; zero plain and one predicated
//! outbound `blcs` to `btree_restore_cursor_position` @ 0x08372ae0).
//! Whole-image ARM decoding finds two inbound plain `bl` calls (0x08388e10,
//! no predicated callers.
//!
//! SQLite's internal page-type accessor restores REQUIRESEEK and FAULT
//! cursors, deliberately discards that restore result, then returns zero for
//! a null current page or `pPage->aData[pPage->hdrOffset]` otherwise. The
//! callers use the result as the b-tree page-type byte (`PTF_*`).
//!
//! Deliberate deviation: target pointer fields are loaded as little-endian
//! `u32` words, rather than host pointers, so the BtCursor and MemPage
//! offsets remain faithful on 64-bit test hosts.

use crate::sqlite::restore_cursor_position::btree_restore_cursor_position;

const CUR_P_PAGE: usize = 0x18;
const CUR_E_STATE: usize = 0x43;
const PAGE_HDR_OFFSET: usize = 0x08;
const PAGE_DATA: usize = 0x44;
const CURSOR_REQUIRESEEK: u8 = 2;

#[inline(always)]
unsafe fn rd_u32(base: *const u8, off: usize) -> u32 {
    u32::from_le(base.add(off).cast::<u32>().read_unaligned())
}

/// `btree_cursor_page_flags` — original: `FUN_08371300` @ 0x08371300
/// (48 bytes; two verified plain inbound `bl` calls and one outbound `blcs`).
///
/// Return the current page's type byte, or zero when there is no current page.
/// REQUIRESEEK and FAULT cursors are first passed to
/// `btree_restore_cursor_position`; as in retailOS, its result is ignored.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_cursor_page_flags(cursor: *mut u8) -> u8 {
    if *cursor.add(CUR_E_STATE) >= CURSOR_REQUIRESEEK {
        btree_restore_cursor_position(cursor);
    }

    let page = rd_u32(cursor, CUR_P_PAGE) as usize as *const u8;
    if page.is_null() {
        0
    } else {
        let data = rd_u32(page, PAGE_DATA) as usize as *const u8;
        *data.add(*page.add(PAGE_HDR_OFFSET) as usize)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x400;
    const CURSOR: usize = 0;
    const PAGE: usize = 0x100;
    const DATA: usize = 0x200;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_CURSOR_PAGE_FLAGS, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u8> {
        let base = *SLAB.as_ref()? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        Some(base)
    }

    #[test]
    fn null_current_page_returns_zero() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_cursor_page_flags"));
            return;
        };
        unsafe {
            assert_eq!(btree_cursor_page_flags(base.add(CURSOR)), 0);
        }
    }

    #[test]
    fn returns_page_type_at_header_offset() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_cursor_page_flags"));
            return;
        };
        unsafe {
            let cursor = base.add(CURSOR);
            let page = base.add(PAGE);
            let data = base.add(DATA);
            cursor.add(CUR_P_PAGE).cast::<u32>().write((page as usize) as u32);
            page.add(PAGE_DATA).cast::<u32>().write((data as usize) as u32);
            *page.add(PAGE_HDR_OFFSET) = 7;
            *data.add(7) = 0x0d;
            assert_eq!(btree_cursor_page_flags(cursor), 0x0d);
        }
    }

    #[test]
    fn header_offset_zero_reads_first_page_data_byte() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_cursor_page_flags"));
            return;
        };
        unsafe {
            let cursor = base.add(CURSOR);
            let page = base.add(PAGE);
            let data = base.add(DATA);
            cursor.add(CUR_P_PAGE).cast::<u32>().write((page as usize) as u32);
            page.add(PAGE_DATA).cast::<u32>().write((data as usize) as u32);
            *data = 0x02;
            assert_eq!(btree_cursor_page_flags(cursor), 0x02);
        }
    }
}
