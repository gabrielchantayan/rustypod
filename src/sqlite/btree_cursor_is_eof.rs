//! Test whether a SQLite B-tree cursor is at end of its current page.
//!
//! `btree_cursor_is_eof` — retailOS `FUN_08371bfc` @ `0x08371bfc` (68 bytes,
//! `0x08371bfc..0x08371c3f`; the next separately linked function begins at
//! `0x08371c40`). Raw ARM decoding finds no outbound `bl`, predicated or plain.
//! Whole-image decoding finds two inbound plain `bl` calls (0x08372348 and
//! 0x083729d4), and no predicated callers.
//!
//! SQLite's `sqlite3BtreeEof`: a missing current-page record is EOF; pages
//! with more than one cell are not. For zero- or one-cell pages, the firmware
//! checks the two-byte cell marker at current-cell offsets +3 and +4. Target
//! pointers remain little-endian u32 words; host fixtures map below 4 GiB.

const CURSOR_CURRENT_PAGE: usize = 0x50;
const PAGE_CELL_COUNT: usize = 0x4c;
const PAGE_CELL_DATA: usize = 0x44;
const PAGE_CELL_OFFSET: usize = 0x08;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

/// `sqlite3BtreeEof` — original: `FUN_08371bfc` @ `0x08371bfc` (68 bytes;
/// two verified plain inbound `bl` calls, no outbound calls).
///
/// Return one when `cursor` has no current page, or when its zero- or
/// one-cell page's current-cell marker is clear; otherwise return zero. The
/// cursor and its current page must be target-aligned and live when non-null.
/// There are no deliberate behavioral deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_cursor_is_eof(cursor: *const u8) -> u32 {
    let page = read_u32(cursor, CURSOR_CURRENT_PAGE) as usize as *const u8;
    if page.is_null() {
        return 1;
    }
    if read_u32(page, PAGE_CELL_COUNT) > 1 {
        return 0;
    }

    let cell = (read_u32(page, PAGE_CELL_DATA) as usize as *const u8).add(*page.add(PAGE_CELL_OFFSET) as usize);
    if *cell.add(3) | *cell.add(4) == 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::{LazyLock, MutexGuard};

    const SLAB_LEN: usize = 0x400;
    const CURSOR: usize = 0;
    const PAGE: usize = 0x100;
    const CELL_DATA: usize = 0x180;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_CURSOR_IS_EOF, SLAB_LEN).map(|pointer| pointer as usize)
    });

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        cursor: *mut u8,
        page: *mut u8,
        cell_data: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let Some(base) = *SLAB else {
                return None;
            };
            unsafe {
                let base = base as *mut u8;
                base.write_bytes(0, SLAB_LEN);
                let cursor = base.add(CURSOR);
                let page = base.add(PAGE);
                let cell_data = base.add(CELL_DATA);
                cursor.add(CURSOR_CURRENT_PAGE).cast::<u32>().write(page as usize as u32);
                page.add(PAGE_CELL_DATA).cast::<u32>().write(cell_data as usize as u32);
                Some(Self { _guard: guard, cursor, page, cell_data })
            }
        }
    }

    #[test]
    fn missing_current_page_is_eof() {
        let Some(fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            fixture.cursor.add(CURSOR_CURRENT_PAGE).cast::<u32>().write(0);
            assert_eq!(btree_cursor_is_eof(fixture.cursor), 1);
        }
    }

    #[test]
    fn multi_cell_page_is_not_eof_without_cell_read() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            fixture.page.add(PAGE_CELL_COUNT).cast::<u32>().write(2);
            assert_eq!(btree_cursor_is_eof(fixture.cursor), 0);
        }
    }

    #[test]
    fn zero_and_one_cell_pages_use_both_marker_bytes() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            *fixture.page.add(PAGE_CELL_OFFSET) = 0;
            assert_eq!(read_u32(fixture.page, PAGE_CELL_DATA), fixture.cell_data as usize as u32);
            for count in [0_u32, 1] {
                fixture.page.add(PAGE_CELL_COUNT).cast::<u32>().write(count);
                *fixture.cell_data.add(3) = 0;
                *fixture.cell_data.add(4) = 0;
                assert_eq!(btree_cursor_is_eof(fixture.cursor), 1);
                *fixture.cell_data.add(3) = 1;
                assert_eq!(btree_cursor_is_eof(fixture.cursor), 0);
                *fixture.cell_data.add(3) = 0;
                *fixture.cell_data.add(4) = 1;
                assert_eq!(btree_cursor_is_eof(fixture.cursor), 0);
            }
        }
    }
}
