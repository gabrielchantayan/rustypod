//! Release the overflow cells associated with a SQLite B-tree page.
//!
//! `clear_page_overflow_cells` — retailOS `FUN_08367a64` at load address
//! `0x08367a64` (168 bytes, `0x08367a64..0x08367b0c`). Raw words establish
//! that `push {r4-r7,lr}` at `0x08367b0c` begins the next separately linked
//! function. A whole-image ARM branch scan finds three inbound plain `bl`
//! calls (0x082b67c8, 0x082b67e4, and 0x082b6b68) and no predicated calls;
//! this body has four outbound plain `bl` instructions (two each to
//! `load_be32` and `clear_overflow_cell`) and no predicated calls.
//!
//! For a non-leaf page, visit every big-endian cell offset, then its right-child
//! pointer, and release each cell's overflow chain. The page's overflow count
//! is cleared only after every release succeeds. Deliberate deviation:
//! `clear_overflow_cell` (`FUN_08367b0c`) is unported, so target builds call it
//! directly while host tests use a dispatch seam.

use crate::util::beload::load_be32;

const CLEAR_OVERFLOW_CELL_ADDRESS: usize = 0x0836_7b0c;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_overflow_cell(shared: u32, cell: u32, page: *mut u8, index: i32) -> i32 {
    let callee: unsafe extern "C" fn(u32, u32, *mut u8, i32) -> i32 =
        core::mem::transmute(CLEAR_OVERFLOW_CELL_ADDRESS);
    callee(shared, cell, page, index)
}

#[cfg(not(target_os = "none"))]
type ClearOverflowCell = unsafe extern "C" fn(u32, u32, *mut u8, i32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_clear_overflow_cell(
    _shared: u32,
    _cell: u32,
    _page: *mut u8,
    _index: i32,
) -> i32 {
    11
}

#[cfg(not(target_os = "none"))]
static mut CLEAR_OVERFLOW_CELL: ClearOverflowCell = unavailable_clear_overflow_cell;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn clear_overflow_cell(shared: u32, cell: u32, page: *mut u8, index: i32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CLEAR_OVERFLOW_CELL))(shared, cell, page, index)
}

/// `clearDatabasePage` cell-release loop — retailOS `FUN_08367a64` @
/// `0x08367a64` (168 bytes; three inbound plain-`bl` calls, no predicated
/// calls).
///
/// `page` must point to a target-layout `MemPage`; its data and shared-object
/// pointers are stored as target-width `u32` words. The unported release
/// helper receives the page's shared word, each resolved cell, the page, and
/// its zero-based cell index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clear_page_overflow_cells(page: *mut u8) -> i32 {
    if page.add(4).read() != 0 {
        return 0;
    }

    let shared = page.add(0x40).cast::<u32>().read();
    let data = page.add(0x44).cast::<u32>().read() as usize as *mut u8;
    let count = page.add(0x14).cast::<u16>().read() as i32;
    let cell_offset = page.add(0x0e).cast::<u16>().read() as usize;
    let mut index = 0;
    while index < count {
        let cell_offset = u16::from_be_bytes([data.add(cell_offset + index as usize * 2).read(),
            data.add(cell_offset + index as usize * 2 + 1).read()]) as usize;
        let result = clear_overflow_cell(shared, load_be32(data.add(cell_offset)), page, index);
        if result != 0 {
            return result;
        }
        index += 1;
    }

    let result = clear_overflow_cell(shared, load_be32(data.add(data.add(8).read() as usize)), page, index);
    page.add(1).write_volatile(0);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_CLEAR_PAGE_OVERFLOW_CELLS, SLAB_LEN).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32, usize, i32); 4] = [(0, 0, 0, 0); 4];
    static mut CALL_COUNT: usize = 0;
    static mut RESULT: i32 = 0;

    unsafe extern "C" fn record(shared: u32, cell: u32, page: *mut u8, index: i32) -> i32 {
        CALLS[CALL_COUNT] = (shared, cell, page as usize, index);
        CALL_COUNT += 1;
        RESULT
    }

    struct Fixture { _guard: MutexGuard<'static, ()>, page: [u8; 0x48], data: *mut u8 }
    impl Fixture {
        fn new() -> Option<Self> {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let Some(data) = (*SLAB).map(|p| p as *mut u8) else {
                note_missing_u32_fixture("sqlite::clear_page_overflow_cells_tests");
                return None;
            };
            unsafe {
                core::ptr::write_bytes(data, 0, SLAB_LEN);
                CLEAR_OVERFLOW_CELL = record;
                CALL_COUNT = 0;
                RESULT = 0;
            }
            Some(Self { _guard: guard, page: [0; 0x48], data })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { unsafe { CLEAR_OVERFLOW_CELL = unavailable_clear_overflow_cell; } }
    }
    #[test]
    fn leaf_page_skips_the_release_helper() {
        let mut fixture = Fixture::new().unwrap();
        fixture.page[4] = 1;
        fixture.page[1] = 9;
        unsafe { assert_eq!(clear_page_overflow_cells(fixture.page.as_mut_ptr()), 0); }
        assert_eq!(unsafe { CALL_COUNT }, 0);
        assert_eq!(fixture.page[1], 9);
    }

    #[test]
    fn releases_each_cell_then_the_right_child_and_clears_overflow_count() {
        let mut fixture = Fixture::new().unwrap();
        unsafe {
            fixture.page.as_mut_ptr().add(0x40).cast::<u32>().write(0x1234_5678);
            fixture.page.as_mut_ptr().add(0x44).cast::<u32>().write(fixture.data as u32);
            fixture.page.as_mut_ptr().add(0x0e).cast::<u16>().write(0x20);
            fixture.page.as_mut_ptr().add(0x14).cast::<u16>().write(2);
            fixture.page[1] = 7;
            fixture.data.add(8).write(0x60);
            fixture.data.add(0x20).write(0); fixture.data.add(0x21).write(0x30);
            fixture.data.add(0x22).write(0); fixture.data.add(0x23).write(0x48);
            fixture.data.add(0x30).cast::<u32>().write(u32::to_be(0x1020_3040));
            fixture.data.add(0x48).cast::<u32>().write(u32::to_be(0x5060_7080));
            fixture.data.add(0x60).cast::<u32>().write(u32::to_be(0x90a0_b0c0));
            assert_eq!(clear_page_overflow_cells(fixture.page.as_mut_ptr()), 0);
            assert_eq!(CALL_COUNT, 3);
            assert_eq!(CALLS[0], (0x1234_5678, 0x1020_3040, fixture.page.as_mut_ptr() as usize, 0));
            assert_eq!(CALLS[1], (0x1234_5678, 0x5060_7080, fixture.page.as_mut_ptr() as usize, 1));
            assert_eq!(CALLS[2], (0x1234_5678, 0x90a0_b0c0, fixture.page.as_mut_ptr() as usize, 2));
        }
        assert_eq!(fixture.page[1], 0);
    }

    #[test]
    fn release_error_stops_before_resetting_overflow_count() {
        let mut fixture = Fixture::new().unwrap();
        unsafe {
            fixture.page.as_mut_ptr().add(0x40).cast::<u32>().write(1);
            fixture.page.as_mut_ptr().add(0x44).cast::<u32>().write(fixture.data as u32);
            fixture.page.as_mut_ptr().add(0x0e).cast::<u16>().write(0x20);
            fixture.page.as_mut_ptr().add(0x14).cast::<u16>().write(1);
            fixture.page[1] = 5;
            fixture.data.add(0x20).write(0); fixture.data.add(0x21).write(0x30);
            RESULT = 9;
            assert_eq!(clear_page_overflow_cells(fixture.page.as_mut_ptr()), 9);
            assert_eq!(CALL_COUNT, 1);
        }
        assert_eq!(fixture.page[1], 5);
    }
}
