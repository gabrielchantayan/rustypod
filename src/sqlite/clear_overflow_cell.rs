//! Release a SQLite B-tree cell's overflow chain.
//!
//! `clear_overflow_cell` — retailOS `FUN_082c3454` at load address
//! `0x082c3454` (212 bytes, `0x082c3454..0x082c3528`). Raw ARM words put the
//! next independently entered function at `0x082c3528`. A whole-image branch
//! scan finds three inbound plain `bl` sites (0x082c35f8, 0x08370fec, and
//! 0x08371778), no predicated inbound `bl`; this body makes seven plain
//! outbound `bl` instructions and no predicated calls.
//!
//! SQLite's `clearCell`: parse the cell, calculate its overflow-page count,
//! reject zero/out-of-range page numbers, then resolve, free, and release each
//! overflow page in order. Deliberate host-only deviation: the three unported
//! SQLite services and the C++ release method use a private dispatch table;
//! target builds retain their verified absolute/direct call boundaries.

use crate::runtime::rt_div::__rt_udiv;
use crate::cxx::release::release_object;
use crate::sqlite::parse_cell::btree_parse_cell_ptr;
use crate::util::beload::load_be32;

const MP_BT: usize = 0x40;
const BT_USABLE_SIZE: usize = 0x1e;
const PAGE_COUNT: usize = 0x0837_e7ac;
const GET_OVERFLOW_PAGE: usize = 0x082d_0838;
const FREE_PAGE: usize = 0x082c_f41c;
const SQLITE_CORRUPT: i32 = 11;
const CELL_INFO_SIZE: usize = 0x20;
const CI_N_PAYLOAD: usize = 0x14;
const CI_N_LOCAL: usize = 0x1a;
const CI_I_OVERFLOW: usize = 0x1c;
const PAGE_OBJECT: usize = 0x48;

type PageCount = unsafe extern "C" fn(u32) -> u32;
type GetOverflowPage = unsafe extern "C" fn(u32, u32, *mut u32, *mut u32) -> i32;
type FreePage = unsafe extern "C" fn(*mut u8) -> i32;
type ReleasePage = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_page_count(pager: u32) -> u32 {
    core::mem::transmute::<usize, PageCount>(PAGE_COUNT)(pager)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn get_overflow_page(shared: u32, page_no: u32, next: *mut u32, page: *mut u32) -> i32 {
    core::mem::transmute::<usize, GetOverflowPage>(GET_OVERFLOW_PAGE)(shared, page_no, next, page)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn free_page(page: *mut u8) -> i32 { core::mem::transmute::<usize, FreePage>(FREE_PAGE)(page) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_page(page: *mut u8) { release_object(page.add(PAGE_OBJECT).cast::<u32>().read() as usize as *mut u8); }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_page_count(_: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_get_overflow_page(_: u32, _: u32, _: *mut u32, _: *mut u32) -> i32 { SQLITE_CORRUPT }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_free_page(_: *mut u8) -> i32 { SQLITE_CORRUPT }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release_page(_: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ClearCellOps { page_count: PageCount, get_overflow_page: GetOverflowPage, free_page: FreePage, release_page: ReleasePage }
#[cfg(not(target_os = "none"))]
static mut CLEAR_CELL_OPS: ClearCellOps = ClearCellOps { page_count: unavailable_page_count, get_overflow_page: unavailable_get_overflow_page, free_page: unavailable_free_page, release_page: unavailable_release_page };

/// `sqlite3BtreeClearCell` — retailOS `FUN_082c3454` @ `0x082c3454` (212
/// bytes; three inbound plain-`bl` calls, no predicated inbound `bl`).
///
/// `page` is a target-layout `MemPage` and `cell` names one of its cells. The
/// page, shared B-tree, and resolved overflow-page pointers are 32-bit words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clear_overflow_cell(page: *mut u8, cell: *const u8) -> i32 {
    let mut info = [0u8; CELL_INFO_SIZE];
    btree_parse_cell_ptr(page, cell, info.as_mut_ptr());
    let overflow_offset = info.as_ptr().add(CI_I_OVERFLOW).cast::<u16>().read_unaligned() as usize;
    if overflow_offset == 0 { return 0; }
    let shared = page.add(MP_BT).cast::<u32>().read_unaligned();
    let usable_size = (shared as usize as *const u8).add(BT_USABLE_SIZE).cast::<u16>().read_unaligned() as u32;
    let payload = info.as_ptr().add(CI_N_PAYLOAD).cast::<u32>().read_unaligned();
    let local = info.as_ptr().add(CI_N_LOCAL).cast::<u16>().read_unaligned() as u32;
    let mut remaining = __rt_udiv(payload.wrapping_sub(local).wrapping_add(usable_size).wrapping_sub(5), usable_size.wrapping_sub(4));
    let mut page_no = load_be32(cell.add(overflow_offset));
    while remaining != 0 {
        if page_no == 0 { return SQLITE_CORRUPT; }
        #[cfg(target_os = "none")]
        let page_count = pager_page_count((shared as usize as *const u32).read_unaligned());
        #[cfg(not(target_os = "none"))]
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(CLEAR_CELL_OPS));
        #[cfg(not(target_os = "none"))]
        let page_count = (ops.page_count)((shared as usize as *const u32).read_unaligned());
        if page_no > page_count { return SQLITE_CORRUPT; }
        let mut resolved = 0u32;
        #[cfg(target_os = "none")]
        let rc = get_overflow_page(shared, page_no, &mut page_no, &mut resolved);
        #[cfg(not(target_os = "none"))]
        let rc = (ops.get_overflow_page)(shared, page_no, &mut page_no, &mut resolved);
        if rc != 0 { return rc; }
        #[cfg(target_os = "none")]
        let rc = free_page(resolved as usize as *mut u8);
        #[cfg(not(target_os = "none"))]
        let rc = (ops.free_page)(resolved as usize as *mut u8);
        if rc != 0 { return rc; }
        #[cfg(target_os = "none")]
        release_page(resolved as usize as *mut u8);
        #[cfg(not(target_os = "none"))]
        (ops.release_page)(resolved as usize as *mut u8);
        remaining -= 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::SQLITE_CLEAR_OVERFLOW_CELL, 0x1000).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    static mut NEXT: u32 = 0;
    static mut FREE_RC: i32 = 0;

    unsafe extern "C" fn page_count(_: u32) -> u32 { CALLS.lock().push("count"); 9 }
    unsafe extern "C" fn get(_: u32, _: u32, next: *mut u32, out: *mut u32) -> i32 { CALLS.lock().push("get"); *next = NEXT; *out = 0x1000; 0 }
    unsafe extern "C" fn free(_: *mut u8) -> i32 { CALLS.lock().push("free"); FREE_RC }
    unsafe extern "C" fn release(_: *mut u8) { CALLS.lock().push("release"); }

    unsafe fn setup() -> Option<(*mut u8, *mut u8)> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, 0x1000);
        let page = base;
        let shared = base.add(0x100);
        page.add(MP_BT).cast::<u32>().write(shared as u32);
        shared.add(BT_USABLE_SIZE).cast::<u16>().write(8);
        page.add(3).write(1); page.add(7).write(1); page.add(9).write(0);
        page.add(10).cast::<u16>().write(0); page.add(12).cast::<u16>().write(0);
        let cell = base.add(0x200);
        cell.write(5); cell.add(1).write(0); cell.add(2).copy_from_nonoverlapping([0, 0, 0, 1].as_ptr(), 4);
        Some((page, cell))
    }
    unsafe fn install() { CLEAR_CELL_OPS = ClearCellOps { page_count, get_overflow_page: get, free_page: free, release_page: release }; }
    #[test]
    fn releases_every_overflow_page_in_order() { let _lock = LOCK.lock(); unsafe { let Some((page, cell)) = setup() else { assert!(note_missing_u32_fixture("sqlite/clear_overflow_cell")); return; }; install(); NEXT = 2; CALLS.lock().clear(); assert_eq!(clear_overflow_cell(page, cell), 0); assert_eq!(*CALLS.lock(), ["count", "get", "free", "release", "count", "get", "free", "release"]); } }
    #[test]
    fn rejects_zero_page_before_services() { let _lock = LOCK.lock(); unsafe { let Some((page, cell)) = setup() else { return; }; install(); cell.add(2).write_bytes(0, 4); CALLS.lock().clear(); assert_eq!(clear_overflow_cell(page, cell), SQLITE_CORRUPT); assert!(CALLS.lock().is_empty()); } }
    #[test]
    fn releases_resolved_page_after_free_error_only_on_success() { let _lock = LOCK.lock(); unsafe { let Some((page, cell)) = setup() else { return; }; install(); NEXT = 0; FREE_RC = 7; CALLS.lock().clear(); assert_eq!(clear_overflow_cell(page, cell), 7); assert_eq!(*CALLS.lock(), ["count", "get", "free"]); FREE_RC = 0; } }
}
