//! SQLite pager pending-page reader — `FUN_082ddc7c` @ **0x082ddc7c**
//! (**56 bytes**, `0x082ddc7c..0x082ddcb0`; the next separately linked
//! function begins with `push {r1,r2,r3,r4,r5,r6,r7,lr}` at `0x082ddcb4`).
//!
//! Whole-image A32 decoding finds three inbound plain `bl` instructions
//! (0x082dd24c, 0x082de98c, and 0x0837e1e4), no predicated `bl` instructions,
//! and no tail branches. The body makes one plain `bl`, to the unported
//! `pager_read_db_page` at 0x083655cc.
//!
//! # Algorithm
//!
//! When the `PgHdr.needRead` byte at +0x20 is nonzero, call
//! `pager_read_db_page(page->pPager, page, page->pgno)`. Propagate a nonzero
//! status without changing the byte; on success, clear it and return zero. A
//! clear byte returns zero without calling the helper.
//!
//! # Deliberate deviations
//!
//! `pager_read_db_page` is not yet ported. Target builds call its verified
//! retailOS address; host builds use a volatile ABI seam. Page pointer fields
//! remain target-width `u32` words, avoiding host pointer-width layout drift.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_PAGER_READ_DB_PAGE: usize = 0x0836_55cc;
const PAGE_PAGER: usize = 0x00 / 4;
const PAGE_NUMBER: usize = 0x04 / 4;
const PAGE_NEEDS_READ: usize = 0x20;

/// ABI of SQLite's unported `readDbPage` helper at 0x083655cc.
pub type PagerReadDbPage = unsafe extern "C" fn(u32, *mut u32, u32) -> i32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct PagerReadPendingOps {
    pub read_db_page: PagerReadDbPage,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pager_read_db_page(_pager: u32, _page: *mut u32, _page_number: u32) -> i32 {
    panic!("install pager pending-read host operations before reading a pending page")
}

/// Host seam for the unported SQLite `readDbPage` helper.
#[cfg(not(target_os = "none"))]
pub static mut PAGER_READ_PENDING_OPS: PagerReadPendingOps = PagerReadPendingOps {
    read_db_page: missing_pager_read_db_page,
};

#[inline(always)]
unsafe fn pager_read_db_page(pager: u32, page: *mut u32, page_number: u32) -> i32 {
    #[cfg(target_os = "none")]
    {
        let helper: PagerReadDbPage = unsafe { core::mem::transmute(RETAIL_PAGER_READ_DB_PAGE) };
        return unsafe { helper(pager, page, page_number) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(PAGER_READ_PENDING_OPS.read_db_page)) };
        unsafe { helper(pager, page, page_number) }
    }
}

/// Reads a pending pager page and clears its `needRead` byte only on success.
///
/// # Safety
///
/// `page` must point to a writable target-layout `PgHdr`; when `needRead` is
/// nonzero, its `pPager` and `pgno` fields must satisfy `readDbPage`'s ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_read_pending")]
pub unsafe extern "C" fn pager_read_pending(page: *mut u32) -> i32 {
    if unsafe { page.cast::<u8>().add(PAGE_NEEDS_READ).read() } == 0 {
        return 0;
    }

    let status = unsafe { pager_read_db_page(page.add(PAGE_PAGER).read(), page, page.add(PAGE_NUMBER).read()) };
    if status == 0 {
        unsafe { page.cast::<u8>().add(PAGE_NEEDS_READ).write(0) };
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static PAGE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_PAGER_READ_PENDING, 0x1000).map(|p| p as usize)
    });
    static mut CALL: Option<(u32, u32, u32)> = None;
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn record_read_db_page(pager: u32, page: *mut u32, page_number: u32) -> i32 {
        unsafe { CALL = Some((pager, page as usize as u32, page_number)) };
        unsafe { STATUS }
    }

    #[test]
    fn clean_page_skips_the_helper() {
        let _guard = LOCK.lock();
        let Some(base) = *PAGE else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let page = base as *mut u32;
        unsafe { page.write_bytes(0, 0x1000 / 4); CALL = None };
        assert_eq!(unsafe { pager_read_pending(page) }, 0);
        assert_eq!(unsafe { CALL }, None);
        assert_eq!(unsafe { page.cast::<u8>().add(PAGE_NEEDS_READ).read() }, 0);
    }

    #[test]
    fn successful_read_forwards_target_words_and_clears_need_read() {
        let _guard = LOCK.lock();
        let Some(base) = *PAGE else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let page = base as *mut u32;
        unsafe {
            page.write_bytes(0, 0x1000 / 4);
            page.add(PAGE_PAGER).write(0x1234_5678);
            page.add(PAGE_NUMBER).write(0x42);
            page.cast::<u8>().add(PAGE_NEEDS_READ).write(7);
            PAGER_READ_PENDING_OPS.read_db_page = record_read_db_page;
            CALL = None;
            STATUS = 0;
        }
        assert_eq!(unsafe { pager_read_pending(page) }, 0);
        assert_eq!(unsafe { CALL }, Some((0x1234_5678, page as usize as u32, 0x42)));
        assert_eq!(unsafe { page.cast::<u8>().add(PAGE_NEEDS_READ).read() }, 0);
    }

    #[test]
    fn failed_read_preserves_need_read() {
        let _guard = LOCK.lock();
        let Some(base) = *PAGE else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let page = base as *mut u32;
        unsafe {
            page.write_bytes(0, 0x1000 / 4);
            page.cast::<u8>().add(PAGE_NEEDS_READ).write(0xff);
            PAGER_READ_PENDING_OPS.read_db_page = record_read_db_page;
            STATUS = -10;
        }
        assert_eq!(unsafe { pager_read_pending(page) }, -10);
        assert_eq!(unsafe { page.cast::<u8>().add(PAGE_NEEDS_READ).read() }, 0xff);
    }
}
