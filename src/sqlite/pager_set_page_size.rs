//! SQLite pager page-size selection — `sqlite3PagerSetPagesize` from pager.c.
//!
//! `pager_set_page_size` — original: `FUN_0837ebf8` @ `0x0837ebf8` (144
//! bytes; 5 direct plain-`bl` call sites, binary-scanned).
//!
//! The raw ARM body spans `0x0837ebf8..0x0837ec88`; the next separately
//! linked function starts at `0x0837ec88`. It accepts a requested u16 page
//! size. A zero request is a query. A different nonzero request is installed
//! only before the pager becomes a memory database or gains pages: it first
//! allocates replacement temporary space, takes the pager activity lease,
//! resets the cache, updates the page size and sector geometry, replaces the
//! old temporary space, then releases the lease. Allocation failure returns
//! `SQLITE_NOMEM` (7), while all other paths return `SQLITE_OK` (0).
//!
//! Deliberate deviation: the file sector-size virtual dispatch remains
//! retailOS-owned at `0x0837dbc0`; `pager_set_sector_size` contains the
//! target-layout Pager update and uses a private host callback for that
//! unported callee.

use crate::cxx::context_activity::context_activity_enter;
use crate::heap::tracked::tracked_free;
use super::mem::sqlite3_malloc;
use super::pager_reset::pager_reset;
use super::pager_set_sector_size::pager_set_sector_size;

/// Target-layout byte offset of `Pager.pageSize`.
const PAGE_SIZE: usize = 0x40;
/// Target-layout byte offset of `Pager.memDb`.
const MEMORY_DATABASE: usize = 0x14;
/// Target-layout byte offset of `Pager.dbSize`.
const DATABASE_SIZE: usize = 0x48;
/// Target-layout byte offset of `Pager.nRef`, used as the activity lease.
const ACTIVITY: usize = 0xe0;
/// Target-layout byte offset of `Pager.pTmpSpace`.
const TEMPORARY_SPACE: usize = 0xe4;

const SQLITE_OK: u32 = 0;
const SQLITE_NOMEM: u32 = 7;


/// `pager_set_page_size` — original: `FUN_0837ebf8` @ `0x0837ebf8` (144
/// bytes; 5 direct plain-`bl` call sites).
///
/// Returns the installed `Pager.pageSize` through `page_size`. A zero request,
/// an unchanged request, a memory pager, or a pager with nonzero `dbSize`
/// leaves the state untouched. Otherwise replaces `pTmpSpace` only after its
/// requested-size allocation succeeds. The activity lease is balanced around
/// every state-changing path.
///
/// # Safety
/// `pager` must name a writable target-layout Pager through `+0xe4`, and
/// `page_size` must be a writable aligned u16. If replacement is permitted,
/// pager reset and the retail sector-size helper must accept `pager`, and the
/// old `pTmpSpace` word must be NULL or a tracked allocation payload.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_set_page_size")]
#[inline(never)]
pub unsafe extern "C" fn pager_set_page_size(pager: *mut u8, page_size: *mut u16) -> u32 {
    let requested_size = page_size.read();
    let current_size = pager.add(PAGE_SIZE).cast::<u32>().read();
    let mut status = SQLITE_OK;

    if requested_size != 0 && current_size != requested_size as u32
        && pager.add(MEMORY_DATABASE).read() == 0
        && pager.add(DATABASE_SIZE).cast::<u32>().read() == 0
    {
        let replacement = sqlite3_malloc(requested_size as i32);
        if replacement.is_null() {
            status = SQLITE_NOMEM;
        } else {
            context_activity_enter(pager);
            pager_reset(pager);
            pager.add(PAGE_SIZE).cast::<u32>().write(requested_size as u32);
            pager_set_sector_size(pager);
            tracked_free(pager.add(TEMPORARY_SPACE).cast::<u32>().read() as usize as *mut u8);
            pager.add(TEMPORARY_SPACE).cast::<u32>().write(replacement as usize as u32);

            let activity = pager.add(ACTIVITY).cast::<u32>();
            activity.write_volatile(activity.read_volatile().wrapping_sub(1));
        }
    }

    page_size.write(pager.add(PAGE_SIZE).cast::<u32>().read() as u16);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::{
        tracked::ALLOC_STATS,
        veneers::tests::{alloc_log, mock_heap, set_alloc_ret},
    };
    use crate::sqlite::mem;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};


    static mut SECTOR_PAGE_SIZE: u32 = 0;
    static mut SECTOR_COUNT: u32 = 0;

    unsafe extern "C" fn recording_set_sector_size(pager: *mut u8) -> u32 {
        SECTOR_COUNT = SECTOR_COUNT.wrapping_add(1);
        SECTOR_PAGE_SIZE = pager.add(PAGE_SIZE).cast::<u32>().read();
        512
    }


    #[test]
    fn pager_set_page_size_queries_gates_failure_and_replacement_order() {
        const FIXTURE_LEN: usize = 0x1000;
        const ALLOCATION_OFFSET: usize = 0x800;

        let Some(base) = try_map_u32_slab(hints::SQLITE_PAGER_SET_PAGE_SIZE, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let _allocator_guard = mem::tests::OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_guard = mock_heap();

        unsafe {
            ALLOC_STATS.soft_limit_callback = 0;
            ALLOC_STATS.current_bytes = 0;
            ALLOC_STATS.peak_bytes = 0;
            set_alloc_ret(core::ptr::null_mut());
            super::super::pager_set_sector_size::set_file_sector_size_for_test(recording_set_sector_size);
            SECTOR_PAGE_SIZE = 0;
            SECTOR_COUNT = 0;

            let pager = base.cast::<u8>();
            pager.add(PAGE_SIZE).cast::<u32>().write(512);
            let mut requested = 0u16;

            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_OK);
            assert_eq!(requested, 512, "zero request queries the installed size");
            assert_eq!(alloc_log().0, 0);

            requested = 1024;
            pager.add(MEMORY_DATABASE).write(1);
            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_OK);
            assert_eq!(requested, 512);
            pager.add(MEMORY_DATABASE).write(0);
            requested = 1024;

            pager.add(DATABASE_SIZE).cast::<u32>().write(1);
            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_OK);
            assert_eq!(requested, 512);
            pager.add(DATABASE_SIZE).cast::<u32>().write(0);
            requested = 1024;
            assert_eq!(alloc_log().0, 0, "gated paths never allocate");

            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_NOMEM);
            assert_eq!(requested, 512, "OOM reports the previous page size");
            assert_eq!(alloc_log().0, 2, "sqlite3_malloc retries once after raw OOM");
            assert_eq!(SECTOR_COUNT, 0, "OOM does not update sector geometry");
            requested = 1024;

            set_alloc_ret(base.add(ALLOCATION_OFFSET));
            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_OK);
            assert_eq!(requested, 1024);
            assert_eq!(alloc_log(), (3, 1024 + 44, 57));
            assert_eq!(SECTOR_COUNT, 1);
            assert_eq!(SECTOR_PAGE_SIZE, 1024, "sector setup sees the new page size");
            assert_eq!(pager.add(PAGE_SIZE).cast::<u32>().read(), 1024);
            assert_eq!(
                pager.add(TEMPORARY_SPACE).cast::<u32>().read(),
                base.add(ALLOCATION_OFFSET + 0x20) as usize as u32,
            );
            assert_eq!(pager.add(ACTIVITY).cast::<u32>().read_volatile(), 0, "activity lease balances");

            requested = 1024;
            assert_eq!(pager_set_page_size(pager, &mut requested), SQLITE_OK);
            assert_eq!(SECTOR_COUNT, 1);

            super::super::pager_set_sector_size::set_file_sector_size_for_test(
                super::super::pager_set_sector_size::unavailable_file_sector_size,
            );
        }
    }
}
