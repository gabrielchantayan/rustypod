//! SQLite pager `dontWrite` transition — `FUN_0837e118` @ 0x0837e118 (116
//! bytes, `0x0837e118..0x0837e18b`).
//!
//! Raw A32 decoding establishes the following sibling at 0x0837e18c and two
//! body calls: plain `bl` to `context_activity_enter` (0x082dd3d8) and plain
//! `bl` to the still-retail `pager_remove_from_journal` (0x082d906c). The
//! whole image has two inbound plain `bl` sites (0x082bd6e0, 0x082cf4d0) and
//! no inbound predicated `bl` sites.
//!
//! Algorithm: memory pagers are untouched. Otherwise take the pager activity
//! lease, mark the page's `alwaysRollback` byte, and remove an in-journal page
//! from the journal list when the pager's journal gate is clear and its exact
//! page-number/original-size predicate permits it. Release the activity lease
//! on every non-memory path.
//!
//! Deliberate deviation: `pager_remove_from_journal` is unported. Target
//! builds call its verified fixed address; host tests inject a recording seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const PAGER_MEMORY_DATABASE: usize = 0x14;
const PAGER_JOURNAL_GATE: usize = 0x09;
const PAGER_DATABASE_SIZE: usize = 0x24 / 4;
const PAGER_ORIGINAL_DATABASE_SIZE: usize = 0x28 / 4;
const PAGER_ACTIVITY: usize = 0xe0;
const PAGE_NUMBER: usize = 0x04 / 4;
const PAGE_IN_JOURNAL: usize = 0x1d;
const PAGE_ALWAYS_ROLLBACK: usize = 0x1f;
const RETAIL_PAGER_REMOVE_FROM_JOURNAL: usize = 0x082d_906c;

type PagerRemoveFromJournal = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
static mut PAGER_REMOVE_FROM_JOURNAL: PagerRemoveFromJournal = missing_pager_remove_from_journal;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pager_remove_from_journal(_: *mut u32) {
    panic!("install pager dont-write host operation before removing a journal page")
}

#[inline(always)]
unsafe fn pager_remove_from_journal(page: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let remove: PagerRemoveFromJournal = core::mem::transmute(RETAIL_PAGER_REMOVE_FROM_JOURNAL);
        remove(page);
    }
    #[cfg(not(target_os = "none"))]
    {
        let remove = core::ptr::read_volatile(addr_of!(PAGER_REMOVE_FROM_JOURNAL));
        remove(page);
    }
}

/// Marks a page as requiring rollback rather than database write-back.
///
/// # Safety
/// `page` must be a writable target-layout `PgHdr` whose first word identifies
/// a writable pager object. On a journal-list removal path, `page` must also
/// satisfy the ABI of retailOS `pager_remove_from_journal`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_dont_write")]
#[inline(never)]
pub unsafe extern "C" fn pager_dont_write(page: *mut u32) {
    let pager = page.read() as usize as *mut u8;
    if pager.add(PAGER_MEMORY_DATABASE).read() != 0 {
        return;
    }

    crate::cxx::context_activity::context_activity_enter(pager);
    page.cast::<u8>().add(PAGE_ALWAYS_ROLLBACK).write(1);

    if page.cast::<u8>().add(PAGE_IN_JOURNAL).read() != 0
        && pager.add(PAGER_JOURNAL_GATE).read() == 0
    {
        let database_size = pager.cast::<u32>().add(PAGER_DATABASE_SIZE).read();
        let page_number = page.add(PAGE_NUMBER).read();
        let original_database_size = pager.cast::<u32>().add(PAGER_ORIGINAL_DATABASE_SIZE).read();
        if database_size != page_number || (original_database_size as i32) >= (database_size as i32) {
            pager_remove_from_journal(page);
        }
    }

    let activity = pager.add(PAGER_ACTIVITY).cast::<u32>();
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut REMOVED: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_remove(page: *mut u32) { REMOVED = page; }

    fn fixture() -> Option<(*mut u32, *mut u8)> {
        let base = try_map_u32_slab(hints::SQLITE_PAGER_DONT_WRITE, 0x1000)?;
        unsafe { Some((base.cast(), base.add(0x200))) }
    }

    #[test]
    fn memory_pager_is_untouched() {
        let _lock = LOCK.lock();
        let Some((page, pager)) = fixture() else { assert!(note_missing_u32_fixture(module_path!())); return; };
        unsafe {
            page.write_bytes(0, 0x1000 / 4);
            page.write(pager as usize as u32);
            pager.add(PAGER_MEMORY_DATABASE).write(1);
            pager.add(PAGER_ACTIVITY).cast::<u32>().write(9);
            REMOVED = core::ptr::null_mut();
            pager_dont_write(page);
            assert_eq!(page.cast::<u8>().add(PAGE_ALWAYS_ROLLBACK).read(), 0);
            assert_eq!(pager.add(PAGER_ACTIVITY).cast::<u32>().read(), 9);
            assert!(REMOVED.is_null());
        }
    }

    #[test]
    fn marks_page_and_removes_it_for_a_different_database_page() {
        let _lock = LOCK.lock();
        let Some((page, pager)) = fixture() else { assert!(note_missing_u32_fixture(module_path!())); return; };
        unsafe {
            page.write_bytes(0, 0x1000 / 4);
            page.write(pager as usize as u32);
            page.add(PAGE_NUMBER).write(7);
            page.cast::<u8>().add(PAGE_IN_JOURNAL).write(1);
            pager.cast::<u32>().add(PAGER_DATABASE_SIZE).write(8);
            pager.add(PAGER_ACTIVITY).cast::<u32>().write(3);
            PAGER_REMOVE_FROM_JOURNAL = record_remove;
            REMOVED = core::ptr::null_mut();
            pager_dont_write(page);
            assert_eq!(page.cast::<u8>().add(PAGE_ALWAYS_ROLLBACK).read(), 1);
            assert_eq!(REMOVED, page);
            assert_eq!(pager.add(PAGER_ACTIVITY).cast::<u32>().read(), 3);
        }
    }

    #[test]
    fn equal_page_skips_removal_only_when_original_size_is_smaller() {
        let _lock = LOCK.lock();
        let Some((page, pager)) = fixture() else { assert!(note_missing_u32_fixture(module_path!())); return; };
        unsafe {
            page.write_bytes(0, 0x1000 / 4);
            page.write(pager as usize as u32);
            page.add(PAGE_NUMBER).write(8);
            page.cast::<u8>().add(PAGE_IN_JOURNAL).write(1);
            pager.cast::<u32>().add(PAGER_DATABASE_SIZE).write(8);
            pager.cast::<u32>().add(PAGER_ORIGINAL_DATABASE_SIZE).write(7);
            PAGER_REMOVE_FROM_JOURNAL = record_remove;
            REMOVED = core::ptr::null_mut();
            pager_dont_write(page);
            assert!(REMOVED.is_null());
        }
    }
}
