//! SQLite pager transaction teardown — `pager_end_transaction`.
//!
//! `pager_end_transaction` — original: `FUN_0837ecac` @ `0x0837ecac` (144
//! bytes, `0x0837ecac..0x0837ed3c`; **3 inbound plain `bl` call sites**, no
//! predicated `bl` sites, verified by decoding every ARM B/BL word in
//! `osos.dec`). The body has three unconditional calls: `context_activity_enter`,
//! `sqlite3_bitvec_destroy`, and `tracked_free`.
//!
//! The function takes an activity lease, then tears down an open transaction.
//! Non-memory pagers release their journal Bitvec. Memory pagers walk the dirty
//! Page list, clearing each page's journal and dirty links before releasing its
//! journal buffer. It clears the dirty-list head, journal-open flag, and
//! Bitvec field, always clears the statement-open flag, drops the lease, and
//! returns zero.
//! Deliberate deviation: target pointer fields and page offsets are loaded and
//! stored as u32 words rather than host pointers, preserving the firmware's
//! 4-byte layout.

use crate::cxx::context_activity::context_activity_enter;
use crate::heap::tracked::tracked_free;
use crate::sqlite::bitvec::{sqlite3_bitvec_destroy, Bitvec};

const JOURNAL_OPEN: usize = 0x09;
const STATEMENT_OPEN: usize = 0x0a;
const MEMORY_DATABASE: usize = 0x14;
const DIRTY_LIST: usize = 0x38;
const PAGE_POOL: usize = 0x3c;
const DIRTY_LIST_HEAD: usize = 0x8c;
const IN_JOURNAL: usize = 0x58;
const PAGE_NEXT_DIRTY: usize = 0x40;
const PAGE_PREV_DIRTY: usize = 0x44;
const PAGE_IN_JOURNAL: usize = 0x48;
const PAGE_JOURNAL_BUFFER: usize = 0x3c;
const ACTIVITY: usize = 0xe0;

/// `pager_end_transaction` — original `FUN_0837ecac` @ `0x0837ecac` (144
/// bytes; 3 inbound plain `bl` call sites and no predicated `bl` sites).
///
/// Releases the transaction journal state when `pager+0x09` is set, clears
/// `pager+0x0a`, balances the activity lease at `+0xe0`, and returns zero.
/// Page and pager pointer fields retain target-width u32 representation.
///
/// # Safety
///
/// `pager` must name a writable target-layout Pager through `+0xe0`. If its
/// journal is open, `+0x58` must be NULL or a live Bitvec allocation. For a
/// memory database, the dirty-list offset at `+0x8c` must name an acyclic
/// chain within the target-width page pool at `+0x3c`; each page's journal
/// buffer must be NULL or a live tracked allocation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_end_transaction")]
#[inline(never)]
pub unsafe extern "C" fn pager_end_transaction(pager: *mut u8) -> u32 {
    context_activity_enter(pager);

    if pager.add(JOURNAL_OPEN).read() != 0 {
        if pager.add(MEMORY_DATABASE).read() == 0 {
            sqlite3_bitvec_destroy(pager.add(IN_JOURNAL).cast::<u32>().read() as usize as *mut Bitvec);
            pager.add(IN_JOURNAL).cast::<u32>().write(0);
        } else {
            let page_pool = pager.add(PAGE_POOL).cast::<u32>().read() as usize as *mut u8;
            let mut page_offset = pager.add(DIRTY_LIST_HEAD).cast::<u32>().read();
            while page_offset != 0 {
                let page = page_pool.add(page_offset as usize);
                let next = page.add(PAGE_NEXT_DIRTY).cast::<u32>().read();
                page.add(PAGE_IN_JOURNAL).write(0);
                page.add(PAGE_NEXT_DIRTY).cast::<u32>().write(0);
                page.add(PAGE_PREV_DIRTY).cast::<u32>().write(0);
                tracked_free(page.add(PAGE_JOURNAL_BUFFER).cast::<u32>().read() as usize as *mut u8);
                page.add(PAGE_JOURNAL_BUFFER).cast::<u32>().write(0);
                page_offset = next;
            }
        }
        pager.add(DIRTY_LIST).cast::<u32>().write(0);
        pager.add(JOURNAL_OPEN).write(0);
        pager.add(DIRTY_LIST_HEAD).cast::<u32>().write(0);
    }

    pager.add(STATEMENT_OPEN).write(0);
    let activity = pager.add(ACTIVITY).cast::<u32>();
    activity.write(activity.read().wrapping_sub(1));
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::pager_end_transaction;

    #[test]
    fn inactive_transaction_only_closes_statement_and_balances_lease() {
        let mut pager = [0u32; 58];
        let pager = pager.as_mut_ptr().cast::<u8>();
        unsafe {
            pager.add(0x0a).write(1);
            pager.add(0x38).cast::<u32>().write(0xfeed_beef);
            pager.add(0xe0).cast::<u32>().write(9);
            assert_eq!(pager_end_transaction(pager), 0);
            assert_eq!(pager.add(0x0a).read(), 0);
            assert_eq!(pager.add(0x38).cast::<u32>().read(), 0xfeed_beef);
            assert_eq!(pager.add(0xe0).cast::<u32>().read(), 9);
        }
    }

    #[test]
    fn open_disk_transaction_releases_null_bitvec_and_resets_journal_state() {
        let mut pager = [0u32; 58];
        let pager = pager.as_mut_ptr().cast::<u8>();
        unsafe {
            pager.add(0x09).write(1);
            pager.add(0x0a).write(1);
            pager.add(0x38).cast::<u32>().write(0xfeed_beef);
            pager.add(0x58).cast::<u32>().write(0);
            pager.add(0x8c).cast::<u32>().write(0xdead_beef);
            pager.add(0xe0).cast::<u32>().write(3);
            assert_eq!(pager_end_transaction(pager), 0);
            assert_eq!(pager.add(0x09).read(), 0);
            assert_eq!(pager.add(0x0a).read(), 0);
            assert_eq!(pager.add(0x38).cast::<u32>().read(), 0);
            assert_eq!(pager.add(0x58).cast::<u32>().read(), 0);
            assert_eq!(pager.add(0x8c).cast::<u32>().read(), 0);
            assert_eq!(pager.add(0xe0).cast::<u32>().read(), 3);
        }
    }

    #[test]
    fn open_memory_transaction_preserves_bitvec_and_clears_empty_dirty_list() {
        let mut pager = [0u32; 58];
        let pager = pager.as_mut_ptr().cast::<u8>();
        unsafe {
            pager.add(0x09).write(1);
            pager.add(0x14).write(1);
            pager.add(0x38).cast::<u32>().write(0xfeed_beef);
            pager.add(0x58).cast::<u32>().write(0xdead_beef);
            pager.add(0x8c).cast::<u32>().write(0);
            pager.add(0xe0).cast::<u32>().write(3);
            assert_eq!(pager_end_transaction(pager), 0);
            assert_eq!(pager.add(0x38).cast::<u32>().read(), 0);
            assert_eq!(pager.add(0x58).cast::<u32>().read(), 0xdead_beef);
            assert_eq!(pager.add(0x8c).cast::<u32>().read(), 0);
            assert_eq!(pager.add(0xe0).cast::<u32>().read(), 3);
        }
    }
}
