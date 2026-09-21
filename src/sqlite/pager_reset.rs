//! SQLite pager cache reset — `pager_reset`.
//!
//! `pager_reset` — original: `FUN_082de404` @ `0x082de404` (112 bytes; 4
//! plain `bl` and 1 `blne` direct call sites, binary-scanned). The raw ARM
//! body is `0x082de404..0x082de474`; the following `push {r4,r5,r6,lr}` at
//! `0x082de474` starts a separate function.
//!
//! When Pager `+0x20` is nonzero, this is a strict no-op. Otherwise it walks
//! the target-width Page list rooted at `pager+0x88`, unlinking each page from
//! the unported page-cache owner, then freeing the page payload at `+0x34`
//! and the page itself. It clears the three list-head words, state word
//! `+0xcc`, the temporary-space word `+0xd0`, and the related `+0x44`/`+0x48`
//! state words in the same order as ARM.
//!
//! Deliberate deviation: host builds retain a private unlink seam so pager
//! reset tests can observe page-unlink ordering. Target builds call the
//! ported `pager_page_unlink` directly.

use crate::heap::tracked::tracked_free;
#[cfg(target_os = "none")]
use crate::sqlite::pager_page_unlink::pager_page_unlink;

const RESET_GUARD: usize = 0x20;
const PAGE_LIST: usize = 0x88;
const PAGE_LIST_TAIL: usize = 0x8c;
const PAGE_DIRTY_LIST: usize = 0x90;
const PAGE_NEXT: usize = 0x18;
const PAGE_PAYLOAD: usize = 0x34;
const RESET_STATE: usize = 0xcc;
const TEMPORARY_SPACE: usize = 0xd0;
const RELATED_STATE: usize = 0x44;
const RELATED_COUNT: usize = 0x48;

type PageUnlink = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlink_page_from_cache(page: *mut u8) {
    pager_page_unlink(page);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PagerResetHostOps {
    unlink_page: PageUnlink,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_page_unlink(_page: *mut u8) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_PAGER_RESET_HOST_OPS: PagerResetHostOps = PagerResetHostOps {
    unlink_page: unavailable_page_unlink,
};

#[cfg(not(target_os = "none"))]
static mut PAGER_RESET_HOST_OPS: PagerResetHostOps = DEFAULT_PAGER_RESET_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlink_page_from_cache(page: *mut u8) {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(PAGER_RESET_HOST_OPS));
    (ops.unlink_page)(page);
}

/// `pager_reset` — original: `FUN_082de404` @ `0x082de404` (112 bytes; 4
/// plain `bl` and 1 `blne` direct call sites, binary-scanned).
///
/// If `pager+0x20` is nonzero, returns without touching any field. Otherwise
/// unlinks and releases every Page at `pager+0x88`, then clears the pager's
/// page-list and temporary-space state. Page links and pointer fields are
/// loaded as u32 words so the target's 4-byte layout remains correct on hosts.
///
/// # Safety
/// `pager` must name a writable target-layout Pager through `+0xd0`. Its page
/// list must be acyclic; every non-NULL page and `+0xd0` payload must be valid
/// tracked allocations, and the target's unported page-cache unlinker must
/// accept each page.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_reset")]
#[inline(never)]
pub unsafe extern "C" fn pager_reset(pager: *mut u8) {
    if pager.add(RESET_GUARD).cast::<u32>().read() != 0 {
        return;
    }

    let mut page = pager.add(PAGE_LIST).cast::<u32>().read() as usize as *mut u8;
    while !page.is_null() {
        let next = page.add(PAGE_NEXT).cast::<u32>().read() as usize as *mut u8;
        unlink_page_from_cache(page);
        tracked_free(page.add(PAGE_PAYLOAD).cast::<u32>().read() as usize as *mut u8);
        tracked_free(page);
        page = next;
    }

    pager.add(PAGE_LIST_TAIL).cast::<u32>().write(0);
    pager.add(PAGE_LIST).cast::<u32>().write(0);
    pager.add(PAGE_DIRTY_LIST).cast::<u32>().write(0);
    pager.add(RESET_STATE).cast::<u32>().write(0);
    tracked_free(pager.add(TEMPORARY_SPACE).cast::<u32>().read() as usize as *mut u8);
    pager.add(RELATED_STATE).cast::<u32>().write(0);
    pager.add(TEMPORARY_SPACE).cast::<u32>().write(0);
    pager.add(RELATED_COUNT).cast::<u32>().write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::{
        tracked::ALLOC_STATS,
        veneers::tests::{free_log, mock_heap},
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static PAGER_RESET_OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut UNLINKED_PAGES: [u32; 2] = [0; 2];
    static mut UNLINK_COUNT: usize = 0;

    unsafe extern "C" fn recording_page_unlink(page: *mut u8) {
        UNLINKED_PAGES[UNLINK_COUNT] = page as usize as u32;
        UNLINK_COUNT += 1;
    }

    unsafe fn tracked_payload(slab: *mut u8, block_offset: usize, size: i32) -> *mut u8 {
        let block = slab.add(block_offset);
        let payload = block.add(0x20);
        block.cast::<i32>().write(size);
        payload.sub(4).cast::<u32>().write(0x18);
        payload
    }

    #[test]
    fn pager_reset_gates_then_unlinks_frees_and_clears() {
        const FIXTURE_LEN: usize = 0x1000;

        let Some(slab) = try_map_u32_slab(hints::SQLITE_PAGER_RESET, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let _ops_guard = PAGER_RESET_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_guard = mock_heap();

        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(PAGER_RESET_HOST_OPS),
                PagerResetHostOps { unlink_page: recording_page_unlink },
            );
            UNLINKED_PAGES = [0; 2];
            UNLINK_COUNT = 0;
            ALLOC_STATS.current_bytes = 0;

            let pager = slab;
            let first_page = tracked_payload(slab, 0x100, 0x40);
            let second_page = tracked_payload(slab, 0x200, 0x40);
            let page_payload = tracked_payload(slab, 0x300, 0x20);
            let temporary_space = tracked_payload(slab, 0x400, 0x20);

            pager.add(RESET_GUARD).cast::<u32>().write(1);
            pager.add(PAGE_LIST).cast::<u32>().write(first_page as usize as u32);
            pager.add(PAGE_LIST_TAIL).cast::<u32>().write(second_page as usize as u32);
            pager.add(PAGE_DIRTY_LIST).cast::<u32>().write(0x1111_1111);
            pager.add(RESET_STATE).cast::<u32>().write(0x2222_2222);
            pager.add(TEMPORARY_SPACE).cast::<u32>().write(temporary_space as usize as u32);
            pager.add(RELATED_STATE).cast::<u32>().write(0x3333_3333);
            pager.add(RELATED_COUNT).cast::<u32>().write(0x4444_4444);
            pager_reset(pager);
            assert_eq!(UNLINK_COUNT, 0, "the guard prevents all releases");
            assert_eq!(pager.add(PAGE_LIST).cast::<u32>().read(), first_page as usize as u32);

            pager.add(RESET_GUARD).cast::<u32>().write(0);
            first_page.add(PAGE_NEXT).cast::<u32>().write(second_page as usize as u32);
            first_page.add(PAGE_PAYLOAD).cast::<u32>().write(page_payload as usize as u32);
            second_page.add(PAGE_NEXT).cast::<u32>().write(0);
            second_page.add(PAGE_PAYLOAD).cast::<u32>().write(0);
            pager_reset(pager);

            assert_eq!(UNLINK_COUNT, 2);
            assert_eq!(UNLINKED_PAGES, [first_page as usize as u32, second_page as usize as u32]);
            for offset in [PAGE_LIST, PAGE_LIST_TAIL, PAGE_DIRTY_LIST, RESET_STATE,
                TEMPORARY_SPACE, RELATED_STATE, RELATED_COUNT]
            {
                assert_eq!(pager.add(offset).cast::<u32>().read(), 0, "field +{offset:#x}");
            }
            assert_eq!(free_log(), (4, temporary_space.sub(0x20), 57),
                "pages, their payload, and temporary space are released in list order");

            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(PAGER_RESET_HOST_OPS),
                DEFAULT_PAGER_RESET_HOST_OPS,
            );
        }
    }
}
