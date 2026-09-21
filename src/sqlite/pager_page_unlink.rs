//! Unlinks a pager page from its owner and allocator lists — `FUN_082d8e30` @
//! 0x082d8e30.
//!
//! Raw `osos.dec` establishes the true 64-byte extent
//! `0x082d8e30..0x082d8e6f`; the literal at `0x082d8e70` is followed by the
//! next independently linked function at `0x082d8e74`. Whole-image A32
//! decoding finds three inbound plain `bl` calls (`0x082b1538`, `0x082de428`,
//! and `0x0839605c`) and no inbound predicated `bl` calls. The body contains
//! one plain `bl` and one conditional tail branch, both to `FUN_082d801c`.
//!
//! Algorithm: remove the page's `+0x10` intrusive-list node from the page
//! owner's list at `page[0] + 0x7c`. When the owner's `+0x14` byte is zero,
//! also remove the page's `+0x2c` node from the global allocator anchor at
//! `0x08adc2c0`.
//!
//! Deliberate deviation: `FUN_082d801c` remains unported and is invoked at its
//! verified fixed target address. Host tests inject the helper rather than
//! mapping target code.

const OWNER: usize = 0x00;
const OWNER_LIST: usize = 0x7c;
const OWNER_HAS_PRIVATE_LIST: usize = 0x14;
const OWNER_NODE: usize = 0x10;
const ALLOCATOR_NODE: usize = 0x2c;
const ALLOCATOR_LIST: usize = 0x08ad_c2c0;
const RETAIL_INTRUSIVE_LIST_REMOVE: usize = 0x082d_801c;

type IntrusiveListRemove = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8);

#[inline(always)]
unsafe fn unlink_with(page: *mut u8, remove: IntrusiveListRemove) {
    let owner = page.cast::<u32>().read() as usize as *mut u8;
    remove(owner.add(OWNER_LIST), page.add(OWNER_NODE), page);
    if owner.add(OWNER_HAS_PRIVATE_LIST).read() == 0 {
        remove(ALLOCATOR_LIST as *mut u8, page.add(ALLOCATOR_NODE), page);
    }
}

/// Removes `page` from the intrusive lists that retain it.
///
/// # Safety
/// `page` must be a writable target-layout page with a valid target-width
/// owner word at `+0x00`. The owner and both list nodes must be valid for the
/// retail intrusive-list remover.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_page_unlink")]
#[inline(never)]
pub unsafe extern "C" fn pager_page_unlink(page: *mut u8) {
    let remove: IntrusiveListRemove = core::mem::transmute(RETAIL_INTRUSIVE_LIST_REMOVE);
    unlink_with(page, remove);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    const SLAB_LEN: usize = 0x1000;
    const PAGE: usize = 0x000;
    const OWNER_OFFSET: usize = 0x100;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, usize, usize); 2] = [(0, 0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_remove(anchor: *mut u8, node: *mut u8, page: *mut u8) {
        CALLS[CALL_COUNT] = (anchor as usize, node as usize, page as usize);
        CALL_COUNT += 1;
    }

    fn fixture() -> Option<(*mut u8, *mut u8)> {
        let slab = try_map_u32_slab(hints::SQLITE_PAGER_PAGE_UNLINK, SLAB_LEN)?;
        unsafe { Some((slab.add(PAGE), slab.add(OWNER_OFFSET))) }
    }

    #[test]
    fn unlinks_owner_and_global_nodes_when_owner_allows_it() {
        let _lock = TEST_LOCK.lock();
        let Some((page, owner)) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/pager_page_unlink"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(page, 0, 0x40);
            core::ptr::write_bytes(owner, 0, 0x100);
            page.cast::<u32>().write(owner as usize as u32);
            owner.add(OWNER_HAS_PRIVATE_LIST).write(0);
            CALL_COUNT = 0;
            unlink_with(page, record_remove);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (owner.add(OWNER_LIST) as usize, page.add(OWNER_NODE) as usize, page as usize));
            assert_eq!(CALLS[1], (ALLOCATOR_LIST, page.add(ALLOCATOR_NODE) as usize, page as usize));
        }
    }

    #[test]
    fn leaves_global_node_linked_for_private_owner() {
        let _lock = TEST_LOCK.lock();
        let Some((page, owner)) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/pager_page_unlink"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(page, 0, 0x40);
            core::ptr::write_bytes(owner, 0, 0x100);
            page.cast::<u32>().write(owner as usize as u32);
            owner.add(OWNER_HAS_PRIVATE_LIST).write(1);
            CALL_COUNT = 0;
            unlink_with(page, record_remove);
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(CALLS[0], (owner.add(OWNER_LIST) as usize, page.add(OWNER_NODE) as usize, page as usize));
        }
    }
}
