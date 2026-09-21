//! Pins a page in its cache — `FUN_082b1520` @ 0x082b1520.
//!
//! Raw `osos.dec` establishes the true 60-byte extent
//! `0x082b1520..0x082b155b`; the next independently linked function begins
//! with `push {r3-r9,sl,fp,lr}` at `0x082b155c`. Whole-image aligned A32
//! decoding finds three inbound plain `bl` calls (`0x082dd270`, `0x08367b7c`,
//! and `0x0837e904`) and zero inbound predicated `bl` calls. The body has one
//! plain `bl`, to `pager_page_unlink`, and no predicated `bl` calls.
//!
//! Algorithm: on a page's zero-to-one reference transition, unlink it from
//! the cache's unpinned lists and increment the cache reference count; then
//! increment the page reference count. Both counters retain ARM's wrapping
//! arithmetic. Deliberate deviations: calls the already-ported
//! `pager_page_unlink` instead of branching to its retail address.

use super::pager_page_unlink::pager_page_unlink;

const OWNER: usize = 0x00;
const PAGE_REFCOUNT: usize = 0x22;
const CACHE_REFCOUNT: usize = 0x48;

#[inline(always)]
unsafe fn pin_with(page: *mut u8, unlink: unsafe extern "C" fn(*mut u8)) {
    let reference_count = page.add(PAGE_REFCOUNT).cast::<u16>();
    if reference_count.read() == 0 {
        unlink(page);
        let owner = page.add(OWNER).cast::<u32>().read() as usize as *mut u8;
        let cache_references = owner.add(CACHE_REFCOUNT).cast::<u32>();
        cache_references.write(cache_references.read().wrapping_add(1));
    }
    reference_count.write(reference_count.read().wrapping_add(1));
}

/// Pins `page`, removing it from unpinned lists on its first reference.
///
/// # Safety
/// `page` must be a writable target-layout page whose `+0x00` owner word
/// points to a writable cache with a `u32` reference count at `+0x48`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pcache_pin_page")]
#[inline(never)]
pub unsafe extern "C" fn pcache_pin_page(page: *mut u8) {
    pin_with(page, pager_page_unlink);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const PAGE: usize = 0x000;
    const OWNER_OFFSET: usize = 0x100;
    static mut UNLINKS: usize = 0;

    unsafe extern "C" fn record_unlink(_: *mut u8) {
        UNLINKS += 1;
    }

    #[test]
    fn unlinks_and_counts_only_the_zero_to_one_transition() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PCACHE_PIN_PAGE, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("sqlite/pcache_pin_page"));
            return;
        };
        unsafe {
            let page = slab.add(PAGE);
            let owner = slab.add(OWNER_OFFSET);
            core::ptr::write_bytes(page, 0, 0x40);
            core::ptr::write_bytes(owner, 0, 0x100);
            page.cast::<u32>().write(owner as usize as u32);
            owner.add(CACHE_REFCOUNT).cast::<u32>().write(u32::MAX);
            UNLINKS = 0;

            pin_with(page, record_unlink);
            assert_eq!(UNLINKS, 1);
            assert_eq!(page.add(PAGE_REFCOUNT).cast::<u16>().read(), 1);
            assert_eq!(owner.add(CACHE_REFCOUNT).cast::<u32>().read(), 0);

            pin_with(page, record_unlink);
            assert_eq!(UNLINKS, 1);
            assert_eq!(page.add(PAGE_REFCOUNT).cast::<u16>().read(), 2);
            assert_eq!(owner.add(CACHE_REFCOUNT).cast::<u32>().read(), 0);
        }
    }
}
