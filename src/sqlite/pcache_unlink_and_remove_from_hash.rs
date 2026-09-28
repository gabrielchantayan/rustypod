//! Unlinks a SQLite cache page, then removes it from its hash chain.
//!
//! `pcache_unlink_and_remove_from_hash` — original `FUN_08396050` @
//! `0x08396050` (32 bytes). Raw `osos.dec` words establish the true extent
//! `0x08396050..0x0839606f`; `0x08396070` starts a separately linked function.
//! Whole-image aligned A32 decoding finds two inbound plain `bl` calls
//! (`0x082de3f4`, `0x082de7dc`) and no inbound predicated `bl` calls. The body
//! has one outbound plain `bl`, to `pager_page_unlink`, no predicated `bl`, and
//! tail-branches to `0x08395fd0` with the page owner and page as r0/r1.
//!
//! Algorithm: preserve the page owner, unlink the page from the pager lists,
//! then transfer to the retail hash-removal routine. Deliberate deviation: the
//! host build dispatches the unported tail target through a callback; the ARM
//! payload retains the retail absolute tail transfer.

#[cfg(not(target_arch = "arm"))]
use super::pager_page_unlink::pager_page_unlink;

#[cfg(not(target_arch = "arm"))]
pub type Retail08395fd0 = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_08395fd0(_: *mut u8, _: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_08395FD0: Retail08395fd0 = missing_retail_08395fd0;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn unlink_and_remove_with(
    page: *mut u8,
    unlink: unsafe extern "C" fn(*mut u8),
    remove_from_hash: Retail08395fd0,
) {
    let cache = page.cast::<u32>().read() as usize as *mut u8;
    unlink(page);
    remove_from_hash(cache, page);
}

/// Unlinks `page`, then removes it from its owner's hash table.
///
/// # Safety
/// `page` must be a writable target-layout page with a valid owner word at
/// `+0x00`; its pager-list links must be valid for `pager_page_unlink`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pcache_unlink_and_remove_from_hash(page: *mut u8) {
    let remove_from_hash = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_08395FD0)) };
    unsafe { unlink_and_remove_with(page, pager_page_unlink, remove_from_hash) }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl pcache_unlink_and_remove_from_hash
    .type pcache_unlink_and_remove_from_hash, %function
pcache_unlink_and_remove_from_hash:
    push    {{r4, r5, r6, lr}}
    ldr     r5, [r0]
    mov     r4, r0
    bl      pager_page_unlink
    mov     r1, r4
    mov     r0, r5
    pop     {{r4, r5, r6, lr}}
    ldr     pc, 1f
1:  .word   0x08395fd0
    .size pcache_unlink_and_remove_from_hash, . - pcache_unlink_and_remove_from_hash
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const SLAB_LEN: usize = 0x100;
    const PAGE: usize = 0x00;
    const CACHE: usize = 0x40;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [(u32, u32); 2] = [(0, 0); 2];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn record_unlink(page: *mut u8) {
        unsafe {
            EVENTS[EVENT_COUNT] = (1, page as usize as u32);
            EVENT_COUNT += 1;
        }
    }

    unsafe extern "C" fn record_remove(cache: *mut u8, page: *mut u8) {
        unsafe {
            EVENTS[EVENT_COUNT] = (cache as usize as u32, page as usize as u32);
            EVENT_COUNT += 1;
        }
    }

    #[test]
    fn unlinks_before_removing_the_page_from_its_owner_hash() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PCACHE_UNLINK_AND_REMOVE_FROM_HASH, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("sqlite/pcache_unlink_and_remove_from_hash"));
            return;
        };
        unsafe {
            let page = slab.add(PAGE);
            let cache = slab.add(CACHE);
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            page.cast::<u32>().write(cache as usize as u32);
            EVENTS = [(0, 0); 2];
            EVENT_COUNT = 0;

            unlink_and_remove_with(page, record_unlink, record_remove);

            assert_eq!(EVENT_COUNT, 2);
            assert_eq!(EVENTS, [(1, page as usize as u32), (cache as usize as u32, page as usize as u32)]);
        }
    }
}
