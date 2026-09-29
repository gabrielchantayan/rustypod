//! Reclaims a SQLite pager-cache page for reuse.
//!
//! `pager_reclaim_cache_page` — original `FUN_082de33c` @ `0x082de33c`
//! (200 bytes; 6 outbound plain-`bl` instructions; 2 inbound plain-`bl` call
//! sites; no predicated BL in either direction). Raw A32 spans
//! `0x082de33c..0x082de403`; the `push` at `0x082de404` starts the next
//! independently entered function. It optionally synchronizes the pager and
//! runs the journal-reset seam, removes an LRU page, prepares it for
//! recycling, then unlinks it from the hash table. Deliberate deviation: the
//! unported sync, journal-reset, and page-prepare routines remain fixed retail
//! address seams on target and private recording seams on host.

const PAGER_PAGE: usize = 0x7c;
const PAGER_BUSY_PAGE: usize = 0x84;
const PAGER_FILE: usize = 0x6c;
const PAGER_SYNC_REQUIRED: usize = 0x0c;
const PAGER_JOURNAL_STATE: usize = 0x30;
const PAGER_NEEDS_SYNC: usize = 0x13;
const PAGE_ON_LRU_LIST: usize = 0x1d;
const PAGE_RECYCLING: usize = 0x1f;
const PAGE_LRU_PREVIOUS: usize = 0x24;
const SQLITE_IOCAP_SAFE_APPEND: u32 = 0x200;

type DeviceCharacteristics = unsafe extern "C" fn(*mut u8) -> u32;
type PagerStatusHelper = unsafe extern "C" fn(*mut u8) -> u32;
type PageHelper = unsafe extern "C" fn(*mut u8);
type PageStatusHelper = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
extern "C" {
    fn pcache_unlink_and_remove_from_hash(page: *mut u8);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn device_characteristics(file: *mut u8) -> u32 {
    crate::sqlite::os_device_characteristics::sqlite_os_device_characteristics(
        file.cast::<crate::sqlite::os_write::SqliteFile>(),
    ) as u32
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_sync(pager: *mut u8) -> u32 {
    let helper: PagerStatusHelper = core::mem::transmute(0x0839_2a20usize);
    helper(pager)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_08398a2c(pager: *mut u8) -> u32 {
    let helper: PagerStatusHelper = core::mem::transmute(0x0839_8a2cusize);
    helper(pager)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn prepare_page_for_recycling(page: *mut u8) -> u32 {
    let helper: PageStatusHelper = core::mem::transmute(0x082d_ecf0usize);
    helper(page)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn remove_from_lru(page: *mut u8) { crate::sqlite::pcache_remove_from_lru_list::pcache_remove_from_lru_list(page) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlink_from_hash(page: *mut u8) { pcache_unlink_and_remove_from_hash(page) }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    device_characteristics: DeviceCharacteristics,
    sync: PagerStatusHelper,
    journal_reset: PagerStatusHelper,
    remove_from_lru: PageHelper,
    prepare_page: PageStatusHelper,
    unlink_from_hash: PageHelper,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_device_characteristics(_: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_status(_: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_page(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: HostOps = HostOps { device_characteristics: no_device_characteristics, sync: no_status, journal_reset: no_status, remove_from_lru: no_page, prepare_page: no_status, unlink_from_hash: no_page };
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = DEFAULT_HOST_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::read_volatile(core::ptr::addr_of!(HOST_OPS)) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn device_characteristics(file: *mut u8) -> u32 { (host_ops().device_characteristics)(file) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_sync(pager: *mut u8) -> u32 { (host_ops().sync)(pager) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_08398a2c(pager: *mut u8) -> u32 { (host_ops().journal_reset)(pager) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn remove_from_lru(page: *mut u8) { (host_ops().remove_from_lru)(page) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn prepare_page_for_recycling(page: *mut u8) -> u32 { (host_ops().prepare_page)(page) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlink_from_hash(page: *mut u8) { (host_ops().unlink_from_hash)(page) }

/// Reclaims the pager's selected cache page, writing its target-width address
/// to `page_out` on success.
///
/// # Safety
/// `pager`, its selected page word at `+0x7c`, and `page_out` must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_reclaim_cache_page")]
#[inline(never)]
pub unsafe extern "C" fn pager_reclaim_cache_page(pager: *mut u8, page_out: *mut u32) -> u32 {
    page_out.write(0);
    let mut page = pager.add(PAGER_BUSY_PAGE).cast::<u32>().read() as usize as *mut u8;
    if page.is_null() && !(pager.add(PAGER_PAGE).cast::<u32>().read() as usize as *mut u8).is_null() {
        let characteristics = device_characteristics(pager.add(PAGER_FILE).cast::<u32>().read() as usize as *mut u8);
        let status = pager_sync(pager);
        if status != 0 { return status; }
        if pager.add(PAGER_SYNC_REQUIRED).read() != 0 && characteristics & SQLITE_IOCAP_SAFE_APPEND == 0 {
            pager.add(PAGER_JOURNAL_STATE).cast::<u32>().write(0);
            let status = retail_08398a2c(pager);
            if status != 0 { return status; }
        }
        page = pager.add(PAGER_PAGE).cast::<u32>().read() as usize as *mut u8;
    }
    if page.add(PAGE_ON_LRU_LIST).read() != 0 {
        remove_from_lru(page);
        page.add(PAGE_ON_LRU_LIST).write(1);
        page.add(PAGE_LRU_PREVIOUS).cast::<u32>().write(0);
        let status = prepare_page_for_recycling(page);
        page.add(PAGE_ON_LRU_LIST).write(0);
        if status != 0 { return status; }
    }
    if page.add(PAGE_RECYCLING).read() != 0 { pager.add(PAGER_NEEDS_SYNC).write(1); }
    unlink_from_hash(page);
    page_out.write(page as usize as u32);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const LEN: usize = 0x400;
    const PAGER: usize = 0;
    const PAGE: usize = 0x200;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut SYNC_STATUS: u32 = 0;
    static mut PREPARE_STATUS: u32 = 0;
    unsafe fn event(value: u32) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn device(file: *mut u8) -> u32 { event(10 + file as usize as u32); 0 }
    unsafe extern "C" fn sync(_: *mut u8) -> u32 { event(2); SYNC_STATUS }
    unsafe extern "C" fn reset(_: *mut u8) -> u32 { event(3); 0 }
    unsafe extern "C" fn lru(_: *mut u8) { event(4) }
    unsafe extern "C" fn prepare(_: *mut u8) -> u32 { event(5); PREPARE_STATUS }
    unsafe extern "C" fn unlink(_: *mut u8) { event(6) }
    unsafe fn install() { core::ptr::write_volatile(core::ptr::addr_of_mut!(HOST_OPS), HostOps { device_characteristics: device, sync, journal_reset: reset, remove_from_lru: lru, prepare_page: prepare, unlink_from_hash: unlink }); EVENTS = [0; 8]; EVENT_COUNT = 0; SYNC_STATUS = 0; PREPARE_STATUS = 0; }
    unsafe fn restore() { core::ptr::write_volatile(core::ptr::addr_of_mut!(HOST_OPS), DEFAULT_HOST_OPS) }

    #[test]
    fn sync_failure_preserves_page_and_clears_output() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = try_map_u32_slab(hints::SQLITE_PAGER_RECLAIM_CACHE_PAGE, LEN) else { assert!(note_missing_u32_fixture(module_path!())); return; };
        unsafe {
            core::ptr::write_bytes(base, 0, LEN); install(); SYNC_STATUS = 9;
            let pager = base.add(PAGER); let page = base.add(PAGE); pager.add(PAGER_PAGE).cast::<u32>().write(page as usize as u32); page.add(PAGE_ON_LRU_LIST).write(1);
            let mut output = u32::MAX;
            assert_eq!(pager_reclaim_cache_page(pager, &mut output), 9);
            assert_eq!(output, 0); assert_eq!(page.add(PAGE_ON_LRU_LIST).read(), 1); assert_eq!(&EVENTS[..EVENT_COUNT], &[10 + 0, 2]);
            restore();
        }
    }

    #[test]
    fn reclaims_lru_page_after_sync_and_journal_reset() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = try_map_u32_slab(hints::SQLITE_PAGER_RECLAIM_CACHE_PAGE, LEN) else { assert!(note_missing_u32_fixture(module_path!())); return; };
        unsafe {
            core::ptr::write_bytes(base, 0, LEN); install();
            let pager = base.add(PAGER); let page = base.add(PAGE); pager.add(PAGER_PAGE).cast::<u32>().write(page as usize as u32); pager.add(PAGER_FILE).cast::<u32>().write(0); pager.add(PAGER_SYNC_REQUIRED).write(1); pager.add(PAGER_JOURNAL_STATE).cast::<u32>().write(77); page.add(PAGE_ON_LRU_LIST).write(2); page.add(PAGE_RECYCLING).write(1); page.add(PAGE_LRU_PREVIOUS).cast::<u32>().write(0xfeed_beef);
            let mut output = 0;
            assert_eq!(pager_reclaim_cache_page(pager, &mut output), 0);
            assert_eq!(output, page as usize as u32); assert_eq!(pager.add(PAGER_JOURNAL_STATE).cast::<u32>().read(), 0); assert_eq!(pager.add(PAGER_NEEDS_SYNC).read(), 1); assert_eq!(page.add(PAGE_ON_LRU_LIST).read(), 0); assert_eq!(page.add(PAGE_LRU_PREVIOUS).cast::<u32>().read(), 0); assert_eq!(&EVENTS[..EVENT_COUNT], &[10, 2, 3, 4, 5, 6]);
            restore();
        }
    }
}
