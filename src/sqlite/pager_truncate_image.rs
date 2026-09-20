//! SQLite pager image truncation — `sqlite3PagerTruncateImage` from pager.c.
//!
//! `pager_truncate_image` — original: `FUN_0837edf0` @ `0x0837edf0` (168
//! bytes; 3 direct plain-`bl` call sites, binary-scanned; no predicated calls).
//!
//! Raw ARM spans `0x0837edf0..0x0837ee98`; `release_object` begins separately
//! at `0x0837ee98`. It rejects a prior pager error, ignores requests at or
//! beyond the current image size, and trims an in-memory pager directly.
//! Otherwise it synchronizes, obtains lock state 4, then tail-dispatches the
//! remaining file/cache truncation helper. Deliberate deviation: those four
//! unported pager helpers use fixed retailOS addresses on target and private
//! recording seams on host; the ported activity lease helper is direct.

use crate::cxx::context_activity::context_activity_enter;

const PAGER_ERROR: usize = 0x20;
const DATABASE_SIZE: usize = 0x24;
const MEMORY_DATABASE: usize = 0x14;
const ACTIVITY: usize = 0xe0;

type PagerPageCountHelper = unsafe extern "C" fn(*mut u8) -> u32;
type PagerStatusHelper = unsafe extern "C" fn(*mut u8) -> u32;
type PagerLockHelper = unsafe extern "C" fn(*mut u8, u32) -> u32;
type PagerTruncateHelper = unsafe extern "C" fn(*mut u8, u32) -> u32;
type PagerCacheHelper = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_page_count(pager: *mut u8) {
    let helper: PagerPageCountHelper = core::mem::transmute(0x0837_e7acusize);
    helper(pager);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_sync(pager: *mut u8) -> u32 {
    let helper: PagerStatusHelper = core::mem::transmute(0x0839_2a20usize);
    helper(pager)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_wait_on_lock(pager: *mut u8) -> u32 {
    let helper: PagerLockHelper = core::mem::transmute(0x082d_e8f4usize);
    helper(pager, 4)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_finish_truncate(pager: *mut u8, page_count: u32) -> u32 {
    let helper: PagerTruncateHelper = core::mem::transmute(0x082d_e6c4usize);
    helper(pager, page_count)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_truncate_cache(pager: *mut u8) {
    let helper: PagerCacheHelper = core::mem::transmute(0x082d_e78cusize);
    helper(pager)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PagerTruncateHostOps {
    page_count: PagerPageCountHelper,
    sync: PagerStatusHelper,
    lock: PagerLockHelper,
    finish: PagerTruncateHelper,
    cache: PagerCacheHelper,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_page_count_helper(_pager: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_status_helper(_pager: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lock_helper(_pager: *mut u8, _state: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_truncate_helper(_pager: *mut u8, _pages: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_cache_helper(_pager: *mut u8) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_PAGER_TRUNCATE_HOST_OPS: PagerTruncateHostOps = PagerTruncateHostOps {
    page_count: unavailable_page_count_helper,
    sync: unavailable_status_helper,
    lock: unavailable_lock_helper,
    finish: unavailable_truncate_helper,
    cache: unavailable_cache_helper,
};

#[cfg(not(target_os = "none"))]
static mut PAGER_TRUNCATE_HOST_OPS: PagerTruncateHostOps = DEFAULT_PAGER_TRUNCATE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PagerTruncateHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PAGER_TRUNCATE_HOST_OPS))
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_page_count(pager: *mut u8) { let _ = (host_ops().page_count)(pager); }

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_sync(pager: *mut u8) -> u32 { (host_ops().sync)(pager) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_wait_on_lock(pager: *mut u8) -> u32 { (host_ops().lock)(pager, 4) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_finish_truncate(pager: *mut u8, page_count: u32) -> u32 {
    (host_ops().finish)(pager, page_count)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_truncate_cache(pager: *mut u8) { (host_ops().cache)(pager) }

/// `pager_truncate_image` — original: `FUN_0837edf0` @ `0x0837edf0` (168
/// bytes; 3 direct plain-`bl` call sites).
///
/// # Safety
/// `pager` must name a writable target-layout Pager through `+0xe0`. Its
/// installed sync, lock, file-truncate, and cache-truncate helpers must accept
/// this pager when their corresponding paths are selected.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_truncate_image")]
#[inline(never)]
pub unsafe extern "C" fn pager_truncate_image(pager: *mut u8, page_count: u32) -> u32 {
    pager_page_count(pager);
    let error = pager.add(PAGER_ERROR).cast::<u32>().read();
    if error != 0 {
        return error;
    }
    if pager.add(DATABASE_SIZE).cast::<u32>().read() <= page_count {
        return 0;
    }
    if pager.add(MEMORY_DATABASE).read() != 0 {
        pager.add(DATABASE_SIZE).cast::<u32>().write(page_count);
        pager_truncate_cache(pager);
        return 0;
    }

    context_activity_enter(pager);
    let status = pager_sync(pager);
    let activity = pager.add(ACTIVITY).cast::<u32>();
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
    if status != 0 {
        return status;
    }

    context_activity_enter(pager);
    let status = pager_wait_on_lock(pager);
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
    if status != 0 {
        return status;
    }
    pager_finish_truncate(pager, page_count)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOG: [u32; 4] = [0; 4];
    static mut LOG_LEN: usize = 0;
    static mut SYNC_STATUS: u32 = 0;
    static mut LOCK_STATUS: u32 = 0;
    static mut FINISH_STATUS: u32 = 0;

    unsafe fn record(value: u32) {
        LOG[LOG_LEN] = value;
        LOG_LEN += 1;
    }
    unsafe extern "C" fn page_count(_pager: *mut u8) -> u32 { record(0); 0 }
    unsafe extern "C" fn sync(_pager: *mut u8) -> u32 { record(1); SYNC_STATUS }
    unsafe extern "C" fn lock(_pager: *mut u8, state: u32) -> u32 { record(10 + state); LOCK_STATUS }
    unsafe extern "C" fn finish(_pager: *mut u8, pages: u32) -> u32 { record(100 + pages); FINISH_STATUS }
    unsafe extern "C" fn cache(_pager: *mut u8) { record(2); }

    unsafe fn install_ops() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PAGER_TRUNCATE_HOST_OPS), PagerTruncateHostOps { page_count, sync, lock, finish, cache });
        LOG = [0; 4]; LOG_LEN = 0; SYNC_STATUS = 0; LOCK_STATUS = 0; FINISH_STATUS = 0;
    }
    unsafe fn restore_ops() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PAGER_TRUNCATE_HOST_OPS), DEFAULT_PAGER_TRUNCATE_HOST_OPS);
    }

    #[test]
    fn pager_truncate_image_rejects_and_truncates_memory_images() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut fixture = [0u32; 64];
        let pager = fixture.as_mut_ptr().cast::<u8>();
        unsafe {
            install_ops();
            pager.add(PAGER_ERROR).cast::<u32>().write(19);
            assert_eq!(pager_truncate_image(pager, 3), 19);
            assert_eq!(&LOG[..LOG_LEN], &[0]);
            LOG_LEN = 0;
            pager.add(PAGER_ERROR).cast::<u32>().write(0);
            pager.add(DATABASE_SIZE).cast::<u32>().write(3);
            assert_eq!(pager_truncate_image(pager, 3), 0);
            assert_eq!(&LOG[..LOG_LEN], &[0]);
            LOG_LEN = 0;
            pager.add(DATABASE_SIZE).cast::<u32>().write(9);
            pager.add(MEMORY_DATABASE).write(1);
            assert_eq!(pager_truncate_image(pager, 3), 0);
            assert_eq!(pager.add(DATABASE_SIZE).cast::<u32>().read(), 3);
            assert_eq!(&LOG[..LOG_LEN], &[0, 2]);
            restore_ops();
        }
    }

    #[test]
    fn pager_truncate_image_balances_leases_and_propagates_disk_failures() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut fixture = [0u32; 64];
        let pager = fixture.as_mut_ptr().cast::<u8>();
        unsafe {
            install_ops();
            pager.add(DATABASE_SIZE).cast::<u32>().write(9);
            pager.add(ACTIVITY).cast::<u32>().write(u32::MAX);
            SYNC_STATUS = 6;
            assert_eq!(pager_truncate_image(pager, 3), 6);
            assert_eq!(pager.add(ACTIVITY).cast::<u32>().read(), u32::MAX);
            assert_eq!(&LOG[..LOG_LEN], &[0, 1]);
            LOG_LEN = 0; SYNC_STATUS = 0; LOCK_STATUS = 8;
            assert_eq!(pager_truncate_image(pager, 3), 8);
            assert_eq!(pager.add(ACTIVITY).cast::<u32>().read(), u32::MAX);
            assert_eq!(&LOG[..LOG_LEN], &[0, 1, 14]);
            LOG_LEN = 0; LOCK_STATUS = 0; FINISH_STATUS = 11;
            assert_eq!(pager_truncate_image(pager, 3), 11);
            assert_eq!(pager.add(ACTIVITY).cast::<u32>().read(), u32::MAX);
            assert_eq!(&LOG[..LOG_LEN], &[0, 1, 14, 103]);
            restore_ops();
        }
    }
}
