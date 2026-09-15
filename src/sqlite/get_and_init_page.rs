//! Acquire and initialize a SQLite b-tree page.
//!
//! `get_and_init_page` — retailOS `FUN_082d05d0` at `0x082d05d0` (96 bytes,
//! `0x082d05d0..0x082d0630`). Raw ARM establishes the following three direct
//! outbound `bl` calls: `context_child_handle_acquire` at `0x08371418`, the
//! still-stock page initializer at `0x08371478`, and
//! `release_via_field_0x48` at `0x0836761c`. A complete image scan finds five
//! inbound calls, all unconditional plain `bl`; there are no predicated calls.
//!
//! A zero page number returns `SQLITE_CORRUPT` (11) without touching the output.
//! Otherwise the function acquires the page handle. A newly acquired page (byte
//! +0 clear) is initialized; initialization failure releases that handle and
//! clears the output word. Existing initialized pages and acquisition failures
//! pass their status through unchanged.
//!
//! Deliberate deviation: page initialization at `0x08371478` remains stock. On
//! target it is a direct call; host tests inject all three external operations
//! because target pointers are four-byte words while host pointers are wider.

use crate::cxx::context_child_handle::context_child_handle_acquire;
use crate::cxx::release::release_via_field_0x48;

const SQLITE_CORRUPT: u32 = 11;

type AcquirePageFn = unsafe extern "C" fn(*mut u8, u32, *mut u32, u32) -> u32;
type InitializePageFn = unsafe extern "C" fn(u32, u32) -> u32;
type ReleasePageFn = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn acquire_page(owner: *mut u8, page_number: u32, out_page: *mut u32) -> u32 {
    context_child_handle_acquire(owner, page_number, out_page.cast(), 0)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_page(page: u32, flags: u32) -> u32 {
    let initialize: InitializePageFn = core::mem::transmute(0x0837_1478usize);
    initialize(page, flags)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_page(page: u32) {
    release_via_field_0x48(page as usize as *mut u8);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps { acquire: AcquirePageFn, initialize: InitializePageFn, release: ReleasePageFn }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_acquire(_owner: *mut u8, _page: u32, _out: *mut u32, _mode: u32) -> u32 { SQLITE_CORRUPT }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_initialize(_page: u32, _flags: u32) -> u32 { SQLITE_CORRUPT }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_page: u32) {}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps { acquire: unavailable_acquire, initialize: unavailable_initialize, release: unavailable_release };

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::read_volatile(core::ptr::addr_of!(HOST_OPS)) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn acquire_page(owner: *mut u8, page: u32, out: *mut u32) -> u32 { (host_ops().acquire)(owner, page, out, 0) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_page(page: u32, flags: u32) -> u32 { (host_ops().initialize)(page, flags) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_page(page: u32) { (host_ops().release)(page) }

/// `get_and_init_page` — original: `FUN_082d05d0` @ `0x082d05d0` (96 bytes;
/// five verified inbound unconditional `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn get_and_init_page(owner: *mut u8, page_number: u32, out_page: *mut u32, flags: u32) -> u32 {
    if page_number == 0 { return SQLITE_CORRUPT; }
    let mut status = acquire_page(owner, page_number, out_page);
    if status == 0 && (*(out_page as *const u32) as usize as *const u8).read() == 0 {
        status = initialize_page(out_page.read(), flags);
        if status != 0 { release_page(out_page.read()); out_page.write(0); }
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    static LOCK: Mutex<()> = Mutex::new(());
    static PAGE_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_GET_AND_INIT_PAGE, 0x1000).map(|page| page as usize)
    });
    static mut RESULT: u32 = 0;
    static mut PAGE: u32 = 0;
    static mut INITIALIZE: u32 = 0;
    static mut RELEASED: u32 = 0;
    unsafe extern "C" fn acquire(_owner: *mut u8, _page: u32, out: *mut u32, _mode: u32) -> u32 { out.write(PAGE); RESULT }
    unsafe extern "C" fn initialize(_page: u32, _flags: u32) -> u32 { INITIALIZE }
    unsafe extern "C" fn release(page: u32) { RELEASED = page; }
    fn setup(result: u32, page: u32, initialize_result: u32) {
        unsafe { RESULT = result; PAGE = page; INITIALIZE = initialize_result; RELEASED = 0; HOST_OPS = HostOps { acquire, initialize, release }; }
    }
    #[test]
    fn rejects_zero_page_without_writing_output() { let _lock = LOCK.lock(); setup(0, 0, 0); let mut out = 0xfeed_beef; assert_eq!(unsafe { get_and_init_page(core::ptr::null_mut(), 0, &mut out, 9) }, 11); assert_eq!(out, 0xfeed_beef); }
    #[test]
    fn initialization_failure_releases_and_clears_output() {
        let _lock = LOCK.lock(); let Some(page) = *PAGE_FIXTURE else { assert!(note_missing_u32_fixture("get_and_init_page")); return; };
        unsafe { (page as *mut u8).write(0); } setup(0, page as u32, 11); let mut out = 0;
        assert_eq!(unsafe { get_and_init_page(core::ptr::null_mut(), 4, &mut out, 7) }, 11); assert_eq!(out, 0); assert_eq!(unsafe { RELEASED }, page as u32);
    }
    #[test]
    fn initialized_page_skips_initializer() {
        let _lock = LOCK.lock(); let Some(page) = *PAGE_FIXTURE else { assert!(note_missing_u32_fixture("get_and_init_page")); return; };
        unsafe { (page as *mut u8).write(1); } setup(0, page as u32, 11); let mut out = 0;
        assert_eq!(unsafe { get_and_init_page(core::ptr::null_mut(), 4, &mut out, 0) }, 0); assert_eq!(out, page as u32); assert_eq!(unsafe { RELEASED }, 0);
    }
}
