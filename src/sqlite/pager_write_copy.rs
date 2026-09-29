//! Mark a SQLite page writable before copying into it — retailOS
//! `FUN_082c4eec` at `0x082c4eec` (76 bytes).
//!
//! Raw ARM words establish the true extent: `push {r4-r6,lr}` starts at
//! `0x082c4eec`, `pop {r4-r6,pc}` ends it at `0x082c4f34`, and the next
//! independent function starts at `0x082c4f38`. The body has two plain,
//! unconditional `bl` calls and no predicated calls: `sqlite3PagerWrite` at
//! `0x0837ef64`, followed by the `__rt_memcpy` veneer at `0x08037db0`.
//! Decoding the whole image finds two inbound plain `bl` calls
//! (`0x082b2a5c`, `0x082b2be4`) and no predicated inbound calls.
//!
//! When `mark_writable` is nonzero, this calls `sqlite3PagerWrite(page)` and
//! returns its nonzero status without reading either copy buffer. Otherwise,
//! or after a successful write mark, it copies `byte_count` bytes from `src`
//! to `dst` and returns zero.
//!
//! Deliberate deviations: the ROM memcpy veneer is called through the
//! established Rust `__rt_memcpy` seam. `sqlite3PagerWrite` remains
//! retailOS-owned; host tests replace that target-only absolute call with a
//! private boundary.

use crate::libc::rt_memcpy::__rt_memcpy;

type PagerWrite = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_write(page: *mut u8) -> i32 {
    let write: PagerWrite = core::mem::transmute(0x0837_ef64usize);
    write(page)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_write(_page: *mut u8) -> i32 {
    11
}

#[cfg(not(target_os = "none"))]
static mut PAGER_WRITE: PagerWrite = unavailable_pager_write;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_pager_write(page: *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PAGER_WRITE))(page)
}

/// `sqlite_pager_write_copy` — original: `FUN_082c4eec` @ `0x082c4eec`
/// (76 bytes; two direct plain-`bl` calls).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_pager_write_copy")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_pager_write_copy(
    dst: *mut u8,
    src: *const u8,
    byte_count: usize,
    mark_writable: i32,
    page: *mut u8,
) -> i32 {
    if mark_writable != 0 {
        #[cfg(target_os = "none")]
        let status = pager_write(page);
        #[cfg(not(target_os = "none"))]
        let status = host_pager_write(page);
        if status != 0 {
            return status;
        }
    }
    __rt_memcpy(dst, src, byte_count);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PAGER_STATUS: i32 = 0;
    static mut PAGER_CALLS: u32 = 0;
    static mut PAGER_PAGE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_pager_write(page: *mut u8) -> i32 {
        PAGER_CALLS += 1;
        PAGER_PAGE = page;
        PAGER_STATUS
    }

    unsafe fn fixture() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock();
        PAGER_WRITE = recording_pager_write;
        PAGER_STATUS = 0;
        PAGER_CALLS = 0;
        PAGER_PAGE = core::ptr::null_mut();
        lock
    }

    #[test]
    fn successful_write_mark_precedes_copy() {
        let _lock = unsafe { fixture() };
        let source = [1, 2, 3, 4];
        let mut destination = [0; 4];
        let mut page = 0u8;
        assert_eq!(unsafe {
            sqlite_pager_write_copy(destination.as_mut_ptr(), source.as_ptr(), 4, 1, &mut page)
        }, 0);
        assert_eq!(destination, source);
        assert_eq!(unsafe { PAGER_CALLS }, 1);
        assert_eq!(unsafe { PAGER_PAGE }, &mut page as *mut u8);
    }

    #[test]
    fn write_failure_leaves_destination_untouched() {
        let _lock = unsafe { fixture() };
        unsafe { PAGER_STATUS = 5; }
        let source = [1, 2, 3];
        let mut destination = [9, 9, 9];
        assert_eq!(unsafe {
            sqlite_pager_write_copy(destination.as_mut_ptr(), source.as_ptr(), 3, 1, core::ptr::null_mut())
        }, 5);
        assert_eq!(destination, [9, 9, 9]);
        assert_eq!(unsafe { PAGER_CALLS }, 1);
    }

    #[test]
    fn unmarked_copy_skips_pager_even_at_zero_length() {
        let _lock = unsafe { fixture() };
        let source = [7u8];
        let mut destination = [8u8];
        assert_eq!(unsafe {
            sqlite_pager_write_copy(destination.as_mut_ptr(), source.as_ptr(), 0, 0, core::ptr::null_mut())
        }, 0);
        assert_eq!(destination, [8]);
        assert_eq!(unsafe { PAGER_CALLS }, 0);
    }
}
