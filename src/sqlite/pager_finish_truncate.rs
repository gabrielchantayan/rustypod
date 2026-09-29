//! SQLite pager truncate completion — `pager_truncate` tail from pager.c.
//!
//! `pager_finish_truncate` — original: `FUN_082de6c4` @ `0x082de6c4` (196
//! bytes; 4 direct plain-`bl` call sites, raw binary-scanned; no predicated
//! `bl` calls). Raw ARM spans `0x082de6c4..0x082de788`; the separately entered
//! `pager_truncate_cache` begins at `0x082de78c` after a four-byte zero literal.
//! When the pager state byte exceeds three and its file has methods, it obtains
//! the current file length, calculates `page_size * page_count`, truncates a
//! longer file or extends a shorter one by writing one zero byte, then commits
//! the page count and discards cached pages.
//!
//! Deliberate deviation: `pager_truncate_cache` remains unported, so target
//! builds call its fixed retailOS address; host tests install a recording seam.

use super::os_file_size::sqlite_os_file_size;
use super::os_truncate::sqlite_os_truncate;
use super::os_write::{sqlite_os_write, SqliteFile};

const PAGE_COUNT: usize = 0x24;
const PAGE_SIZE: usize = 0x40;
const FILE: usize = 0x6c;

type PagerTruncateCache = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_truncate_cache(pager: *mut u8) {
    let helper: PagerTruncateCache = core::mem::transmute(0x082d_e78cusize);
    helper(pager);
}

#[cfg(not(target_os = "none"))]
static mut PAGER_TRUNCATE_CACHE: PagerTruncateCache = unavailable_pager_truncate_cache;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_truncate_cache(_pager: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pager_truncate_cache(pager: *mut u8) {
    (core::ptr::read_volatile(core::ptr::addr_of!(PAGER_TRUNCATE_CACHE)))(pager);
}

/// `pager_finish_truncate` — original: `FUN_082de6c4` @ `0x082de6c4` (196
/// bytes; 4 direct plain-`bl` call sites; no predicated calls).
///
/// # Safety
/// `pager` must be a writable target-layout Pager with a valid `sqlite3_file`
/// pointer at `+0x6c`. Its file methods and cache-truncate helper must be
/// callable for the path selected by the current file size.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_finish_truncate")]
#[inline(never)]
pub unsafe extern "C" fn pager_finish_truncate(pager: *mut u8, page_count: u32) -> i32 {
    if pager.add(0x0e).read() > 3 {
        let file = pager.add(FILE).cast::<u32>().read() as usize as *mut SqliteFile;
        if !(*file).methods.is_null() {
            let mut file_size = 0i64;
            let status = sqlite_os_file_size(file, &mut file_size);
            if status != 0 {
                return status;
            }

            let target_size = (pager.add(PAGE_SIZE).cast::<i32>().read() as i64) * page_count as i64;
            if target_size != file_size {
                let status = if target_size < file_size {
                    sqlite_os_truncate(file, target_size)
                } else {
                    sqlite_os_write(file, core::ptr::addr_of!(ZERO), 1, target_size - 1)
                };
                if status != 0 {
                    return status;
                }
            }
        }
    }

    pager.add(PAGE_COUNT).cast::<u32>().write(page_count);
    pager_truncate_cache(pager);
    0
}

static ZERO: u8 = 0;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use super::super::os_write::SqliteIoMethods;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FILE_SIZE: i64 = 0;
    static mut FILE_STATUS: i32 = 0;
    static mut TRUNCATE: Option<i64> = None;
    static mut WRITE: Option<(u32, i64)> = None;
    static mut CACHE_CALLS: u32 = 0;

    unsafe extern "C" fn close(_file: *mut SqliteFile) -> i32 { 0 }
    unsafe extern "C" fn read(_file: *mut SqliteFile, _buffer: *mut u8, _amount: u32, _offset: i64) -> i32 { 0 }
    unsafe extern "C" fn write(_file: *mut SqliteFile, buffer: *const u8, amount: u32, offset: i64) -> i32 {
        assert_eq!(buffer.read(), 0); WRITE = Some((amount, offset)); 0
    }
    unsafe extern "C" fn truncate(_file: *mut SqliteFile, size: i64) -> i32 { TRUNCATE = Some(size); 0 }
    unsafe extern "C" fn sync(_file: *mut SqliteFile, _flags: u32) -> i32 { 0 }
    unsafe extern "C" fn file_size(_file: *mut SqliteFile, out: *mut i64) -> i32 { out.write(FILE_SIZE); FILE_STATUS }
    unsafe extern "C" fn cache(_pager: *mut u8) { CACHE_CALLS += 1; }

    static METHODS: SqliteIoMethods = SqliteIoMethods { version: 1, close, read, write, truncate, sync, file_size };

    unsafe fn reset() {
        FILE_SIZE = 0; FILE_STATUS = 0; TRUNCATE = None; WRITE = None; CACHE_CALLS = 0;
        core::ptr::write_volatile(addr_of_mut!(PAGER_TRUNCATE_CACHE), cache);
    }

    #[test]
    fn pager_finish_truncate_updates_cache_only_after_successful_file_resize() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PAGER_FINISH_TRUNCATE, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let pager = slab;
            let file = slab.add(0x200).cast::<SqliteFile>();
            file.write(SqliteFile { methods: addr_of!(METHODS) });
            pager.add(FILE).cast::<u32>().write(file as usize as u32);
            pager.add(PAGE_SIZE).cast::<i32>().write(512);
            pager.add(PAGE_COUNT).cast::<u32>().write(99);
            pager.add(0x0e).write(4);
            reset(); FILE_STATUS = 5;
            assert_eq!(pager_finish_truncate(pager, 3), 5);
            assert_eq!(pager.add(PAGE_COUNT).cast::<u32>().read(), 99);
            assert_eq!(CACHE_CALLS, 0);
            reset(); FILE_SIZE = 4096;
            assert_eq!(pager_finish_truncate(pager, 3), 0);
            assert_eq!(TRUNCATE, Some(1536)); assert_eq!(WRITE, None);
            assert_eq!(pager.add(PAGE_COUNT).cast::<u32>().read(), 3); assert_eq!(CACHE_CALLS, 1);
            reset(); pager.add(0x0e).write(3);
            assert_eq!(pager_finish_truncate(pager, 7), 0);
            assert_eq!(TRUNCATE, None); assert_eq!(WRITE, None); assert_eq!(CACHE_CALLS, 1);
            pager.add(0x0e).write(4);
            reset(); FILE_SIZE = 512;
            assert_eq!(pager_finish_truncate(pager, 3), 0);
            assert_eq!(TRUNCATE, None); assert_eq!(WRITE, Some((1, 1535))); assert_eq!(CACHE_CALLS, 1);
        }
    }
}
