//! SQLite pager database-page reader — `FUN_083655cc` @ **0x083655cc**
//! (**112 bytes**, `0x083655cc..0x0836563c`; the next separately linked
//! function begins at `0x08365640`).
//!
//! Raw A32 decoding finds two inbound plain `bl` instructions (0x082dd1e0 and
//! 0x082ddc98), no inbound predicated `bl` instructions, one outbound plain
//! `bl` to `sqlite_os_read`, and one outbound `bleq` to the `__rt_memcpy` ROM
//! veneer. The trailing word at 0x0836563c is the `SQLITE_IOERR_READ` literal.
//!
//! # Algorithm
//!
//! If the pager's primary file field is null, return `SQLITE_IOERR_READ`.
//! Otherwise read one page into `page->pData` at signed offset
//! `(page_number - 1) * pager->pageSize`. For page one, copy its 16-byte
//! database-header portion at `pData + 0x18` to the pager's header cache at
//! `+0xe8`, even when the read reports an error.
//!
//! # Deliberate deviations
//!
//! The retail `bleq` reaches the known ROM `__rt_memcpy` veneer
//! (0x08037db0 -> 0x22000020); this port calls the equivalent Rust runtime
//! implementation directly. Target-layout pointers remain `u32` words so
//! host pointer width cannot alter pager or page field offsets.

use crate::libc::rt_memcpy::__rt_memcpy;
use super::os_read::sqlite_os_read;
use super::os_write::SqliteFile;

const SQLITE_IOERR_READ: i32 = 0x20a;
const PAGER_PAGE_SIZE: usize = 0x40 / 4;
const PAGER_FILE: usize = 0x6c / 4;
const PAGER_HEADER: usize = 0xe8;
const PAGE_DATA: usize = 0x34 / 4;

/// Reads one database page through the pager's primary SQLite file.
///
/// # Safety
///
/// `pager` and `page` must name writable target-layout objects. When the
/// pager file word is nonzero, it must name a valid [`SqliteFile`] and the
/// page data word must name a buffer valid for the pager page size.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pager_read_db_page(pager: *mut u32, page: *mut u32, page_number: u32) -> i32 {
    let file = pager.add(PAGER_FILE).read() as usize as *mut SqliteFile;
    if file.is_null() {
        return SQLITE_IOERR_READ;
    }

    let page_size = pager.add(PAGER_PAGE_SIZE).read();
    let data = page.add(PAGE_DATA).read() as usize as *mut u8;
    let offset = i64::from(page_size as i32) * i64::from(page_number.wrapping_sub(1));
    let status = sqlite_os_read(file, data, page_size, offset);
    if page_number == 1 {
        __rt_memcpy(pager.cast::<u8>().add(PAGER_HEADER), data.add(0x18), 16);
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_write::{SqliteCloseFn, SqliteFileSizeFn, SqliteIoMethods, SqliteReadFn, SqliteSyncFn, SqliteTruncateFn, SqliteWriteFn};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    const SLAB_LEN: usize = 0x1000;
    const PAGE: usize = 0x200;
    const DATA: usize = 0x600;
    static LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static STATUS: AtomicI32 = AtomicI32::new(0);
    static LAST_FILE: AtomicUsize = AtomicUsize::new(0);
    static LAST_AMOUNT: AtomicU32 = AtomicU32::new(0);
    static LAST_OFFSET: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn record_read(file: *mut SqliteFile, buffer: *mut u8, amount: u32, offset: i64) -> i32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_FILE.store(file as usize, Ordering::Relaxed);
        LAST_AMOUNT.store(amount, Ordering::Relaxed);
        LAST_OFFSET.store(offset as i32, Ordering::Relaxed);
        for index in 0..amount as usize { buffer.add(index).write(index as u8); }
        STATUS.load(Ordering::Relaxed)
    }
    unsafe extern "C" fn unused_close(_: *mut SqliteFile) -> i32 { 0 }
    unsafe extern "C" fn unused_write(_: *mut SqliteFile, _: *const u8, _: u32, _: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_truncate(_: *mut SqliteFile, _: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_sync(_: *mut SqliteFile, _: u32) -> i32 { 0 }
    unsafe extern "C" fn unused_file_size(_: *mut SqliteFile, _: *mut i64) -> i32 { 0 }

    static METHODS: SqliteIoMethods = SqliteIoMethods {
        version: 1,
        close: unused_close as SqliteCloseFn,
        read: record_read as SqliteReadFn,
        write: unused_write as SqliteWriteFn,
        truncate: unused_truncate as SqliteTruncateFn,
        sync: unused_sync as SqliteSyncFn,
        file_size: unused_file_size as SqliteFileSizeFn,
    };

    unsafe fn fixture() -> Option<(*mut u32, *mut u32, *mut SqliteFile)> {
        let base = try_map_u32_slab(hints::SQLITE_PAGER_READ_DB_PAGE, SLAB_LEN)?;
        base.write_bytes(0, SLAB_LEN);
        let pager = base.cast::<u32>();
        let page = base.add(PAGE).cast::<u32>();
        let data = base.add(DATA);
        let file = base.add(0x400).cast::<SqliteFile>();
        file.write(SqliteFile { methods: &METHODS });
        pager.add(PAGER_PAGE_SIZE).write(64);
        pager.add(PAGER_FILE).write(file as usize as u32);
        page.add(PAGE_DATA).write(data as usize as u32);
        Some((pager, page, file))
    }

    #[test]
    fn reads_page_at_page_relative_offset_and_caches_page_one_header_after_error() {
        let _lock = LOCK.lock();
        let Some((pager, page, file)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        CALLS.store(0, Ordering::Relaxed);
        STATUS.store(-522, Ordering::Relaxed);
        unsafe { pager.cast::<u8>().add(PAGER_HEADER).write_bytes(0xaa, 16); }

        assert_eq!(unsafe { pager_read_db_page(pager, page, 1) }, -522);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_FILE.load(Ordering::Relaxed), file as usize);
        assert_eq!(LAST_AMOUNT.load(Ordering::Relaxed), 64);
        assert_eq!(LAST_OFFSET.load(Ordering::Relaxed), 0);
        assert_eq!(unsafe { core::slice::from_raw_parts(pager.cast::<u8>().add(PAGER_HEADER), 16) }, &[0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]);
    }

    #[test]
    fn null_file_fails_without_reading_or_changing_header() {
        let _lock = LOCK.lock();
        let Some((pager, page, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        CALLS.store(0, Ordering::Relaxed);
        unsafe { pager.add(PAGER_FILE).write(0); pager.cast::<u8>().add(PAGER_HEADER).write_bytes(0x5a, 16); }

        assert_eq!(unsafe { pager_read_db_page(pager, page, 3) }, SQLITE_IOERR_READ);
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert!(unsafe { core::slice::from_raw_parts(pager.cast::<u8>().add(PAGER_HEADER), 16) }.iter().all(|&byte| byte == 0x5a));
    }

    #[test]
    fn later_page_uses_signed_page_size_offset_without_header_copy() {
        let _lock = LOCK.lock();
        let Some((pager, page, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        CALLS.store(0, Ordering::Relaxed);
        STATUS.store(0, Ordering::Relaxed);
        unsafe { pager.add(PAGER_PAGE_SIZE).write((-64i32) as u32); pager.cast::<u8>().add(PAGER_HEADER).write_bytes(0x33, 16); }

        assert_eq!(unsafe { pager_read_db_page(pager, page, 3) }, 0);
        assert_eq!(LAST_OFFSET.load(Ordering::Relaxed), -128);
        assert!(unsafe { core::slice::from_raw_parts(pager.cast::<u8>().add(PAGER_HEADER), 16) }.iter().all(|&byte| byte == 0x33));
    }
}
