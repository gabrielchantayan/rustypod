//! `sqlite_os_sector_size` — original: `FUN_0837dbc0` @ **0x0837dbc0**.
//!
//! The raw ARM body is 24 bytes (`0x0837dbc0..0x0837dbd8`); the next separately
//! linked function starts at `0x0837dbd8`.
//!
//! ```text
//! 0837dbc0  ldr   r1,[r0]          ; file->pMethods
//! 0837dbc4  ldr   r1,[r1,#0x2c]    ; xSectorSize
//! 0837dbc8  cmp   r1,#0
//! 0837dbcc  moveq r0,#0
//! 0837dbd0  bxne  r1
//! 0837dbd4  bx    lr
//! ```
//!
//! Two direct, unconditional `bl` call sites target this function
//! (`0x08369058`, `0x0837e584`); there are no predicated direct `bl` calls.
//!
//! # Algorithm
//!
//! Load `sqlite3_file::pMethods`, then return 512 when its `xSectorSize` slot
//! at `+0x2c` is null; otherwise tail-dispatch `xSectorSize(file)`.
//!
//! # Deliberate deviations
//!
//! The shared recovered method-table prefix ends at `+0x18`, so this port reads
//! the `+0x2c` entry by native-width word index. That preserves the target slot
//! while allowing host tests to use callable native-width function pointers.

use super::os_write::SqliteFile;

/// ABI of SQLite's `sqlite3_io_methods::xSectorSize` entry.
pub type SqliteSectorSizeFn = unsafe extern "C" fn(*mut SqliteFile) -> u32;

/// Word index of `sqlite3_io_methods::xSectorSize` (`+0x2c` on target).
const SECTOR_SIZE_WORD: usize = 11;

/// `sqlite_os_sector_size` — original: `FUN_0837dbc0` @ `0x0837dbc0` (24
/// bytes; two unconditional direct `bl` call sites; no predicated direct `bl`).
///
/// Returns 512 for a null `xSectorSize` slot; otherwise tail-dispatches the
/// `sqlite3_io_methods::xSectorSize` entry at `+0x2c`.
///
/// # Safety
///
/// `file` must point to a readable `sqlite3_file` whose methods field names a
/// readable method table through its `+0x2c` slot. A non-null slot must be a
/// callable `SqliteSectorSizeFn`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_sector_size(file: *mut SqliteFile) -> u32 {
    let slot = ((*file).methods as *const usize).add(SECTOR_SIZE_WORD).read();
    if slot == 0 {
        512
    } else {
        let sector_size: SqliteSectorSizeFn = core::mem::transmute(slot);
        sector_size(file)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_write::{
        SqliteCloseFn, SqliteFileSizeFn, SqliteIoMethods, SqliteReadFn, SqliteSyncFn,
        SqliteTruncateFn, SqliteWriteFn,
    };
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut FILE: usize = 0;

    unsafe extern "C" fn recording_sector_size(file: *mut SqliteFile) -> u32 {
        CALLS += 1;
        FILE = file as usize;
        4096
    }

    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 { 0 }
    unsafe extern "C" fn unused_read(_file: *mut SqliteFile, _buffer: *mut u8, _amount: u32, _offset: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_write(_file: *mut SqliteFile, _buffer: *const u8, _amount: u32, _offset: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 { 0 }
    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 { 0 }

    #[repr(C)]
    struct FullMethods {
        prefix: SqliteIoMethods,
        lock: usize,
        unlock: usize,
        check_reserved_lock: usize,
        file_control: usize,
        sector_size: usize,
    }

    fn methods(sector_size: usize) -> FullMethods {
        FullMethods {
            prefix: SqliteIoMethods {
                version: 1,
                close: unused_close as SqliteCloseFn,
                read: unused_read as SqliteReadFn,
                write: unused_write as SqliteWriteFn,
                truncate: unused_truncate as SqliteTruncateFn,
                sync: unused_sync as SqliteSyncFn,
                file_size: unused_file_size as SqliteFileSizeFn,
            },
            lock: 1,
            unlock: 2,
            check_reserved_lock: 3,
            file_control: 4,
            sector_size,
        }
    }

    #[test]
    fn returns_512_without_calling_a_null_sector_size_slot() {
        let _lock = LOCK.lock();
        let full = methods(0);
        let mut file = SqliteFile { methods: core::ptr::addr_of!(full.prefix) };

        unsafe {
            CALLS = 0;
            assert_eq!(sqlite_os_sector_size(&mut file), 512);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn dispatches_only_the_sector_size_slot() {
        let _lock = LOCK.lock();
        let full = methods(recording_sector_size as SqliteSectorSizeFn as usize);
        let mut file = SqliteFile { methods: core::ptr::addr_of!(full.prefix) };

        unsafe {
            CALLS = 0;
            FILE = 0;
            assert_eq!(sqlite_os_sector_size(&mut file), 4096);
            assert_eq!(CALLS, 1);
            assert_eq!(FILE, core::ptr::addr_of_mut!(file) as usize);
        }
    }
}
