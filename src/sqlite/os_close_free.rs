//! `sqlite_os_close_free` — original: `FUN_0837db18` @ **0x0837db18**
//! (**32 bytes**, `0x0837db18..0x0837db38`; the next separately linked
//! function begins at `0x0837db38` with a literal-load veneer).
//!
//! Raw ARM decoding gives two outbound plain `bl` calls and no predicated
//! `bl`: `sqlite_os_close` @ `0x0837dae8`, then `tracked_free` @
//! `0x083906f4`. It saves the close status in `r4` across the free and returns
//! that status. This is SQLite's `sqlite3OsCloseFree`: close the file's VFS
//! handle, release the file object, and preserve the close result.
//!
//! # Deliberate deviations
//!
//! The retail function makes two direct ARM calls. Rust invokes the existing
//! ports directly; the private helper accepts the free operation so host tests
//! can observe ordering without fabricating a tracked allocator block.

use crate::heap::tracked::tracked_free;
use crate::sqlite::os_close::sqlite_os_close;
use crate::sqlite::os_write::SqliteFile;

/// Close a SQLite file object, release its storage, and return the close status.
///
/// # Safety
///
/// `file` must meet [`sqlite_os_close`]'s requirements and must be a live
/// tracked-allocation payload accepted by [`tracked_free`]. It is released even
/// when closing reports an error, exactly as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_close_free(file: *mut SqliteFile) -> i32 {
    unsafe { sqlite_os_close_free_with(file, tracked_free) }
}

unsafe fn sqlite_os_close_free_with(
    file: *mut SqliteFile,
    free: unsafe extern "C" fn(*mut u8),
) -> i32 {
    let status = unsafe { sqlite_os_close(file) };
    unsafe { free(file.cast()) };
    status
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
    static EVENTS: Mutex<std::vec::Vec<&'static str>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn close(file: *mut SqliteFile) -> i32 {
        assert!(!(*file).methods.is_null());
        EVENTS.lock().push("close");
        -7
    }

    unsafe extern "C" fn free(file: *mut u8) {
        assert!(!file.is_null());
        EVENTS.lock().push("free");
    }

    unsafe extern "C" fn unused_read(
        _file: *mut SqliteFile,
        _buffer: *mut u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 { 0 }
    unsafe extern "C" fn unused_write(
        _file: *mut SqliteFile,
        _buffer: *const u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 { 0 }
    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 { 0 }
    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 { 0 }

    fn methods() -> SqliteIoMethods {
        SqliteIoMethods {
            version: 2,
            close: close as SqliteCloseFn,
            read: unused_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
            truncate: unused_truncate as SqliteTruncateFn,
            sync: unused_sync as SqliteSyncFn,
            file_size: unused_file_size as SqliteFileSizeFn,
        }
    }

    #[test]
    fn closes_before_freeing_and_preserves_close_status() {
        let _lock = LOCK.lock();
        EVENTS.lock().clear();
        let methods = methods();
        let mut file = SqliteFile { methods: &methods };

        let status = unsafe { sqlite_os_close_free_with(&mut file, free) };

        assert_eq!(status, -7);
        assert!(file.methods.is_null());
        assert_eq!(*EVENTS.lock(), ["close", "free"]);
    }

    #[test]
    fn frees_an_already_closed_file_and_returns_ok() {
        let _lock = LOCK.lock();
        EVENTS.lock().clear();
        let mut file = SqliteFile { methods: core::ptr::null() };

        let status = unsafe { sqlite_os_close_free_with(&mut file, free) };

        assert_eq!(status, 0);
        assert_eq!(*EVENTS.lock(), ["free"]);
    }
}
