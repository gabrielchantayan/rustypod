//! `sqlite_os_truncate` — original: `FUN_0837dbec` @ **0x0837dbec**
//! (**12 bytes**, `0x0837dbec..0x0837dbf8`; the next separately linked
//! function starts at `0x0837dbf8`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837dbec  ldr  r1,[r0]       ; methods = file->pMethods
//! 0837dbf0  ldr  r1,[r1,#16]   ; methods->xTruncate at +0x10
//! 0837dbf4  bx   r1            ; tail-dispatch xTruncate(file, size)
//! ```
//!
//! **4 direct call sites, all unconditional plain `bl`**: binary decoding
//! finds calls at `0x082bd820`, `0x082ddb20`, `0x082de740`, and `0x08398cc8`;
//! no predicated `bl` or tail branch targets this wrapper. The target occurs in
//! no aligned image data word. The adjacent `0x0837db44..0x0837dc18`
//! forwarding family is SQLite's `sqlite3_io_methods`; slot `+0x10` is
//! `xTruncate`. Like the raw code, this wrapper performs no NULL checks.
//!
//! # Algorithm
//!
//! Forward `file` and `size` to the file method table's `xTruncate` entry at
//! `+0x10`, returning SQLite's status code unchanged.
//!
//! # Deliberate deviations
//!
//! LLVM retains the terminal `bx`, but surrounds it with a frame-pointer save
//! and restore, producing six instructions rather than the retail three.
//! Native-width host pointers change the host table layout; the shared table
//! asserts the `+0x10` slot on 32-bit targets.

use super::os_write::SqliteFile;

/// sqlite_os_truncate — original: `FUN_0837dbec` @ `0x0837dbec` (12 bytes; 4
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Dispatches SQLite's `sqlite3_io_methods::xTruncate` (`+0x10`) for `file`,
/// forwarding `size` and returning the method status unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xTruncate` entry. Neither pointer is NULL-checked,
/// exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_truncate(file: *mut SqliteFile, size: i64) -> i32 {
    ((*(*file).methods).truncate)(file, size)
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

    #[derive(Default)]
    struct Recorder {
        calls: u32,
        file: usize,
        size: i64,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        size: 0,
    });

    unsafe extern "C" fn recording_truncate(file: *mut SqliteFile, size: i64) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.size = size;
        -0x184
    }

    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 { panic!("unexpected xClose") }
    unsafe extern "C" fn unused_read(_file: *mut SqliteFile, _buffer: *mut u8, _amount: u32, _offset: i64) -> i32 { panic!("unexpected xRead") }
    unsafe extern "C" fn unused_write(_file: *mut SqliteFile, _buffer: *const u8, _amount: u32, _offset: i64) -> i32 { panic!("unexpected xWrite") }
    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 { panic!("unexpected xSync") }
    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 { panic!("unexpected xFileSize") }

    fn methods() -> SqliteIoMethods {
        SqliteIoMethods {
            version: 1,
            close: unused_close as SqliteCloseFn,
            read: unused_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
            truncate: recording_truncate as SqliteTruncateFn,
            sync: unused_sync as SqliteSyncFn,
            file_size: unused_file_size as SqliteFileSizeFn,
        }
    }

    #[test]
    fn forwards_extreme_truncate_sizes_to_xtruncate() {
        let _lock = LOCK.lock();
        for size in [0, -1, i64::MIN, i64::MAX] {
            *RECORDER.lock() = Recorder::default();
            let methods = methods();
            let mut file = SqliteFile { methods: &methods };

            let status = unsafe { sqlite_os_truncate(&mut file, size) };

            let recorder = RECORDER.lock();
            assert_eq!(status, -0x184);
            assert_eq!(recorder.calls, 1);
            assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
            assert_eq!(recorder.size, size);
        }
    }
}
