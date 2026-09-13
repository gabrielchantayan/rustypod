//! `sqlite_os_file_size` — original: `FUN_0837db60` @ **0x0837db60**
//! (**12 bytes**, `0x0837db60..0x0837db6c`; the next separately linked
//! function starts at `0x0837db6c`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837db60  ldr  r2,[r0]           ; file->pMethods
//! 0837db64  ldr  r2,[r2,#24]       ; xFileSize at +0x18
//! 0837db68  bx   r2
//! ```
//!
//! **6 direct `bl` call sites, all unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds `0x082dd8d8`, `0x082ddf2c`,
//! `0x082de6f4`, `0x08365bac`, `0x0837e7fc`, and `0x08398ca0`; there are no
//! predicated direct calls or direct tail branches. The adjacent
//! `0x0837db44..0x0837dc18` forwarding family matches SQLite's
//! `sqlite3_io_methods`, whose `+0x18` slot is `xFileSize`. This wrapper has
//! no NULL guards; the file, its methods, and the slot must be readable and
//! callable.
//!
//! # Algorithm
//!
//! Tail-dispatch `file` and `out_size` to
//! `sqlite3_io_methods::xFileSize` at `+0x18`, returning the SQLite status
//! code unchanged.
//!
//! # Deliberate deviations
//!
//! `sqlite3_io_methods` is runtime data. Rust models the known method-table
//! prefix with native-width function pointers for host tests, while a
//! target-only assertion retains the `+0x18` ABI offset.

use super::os_write::SqliteFile;

/// sqlite_os_file_size — original: `FUN_0837db60` @ `0x0837db60` (12 bytes;
/// 6 unconditional direct `bl` call sites, binary-scanned).
///
/// Tail-dispatches SQLite's `sqlite3_io_methods::xFileSize` (`+0x18`) for
/// `file` and `out_size`, returning its status unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xFileSize` entry. `out_size` is forwarded
/// without validation, exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_file_size(file: *mut SqliteFile, out_size: *mut i64) -> i32 {
    ((*(*file).methods).file_size)(file, out_size)
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
        out_size: usize,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        out_size: 0,
    });

    unsafe extern "C" fn recording_file_size(file: *mut SqliteFile, out_size: *mut i64) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.out_size = out_size as usize;
        *out_size = i64::MIN;
        -0x2f
    }

    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 {
        panic!("unexpected xClose")
    }

    unsafe extern "C" fn unused_read(
        _file: *mut SqliteFile,
        _buffer: *mut u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 {
        panic!("unexpected xRead")
    }

    unsafe extern "C" fn unused_write(
        _file: *mut SqliteFile,
        _buffer: *const u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 {
        panic!("unexpected xWrite")
    }

    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 {
        panic!("unexpected xTruncate")
    }

    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 {
        panic!("unexpected xSync")
    }

    fn methods() -> SqliteIoMethods {
        SqliteIoMethods {
            version: 1,
            close: unused_close as SqliteCloseFn,
            read: unused_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
            truncate: unused_truncate as SqliteTruncateFn,
            sync: unused_sync as SqliteSyncFn,
            file_size: recording_file_size as SqliteFileSizeFn,
        }
    }

    #[test]
    fn forwards_exact_file_and_out_size_to_xfile_size() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = methods();
        let mut file = SqliteFile { methods: &methods };
        let mut out_size = i64::MAX;

        let status = unsafe { sqlite_os_file_size(&mut file, &mut out_size) };

        let recorder = RECORDER.lock();
        assert_eq!(status, -0x2f);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(recorder.out_size, core::ptr::addr_of_mut!(out_size) as usize);
        assert_eq!(out_size, i64::MIN);
    }
}
