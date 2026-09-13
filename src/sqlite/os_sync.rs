//! `sqlite_os_sync` — original: `FUN_0837dbe0` @ **0x0837dbe0**
//! (**12 bytes**, `0x0837dbe0..0x0837dbec`; the next separately linked
//! function begins at `0x0837dbec`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837dbe0  ldr  r2,[r0]       ; methods = file->pMethods
//! 0837dbe4  ldr  r2,[r2,#20]   ; methods->xSync (io_methods +0x14)
//! 0837dbe8  bx   r2            ; tail-dispatch xSync(file, flags)
//! ```
//!
//! **6 direct call sites, all unconditional plain `bl`**: binary-scanning
//! every ARM B/BL word in `osos.dec` finds calls at `0x082bd914`,
//! `0x082ddb54`, `0x0837dfd8`, `0x08392a74`, `0x08392ac8`, and
//! `0x083973c0`; no predicated call or tail branch targets this wrapper.
//! The target address occurs in no image data word. The surrounding
//! `0x0837db44..0x0837dc18` forwarding family matches SQLite's
//! `sqlite3_io_methods`: after the version word, slot `+0x14` is `xSync`.
//! Like the raw code, this wrapper performs no NULL checks.
//!
//! # Algorithm
//!
//! Forward `file` and `flags` to the file method table's `xSync` entry at
//! `+0x14`, returning SQLite's status code unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM body tail-branches to `xSync`. LLVM retains that terminal `bx` for
//! this port, but surrounds it with a frame-pointer save and restore, so the
//! generated target body is six instructions rather than the retail three.
//! The runtime method table is represented by native-width function pointers
//! on hosts; the slot is asserted at `+0x14` on 32-bit target builds.

use super::os_write::SqliteFile;

/// sqlite_os_sync — original: `FUN_0837dbe0` @ `0x0837dbe0` (12 bytes; 6
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Dispatches SQLite's `sqlite3_io_methods::xSync` (`+0x14`) for `file`,
/// forwarding `flags` and returning the method status unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xSync` entry. Neither pointer is NULL-checked,
/// exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_sync(file: *mut SqliteFile, flags: u32) -> i32 {
    ((*(*file).methods).sync)(file, flags)
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
        flags: u32,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        flags: 0,
    });

    unsafe extern "C" fn recording_sync(file: *mut SqliteFile, flags: u32) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.flags = flags;
        -0x183
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

    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 {
        panic!("unexpected xFileSize")
    }

    fn methods() -> SqliteIoMethods {
        SqliteIoMethods {
            version: 1,
            close: unused_close as SqliteCloseFn,
            read: unused_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
            truncate: unused_truncate as SqliteTruncateFn,
            sync: recording_sync as SqliteSyncFn,
            file_size: unused_file_size as SqliteFileSizeFn,
        }
    }

    #[test]
    fn forwards_zero_and_composite_sync_flags_to_xsync() {
        let _lock = LOCK.lock();
        for flags in [0, 0x10, u32::MAX] {
            *RECORDER.lock() = Recorder::default();
            let methods = methods();
            let mut file = SqliteFile { methods: &methods };

            let status = unsafe { sqlite_os_sync(&mut file, flags) };

            let recorder = RECORDER.lock();
            assert_eq!(status, -0x183);
            assert_eq!(recorder.calls, 1);
            assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
            assert_eq!(recorder.flags, flags);
        }
    }
}
