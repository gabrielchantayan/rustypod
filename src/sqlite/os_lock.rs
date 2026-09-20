//! `sqlite_os_lock` — original: `FUN_0837db74` @ **0x0837db74**
//! (**12 bytes**, `0x0837db74..0x0837db80`; the next separately linked
//! function starts at `0x0837db80`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837db74  ldr  r0,[r0]           ; file->pMethods
//! 0837db78  ldr  r2,[r2,#28]       ; xLock at +0x1c
//! 0837db7c  bx   r2
//! ```
//!
//! **3 direct `bl` call sites, all unconditional**; there are no predicated
//! direct calls. The surrounding `0x0837db44..0x0837dc18` forwarding family
//! matches SQLite's `sqlite3_io_methods`, whose `+0x1c` slot is `xLock`.
//! This wrapper has no NULL guards; the file, its methods, and the slot must
//! be readable and callable.
//!
//! # Algorithm
//!
//! Tail-dispatch `file` and `lock_level` to `sqlite3_io_methods::xLock` at
//! `+0x1c`, returning the SQLite status code unchanged.
//!
//! # Deliberate deviations
//!
//! `sqlite3_io_methods` is runtime data. The shared Rust prefix ends at
//! `+0x18`, so the port reads the `+0x1c` entry by pointer-sized word index.
//! This preserves the target offset and lets host fixtures use native-width
//! function pointers.

use super::os_write::SqliteFile;

/// ABI of SQLite's `sqlite3_io_methods::xLock` entry.
pub type SqliteLockFn = unsafe extern "C" fn(*mut SqliteFile, i32) -> i32;

/// Word index of `xLock` in `sqlite3_io_methods`: `+0x1c` on the 32-bit
/// target, and seven pointer-sized entries on both target and host builds.
const LOCK_WORD: usize = 7;

/// sqlite_os_lock — original: `FUN_0837db74` @ `0x0837db74` (12 bytes;
/// 3 unconditional direct `bl` call sites, binary-scanned).
///
/// Tail-dispatches SQLite's `sqlite3_io_methods::xLock` (`+0x1c`) for `file`
/// and `lock_level`, returning its status unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xLock` entry at `+0x1c`. Both arguments are
/// forwarded without validation, exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_lock(file: *mut SqliteFile, lock_level: i32) -> i32 {
    let slot = ((*file).methods as *const usize).add(LOCK_WORD).read();
    let lock: SqliteLockFn = core::mem::transmute(slot);
    lock(file, lock_level)
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
        lock_level: i32,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder { calls: 0, file: 0, lock_level: 0 });

    unsafe extern "C" fn recording_lock(file: *mut SqliteFile, lock_level: i32) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.lock_level = lock_level;
        -7
    }

    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 { panic!("unexpected xClose") }
    unsafe extern "C" fn unused_read(_file: *mut SqliteFile, _buffer: *mut u8, _amount: u32, _offset: i64) -> i32 { panic!("unexpected xRead") }
    unsafe extern "C" fn unused_write(_file: *mut SqliteFile, _buffer: *const u8, _amount: u32, _offset: i64) -> i32 { panic!("unexpected xWrite") }
    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 { panic!("unexpected xTruncate") }
    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 { panic!("unexpected xSync") }
    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 { panic!("unexpected xFileSize") }

    #[repr(C)]
    struct FullMethods {
        prefix: SqliteIoMethods,
        lock: usize,
    }

    fn full_methods(lock: SqliteLockFn) -> FullMethods {
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
            lock: lock as usize,
        }
    }

    #[test]
    fn slot_word_index_is_7() {
        assert_eq!(LOCK_WORD, 7);
    }

    #[test]
    fn forwards_exact_file_lock_level_and_status() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = full_methods(recording_lock as SqliteLockFn);
        let mut file = SqliteFile { methods: core::ptr::addr_of!(methods.prefix) };

        let status = unsafe { sqlite_os_lock(&mut file, i32::MIN) };

        let recorder = RECORDER.lock();
        assert_eq!(status, -7);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of!(file) as usize);
        assert_eq!(recorder.lock_level, i32::MIN);
    }
}
