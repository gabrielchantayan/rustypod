//! `sqlite_os_close` — original: `FUN_0837dae8` @ **0x0837dae8**
//! (**48 bytes**, `0x0837dae8..0x0837db18`; the next separately linked
//! function starts with `push {r4,r5,r6,lr}` at `0x0837db18`, so Ghidra's
//! 48-byte extent is exact; no trailing literal pool).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837dae8  push {r4,lr}
//! 0837daec  mov  r4, r0          ; file
//! 0837daf0  ldr  r1, [r4]        ; methods = file->pMethods
//! 0837daf4  mov  r0, #0          ; rc = SQLITE_OK
//! 0837daf8  cmp  r1, #0
//! 0837dafc  popeq {r4,pc}        ; no methods: return 0
//! 0837db00  ldr  r1, [r1, #4]    ; methods->xClose (io_methods +0x04)
//! 0837db04  mov  r0, r4
//! 0837db08  blx  r1              ; rc = xClose(file)
//! 0837db0c  mov  r1, #0
//! 0837db10  str  r1, [r4]        ; file->pMethods = NULL
//! 0837db14  pop  {r4,pc}
//! ```
//!
//! **12 direct call sites, binary-scanned from every ARM B/BL word in
//! `osos.dec`: 10 unconditional `bl`, 2 `blne`** (`0x0837de14`,
//! `0x0837de2c` — both gated on a flag byte of the owning object, not on
//! `file`; this wrapper never NULL-checks `file` itself). The address
//! occurs in no image data word, so it is never dispatched virtually.
//!
//! This is SQLite's `sqlite3OsClose` from `os.c`:
//!
//! ```c
//! int sqlite3OsClose(sqlite3_file *pId){
//!   int rc = SQLITE_OK;
//!   if( pId->pMethods ){
//!     rc = pId->pMethods->xClose(pId);
//!     pId->pMethods = 0;
//!   }
//!   return rc;
//! }
//! ```
//!
//! `sqlite3_io_methods` slot `+0x04` is `xClose`; the neighbouring
//! forwarding family `0x0837db44..0x0837dc18` (including the ported
//! `sqlite_os_write` @ `0x0837dbf8`) matches the same method table.
//! Nulling `pMethods` after the close marks the file closed: a repeated
//! call on the same file object is a no-op returning `SQLITE_OK` (0).
//! The sibling at `0x0837db18` calls this wrapper and then frees the
//! file object itself through `sqlite3_free` (`0x083906f4`, the ported
//! `tracked_free`).
//!
//! # Deliberate deviations
//! `sqlite3_io_methods` is runtime data. The port dispatches the supplied
//! method table itself; its host representation uses native-width function
//! pointers, while the named slot is asserted to remain at target offset
//! `+0x04` on 32-bit builds (shared struct in `crate::sqlite::os_write`).

use crate::sqlite::os_write::SqliteFile;

/// sqlite_os_close — original: `FUN_0837dae8` @ `0x0837dae8` (48 bytes;
/// 12 direct call sites binary-scanned: 10 `bl`, 2 `blne`).
///
/// If `file`'s method-table pointer is non-NULL, dispatches
/// `sqlite3_io_methods::xClose` (`+0x04`) with `file`, then NULLs the
/// method-table pointer; returns the method status. With a NULL method
/// table, returns 0 (`SQLITE_OK`) without touching memory.
///
/// # Safety
///
/// `file` must point to a readable, writable `sqlite3_file` whose
/// `methods` field is either NULL or names a readable method table with a
/// callable `xClose` entry. `file` itself is never NULL-checked, exactly
/// as the ARM original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_close(file: *mut SqliteFile) -> i32 {
    let methods = (*file).methods;
    if methods.is_null() {
        return 0;
    }
    let status = ((*methods).close)(file);
    (*file).methods = core::ptr::null();
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_write::{SqliteCloseFn, SqliteIoMethods, SqliteReadFn, SqliteWriteFn};
    use parking_lot::Mutex;

    unsafe extern "C" fn unused_write(
        _file: *mut SqliteFile,
        _buffer: *const u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn unused_read(
        _file: *mut SqliteFile,
        _buffer: *mut u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 {
        0
    }

    fn methods(close: SqliteCloseFn) -> SqliteIoMethods {
        SqliteIoMethods {
            version: 2,
            close,
            read: unused_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
        }
    }

    #[derive(Default)]
    struct Recorder {
        calls: u32,
        file: usize,
        methods_during_call: usize,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        methods_during_call: 0,
    });

    unsafe extern "C" fn recording_close(file: *mut SqliteFile) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        // The original nulls pMethods only after xClose returns.
        recorder.methods_during_call = (*file).methods as usize;
        -7
    }

    #[test]
    fn null_methods_returns_ok_without_dispatch() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let mut file = SqliteFile {
            methods: core::ptr::null(),
        };

        let status = unsafe { sqlite_os_close(&mut file) };

        assert_eq!(status, 0);
        assert!(file.methods.is_null());
        assert_eq!(RECORDER.lock().calls, 0);
    }

    #[test]
    fn dispatches_xclose_then_nulls_methods() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = methods(recording_close);
        let mut file = SqliteFile {
            methods: &methods,
        };

        let status = unsafe { sqlite_os_close(&mut file) };

        let recorder = RECORDER.lock();
        assert_eq!(status, -7);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(
            recorder.methods_during_call,
            core::ptr::addr_of!(methods) as usize
        );
        assert!(file.methods.is_null());
    }

    #[test]
    fn second_close_on_same_file_is_a_noop() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = methods(recording_close);
        let mut file = SqliteFile {
            methods: &methods,
        };

        let first = unsafe { sqlite_os_close(&mut file) };
        let second = unsafe { sqlite_os_close(&mut file) };

        assert_eq!(first, -7);
        assert_eq!(second, 0);
        assert_eq!(RECORDER.lock().calls, 1);
    }
}
