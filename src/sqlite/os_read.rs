//! `sqlite_os_read` — original: `FUN_0837dba0` @ **0x0837dba0**
//! (**32 bytes**, `0x0837dba0..0x0837dbc0`; the next separately linked
//! function starts at `0x0837dbc0`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837dba0  push {r2,r3,r4,lr}
//! 0837dba4  ldr  r3,[sp,#16]       ; incoming fifth argument
//! 0837dba8  ldr  ip,[sp,#20]       ; incoming sixth argument
//! 0837dbac  stm  sp,{r3,ip}        ; stack arguments for the virtual call
//! 0837dbb0  ldr  r3,[r0]           ; target vtable
//! 0837dbb4  ldr  r3,[r3,#8]        ; slot +0x08
//! 0837dbb8  blx  r3
//! 0837dbbc  pop  {r2,r3,r4,pc}
//! ```
//!
//! **9 direct `bl` call sites, all unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds calls at `0x082dd6c4`, `0x082dd944`,
//! `0x082de1ac`, `0x083655ac`, `0x08365614`, `0x08365a5c`, `0x08365c58`,
//! `0x08365cb8`, and `0x08372570`; no predicated call or tail branch targets
//! this wrapper. The surrounding `0x0837db44..0x0837dc18` forwarding family
//! matches SQLite's `sqlite3_io_methods`: slot `+0x08` is `xRead`. This
//! wrapper has no NULL guards; the file, its methods, and the slot must be
//! readable and callable.
//!
//! # Algorithm
//!
//! Forward `file`, mutable `buffer`, `amount`, and the 64-bit `offset` to the
//! file method table's `xRead` entry at `+0x08`, returning SQLite's status code
//! unchanged. `r3` is AAPCS padding before the aligned stack-passed offset.
//!
//! # Deliberate deviations
//!
//! `sqlite3_io_methods` is runtime data. The port dispatches the supplied
//! method table itself; its host representation uses native-width function
//! pointers, while the named slot is asserted to remain at target offset
//! `+0x08` on 32-bit builds.

use super::os_write::SqliteFile;

/// sqlite_os_read — original: `FUN_0837dba0` @ `0x0837dba0` (32 bytes; 9
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Dispatches SQLite's `sqlite3_io_methods::xRead` (`+0x08`) for `file`,
/// forwarding `buffer`, `amount`, and the aligned stack-passed `offset`
/// unchanged. The method status is returned unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xRead` entry. `buffer` and every argument are
/// passed through without validation, exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_read(
    file: *mut SqliteFile,
    buffer: *mut u8,
    amount: u32,
    offset: i64,
) -> i32 {
    ((*(*file).methods).read)(file, buffer, amount, offset)
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
        buffer: usize,
        amount: u32,
        offset: i64,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        buffer: 0,
        amount: 0,
        offset: 0,
    });

    unsafe extern "C" fn recording_read(
        file: *mut SqliteFile,
        buffer: *mut u8,
        amount: u32,
        offset: i64,
    ) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.buffer = buffer as usize;
        recorder.amount = amount;
        recorder.offset = offset;
        -522
    }
    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 {
        0
    }
    unsafe extern "C" fn unused_write(
        _file: *mut SqliteFile,
        _buffer: *const u8,
        _amount: u32,
        _offset: i64,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 {
        0
    }

    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 {
        0
    }

    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 {
        0
    }

    #[test]
    fn forwards_mutable_buffer_zero_amount_and_minimum_i64_offset_to_xread() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = SqliteIoMethods {
            version: 1,
            close: unused_close as SqliteCloseFn,
            read: recording_read as SqliteReadFn,
            write: unused_write as SqliteWriteFn,
            truncate: unused_truncate as SqliteTruncateFn,
            sync: unused_sync as SqliteSyncFn,
            file_size: unused_file_size as SqliteFileSizeFn,
        };
        let mut file = SqliteFile { methods: &methods };
        let mut buffer = [0xa5_u8, 0x5a];

        let status = unsafe { sqlite_os_read(&mut file, buffer.as_mut_ptr(), 0, i64::MIN) };

        let recorder = RECORDER.lock();
        assert_eq!(status, -522);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(recorder.buffer, buffer.as_mut_ptr() as usize);
        assert_eq!(recorder.amount, 0);
        assert_eq!(recorder.offset, i64::MIN);
    }
}
