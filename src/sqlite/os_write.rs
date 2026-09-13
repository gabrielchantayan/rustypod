//! `sqlite_os_write` — original: `FUN_0837dbf8` @ **0x0837dbf8**
//! (**32 bytes**, `0x0837dbf8..0x0837dc18`; the next separately linked
//! function starts at `0x0837dc18`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837dbf8  push {r2,r3,r4,lr}
//! 0837dbfc  ldr  r3,[sp,#16]       ; incoming fifth argument
//! 0837dc00  ldr  ip,[sp,#20]       ; incoming sixth argument
//! 0837dc04  stm  sp,{r3,ip}        ; stack arguments for the virtual call
//! 0837dc08  ldr  r3,[r0]           ; target vtable
//! 0837dc0c  ldr  r3,[r3,#12]       ; slot +0x0c
//! 0837dc10  blx  r3
//! 0837dc14  pop  {r2,r3,r4,pc}
//! ```
//!
//! **13 direct `bl` call sites, all unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds no predicated calls or tail branches.
//! The surrounding `0x0837db44..0x0837dc18` forwarding family matches
//! SQLite's `sqlite3_io_methods`: slot `+0x0c` is `xWrite`. This wrapper has
//! no NULL guards; the file, its methods, and the slot must be readable and
//! callable.
//!
//! # Algorithm
//! Forward `file`, `buffer`, `amount`, and the 64-bit `offset` to the file
//! method table's `xWrite` entry at `+0x0c`, returning SQLite's status code
//! unchanged. `r3` is AAPCS padding before the aligned stack-passed offset.
//!
//! # Deliberate deviations
//! `sqlite3_io_methods` is runtime data. The port dispatches the supplied
//! method table itself; its host representation uses native-width function
//! pointers, while the named slot is asserted to remain at target offset
//! `+0x0c` on 32-bit builds.

/// The leading `sqlite3_file` field used by [`sqlite_os_write`].
#[repr(C)]
pub struct SqliteFile {
    pub methods: *const SqliteIoMethods,
}

/// Recovered prefix of SQLite's `sqlite3_io_methods`.
#[repr(C)]
pub struct SqliteIoMethods {
    /// `+0x00`: interface version.
    pub version: u32,
    /// `+0x04`: `xClose(file)`; dispatched by `sqlite_os_close`
    /// (`crate::sqlite::os_close`).
    pub close: SqliteCloseFn,
    /// `+0x08`: `xRead(file, buffer, amount, offset)`.
    pub read: SqliteReadFn,
    /// `+0x0c`: `xWrite(file, buffer, amount, offset)`.
    pub write: SqliteWriteFn,
    /// `+0x10`: `xTruncate(file, size)`.
    pub truncate: SqliteTruncateFn,
    /// `+0x14`: `xSync(file, flags)`.
    pub sync: SqliteSyncFn,
    /// `+0x18`: `xFileSize(file, size)`.
    pub file_size: SqliteFileSizeFn,
}

/// ABI of SQLite's `sqlite3_io_methods::xClose` entry.
pub type SqliteCloseFn = unsafe extern "C" fn(*mut SqliteFile) -> i32;

/// ABI of SQLite's `sqlite3_io_methods::xRead` entry.
pub type SqliteReadFn = unsafe extern "C" fn(
    *mut SqliteFile,
    *mut u8,
    u32,
    i64,
) -> i32;

/// ABI of SQLite's `sqlite3_io_methods::xWrite` entry.
pub type SqliteWriteFn = unsafe extern "C" fn(
    *mut SqliteFile,
    *const u8,
    u32,
    i64,
) -> i32;

/// ABI of SQLite's `sqlite3_io_methods::xTruncate` entry.
pub type SqliteTruncateFn = unsafe extern "C" fn(*mut SqliteFile, i64) -> i32;

/// ABI of SQLite's `sqlite3_io_methods::xSync` entry.
pub type SqliteSyncFn = unsafe extern "C" fn(*mut SqliteFile, u32) -> i32;

/// ABI of SQLite's `sqlite3_io_methods::xFileSize` entry.
pub type SqliteFileSizeFn = unsafe extern "C" fn(*mut SqliteFile, *mut i64) -> i32;

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(SqliteIoMethods, close)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(SqliteIoMethods, read)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SqliteIoMethods, write)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(SqliteIoMethods, truncate)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(SqliteIoMethods, sync)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(SqliteIoMethods, file_size)];

/// sqlite_os_write — original: `FUN_0837dbf8` @ `0x0837dbf8` (32 bytes;
/// 13 unconditional direct `bl` call sites, binary-scanned).
///
/// Dispatches SQLite's `sqlite3_io_methods::xWrite` (`+0x0c`) for `file`,
/// forwarding `buffer`, `amount`, and the aligned stack-passed `offset`
/// unchanged. The method status is returned unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a readable
/// method table with a callable `xWrite` entry. `buffer` and every argument are
/// passed through without validation, exactly as the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_write(
    file: *mut SqliteFile,
    buffer: *const u8,
    amount: u32,
    offset: i64,
) -> i32 {
    ((*(*file).methods).write)(file, buffer, amount, offset)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
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

    unsafe extern "C" fn recording_write(
        file: *mut SqliteFile,
        buffer: *const u8,
        amount: u32,
        offset: i64,
    ) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        recorder.buffer = buffer as usize;
        recorder.amount = amount;
        recorder.offset = offset;
        -123
    }
    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 {
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
    fn forwards_buffer_amount_and_aligned_i64_offset_to_xwrite() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let methods = SqliteIoMethods {
            version: 1,
            close: unused_close,
            read: unused_read,
            write: recording_write,
            truncate: unused_truncate,
            sync: unused_sync,
            file_size: unused_file_size,
        };
        let mut file = SqliteFile { methods: &methods };
        let buffer = [0xa5_u8, 0x5a];
        let offset = -0x0102_0304_0506_0708_i64;

        let status = unsafe { sqlite_os_write(&mut file, buffer.as_ptr(), 0x1c, offset) };

        let recorder = RECORDER.lock();
        assert_eq!(status, -123);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(recorder.buffer, buffer.as_ptr() as usize);
        assert_eq!(recorder.amount, 0x1c);
        assert_eq!(recorder.offset, offset);
    }
}
