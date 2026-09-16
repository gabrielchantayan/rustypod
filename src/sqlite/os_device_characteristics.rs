//! `sqlite_os_device_characteristics` — original: `FUN_0837db4c` @
//! **0x0837db4c** (**12 bytes**, `0x0837db4c..0x0837db58`; the next
//! separately linked thunk starts at `0x0837db58` and has its own `bl`
//! caller at `0x0838f904`, so Ghidra's 12-byte extent is exact).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837db4c  ldr  r1,[r0]           ; file->pMethods
//! 0837db50  ldr  r1,[r1,#0x30]     ; xDeviceCharacteristics at +0x30
//! 0837db54  bx   r1
//! ```
//!
//! **4 direct `bl` call sites, all unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds `0x082de36c`, `0x08392a48`,
//! `0x083973ac`, and `0x08398a94` (all cond `0xe`); there are no predicated
//! direct calls, no direct tail branches, and the address occurs in no
//! image data word (never dispatched virtually). The adjacent
//! `0x0837db44..0x0837dc18` forwarding family matches SQLite's
//! `sqlite3_io_methods`, whose `+0x30` slot is `xDeviceCharacteristics`.
//! This wrapper has no NULL guards; the file, its methods, and the slot
//! must be readable and callable.
//!
//! # Algorithm
//!
//! Tail-dispatch `file` to `sqlite3_io_methods::xDeviceCharacteristics`
//! at `+0x30`, returning the SQLite status/flags word unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM thunk loads the slot into `r1`, clobbering AAPCS argument
//! register 1; this is safe because `xDeviceCharacteristics(file)` is
//! unary. `sqlite3_io_methods` is runtime data: the shared
//! [`SqliteIoMethods`] struct models only the recovered prefix through
//! `+0x18`, so this port reads the `+0x30` slot by word index (12 words
//! on both target and host pointer widths) and casts it to the slot ABI
//! instead of growing the shared struct past what is verified.

use super::os_write::SqliteFile;

/// ABI of SQLite's `sqlite3_io_methods::xDeviceCharacteristics` entry.
pub type SqliteDeviceCharacteristicsFn = unsafe extern "C" fn(*mut SqliteFile) -> i32;

/// Word index of `xDeviceCharacteristics` in `sqlite3_io_methods`:
/// `+0x30` on the 32-bit target is 12 pointer-sized slots, and every
/// entry is pointer-sized on host builds too, so the index is 12 on both.
const DEVICE_CHARACTERISTICS_WORD: usize = 12;

/// sqlite_os_device_characteristics — original: `FUN_0837db4c` @
/// `0x0837db4c` (12 bytes; 4 unconditional direct `bl` call sites,
/// binary-scanned).
///
/// Tail-dispatches SQLite's `sqlite3_io_methods::xDeviceCharacteristics`
/// (`+0x30`) for `file`, returning its status unchanged.
///
/// # Safety
///
/// `file` must point to a `sqlite3_file` whose `methods` field names a
/// readable method table with a callable `xDeviceCharacteristics` entry at
/// `+0x30`. The file pointer is forwarded without validation, exactly as
/// the ARM wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_device_characteristics(file: *mut SqliteFile) -> i32 {
    let slot =
        ((*file).methods as *const usize).add(DEVICE_CHARACTERISTICS_WORD).read();
    let device_characteristics: SqliteDeviceCharacteristicsFn =
        core::mem::transmute(slot);
    device_characteristics(file)
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
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder { calls: 0, file: 0 });

    unsafe extern "C" fn recording_device_characteristics(file: *mut SqliteFile) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.file = file as usize;
        0x0000_0112
    }

    unsafe extern "C" fn unexpected_device_characteristics(_file: *mut SqliteFile) -> i32 {
        panic!("unexpected xDeviceCharacteristics")
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

    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 {
        panic!("unexpected xFileSize")
    }

    /// Method table laid out through the `+0x30` slot: the shared
    /// `SqliteIoMethods` prefix followed by the five pointer-sized slots
    /// the port skips, then the dispatched entry.
    #[repr(C)]
    struct FullMethods {
        prefix: SqliteIoMethods,
        lock: usize,
        unlock: usize,
        check_reserved_lock: usize,
        file_control: usize,
        sector_size: usize,
        device_characteristics: usize,
    }

    fn full_methods(device_characteristics: SqliteDeviceCharacteristicsFn) -> FullMethods {
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
            lock: 0xdead_beef,
            unlock: 0xcafe_f00d,
            check_reserved_lock: 0x1234_5678,
            file_control: 0x0bad_c0de,
            sector_size: 0xfeed_face,
            device_characteristics: device_characteristics as usize,
        }
    }

    #[test]
    fn slot_word_index_is_12() {
        assert_eq!(DEVICE_CHARACTERISTICS_WORD, 12);
    }

    #[test]
    fn forwards_exact_file_and_returns_status_unchanged() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let full = full_methods(recording_device_characteristics as SqliteDeviceCharacteristicsFn);
        let mut file = SqliteFile {
            methods: core::ptr::addr_of!(full.prefix),
        };

        let status = unsafe { sqlite_os_device_characteristics(&mut file) };

        let recorder = RECORDER.lock();
        assert_eq!(status, 0x0000_0112);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
    }

    #[test]
    fn reads_only_the_0x30_slot() {
        let _lock = LOCK.lock();
        let full = full_methods(unexpected_device_characteristics as SqliteDeviceCharacteristicsFn);
        let mut file = SqliteFile {
            methods: core::ptr::addr_of!(full.prefix),
        };

        // Corrupt every other pointer slot past the recovered prefix; the
        // port must still call the live +0x30 entry, so install it last.
        let full = FullMethods {
            device_characteristics: recording_device_characteristics
                as SqliteDeviceCharacteristicsFn as usize,
            ..full
        };
        file.methods = core::ptr::addr_of!(full.prefix);

        *RECORDER.lock() = Recorder::default();
        let status = unsafe { sqlite_os_device_characteristics(&mut file) };

        assert_eq!(status, 0x0000_0112);
        assert_eq!(RECORDER.lock().calls, 1);
    }
}
