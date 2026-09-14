//! `sqlite_write32bits` — original: `FUN_083989f8` @ **0x083989f8**
//! (**52 bytes**, `0x083989f8..0x08398a2c`; the next separately linked
//! function starts at `0x08398a2c`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 083989f8  push {r1,r2,r3,r4,r5,lr}
//! 083989fc  mov  r5,r0
//! 08398a00  ldr  r1,[sp,#24]        ; value, stack-passed after i64 offset
//! 08398a04  add  r0,sp,#8           ; four-byte local buffer
//! 08398a08  mov  r4,r2              ; offset low word
//! 08398a0c  bl   0x083816cc          ; store_be32(local, value)
//! 08398a10  mov  r2,#4
//! 08398a14  add  r1,sp,#8
//! 08398a18  mov  r0,r5
//! 08398a1c  str  r3,[sp,#4]         ; offset high word
//! 08398a20  str  r4,[sp]            ; offset low word
//! 08398a24  bl   0x0837dbf8          ; sqlite_os_write(file, local, 4, offset)
//! 08398a28  pop  {r1,r2,r3,r4,r5,pc}
//! ```
//!
//! **Five direct `bl` call sites, all unconditional**: decoding every ARM
//! `B`/`BL` word in `osos.dec` finds calls at 0x082deab4, 0x082deb18,
//! 0x082dec68, 0x08392a9c, and 0x08398bfc; no predicated call or tail branch
//! targets this entry.
//!
//! # Algorithm
//!
//! Serialize `value` in a four-byte stack buffer as big-endian, then forward
//! that buffer, its fixed length, and `offset` to SQLite's xWrite wrapper.
//! Return the wrapper's status unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM implementation's local buffer has only call lifetime. Rust uses a
//! `[u8; 4]` with the same lifetime; the observable bytes, offset, and status
//! are unchanged.

use crate::sqlite::os_write::{sqlite_os_write, SqliteFile};
use crate::util::beload::store_be32;

/// sqlite_write32bits — original: `FUN_083989f8` @ `0x083989f8` (52 bytes;
/// five unconditional direct `bl` call sites, binary-scanned).
///
/// Encodes `value` as four big-endian bytes and writes it through `file` at
/// `offset`. Returns the xWrite method's SQLite status unchanged.
///
/// # Safety
///
/// `file` must satisfy [`sqlite_os_write`]'s requirements. The xWrite method
/// receives a valid, four-byte temporary buffer for the duration of the call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_write32bits")]
pub unsafe extern "C" fn sqlite_write32bits(
    file: *mut SqliteFile,
    offset: i64,
    value: u32,
) -> i32 {
    let mut encoded = [0_u8; 4];
    store_be32(encoded.as_mut_ptr(), value);
    sqlite_os_write(file, encoded.as_ptr(), 4, offset)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_write::{SqliteCloseFn, SqliteFileSizeFn, SqliteIoMethods, SqliteReadFn, SqliteSyncFn, SqliteTruncateFn};
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: u32,
        file: usize,
        amount: u32,
        offset: i64,
        bytes: [u8; 4],
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        file: 0,
        amount: 0,
        offset: 0,
        bytes: [0; 4],
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
        recorder.amount = amount;
        recorder.offset = offset;
        recorder.bytes.copy_from_slice(core::slice::from_raw_parts(buffer, 4));
        -123
    }

    unsafe extern "C" fn unused_close(_file: *mut SqliteFile) -> i32 { 0 }
    unsafe extern "C" fn unused_read(_file: *mut SqliteFile, _buffer: *mut u8, _amount: u32, _offset: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_truncate(_file: *mut SqliteFile, _size: i64) -> i32 { 0 }
    unsafe extern "C" fn unused_sync(_file: *mut SqliteFile, _flags: u32) -> i32 { 0 }
    unsafe extern "C" fn unused_file_size(_file: *mut SqliteFile, _size: *mut i64) -> i32 { 0 }

    #[test]
    fn writes_big_endian_word_at_full_i64_offsets() {
        let _lock = LOCK.lock();
        let methods = SqliteIoMethods {
            version: 1,
            close: unused_close as SqliteCloseFn,
            read: unused_read as SqliteReadFn,
            write: recording_write,
            truncate: unused_truncate as SqliteTruncateFn,
            sync: unused_sync as SqliteSyncFn,
            file_size: unused_file_size as SqliteFileSizeFn,
        };
        let mut file = SqliteFile { methods: &methods };

        for (offset, value, expected) in [
            (i64::MIN, 0x0000_0000, [0x00, 0x00, 0x00, 0x00]),
            (-0x0102_0304_0506_0708, 0x0102_0304, [0x01, 0x02, 0x03, 0x04]),
            (i64::MAX, 0xffff_ffff, [0xff, 0xff, 0xff, 0xff]),
        ] {
            *RECORDER.lock() = Recorder::default();

            let status = unsafe { sqlite_write32bits(&mut file, offset, value) };

            let recorder = RECORDER.lock();
            assert_eq!(status, -123);
            assert_eq!(recorder.calls, 1);
            assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
            assert_eq!(recorder.amount, 4);
            assert_eq!(recorder.offset, offset);
            assert_eq!(recorder.bytes, expected);
        }
    }
}
