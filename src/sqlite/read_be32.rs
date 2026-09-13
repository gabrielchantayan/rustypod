//! SQLite file big-endian word reader — `FUN_08365598` @ **0x08365598**
//! (**52 bytes**, `0x08365598..0x083655c8`; the next separately linked
//! function begins with `push {r2,r3,r4,r5,r6,r7,r8,lr}` at `0x083655cc`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 08365598  push {r1,r2,r3,r4,r5,lr}
//! 0836559c  ldr  r4,[sp,#24]       ; out
//! 083655a0  strd r2,[sp]           ; offset's aligned stack arguments
//! 083655a4  mov  r2,#4
//! 083655a8  add  r1,sp,#8          ; four-byte local buffer
//! 083655ac  bl   0x0837dba0        ; sqlite_os_read(file, buffer, 4, offset)
//! 083655b0  movs r3,r0
//! 083655b4  bne  0x083655c4
//! 083655b8  add  r0,sp,#8
//! 083655bc  bl   0x0837a158        ; load_be32
//! 083655c0  str  r0,[r4]
//! 083655c4  mov  r0,r3
//! 083655c8  pop  {r1,r2,r3,r4,r5,pc}
//! ```
//!
//! **9 direct `bl` call sites, all unconditional**: decoding every ARM B/BL
//! word in `osos.dec` finds calls at `0x082de188`, `0x082de22c`, `0x08365aa4`,
//! `0x08365ac8`, `0x08365ae4`, `0x08365b08`, `0x08365b60`, `0x08365bf0`, and
//! `0x08365c2c`; no predicated call or tail branch targets this function.
//!
//! # Algorithm
//!
//! Read exactly four bytes from a SQLite file at `offset`. On `SQLITE_OK` (0),
//! decode the bytes as a big-endian `u32` and store it through `out`; otherwise
//! leave `out` unchanged and return the read status unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM stack word is uninitialized before `xRead`; it is consumed only when
//! a successful xRead contract has initialized all four bytes. `MaybeUninit`
//! preserves that contract without inventing a zero-filled precondition.

use core::mem::MaybeUninit;

use super::os_read::sqlite_os_read;
use super::os_write::SqliteFile;
use crate::util::beload::load_be32;

/// sqlite_read_be32 — original: `FUN_08365598` @ `0x08365598` (52 bytes; 9
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Reads four bytes through [`sqlite_os_read`]. A zero status stores the
/// big-endian decoded word through `out`; a nonzero status leaves `out`
/// untouched. The original has no NULL guards.
///
/// # Safety
///
/// `file` must identify a readable SQLite file and `out` must be writable.
/// The method table must honor SQLite's success contract by writing all four
/// bytes before returning zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_read_be32")]
pub unsafe extern "C" fn sqlite_read_be32(
    file: *mut SqliteFile,
    offset: i64,
    out: *mut u32,
) -> i32 {
    let mut bytes = MaybeUninit::<[u8; 4]>::uninit();
    let status = unsafe { sqlite_os_read(file, bytes.as_mut_ptr().cast(), 4, offset) };
    if status == 0 {
        unsafe { out.write(load_be32(bytes.as_ptr().cast())) };
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_write::{SqliteCloseFn, SqliteIoMethods, SqliteWriteFn};

    #[repr(C)]
    struct TestFile {
        file: SqliteFile,
        expected_file: *mut SqliteFile,
        requested_buffer: *mut u8,
        requested_amount: u32,
        requested_offset: i64,
        status: i32,
        bytes: [u8; 4],
    }

    unsafe extern "C" fn close_unused(_: *mut SqliteFile) -> i32 {
        panic!("unexpected xClose")
    }

    unsafe extern "C" fn write_unused(_: *mut SqliteFile, _: *const u8, _: u32, _: i64) -> i32 {
        panic!("unexpected xWrite")
    }

    unsafe extern "C" fn truncate_unused(_: *mut SqliteFile, _: i64) -> i32 {
        panic!("unexpected xTruncate")
    }

    unsafe extern "C" fn sync_unused(_: *mut SqliteFile, _: u32) -> i32 {
        panic!("unexpected xSync")
    }

    unsafe extern "C" fn read_recording(
        file: *mut SqliteFile,
        buffer: *mut u8,
        amount: u32,
        offset: i64,
    ) -> i32 {
        let fixture = unsafe { &mut *file.cast::<TestFile>() };
        fixture.expected_file = file;
        fixture.requested_buffer = buffer;
        fixture.requested_amount = amount;
        fixture.requested_offset = offset;
        if fixture.status == 0 {
            unsafe { buffer.copy_from_nonoverlapping(fixture.bytes.as_ptr(), fixture.bytes.len()) };
        }
        fixture.status
    }

    fn methods() -> SqliteIoMethods {
        SqliteIoMethods {
            version: 1,
            close: close_unused as SqliteCloseFn,
            read: read_recording,
            write: write_unused as SqliteWriteFn,
            truncate: truncate_unused,
            sync: sync_unused,
        }
    }

    #[test]
    fn successful_read_forwards_offset_and_decodes_every_byte_lane() {
        for (bytes, expected) in [
            ([0, 0, 0, 0], 0),
            ([0xff, 0xff, 0xff, 0xff], u32::MAX),
            ([0x80, 0x01, 0xfe, 0x7f], 0x8001_fe7f),
        ] {
            let methods = methods();
            let mut fixture = TestFile {
                file: SqliteFile { methods: &methods },
                expected_file: core::ptr::null_mut(),
                requested_buffer: core::ptr::null_mut(),
                requested_amount: 0,
                requested_offset: 0,
                status: 0,
                bytes,
            };
            let mut out = 0x5afe_5afe;
            let file = core::ptr::addr_of_mut!(fixture.file);

            assert_eq!(unsafe { sqlite_read_be32(file, i64::MIN, &mut out) }, 0);
            assert_eq!(out, expected, "bytes={bytes:02x?}");
            assert_eq!(fixture.expected_file, file);
            assert!(!fixture.requested_buffer.is_null());
            assert_eq!(fixture.requested_amount, 4);
            assert_eq!(fixture.requested_offset, i64::MIN);
        }
    }

    #[test]
    fn failed_read_preserves_output_and_returns_status() {
        let methods = methods();
        let mut fixture = TestFile {
            file: SqliteFile { methods: &methods },
            expected_file: core::ptr::null_mut(),
            requested_buffer: core::ptr::null_mut(),
            requested_amount: 0,
            requested_offset: 0,
            status: -522,
            bytes: [0xde, 0xad, 0xbe, 0xef],
        };
        let mut out = 0x5afe_5afe;
        let file = core::ptr::addr_of_mut!(fixture.file);

        assert_eq!(unsafe { sqlite_read_be32(file, 0x0123_4567_89ab_cdef, &mut out) }, -522);
        assert_eq!(out, 0x5afe_5afe);
        assert_eq!(fixture.expected_file, file);
        assert!(!fixture.requested_buffer.is_null());
        assert_eq!(fixture.requested_amount, 4);
        assert_eq!(fixture.requested_offset, 0x0123_4567_89ab_cdef);
    }
}
