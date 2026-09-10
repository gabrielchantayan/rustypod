//! `jpeg_stream_read_byte` — original: `FUN_082105b0` @ `0x082105b0`
//! (76 bytes; 10 verified direct `bl` call sites, all unconditional).
//!
//! # Algorithm
//!
//! The JPEG container parser keeps its file handle at `stream + 0x08`, its
//! error status at `+0x04`, and its consumed-byte counter at `+0x14`. A null
//! handle stores `-7` in the error status and returns zero. Otherwise, it asks
//! the existing platform file-read wrapper for one byte, ignores both that
//! wrapper's status and transferred count, increments the counter, and returns
//! the byte zero-extended. The counter advances even when the underlying read
//! reports an error.
//!
//! Raw branch decoding over `osos.dec` found 10 direct call sites, every one
//! an unconditional `bl`; no predicated calls or tail `b` branches target this
//! entry. Its immediate callers parse JPEG markers and big-endian lengths.
//!
//! Deliberate deviation: none. The already-ported `retail_file_read` supplies
//! the stock zero control word and retains its established host boundary.

use core::ffi::c_void;

/// Firmware layout of the stream prefix consumed by [`jpeg_stream_read_byte`].
///
/// `file_handle` remains a target-width word so all fields retain their retailOS
/// offsets on the 64-bit host as well as the 32-bit ARM target.
#[repr(C)]
pub struct JpegStream {
    _unknown_00: u32,
    pub error_status: u32,
    pub file_handle: u32,
    _unknown_0c: [u32; 2],
    pub bytes_read: u32,
}

/// Reads one byte from a JPEG parser stream — original: `FUN_082105b0` @
/// `0x082105b0` (76 bytes; 10 unconditional `bl` call sites).
///
/// The original has no stream or output guard. A null file handle is the only
/// special case: it stores `-7` at `stream + 0x04` and returns zero. Every
/// non-null handle calls [`crate::fs::file_read::retail_file_read`] with a
/// count of one, ignores its status and transferred count, increments
/// `stream + 0x14` with ARM's wrapping arithmetic, and returns the byte.
///
/// # Safety
///
/// `stream` must point to a valid [`JpegStream`], and a non-null file-handle
/// word must identify a handle accepted by the platform file-read body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.jpeg_stream_read_byte")]
#[inline(never)]
pub unsafe extern "C" fn jpeg_stream_read_byte(stream: *mut JpegStream) -> u32 {
    let stream = unsafe { &mut *stream };
    if stream.file_handle == 0 {
        stream.error_status = (-7i32) as u32;
        return 0;
    }

    let mut byte = 0u8;
    let mut transferred = 0u32;
    unsafe {
        crate::fs::file_read::retail_file_read(
            stream.file_handle as usize as *mut c_void,
            1,
            &mut byte,
            &mut transferred,
        );
    }
    stream.bytes_read = stream.bytes_read.wrapping_add(1);
    byte as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::file_read::{reset_retail_file_read_body, RetailFileReadBody, RETAIL_FILE_READ_BODY};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::JPEG_STREAM_READ_BYTE, SLAB_LEN).map(|base| base as usize)
    });

    static mut CALLS: u32 = 0;
    static mut STATUS: i32 = 0;
    static mut BYTE: u8 = 0;
    static mut TRANSFERRED: u32 = 0;
    static mut SEEN_HANDLE: usize = 0;
    static mut SEEN_COUNT: u32 = 0;
    static mut SEEN_INITIAL_TRANSFERRED: u32 = 0;

    unsafe extern "C" fn recording_read_body(
        handle: *mut c_void,
        count: u32,
        buffer: *mut u8,
        transferred: *mut u32,
        control: u32,
    ) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_HANDLE = handle as usize;
            SEEN_COUNT = count;
            SEEN_INITIAL_TRANSFERRED = *transferred;
            assert_eq!(control, 0);
            *buffer = BYTE;
            *transferred = TRANSFERRED;
            STATUS
        }
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_retail_file_read_body();
                CALLS = 0;
                STATUS = 0;
                BYTE = 0;
                TRANSFERRED = 0;
                SEEN_HANDLE = 0;
                SEEN_COUNT = 0;
                SEEN_INITIAL_TRANSFERRED = 0;
            }
        }
    }

    fn stream_fixture() -> Option<*mut JpegStream> {
        let stream = (*SLAB)? as *mut JpegStream;
        unsafe {
            core::ptr::write_bytes(stream.cast::<u8>(), 0, SLAB_LEN);
        }
        Some(stream)
    }

    unsafe fn install(status: i32, byte: u8, transferred: u32) {
        unsafe {
            CALLS = 0;
            STATUS = status;
            BYTE = byte;
            TRANSFERRED = transferred;
            core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY)
                .write_volatile(recording_read_body as RetailFileReadBody);
        }
    }

    #[test]
    fn null_handle_latches_minus_seven_without_reading() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(stream) = stream_fixture() else {
            note_missing_u32_fixture("jpeg::stream_read_byte");
            return;
        };
        let _reset = Reset;

        unsafe {
            (*stream).error_status = 0x1234_5678;
            (*stream).bytes_read = 41;
            assert_eq!(jpeg_stream_read_byte(stream), 0);
            assert_eq!((*stream).error_status, (-7i32) as u32);
            assert_eq!((*stream).bytes_read, 41);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn returns_the_read_byte_and_ignores_read_status_and_transfer_count() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(stream) = stream_fixture() else {
            note_missing_u32_fixture("jpeg::stream_read_byte");
            return;
        };
        let _reset = Reset;

        unsafe {
            let handle = (stream.cast::<u8>()).add(0x200).cast::<c_void>();
            (*stream).file_handle = handle as usize as u32;
            (*stream).error_status = 0x55aa_aa55;
            (*stream).bytes_read = 9;
            install(-23, 0xf1, 0);

            assert_eq!(jpeg_stream_read_byte(stream), 0xf1);
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_HANDLE, handle as usize);
            assert_eq!(SEEN_COUNT, 1);
            assert_eq!(SEEN_INITIAL_TRANSFERRED, 0);
            assert_eq!((*stream).error_status, 0x55aa_aa55);
            assert_eq!((*stream).bytes_read, 10);
        }
    }

    #[test]
    fn byte_counter_wraps_after_each_non_null_read() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(stream) = stream_fixture() else {
            note_missing_u32_fixture("jpeg::stream_read_byte");
            return;
        };
        let _reset = Reset;

        unsafe {
            let handle = (stream.cast::<u8>()).add(0x200).cast::<c_void>();
            (*stream).file_handle = handle as usize as u32;
            (*stream).bytes_read = u32::MAX;
            install(0, 0x80, 1);

            assert_eq!(jpeg_stream_read_byte(stream), 0x80);
            assert_eq!((*stream).bytes_read, 0);
            assert_eq!(CALLS, 1);
        }
    }
}
