//! `jpeg_stream_read_u16` — original: `FUN_08210624` @ `0x08210624`
//! (72 bytes; four verified inbound plain `bl` call sites, zero predicated).
//!
//! # Algorithm
//!
//! Read two bytes through [`super::stream_read_byte::jpeg_stream_read_byte`].
//! The `0x4d4d` byte-order tag (`"MM"`) returns the first byte as the high
//! byte; every other tag returns the first byte as the low byte. The raw ARM
//! contains four static `bl` instructions over the two mutually-exclusive
//! paths, so each invocation performs exactly two reads.
//!
//! Deliberate deviation: the byte-order comparison is volatile to keep LLVM
//! from hoisting the common first read above the original's branch.

use super::stream_read_byte::{jpeg_stream_read_byte, JpegStream};

/// Reads a JPEG stream's next 16-bit value using its caller-selected byte order
/// — original: `FUN_08210624` @ `0x08210624` (72 bytes).
///
/// # Safety
///
/// `stream` must satisfy [`jpeg_stream_read_byte`]'s safety requirements for
/// two consecutive reads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn jpeg_stream_read_u16(stream: *mut JpegStream, byte_order: u32) -> u32 {
    if unsafe { core::ptr::read_volatile(&byte_order) } == 0x4d4d {
        let high = unsafe { jpeg_stream_read_byte(stream) } << 8;
        let low = unsafe { jpeg_stream_read_byte(stream) };
        low | high
    } else {
        let low = unsafe { jpeg_stream_read_byte(stream) };
        let high = unsafe { jpeg_stream_read_byte(stream) } << 8;
        low | high
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::file_read::{reset_retail_file_read_body, RetailFileReadBody, RETAIL_FILE_READ_BODY};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ffi::c_void;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::JPEG_STREAM_READ_U16, SLAB_LEN).map(|base| base as usize)
    });
    static mut BYTES: [u8; 2] = [0; 2];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn read_two_bytes(
        _handle: *mut c_void,
        _count: u32,
        buffer: *mut u8,
        _transferred: *mut u32,
        _control: u32,
    ) -> i32 {
        unsafe {
            *buffer = BYTES[CALLS];
            CALLS += 1;
        }
        0
    }

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_retail_file_read_body();
                BYTES = [0; 2];
                CALLS = 0;
            }
        }
    }

    #[test]
    fn combines_two_consecutive_bytes_in_the_selected_order() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(base) = *SLAB else {
            note_missing_u32_fixture("jpeg::stream_read_u16");
            return;
        };
        let _reset = Reset;
        let stream = base as *mut JpegStream;
        unsafe {
            core::ptr::write_bytes(stream.cast::<u8>(), 0, SLAB_LEN);
            (*stream).file_handle = (base + 0x200) as u32;
            BYTES = [0x12, 0x34];
            core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY)
                .write_volatile(read_two_bytes as RetailFileReadBody);

            assert_eq!(jpeg_stream_read_u16(stream, 0x4d4d), 0x1234);
            assert_eq!(CALLS, 2);
            assert_eq!((*stream).bytes_read, 2);

            BYTES = [0x12, 0x34];
            CALLS = 0;
            assert_eq!(jpeg_stream_read_u16(stream, 0x4949), 0x3412);
            assert_eq!(CALLS, 2);
            assert_eq!((*stream).bytes_read, 4);
        }
    }
}
