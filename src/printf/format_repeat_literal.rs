//! Repeated formatter literal — `FUN_082b4648` @ `0x082b4648`.
//!
//! True extent: 76 bytes through `0x082b4694` (72 instruction bytes and a
//! four-byte literal pool). Verified inbound calls: zero plain BLs, two
//! predicated BLGTs at 0x083985ac/0x083985d8. Outbound: one plain BL,
//! zero predicated BLs, and one BGT tail call to the append worker.
//!
//! Append the first 29 bytes at 0x088fcb90 repeatedly, then append the
//! remaining 1..28 bytes. The loop comparison is unsigned, so even counts
//! with bit 31 set are not negative requests. Do not stop on writer failure;
//! the stock append worker owns failure/truncation handling.
//!
//! Deliberate deviations: Rust expresses the final tail branch as a call;
//! host builds mirror the exact raw literal bytes and expose the unported
//! append worker as a seam. The literal is NOT assumed to contain spaces.

use core::ffi::c_void;

/// Stock length-explicit buffer append worker at 0x08384ce4.
pub type FormatBufferAppendFn = unsafe extern "C" fn(*mut c_void, *const u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_append(buffer: *mut c_void, bytes: *const u8, count: u32) {
    let append: FormatBufferAppendFn = core::mem::transmute(0x0838_4ce4usize);
    append(buffer, bytes, count);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append(_: *mut c_void, _: *const u8, _: u32) {
    panic!("format_repeat_literal requires buffer append worker 0x08384ce4")
}

#[cfg(target_os = "none")]
pub static mut FORMAT_BUFFER_APPEND: FormatBufferAppendFn = firmware_append;
#[cfg(not(target_os = "none"))]
pub static mut FORMAT_BUFFER_APPEND: FormatBufferAppendFn = missing_append;

#[cfg(target_os = "none")]
const REPEAT_LITERAL: *const u8 = 0x088f_cb90 as *const u8;
#[cfg(not(target_os = "none"))]
const HOST_LITERAL: [u8; 29] = [
    0x00, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x09, 0x0e, 0xad, 0x0d, 0x08, 0x40, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x0a, 0x0e, 0xad, 0x0d,
    0x10, 0x40, 0x00, 0x00, 0x07,
];
#[cfg(not(target_os = "none"))]
const REPEAT_LITERAL: *const u8 = HOST_LITERAL.as_ptr();

/// Append `count` bytes of the firmware's repeating formatter literal.
/// `buffer` must satisfy the stock append worker's buffer-object contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn format_repeat_literal(buffer: *mut c_void, mut count: u32) {
    while count >= 29 {
        FORMAT_BUFFER_APPEND(buffer, REPEAT_LITERAL, 29);
        count -= 29;
    }
    if count != 0 {
        FORMAT_BUFFER_APPEND(buffer, REPEAT_LITERAL, count);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    struct BoundedBuffer {
        bytes: Vec<u8>,
        capacity: usize,
        failed: bool,
    }

    unsafe extern "C" fn append(buffer: *mut c_void, bytes: *const u8, count: u32) {
        let buffer = &mut *buffer.cast::<BoundedBuffer>();
        if buffer.failed { return; }
        let count = count as usize;
        let available = buffer.capacity - buffer.bytes.len();
        buffer.bytes.extend_from_slice(core::slice::from_raw_parts(bytes, count.min(available)));
        if count > available { buffer.failed = true; }
    }

    #[test]
    fn repeats_prefix_across_chunk_and_truncation_boundaries() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = FORMAT_BUFFER_APPEND;
            FORMAT_BUFFER_APPEND = append;
            for count in [0, 1, 28, 29, 30, 57, 58, 59, 340] {
                for capacity in [0, 1, 28, 29, 30, 58, 341] {
                    let mut buffer = BoundedBuffer { bytes: Vec::new(), capacity, failed: false };
                    format_repeat_literal((&mut buffer as *mut BoundedBuffer).cast(), count);
                    let expected: Vec<u8> = (0..(count as usize).min(capacity))
                        .map(|index| HOST_LITERAL[index % 29]).collect();
                    assert_eq!(buffer.bytes, expected, "count={count}, capacity={capacity}");
                    assert_eq!(buffer.failed, count as usize > capacity);
                }
            }
            // Zero count must not inspect the object or invoke the worker.
            format_repeat_literal(core::ptr::null_mut(), 0);
            FORMAT_BUFFER_APPEND = saved;
        }
    }
}
