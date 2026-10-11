//! Validated backing-stream write — `FUN_0805b834` @ `0x0805b834`.
//!
//! True extent: 56 bytes, [0x0805b834, 0x0805b86c); the next function
//! begins with PUSH. Raw A32 decoding verifies two plain outbound BLs
//! (validator 0x08087974 and writer 0x0805ae18), zero predicated BLs,
//! and two plain inbound BLs (0x08042dd8, 0x0804332c), zero predicated.
//! Validate the mrts handle, then write its +4 descriptor using the requested
//! count, data address, flags zero, and the same in/out count pointer.
//! Return either validation failure or the backend status without translating
//! errors or requiring a full write. Deliberate deviation: reuse the Rust
//! validator; the still-retail backend is a volatile host-replaceable seam.

use core::ptr::{addr_of, read_volatile};

/// Verified ABI of the retail write/error-translation wrapper at 0x0805ae18.
pub type FileWriteBackend = unsafe extern "C" fn(u32, u32, u32, u32, *mut u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_file_write(
    descriptor: u32, data: u32, requested: u32, flags: u32, transferred: *mut u32,
) -> i32 {
    let write: FileWriteBackend = core::mem::transmute(0x0805ae18usize);
    write(descriptor, data, requested, flags, transferred)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_file_write(_: u32, _: u32, _: u32, _: u32, _: *mut u32) -> i32 {
    panic!("validated_file_write requires retail backend 0x0805ae18")
}

pub static mut FILE_WRITE_BACKEND: FileWriteBackend = firmware_file_write;

/// # Safety
/// A non-null handle must be word-aligned and readable for its tag; a valid
/// handle must also contain its descriptor at word 1. On validation success,
/// `transferred` must be readable/writable and `data` must satisfy the retail
/// backend's address contract for the requested count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn validated_file_write(
    handle: *const u32, transferred: *mut u32, data: u32,
) -> i32 {
    let status = crate::stream_handle_validate::stream_handle_validate(handle);
    if status != 0 {
        return status;
    }
    let requested = transferred.read();
    let descriptor = handle.add(1).read();
    let write = read_volatile(addr_of!(FILE_WRITE_BACKEND));
    write(descriptor, data, requested, 0, transferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model a bounded writer: descriptor selects capacity, data supplies a
    // source word, and the output count reports actual consumption.
    unsafe extern "C" fn bounded_write(
        capacity: u32, data: u32, requested: u32, flags: u32, transferred: *mut u32,
    ) -> i32 {
        assert_eq!(flags, 0);
        assert_eq!(data, 0x1234);
        assert_eq!(transferred.read(), requested);
        transferred.write(core::cmp::min(capacity, requested));
        if capacity == u32::MAX { -43 } else { 0 }
    }

    #[test]
    fn validation_gates_access_and_short_writes_preserve_backend_results() {
        unsafe {
            let saved = FILE_WRITE_BACKEND;
            FILE_WRITE_BACKEND = bounded_write;
            assert_eq!(validated_file_write(core::ptr::null(), core::ptr::null_mut(), 0), -50);
            let foreign_tag = 0;
            assert_eq!(validated_file_write(&foreign_tag, core::ptr::null_mut(), 0), -50);
            for (capacity, requested, expected_count, expected_status) in [
                (4, 0, 0, 0), (4, 3, 3, 0), (4, 9, 4, 0),
                (u32::MAX, 9, 9, -43), (4, u32::MAX, 4, 0),
            ] {
                let handle = [crate::stream_handle_validate::MRTS_TAG, capacity];
                let mut transferred = requested;
                assert_eq!(validated_file_write(handle.as_ptr(), &mut transferred, 0x1234), expected_status);
                assert_eq!(transferred, expected_count);
                assert_eq!(handle, [crate::stream_handle_validate::MRTS_TAG, capacity]);
            }
            FILE_WRITE_BACKEND = saved;
        }
    }
}
