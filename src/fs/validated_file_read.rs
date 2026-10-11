//! Validated backing-stream read — `FUN_0805b7cc` @ `0x0805b7cc`.
//!
//! True extent: 56 bytes, [0x0805b7cc, 0x0805b804), ending in POP to
//! PC before the next function's PUSH. Independently decoded raw A32 words
//! contain two plain outbound BLs (0x08087974 and 0x0805a6e8), no predicated
//! BLs; inbound calls are two plain BLs at 0x08043070 and 0x080430a4.
//! Validate the mrts tag before reading either the count or descriptor word
//! at +4. Forward descriptor, destination, requested count, mode 2, and the
//! same in/out count pointer to the retail read/error-translation wrapper.
//! Return its status unchanged, including partial-read errors. Ghidra's void
//! return is incorrect. Deliberate deviation: reuse the Rust validator and
//! checked-read port; host tests inject a finite stream into the algorithm.

/// # Safety
/// A non-null handle must be aligned and readable for its tag. A valid handle
/// must also have a descriptor at word 1. After validation, `transferred`
/// must be readable/writable and `destination` must satisfy the retail read
/// backend's address contract for the requested count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn validated_file_read(
    handle: *const u32, transferred: *mut u32, destination: u32,
) -> i32 {
    validated_read(handle, transferred, destination, super::file_read_checked::file_read_checked)
}

#[inline(always)]
unsafe fn validated_read(
    handle: *const u32, transferred: *mut u32, destination: u32,
    read: unsafe extern "C" fn(u32, u32, u32, u32, *mut u32) -> i32,
) -> i32 {
    let status = crate::stream_handle_validate::stream_handle_validate(handle);
    if status != 0 {
        return status;
    }
    let requested = transferred.read();
    let descriptor = handle.add(1).read();
    read(descriptor, destination, requested, 2, transferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model a finite input stream: descriptor is the remaining byte count.
    // A short read updates the count and returns the retail EOF status.
    unsafe extern "C" fn finite_read(
        remaining: u32, _: u32, requested: u32, _: u32, transferred: *mut u32,
    ) -> i32 {
        if remaining == u32::MAX {
            return -43;
        }
        transferred.write(core::cmp::min(remaining, requested));
        if requested > remaining { -39 } else { 0 }
    }

    #[test]
    fn invalid_handles_gate_memory_access_and_partial_reads_preserve_status() {
        unsafe {
            assert_eq!(validated_read(core::ptr::null(), core::ptr::null_mut(), 0, finite_read), -50);
            for tag in [0, u32::MAX, crate::stream_handle_validate::MRTS_TAG ^ 1] {
                assert_eq!(validated_read(&tag, core::ptr::null_mut(), 0, finite_read), -50);
            }
            for (remaining, requested, count, status) in [
                (0, 0, 0, 0), (0, 1, 0, -39), (4, 0, 0, 0),
                (4, 4, 4, 0), (4, 5, 4, -39), (4, u32::MAX, 4, -39),
                (u32::MAX, 9, 9, -43),
            ] {
                let handle = [crate::stream_handle_validate::MRTS_TAG, remaining];
                let mut transferred = requested;
                assert_eq!(validated_read(handle.as_ptr(), &mut transferred, 0x1234, finite_read), status);
                assert_eq!(transferred, count);
                assert_eq!(handle, [crate::stream_handle_validate::MRTS_TAG, remaining]);
            }
        }
    }
}
