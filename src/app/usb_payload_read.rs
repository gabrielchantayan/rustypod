//! Synchronous USB payload read — `FUN_08160dd4` @ `0x08160dd4`.
//!
//! True extent: 64 bytes, ending at the independent request-load/tail-branch
//! function at `0x08160e14`. Whole-image aligned A32 decoding finds two
//! incoming plain BLs (`0x08160d40`, `0x081d9430`), no predicated incoming
//! BLs, one outgoing plain BL (`0x08160dfc` -> `0x082948f4`), and no
//! predicated outgoing BLs. Read owner word +0x0c, seed completed bytes
//! with length, synchronously receive on endpoint 2, and return completed
//! bytes on status zero or zero on any error.
//!
//! Deliberate deviations: a private generic operation boundary enables host
//! tests, matching usb_payload_write. The unported OUT transfer wrapper at
//! 0x082948f4 retains its exact six-argument ABI; raw words prove that it
//! rejects direction bit 0x80 and otherwise calls engine 0x082933e0.
//! Ghidra's void callee return is corrected from the raw status check.
//! Target pointers remain four-byte owner words on 64-bit hosts.

type OutTransfer = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, *mut u32, u32) -> i32;

unsafe fn read_with(
    owner: *const u32, buffer: *mut u8, length: u32,
    transfer: impl FnOnce(*mut u8, u32, *mut u8, u32, *mut u32, u32) -> i32,
) -> u32 {
    let request = unsafe { owner.add(3).read() } as usize as *mut u8;
    let mut completed = length;
    let status = transfer(request, 2, buffer, length, &mut completed, 0);
    if status != 0 { 0 } else { completed }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_out_transfer(_: *mut u8, _: u32, _: *mut u8, _: u32, _: *mut u32, _: u32) -> i32 {
    panic!("retail USB OUT transfer is unavailable on host")
}

#[cfg(not(target_os = "none"))]
pub(crate) static mut HOST_OUT_TRANSFER: OutTransfer = unavailable_out_transfer;

/// Receives a payload and returns completed bytes, or zero on transfer error.
///
/// # Safety
/// `owner` must contain four aligned target words. Word +0x0c must identify
/// a live retail USB request; `buffer` must be writable for `length` bytes
/// and satisfy the synchronous retail OUT transfer's storage requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_payload_read(owner: *const u32, buffer: *mut u8, length: u32) -> u32 {
    #[cfg(target_os = "none")]
    let transfer: OutTransfer = unsafe { core::mem::transmute(0x0829_48f4usize) };
    #[cfg(not(target_os = "none"))]
    let transfer = unsafe { HOST_OUT_TRANSFER };
    unsafe { read_with(owner, buffer, length, |request, endpoint, data, count, completed, mode| {
        transfer(request, endpoint, data, count, completed, mode)
    }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_completion_preserves_partial_zero_and_unmodified_counts() {
        let owner = [0, 0, 0, 0];
        for length in [0, 1, 31, u32::MAX] {
            let unchanged = unsafe { read_with(owner.as_ptr(), core::ptr::null_mut(), length,
                |_, _, _, _, _, _| 0) };
            assert_eq!(unchanged, length);
            for completed_bytes in [0, 1, length / 2, u32::MAX] {
                let result = unsafe { read_with(owner.as_ptr(), core::ptr::null_mut(), length,
                    |_, _, _, _, completed, _| { completed.write(completed_bytes); 0 }) };
                assert_eq!(result, completed_bytes);
            }
        }
    }

    #[test]
    fn any_nonzero_status_discards_even_partial_completion() {
        let owner = [0, 0, 0, 0];
        for status in [1, -1, i32::MIN, i32::MAX] {
            for overwrite in [false, true] {
                let result = unsafe { read_with(owner.as_ptr(), core::ptr::null_mut(), 31,
                    |_, _, _, _, completed, _| {
                        if overwrite { completed.write(13); }
                        status
                    }) };
                assert_eq!(result, 0);
            }
        }
    }
}
