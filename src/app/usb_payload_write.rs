//! Synchronous USB payload write — `FUN_08160e24` @ `0x08160e24`.
//!
//! True size: 64 bytes, up to the next push prologue at `0x08160e64`.
//! Raw A32 decoding verifies two plain inbound BLs (`0x08160a14`,
//! `0x081d9478`), one plain outgoing BL to `usb_in_transfer` at
//! `0x08294984`, and zero predicated inbound or outgoing BLs.
//! Reads the request word at owner +0x0c, seeds completed bytes with the
//! requested length, then synchronously transfers on endpoint 0x83.
//! Returns completed bytes on status zero, otherwise zero.
//!
//! Deliberate deviations: a private generic operation boundary permits host
//! tests without the retail engine; production uses the existing Rust callee.
//! Target pointer storage remains a four-byte word even on a 64-bit host.

use super::usb_in_transfer::usb_in_transfer;

unsafe fn write_with(
    owner: *const u32, buffer: *const u8, length: u32,
    transfer: impl FnOnce(*mut u8, u32, *const u8, u32, *mut u32, u32) -> i32,
) -> u32 {
    let request = unsafe { owner.add(3).read() } as usize as *mut u8;
    let mut completed = length;
    let status = transfer(request, 0x83, buffer, length, &mut completed, 0);
    if status != 0 { 0 } else { completed }
}

/// Writes a payload through the owner's USB request and returns completed bytes.
///
/// # Safety
/// `owner` must contain at least four aligned target words. Its word at +0x0c
/// and `buffer` must meet `usb_in_transfer`'s synchronous transfer requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_payload_write(owner: *const u32, buffer: *const u8, length: u32) -> u32 {
    unsafe { write_with(owner, buffer, length, |request, endpoint, data, count, completed, mode| {
        usb_in_transfer(request, endpoint, data, count, completed, mode)
    }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_completion_can_be_partial_zero_or_unmodified() {
        let owner = [0, 0, 0, 0];
        for length in [0, 1, 13, u32::MAX] {
            let unchanged = unsafe { write_with(owner.as_ptr(), core::ptr::null(), length,
                |_, _, _, _, _, _| 0) };
            assert_eq!(unchanged, length);
            for completed_bytes in [0, 1, length / 2, u32::MAX] {
                let result = unsafe { write_with(owner.as_ptr(), core::ptr::null(), length,
                    |_, _, _, _, completed, _| { completed.write(completed_bytes); 0 }) };
                assert_eq!(result, completed_bytes);
            }
        }
    }

    #[test]
    fn any_nonzero_status_discards_completion() {
        let owner = [0, 0, 0, 0];
        for status in [1, -1, i32::MIN, i32::MAX] {
            for overwrite in [false, true] {
                let result = unsafe { write_with(owner.as_ptr(), core::ptr::null(), 13,
                    |_, _, _, _, completed, _| {
                        if overwrite { completed.write(u32::MAX); }
                        status
                    }) };
                assert_eq!(result, 0);
            }
        }
    }
}
