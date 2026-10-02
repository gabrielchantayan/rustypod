//! Checked USB IN transfer — `FUN_08294984` @ `0x08294984`.
//!
//! True extent: 48 bytes, ending at `0x082949b4`, the next function's
//! literal-load entry. Whole-image A32 decoding verifies two plain inbound
//! BL sites (`0x08160e4c`, `0x081e1d44`), zero predicated inbound BL sites,
//! and one plain outgoing BL to `0x082933e0` (zero predicated outgoing BLs).
//! Rejects endpoints without direction bit 0x80 with -1; otherwise invokes
//! the transfer engine with all six arguments unchanged and returns its status.
//!
//! Deliberate deviations: fixes Ghidra's void return using raw `mvneq r0,#0`
//! and both callers' status checks. The unported engine remains a direct
//! target-address operation with a replaceable host seam. No extra validation.

type Transfer = unsafe extern "C" fn(*mut u8, u32, *const u8, u32, *mut u32, u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_transfer(_: *mut u8, _: u32, _: *const u8, _: u32, _: *mut u32, _: u32) -> i32 {
    panic!("retail USB transfer engine is unavailable on host")
}
#[cfg(not(target_os = "none"))]
static mut HOST_TRANSFER: Transfer = unavailable_transfer;

/// Performs a transfer only for an IN endpoint (direction bit 0x80).
///
/// # Safety
/// For an IN endpoint, `request`, `buffer`, and `completed` must satisfy the
/// retail transfer engine's lifetime and storage requirements. For rejected
/// endpoints no pointer is dereferenced and `completed` is left untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_in_transfer(request: *mut u8, endpoint: u32, buffer: *const u8, length: u32, completed: *mut u32, asynchronous: u32) -> i32 {
    if endpoint & 0x80 == 0 { return -1; }
    #[cfg(target_os = "none")]
    let transfer: Transfer = unsafe { core::mem::transmute(0x0829_33e0usize) };
    #[cfg(not(target_os = "none"))]
    let transfer = unsafe { HOST_TRANSFER };
    unsafe { transfer(request, endpoint, buffer, length, completed, asynchronous) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_clear_direction_byte_without_touching_storage() {
        let mut completed = 0xdead_beef;
        for high in [0, 0x100, 0x8000_0000, 0xffff_ff00] {
            for low in 0..0x80 {
                assert_eq!(unsafe { usb_in_transfer(core::ptr::null_mut(), high | low,
                    core::ptr::null(), u32::MAX, &mut completed, u32::MAX) }, -1);
                assert_eq!(completed, 0xdead_beef);
            }
        }
    }
}
