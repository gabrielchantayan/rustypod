//! `media_operation_status_set` — original: `FUN_08005e88` @ 0x08005e88
//! (12 bytes; literal-pool word @ 0x08005e94 = 0x22008ca0).
//!
//! Stores its one-byte status argument into the media-operation status byte.
//! Its two direct callers establish the name: the media operation completion
//! path records status 5 after its callback reports completion, while the
//! media metadata-load failure path records status 3 before notifying its
//! error context. The retail body is exactly `ldr r1, [literal]; strb r0,
//! [r1]; bx lr`; it performs no read, validation, or synchronization.
//!
//! On target the byte is the firmware global at 0x22008ca0. Host builds use
//! a private byte stand-in so the exact store is directly behavioral-testable.

/// Firmware address of the media operation's one-byte status global.
#[cfg(target_os = "none")]
const MEDIA_OPERATION_STATUS_ADDRESS: *mut u8 = 0x2200_8ca0 as *mut u8;

/// Host stand-in for the firmware media-operation status byte.
#[cfg(not(target_os = "none"))]
static mut HOST_MEDIA_OPERATION_STATUS: u8 = 0;

#[inline(always)]
unsafe fn media_operation_status_byte() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        MEDIA_OPERATION_STATUS_ADDRESS
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_MEDIA_OPERATION_STATUS)
    }
}

/// media_operation_status_set — original: `FUN_08005e88` @ 0x08005e88
/// (12 bytes).
///
/// Writes `status` to the media-operation status byte at 0x22008ca0. This is
/// a plain byte store: each call replaces the preceding status unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_operation_status_set(status: u8) {
    media_operation_status_byte().write(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_each_caller_status_and_replaces_the_previous_byte() {
        unsafe {
            media_operation_status_byte().write(0xa5);
            media_operation_status_set(5);
            assert_eq!(media_operation_status_byte().read(), 5);

            media_operation_status_set(3);
            assert_eq!(media_operation_status_byte().read(), 3);
        }
    }

    #[test]
    fn stores_the_full_byte_without_interpretation() {
        for status in [0, 1, 3, 5, 0x80, 0xff] {
            unsafe {
                media_operation_status_set(status);
                assert_eq!(media_operation_status_byte().read(), status);
            }
        }
    }
}
