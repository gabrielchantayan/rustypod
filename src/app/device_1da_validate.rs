//! Validate the `/iPod_Control/Device/1da` marker.
//!
//! Original: `FUN_08164bf4` @ `0x08164bf4`. True extent is 140 bytes
//! (`0x08164bf4..0x08164c80`): 112 instruction bytes followed by a 28-byte
//! inline path/padding region. Raw A32 decoding verifies two inbound plain
//! BLs (0x08164264, 0x081647e0), five outbound plain BLs, and no predicated
//! BLs. The next real function starts at 0x08164c80.
//!
//! Send gateway payload 54 with flag zero, query the path with flags zero,
//! and, only for a nonzero query, fill a 128-byte buffer with 0x5d and pass
//! it to retained retailOS 0x082d4474 with the path. Return one only when
//! that call returns zero. Always send payload 54 with timeout 1000 last.
//! Deliberate deviations: move the literal into Rust read-only storage and
//! use a typed array instead of the original sp+4 storage. The ADS memset
//! argument order (dst, length, value) is represented by array initialization.
//! No callee identity is invented for 0x082d4474; device builds call its
//! verified address, and host execution of that boundary is unsupported.

const MARKER_PATH: &[u8; 25] = b"/iPod_Control/Device/1da\0";

#[inline(always)]
fn validate_with(
    mut acquire: impl FnMut(),
    mut query: impl FnMut(*const u8, u32) -> u32,
    mut validate: impl FnMut(&mut [u8; 128], *const u8) -> u32,
    mut release: impl FnMut(),
) -> u32 {
    acquire();
    let mut result = 0;
    if query(MARKER_PATH.as_ptr(), 0) != 0 {
        let mut buffer = [0x5d; 128];
        if validate(&mut buffer, MARKER_PATH.as_ptr()) == 0 {
            result = 1;
        }
    }
    release();
    result
}

#[inline(never)]
unsafe fn retained_validator(buffer: *mut u8, length: u32, path: *const u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8, u32, *const u8) -> u32 =
            core::mem::transmute(0x082d_4474usize);
        call(buffer, length, path)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (buffer, length, path);
        panic!("retailOS boundary 0x082d4474 requires device execution")
    }
}

/// Return one when the existing device marker passes the retained validator.
///
/// # Safety
/// Requires a running retailOS gateway, filesystem, and validator at
/// 0x082d4474; the validator must not retain the temporary buffer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn device_1da_validate() -> u32 {
    validate_with(
        || crate::kernel::gateway_request_blocking::gateway_request_blocking(54, 0),
        |path, flags| crate::app::path_exists::path_exists(path, flags),
        |buffer, path| retained_validator(buffer.as_mut_ptr(), 128, path),
        || crate::kernel::gateway_request::gateway_request_timed(54, 1000),
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::RefCell;

    #[test]
    fn missing_marker_skips_validation_but_releases_gateway() {
        let events = RefCell::new(std::vec::Vec::new());
        let result = validate_with(
            || events.borrow_mut().push("acquire"),
            |_, _| { events.borrow_mut().push("query"); 0 },
            |_, _| panic!("missing path must not be validated"),
            || events.borrow_mut().push("release"),
        );
        assert_eq!(result, 0);
        assert_eq!(*events.borrow(), ["acquire", "query", "release"]);
    }

    #[test]
    fn present_marker_accepts_only_zero_status_and_releases_after_validation() {
        for exists in [1, 0x8000_0000, u32::MAX] {
            for status in [0, 1, 13, u32::MAX] {
                let events = RefCell::new(std::vec::Vec::new());
                let result = validate_with(
                    || events.borrow_mut().push("acquire"),
                    |path, flags| {
                        events.borrow_mut().push("query");
                        assert_eq!(flags, 0);
                        assert_eq!(unsafe { core::slice::from_raw_parts(path, 25) }, MARKER_PATH);
                        exists
                    },
                    |buffer, path| {
                        events.borrow_mut().push("validate");
                        assert_eq!(buffer, &[0x5d; 128]);
                        assert_eq!(path, MARKER_PATH.as_ptr());
                        // The original result depends only on status, not buffer contents.
                        buffer.fill(0);
                        status
                    },
                    || events.borrow_mut().push("release"),
                );
                assert_eq!(result, u32::from(status == 0));
                assert_eq!(*events.borrow(), ["acquire", "query", "validate", "release"]);
            }
        }
    }
}
