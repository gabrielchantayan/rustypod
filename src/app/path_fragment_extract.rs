//! path_fragment_extract — `FUN_0805acb8` @ 0x0805acb8.
//!
//! True extent [0x0805acb8, 0x0805ad40): 136 bytes, no literals; the next
//! function starts with PUSH. Two incoming plain BLs, five outgoing plain
//! BLs, and no predicated BLs. Reject NULL arguments with -50. Selector zero
//! copies 35 bytes from counted-path payload +2, or invokes the configured
//! prefix rewrite at 0x080ccac8 with capacity 36. Nonzero selectors copy
//! 35 bytes from +21 BEFORE rejecting payload lengths <=35. On success,
//! store the selector's low byte at output +36; byte +35 is not forced NUL.
//! No target behavioral deviations. The unported prefix rewrite remains a
//! firmware seam; hosts must install it before exercising that branch.

use crate::app::configured_path_prefix_matches::configured_path_prefix_matches;
use crate::libc::{strlen::strlen, strncpy::strncpy};

/// Unported configured-prefix replacement at 0x080ccac8. Its return value
/// (required capacity or a destination pointer) is ignored by this caller.
pub type ConfiguredPathPrefixRewrite = unsafe extern "C" fn(*mut u8, *const u8, u32) -> usize;

unsafe extern "C" fn firmware_configured_path_prefix_rewrite(
    output: *mut u8, path: *const u8, capacity: u32,
) -> usize {
    #[cfg(target_os = "none")]
    {
        let rewrite: ConfiguredPathPrefixRewrite = core::mem::transmute(0x080c_cac8usize);
        rewrite(output, path, capacity)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (output, path, capacity);
        panic!("configured path prefix rewrite requires a host implementation")
    }
}

pub static mut CONFIGURED_PATH_PREFIX_REWRITE_IMPL: ConfiguredPathPrefixRewrite =
    firmware_configured_path_prefix_rewrite;

/// # Safety
/// Non-NULL `path` must contain a readable NUL-terminated payload at +2 and
/// at least 35 readable bytes from +21 for a nonzero selector. `output` must
/// hold 37 writable bytes, with no overlap with the copied source. The zero
/// selector also requires the live prefix configuration and rewrite seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_fragment_extract(
    path: *const u8, output: *mut u8, selector: u32,
) -> i32 {
    if path.is_null() || output.is_null() {
        return -50;
    }
    if selector == 0 {
        if configured_path_prefix_matches(path.add(2)) == 0 {
            strncpy(output, path.add(2), 35);
        } else {
            let rewrite = core::ptr::read_volatile(
                core::ptr::addr_of!(CONFIGURED_PATH_PREFIX_REWRITE_IMPL),
            );
            rewrite(output, path.add(2), 36);
        }
    } else {
        strncpy(output, path.add(21), 35);
        if strlen(path.add(2)) <= 35 {
            return -50;
        }
    }
    output.add(36).write(selector as u8);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_preserve_output() {
        let mut output = [0xa5; 39];
        unsafe {
            assert_eq!(path_fragment_extract(core::ptr::null(), output.as_mut_ptr(), 0), -50);
            assert_eq!(path_fragment_extract(core::ptr::null(), core::ptr::null_mut(), 1), -50);
            assert_eq!(path_fragment_extract(b"\0\0\0".as_ptr(), core::ptr::null_mut(), 1), -50);
        }
        assert_eq!(output, [0xa5; 39]);
    }
    #[test]
    fn zero_selector_copies_payload_with_padding_or_truncation() {
        use crate::app::configured_path_prefix_matches::tests::{TEST_LOCK, set_prefix};
        let _guard = TEST_LOCK.lock();
        let prefix = b"reserved/";
        unsafe { set_prefix(prefix.as_ptr(), prefix.len()); }
        for length in [0usize, 1, 34, 35, 36, 60] {
            let mut path = [0u8; 68];
            path[..2].copy_from_slice(&(length as u16).to_le_bytes());
            path[2..2 + length].fill(b'x');
            let mut output = [0xa5; 39];
            let mut expected = output;
            for i in 0..35 { expected[1 + i] = if i < length { b'x' } else { 0 }; }
            expected[37] = 0;
            unsafe {
                assert_eq!(path_fragment_extract(path.as_ptr(), output.as_mut_ptr().add(1), 0), 0);
            }
            assert_eq!(output, expected, "length={length}");
        }
    }


    #[test]
    fn length_boundary_copy_before_error_and_selector_truncation() {
        for length in [0usize, 19, 20, 34, 35, 36, 53, 54, 55, 75] {
            for selector in [1u32, 255, 256, u32::MAX] {
                let mut path = [0u8; 84];
                for i in 0..length { path[2 + i] = b'a' + (i % 26) as u8; }
                let mut output = [0xa5; 39];
                let mut expected = output;
                let mut ended = false;
                for i in 0..35 {
                    ended |= path[21 + i] == 0;
                    expected[1 + i] = if ended { 0 } else { path[21 + i] };
                }
                let status = if length <= 35 { -50 } else { 0 };
                if status == 0 { expected[37] = selector as u8; }
                unsafe {
                    assert_eq!(path_fragment_extract(path.as_ptr(), output.as_mut_ptr().add(1), selector), status);
                }
                assert_eq!(output, expected, "length={length}, selector={selector}");
            }
        }
    }
}
