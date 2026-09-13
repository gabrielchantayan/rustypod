//! Clears an optional single-byte output.

/// `clear_optional_byte` — original: `FUN_0805d9f0` @ **0x0805d9f0** (20
/// instruction bytes; 7 verified inbound `bl` call sites: 6 unconditional,
/// 1 `bleq`).
///
/// The raw ARM body is `movs r1,r0; movne r0,#0; strbne r0,[r1]; ldreq
/// r0,[pc,#0]; bx lr`, with literal-pool word `0xffff5bd9` immediately after
/// it. A non-NULL output receives zero and returns success. A NULL output is
/// not dereferenced and returns the literal status `-42023`. The one `bleq`
/// caller at 0x0804ff38 is caller-gated; the other six calls are unconditional.
/// Deliberate deviations: none.
///
/// # Safety
///
/// If `output` is non-NULL, it must be valid and writable for one byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.clear_optional_byte")]
#[inline(never)]
pub unsafe extern "C" fn clear_optional_byte(output: *mut u8) -> i32 {
    if output.is_null() {
        -42_023
    } else {
        output.write(0);
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::clear_optional_byte;

    #[test]
    fn clears_only_the_requested_byte_and_returns_success() {
        let mut bytes = [0x5a, 0xa5, 0x3c];

        let status = unsafe { clear_optional_byte(bytes.as_mut_ptr().add(1)) };

        assert_eq!(status, 0);
        assert_eq!(bytes, [0x5a, 0, 0x3c]);
    }

    #[test]
    fn null_output_returns_firmware_status_without_writing() {
        let status = unsafe { clear_optional_byte(core::ptr::null_mut()) };

        assert_eq!(status, -42_023);
    }
}
