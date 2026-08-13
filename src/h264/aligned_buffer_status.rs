//! H.264 aligned-buffer status validation.
//!
//! `h264_aligned_buffer_status` — original: `FUN_080276c8` @ 0x080276c8
//! (40 bytes; leaf function). The recovered ARM body first returns status 2
//! for a null buffer, then treats its second argument as a signed 32-bit
//! value: exactly a positive multiple of 16 returns status 0; zero, negative,
//! and non-16-byte-aligned values return status 3. No direct `bl` caller was
//! recovered in the code graph, so the arguments and status values retain
//! their ABI-level names rather than speculating about a higher-level format.

/// Validates a buffer presence plus its positive 16-byte-aligned value.
///
/// Returns 2 when `buffer` is null, 0 when `aligned_value` is positive and a
/// multiple of 16, and 3 for every other value. This preserves the ARM
/// comparison's signed interpretation of `r1`; values with bit 31 set are
/// invalid even if their low four bits are clear. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_aligned_buffer_status(
    buffer: *const u8,
    aligned_value: i32,
) -> u32 {
    if buffer.is_null() {
        return 2;
    }

    if aligned_value <= 0 {
        return 3;
    }

    if aligned_value & 0xf == 0 {
        0
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_buffer_has_its_own_status_before_value_validation() {
        assert_eq!(
            unsafe { h264_aligned_buffer_status(core::ptr::null(), 16) },
            2
        );
    }

    #[test]
    fn zero_and_negative_values_are_invalid_even_when_aligned() {
        let buffer = core::ptr::NonNull::<u8>::dangling().as_ptr();
        for value in [0, -16, i32::MIN] {
            assert_eq!(unsafe { h264_aligned_buffer_status(buffer, value) }, 3, "{value}");
        }
    }

    #[test]
    fn positive_unaligned_values_are_invalid() {
        let buffer = core::ptr::NonNull::<u8>::dangling().as_ptr();
        for value in [1, 15, 17] {
            assert_eq!(unsafe { h264_aligned_buffer_status(buffer, value) }, 3, "{value}");
        }
    }

    #[test]
    fn positive_sixteen_byte_multiples_succeed() {
        let buffer = core::ptr::NonNull::<u8>::dangling().as_ptr();
        for value in [16, 32, i32::MAX - 15] {
            assert_eq!(unsafe { h264_aligned_buffer_status(buffer, value) }, 0, "{value}");
        }
    }
}
