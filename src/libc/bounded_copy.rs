//! strcpy_bounded_nul — original: `FUN_08045ee0` @ 0x08045ee0 (52 bytes).
//!
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/002/08045ee0_FUN_08045ee0.c`.
//! The ARM leaf reads the current source byte before comparing its signed
//! 32-bit copied-byte counter with `limit`. It copies only non-NUL bytes while
//! the counter is unequal to `limit`, then always writes one terminating NUL
//! at the current destination cursor. Consequently, a zero limit terminates
//! `dst` without copying, and a negative limit behaves as an effectively
//! unbounded copy for ordinary finite strings (the equality counter starts at
//! zero and increments with ARM's wrapping 32-bit arithmetic).

/// Copies non-NUL bytes from `src` into `dst` until `src` is NUL or the
/// signed 32-bit copied-byte counter equals `limit`, then writes a NUL.
///
/// # Safety
/// `src` must be valid to read through its first NUL, unless an earlier
/// counter equality stops the copy; the first byte is still read when
/// `limit == 0`. `dst` must be valid for every copied byte plus the final NUL.
/// Ranges may overlap and retain the original's forward byte-copy behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strcpy_bounded_nul(
    mut src: *const u8,
    mut dst: *mut u8,
    limit: i32,
) {
    let mut copied = 0i32;

    loop {
        let byte = src.read_volatile();
        if byte == 0 || copied == limit {
            break;
        }

        dst.write_volatile(byte);
        src = src.add(1);
        dst = dst.add(1);
        copied = copied.wrapping_add(1);
    }

    dst.write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct transcription of the original's `ldrb; cmp; cmpne; bne` loop.
    unsafe fn reference(mut src: *const u8, mut dst: *mut u8, limit: i32) {
        let mut copied = 0i32;
        loop {
            let byte = *src;
            if byte == 0 || copied == limit {
                break;
            }
            *dst = byte;
            src = src.add(1);
            dst = dst.add(1);
            copied = copied.wrapping_add(1);
        }
        *dst = 0;
    }

    fn assert_matches_reference(source: &[u8], limit: i32) {
        let mut actual = [0xa5u8; 16];
        let mut expected = actual;
        unsafe {
            strcpy_bounded_nul(source.as_ptr(), actual.as_mut_ptr().add(2), limit);
            reference(source.as_ptr(), expected.as_mut_ptr().add(2), limit);
        }
        assert_eq!(actual, expected, "source={source:?}, limit={limit}");
        assert_eq!(actual[..2], [0xa5; 2], "prefix guard");
    }

    #[test]
    fn zero_limit_only_writes_destination_nul() {
        assert_matches_reference(b"abc\0sentinel", 0);
    }

    #[test]
    fn positive_limits_stop_at_each_counter_equality() {
        let source = b"abcd\0sentinel";
        for limit in 0..=6 {
            assert_matches_reference(source, limit);
        }
    }

    #[test]
    fn source_nul_precedes_an_unreached_positive_limit() {
        assert_matches_reference(b"ab\0must-not-copy", 5);
    }

    #[test]
    fn negative_limit_copies_through_source_nul() {
        for limit in [-1, -17, i32::MIN] {
            assert_matches_reference(b"abc\0must-not-copy", limit);
        }
    }
}
