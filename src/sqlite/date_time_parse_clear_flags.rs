//! Reset transient flags after parsing a date/time expression.
//!
//! Original: `FUN_082c3718` at load address 0x082c3718 (20 bytes).
//! Verified calls: 4 direct `bl` sites, all unconditional
//! (0x082df120, 0x082df284, 0x082df2d0, 0x082df5f8).
//! Algorithm: clear the parse-result bytes at offsets +0x28, +0x29, and
//! +0x2b, in that order; byte +0x2a is deliberately preserved. Although the
//! ARM implementation also leaves r0 unchanged, the verified call sites use
//! its void ABI result. Deliberate deviations: none.

/// Clears the transient parse-result flags at +0x28, +0x29, and +0x2b.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn date_time_parse_clear_flags(result: *mut u8) {
    result.add(0x28).write_volatile(0);
    result.add(0x29).write_volatile(0);
    result.add(0x2b).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::date_time_parse_clear_flags;

    #[test]
    fn clears_only_the_three_transient_flags() {
        let mut result = [0xa5u8; 0x2c];
        result[0x28] = 1;
        result[0x29] = 2;
        result[0x2a] = 3;
        result[0x2b] = 4;

        unsafe { date_time_parse_clear_flags(result.as_mut_ptr()) };
        assert_eq!(&result[0x28..], &[0, 0, 3, 0]);
        assert!(result[..0x28].iter().all(|&byte| byte == 0xa5));
    }
}
