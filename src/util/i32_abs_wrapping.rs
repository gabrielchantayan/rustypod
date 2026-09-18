//! i32_abs_wrapping — original: `FUN_080e75d8` @ 0x080e75d8 (12 bytes;
//! four direct `bl` call sites, all unconditional).
//!
//! Raw osos.dec words `e3500000 b2600000 e12fff1e` establish the exact
//! three-instruction body at 0x080e75d8..0x080e75e4; `add r0, r0, r1` at
//! 0x080e75e4 begins the next function. It compares `value` to zero and,
//! only when negative, computes `0 - value` in 32-bit two's-complement
//! arithmetic. Thus `i32::MIN` deliberately remains unchanged. Whole-image
//! A32 decoding finds four plain inbound `bl` calls (0x0821678c, 0x0821c73c,
//! 0x0821e280, and 0x0821fe3c) and no predicated `bl` calls. No deliberate
//! deviations.

/// i32_abs_wrapping — original: `FUN_080e75d8` @ 0x080e75d8 (12 bytes).
///
/// Returns the retailOS two's-complement absolute value; `i32::MIN` wraps to
/// itself, matching ARM `rsblt r0, r0, #0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.i32_abs_wrapping"]
pub extern "C" fn i32_abs_wrapping(value: i32) -> i32 {
    if value < 0 { value.wrapping_neg() } else { value }
}

#[cfg(test)]
mod tests {
    use super::i32_abs_wrapping;

    #[test]
    fn preserves_nonnegative_values_and_negates_negative_values() {
        assert_eq!(i32_abs_wrapping(0), 0);
        assert_eq!(i32_abs_wrapping(1), 1);
        assert_eq!(i32_abs_wrapping(i32::MAX), i32::MAX);
        assert_eq!(i32_abs_wrapping(-1), 1);
        assert_eq!(i32_abs_wrapping(-123_456_789), 123_456_789);
    }

    #[test]
    fn wraps_the_unrepresentable_absolute_value() {
        assert_eq!(i32_abs_wrapping(i32::MIN), i32::MIN);
    }
}
