//! is_zero — `FUN_08027afc` @ 0x08027afc (12 bytes).
//!
//! The ARM leaf subtracts its unsigned input from one, retaining that result
//! only when the subtraction did not borrow. It therefore returns one for
//! zero and zero for every other `u32` input.

/// is_zero — original: `FUN_08027afc` @ 0x08027afc (12 bytes).
///
/// Returns one only when `value` is zero; the C ABI returns the result in r0.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn is_zero(value: u32) -> u32 {
    u32::from(value == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_predicate_matches_the_unsigned_arm_range() {
        for (value, expected) in [
            (0u32, 1u32),
            (1, 0),
            (2, 0),
            (u32::MAX - 1, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(is_zero(value), expected, "value {value:#010x}");
        }
    }
}
