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

/// is_zero_or_power_of_two — original: `FUN_0825ebb4` @ 0x0825ebb4
/// (24 bytes).
///
/// Returns one when `value` is zero or has exactly one bit set, and zero
/// otherwise. The ARM leaf forms `-value`, clears its lowest set bit with
/// `value & ~(-value)`, and maps the resulting zero flag to the `u32` C-ABI
/// result in r0. Consequently, unlike a conventional power-of-two predicate,
/// zero deliberately counts as true.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn is_zero_or_power_of_two(value: u32) -> u32 {
    u32::from(value & value.wrapping_sub(1) == 0)
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

    /// Literal model of the recovered C expression:
    /// `value & ~(~value + 1) == 0`.
    fn reference_is_zero_or_power_of_two(value: u32) -> u32 {
        u32::from(value & !(!value).wrapping_add(1) == 0)
    }

    #[test]
    fn zero_or_power_of_two_matches_recovered_expression() {
        // Exhaust the range where adjacent powers are densely represented,
        // including the deliberate zero-is-true contract.
        for value in 0..=0x1_0000u32 {
            assert_eq!(
                is_zero_or_power_of_two(value),
                reference_is_zero_or_power_of_two(value),
                "value {value:#010x}"
            );
        }
    }

    #[test]
    fn zero_or_power_of_two_covers_every_u32_bit_position() {
        assert_eq!(is_zero_or_power_of_two(0), 1, "zero is deliberately true");
        for bit in 0..32 {
            let power = 1u32 << bit;
            assert_eq!(is_zero_or_power_of_two(power), 1, "bit {bit}");
            if bit > 1 {
                assert_eq!(is_zero_or_power_of_two(power - 1), 0, "below bit {bit}");
            }
            if bit != 0 && bit != 31 {
                assert_eq!(is_zero_or_power_of_two(power + 1), 0, "above bit {bit}");
            }
        }
        for value in [u32::MAX, u32::MAX - 1, 0x8000_0001, 0xc000_0000] {
            assert_eq!(
                is_zero_or_power_of_two(value),
                reference_is_zero_or_power_of_two(value),
                "value {value:#010x}"
            );
        }
    }
}
