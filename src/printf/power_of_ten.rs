//! Decimal power helper used by the floating-point formatter.
//!
//! `decimal_power_of_ten` — retailOS `FUN_080e83b8` at **0x080e83b8**.
//! True extent: **64 bytes** (`0x080e83b8..0x080e83f7`): 48 bytes of code
//! followed by two double literals; `0x080e83f8` starts the next real
//! function. Verified incoming call count: **3 plain `bl` calls**, at
//! 0x080e8018, 0x080e8054, and 0x080e8078; **0 predicated `bl` calls**.
//!
//! The function initializes the soft-float result to 1.0, then multiplies it
//! by the embedded 10.0 literal once per count, returning 10^count. The raw
//! A32 loop preserves r0:r1 for a zero count, so zero returns 1.0.
//!
//! Deliberate deviations: none. It calls the committed `__dmul` seam directly,
//! preserving the original soft-float operation and its non-IEEE edge behavior.

/// Returns the soft-float bit pattern for 10 raised to `count`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decimal_power_of_ten(mut count: u32) -> u64 {
    let multiply = crate::fp::fp_dmul::__dmul;
    let mut result = 1.0f64.to_bits();
    let ten = 10.0f64.to_bits();

    while count != 0 {
        result = unsafe { multiply(result, ten) };
        count -= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::decimal_power_of_ten;

    #[test]
    fn returns_one_for_zero_count() {
        assert_eq!(unsafe { decimal_power_of_ten(0) }, 1.0f64.to_bits());
    }

    #[test]
    fn builds_formatter_precision_powers() {
        for count in [1, 2, 6, 9, 10] {
            assert_eq!(
                unsafe { decimal_power_of_ten(count) },
                10.0f64.powi(count as i32).to_bits(),
            );
        }
    }
}
