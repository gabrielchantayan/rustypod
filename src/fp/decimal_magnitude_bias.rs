//! Decimal magnitude helper used by the audio metadata formatter.
//!
//! `decimal_magnitude_bias` — retailOS `FUN_082ccc90` at `0x082ccc90`.
//! True size: 116 bytes (`0x082ccc90..0x082ccd04`), ending before its
//! four-word literal pool. Verified call count: four incoming plain `bl`
//! instructions and no incoming predicated `bl`; it makes three plain calls
//! per loop iteration (`__dcmpgt`, `__dadd`, and `__dmul`).
//!
//! Starting with a decimal scale of 1.0 and a result of 10.0, the original
//! increments the result and multiplies the scale by 10.0 while `value` is
//! greater than the scale. The comparison deliberately uses retailOS's
//! soft-float comparison semantics, including its NaN and denormal handling.
//! Deliberate deviation: ARM observes the C flag directly after `__dcmpgt`;
//! the Rust helper returns packed flags, so this port tests its C bit.

#[cfg(not(target_os = "none"))]
use crate::fp::{fp_compare::__dcmpgt, fp_dadd::__dadd, fp_dmul::__dmul};

#[cfg(target_os = "none")]
unsafe extern "C" {
    #[link_name = "__dcmpgt"]
    fn retail_dcmpgt(value: u64, scale: u64) -> u32;
    #[link_name = "__dadd"]
    fn retail_dadd(value: u64, increment: u64) -> u64;
    #[link_name = "__dmul"]
    fn retail_dmul(value: u64, scale: u64) -> u64;
}

const ONE: u64 = 0x3ff0_0000_0000_0000;
const TEN: u64 = 0x4024_0000_0000_0000;

/// Returns the retailOS decimal magnitude bias for a soft-float double.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decimal_magnitude_bias(value: u64) -> u64 {
    let mut result = TEN;
    let mut scale = ONE;

    while compare_gt(value, scale) & 2 == 0 {
        result = add(result, ONE);
        scale = multiply(scale, TEN);
    }

    result
}
#[inline]
unsafe fn compare_gt(value: u64, scale: u64) -> u32 {
    #[cfg(target_os = "none")]
    return retail_dcmpgt(value, scale);
    #[cfg(not(target_os = "none"))]
    return __dcmpgt(value, scale);
}

#[inline]
unsafe fn add(value: u64, increment: u64) -> u64 {
    #[cfg(target_os = "none")]
    return retail_dadd(value, increment);
    #[cfg(not(target_os = "none"))]
    return __dadd(value, increment);
}

#[inline]
unsafe fn multiply(value: u64, scale: u64) -> u64 {
    #[cfg(target_os = "none")]
    return retail_dmul(value, scale);
    #[cfg(not(target_os = "none"))]
    return __dmul(value, scale);
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn bits(value: f64) -> u64 {
        value.to_bits()
    }

    #[test]
    fn stops_at_each_decimal_power_boundary() {
        let cases = [
            (-1.0, 10.0),
            (0.0, 10.0),
            (1.0, 10.0),
            (1.000_000_000_000_000_2, 11.0),
            (10.0, 11.0),
            (10.000_000_000_000_002, 12.0),
            (100.0, 12.0),
            (100.000_000_000_000_01, 13.0),
        ];

        for (value, expected) in cases {
            assert_eq!(unsafe { decimal_magnitude_bias(bits(value)) }, bits(expected));
        }
    }

    #[test]
    fn unordered_input_preserves_initial_result() {
        assert_eq!(unsafe { decimal_magnitude_bias(f64::NAN.to_bits()) }, TEN);
    }
}
