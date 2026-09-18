//! signed_clamp_i32 — original: `FUN_080f0f84` @ 0x080f0f84 (32 bytes;
//! 12 direct `bl` call sites, all unconditional).
//!
//! The raw ARM body is eight instructions from 0x080f0f84 through
//! 0x080f0fa0; the separately linked signed low-clamp siblings at
//! 0x080f0f44 and 0x080f0f64 end before this entry, and `smull` at
//! 0x080f0fa4 starts the next function. It clamps `value` with signed
//! comparisons in the original order: values below `lower` return `lower`,
//! otherwise values above `upper` return `upper`, and the remainder pass
//! through. Consequently an inverted interval keeps the low-bound arm's
//! precedence instead of treating bounds as an error.
//!
//! A complete osos.dec decode finds twelve direct inbound `bl` instructions
//! (0x082485f0, 0x08248604, 0x08248618, 0x0824862c, 0x08248650, 0x08248664,
//! 0x08248678, 0x0824868c, 0x08253ec4, 0x08253edc, 0x08253ef4, and
//! 0x08253f0c), no predicated calls, and one non-call tail `b` at
//! 0x082a05d0. No deliberate deviations.

/// signed_clamp_i32 — original: `FUN_080f0f84` @ 0x080f0f84 (32 bytes).
///
/// Applies the retailOS signed lower-then-upper clamp. The branch ordering
/// remains observable when `lower > upper`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.signed_clamp_i32"]
pub extern "C" fn signed_clamp_i32(value: i32, lower: i32, upper: i32) -> i32 {
    if value < lower {
        lower
    } else if value > upper {
        upper
    } else {
        value
    }
}
/// signed_clamp_i32_q16 — original: `FUN_080f0f44` @ 0x080f0f44 (32 bytes;
/// 6 direct `bl` call sites, all unconditional).
///
/// Raw ARM confirms the exact extent 0x080f0f44..0x080f0f64; the following
/// independently linked function at 0x080f0f64 is byte-identical. This
/// lower-then-upper signed clamp returns `lower` below the range, `upper`
/// above it, and `value` otherwise. All six callers use the Q16 interval
/// 0..0x10000. No deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.signed_clamp_i32_q16"]
pub extern "C" fn signed_clamp_i32_q16(value: i32, lower: i32, upper: i32) -> i32 {
    if value < lower {
        lower
    } else if value > upper {
        upper
    } else {
        value
    }
}
/// signed_clamp_i32_q16_secondary — original: `FUN_080f0f64` @
/// 0x080f0f64 (32 bytes; four direct `bl` call sites, all unconditional).
///
/// Raw osos.dec words establish the exact eight-instruction body from
/// 0x080f0f64 through 0x080f0f80; the byte-identical
/// `signed_clamp_i32` entry begins at 0x080f0f84. It performs signed
/// lower-then-upper clamping, preserving the lower-bound precedence for an
/// inverted interval. Whole-image A32 decoding finds four inbound plain
/// `bl` instructions (0x08255114, 0x08255130, 0x0825514c, and 0x08255168)
/// and no predicated calls. No deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.signed_clamp_i32_q16_secondary"]
pub extern "C" fn signed_clamp_i32_q16_secondary(value: i32, lower: i32, upper: i32) -> i32 {
    if value < lower {
        lower
    } else if value > upper {
        upper
    } else {
        value
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bounds_include_extreme_values() {
        assert_eq!(signed_clamp_i32(i32::MIN, -7, 7), -7);
        assert_eq!(signed_clamp_i32(-7, -7, 7), -7);
        assert_eq!(signed_clamp_i32(0, -7, 7), 0);
        assert_eq!(signed_clamp_i32(7, -7, 7), 7);
        assert_eq!(signed_clamp_i32(i32::MAX, -7, 7), 7);
    }

    #[test]
    fn comparisons_are_signed_not_unsigned() {
        assert_eq!(signed_clamp_i32(-1, 0, i32::MAX), 0);
        assert_eq!(signed_clamp_i32(0, i32::MIN, -1), -1);
        assert_eq!(signed_clamp_i32(i32::MIN, i32::MIN, i32::MAX), i32::MIN);
        assert_eq!(signed_clamp_i32(i32::MAX, i32::MIN, i32::MAX), i32::MAX);
    }

    #[test]
    fn inverted_bounds_preserve_lower_branch_precedence() {
        assert_eq!(signed_clamp_i32(-5, 10, 0), 10);
        assert_eq!(signed_clamp_i32(10, 10, 0), 0);
        assert_eq!(signed_clamp_i32(20, 10, 0), 0);
    }

    #[test]
    fn q16_clamp_covers_the_real_interval_and_inverted_bounds() {
        assert_eq!(signed_clamp_i32_q16(i32::MIN, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16(-1, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16(0, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16(0x8000, 0, 0x10000), 0x8000);
        assert_eq!(signed_clamp_i32_q16(0x10000, 0, 0x10000), 0x10000);
        assert_eq!(signed_clamp_i32_q16(0x10001, 0, 0x10000), 0x10000);
        assert_eq!(signed_clamp_i32_q16(i32::MAX, 0, 0x10000), 0x10000);
        assert_eq!(signed_clamp_i32_q16(0, 10, -10), 10);
        assert_eq!(signed_clamp_i32_q16(10, 10, -10), -10);
    }

    #[test]
    fn secondary_q16_clamp_matches_inbound_call_range_and_signed_edges() {
        assert_eq!(signed_clamp_i32_q16_secondary(i32::MIN, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16_secondary(-1, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16_secondary(0, 0, 0x10000), 0);
        assert_eq!(signed_clamp_i32_q16_secondary(0x8000, 0, 0x10000), 0x8000);
        assert_eq!(signed_clamp_i32_q16_secondary(0x10000, 0, 0x10000), 0x10000);
        assert_eq!(signed_clamp_i32_q16_secondary(i32::MAX, 0, 0x10000), 0x10000);
        assert_eq!(signed_clamp_i32_q16_secondary(0, 10, -10), 10);
        assert_eq!(signed_clamp_i32_q16_secondary(10, 10, -10), -10);
    }
}
