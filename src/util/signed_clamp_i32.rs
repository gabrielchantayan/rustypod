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
}
