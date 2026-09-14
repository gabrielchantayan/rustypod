//! SQLite's binary64 NaN predicate.
//!
//! - `sqlite_is_nan` — original: `FUN_0837cb44` @ 0x0837cb44 (28 bytes,
//!   0x0837cb44..0x0837cb60; **5 `bl` call sites**, all unconditional and
//!   binary-scanned from osos.dec: 0x082c40d8, 0x083879c0, 0x0838c0dc,
//!   0x0838cda4, and 0x08397e68). Upstream SQLite 3.5's `sqlite3IsNaN`.
//!
//! ### Algorithm
//!
//! The retail body copies its sole binary64 argument from `r0:r1` to
//! `r2:r3`, calls the already-ported ADS `__dcmpeq` helper @ 0x083eb748 to
//! compare the value with itself, then normalizes the comparison's `NE` flag
//! to an `int`: NaN is unordered and therefore unequal to itself. This port
//! recognizes the same IEEE-754 representation directly: an all-ones exponent
//! and nonzero fraction means NaN.
//!
//! ### Deliberate deviations
//!
//! The original reaches `__dcmpeq` and obtains its result from CPSR flags;
//! this port tests the binary64 bits directly and returns the equivalent
//! `0`/`1` C integer. That avoids making a flag-returning helper part of the
//! Rust ABI. The helper's denormal flush behavior cannot affect a
//! self-comparison: every non-NaN, including either signed zero and every
//! denormal, compares equal to itself.

const EXPONENT_MASK: u64 = 0x7ff0_0000_0000_0000;
const FRACTION_MASK: u64 = 0x000f_ffff_ffff_ffff;

/// sqlite_is_nan — original: `FUN_0837cb44` @ 0x0837cb44 (28 bytes; 5 `bl`
/// call sites, all unconditional).
///
/// `sqlite3IsNaN`: return 1 precisely for either quiet or signaling binary64
/// NaN, regardless of sign or payload; return 0 for every finite value,
/// signed zero, subnormal, and infinity.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_is_nan")]
#[inline(never)]
pub extern "C" fn sqlite_is_nan(value: f64) -> i32 {
    let bits = value.to_bits();
    ((bits & EXPONENT_MASK) == EXPONENT_MASK && (bits & FRACTION_MASK) != 0) as i32
}

#[cfg(test)]
mod tests {
    use super::sqlite_is_nan;

    #[test]
    fn distinguishes_all_binary64_classes() {
        let non_nan = [
            0x0000_0000_0000_0000, // +0
            0x8000_0000_0000_0000, // -0
            0x0000_0000_0000_0001, // smallest positive subnormal
            0x800f_ffff_ffff_ffff, // largest negative subnormal
            0x0010_0000_0000_0000, // smallest normal
            0x7fef_ffff_ffff_ffff, // largest finite
            0x7ff0_0000_0000_0000, // +infinity
            0xfff0_0000_0000_0000, // -infinity
        ];
        for bits in non_nan {
            assert_eq!(sqlite_is_nan(f64::from_bits(bits)), 0, "{bits:#018x}");
        }

        let nan = [
            0x7ff0_0000_0000_0001, // positive signaling NaN
            0xfff0_0000_0000_0001, // negative signaling NaN
            0x7ff8_0000_0000_0000, // positive quiet NaN
            0xffff_ffff_ffff_ffff, // negative quiet NaN, maximum payload
        ];
        for bits in nan {
            assert_eq!(sqlite_is_nan(f64::from_bits(bits)), 1, "{bits:#018x}");
        }
    }
}
