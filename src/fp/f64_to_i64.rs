//! SQLite's guarded binary64-to-i64 conversion.
//!
//! ## Original and extent
//!
//! `FUN_082c67f4` at load address **0x082c67f4** occupies
//! **0x082c67f4..0x082c6850 (92 bytes)**: 76 bytes of instructions followed
//! by its 16-byte literal pool; the next real function starts with `push` at
//! 0x082c6850. Decoding the instruction words verifies **one plain `bl`**
//! (`__dcmplt` @ 0x083eb9c0) and **one predicated `blcs`** (`__dcmpgt` @
//! 0x083ebe38). The in-range path tail-branches to `__d2ll` @ 0x083ece5c.
//!
//! ## Algorithm
//!
//! The wrapper compares its input with -2^63 and +2^63. An ordered value
//! below the lower bound or above the upper bound returns i64::MIN; the
//! upper-bound equality reaches `__d2ll`, which itself clamps it to i64::MAX.
//! NaNs reach `__d2ll` and therefore preserve its retail trap result (zero).
//!
//! ## Deliberate deviations
//!
//! Rust cannot preserve CPSR across calls. The compare helpers' packed C flag
//! is tested explicitly instead. Volatile function-pointer loads retain the
//! three retail call boundaries and prevent LLVM from inlining the soft-float
//! helpers into this hookable wrapper.

use super::fp_compare::{__dcmplt, __dcmpgt, FLAGS_GREATER};
use super::fp_dconv::__d2ll;

/// f64_to_i64 — original: `FUN_082c67f4` @ 0x082c67f4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f64_to_i64(value: f64) -> i64 {
    let dcmplt: extern "C" fn(u64, u64) -> u32 =
        core::ptr::read_volatile(&(__dcmplt as extern "C" fn(u64, u64) -> u32));
    let dcmpgt: extern "C" fn(u64, u64) -> u32 =
        core::ptr::read_volatile(&(__dcmpgt as extern "C" fn(u64, u64) -> u32));
    let d2ll: unsafe extern "C" fn(u64) -> i64 =
        core::ptr::read_volatile(&(__d2ll as unsafe extern "C" fn(u64) -> i64));
    let bits = value.to_bits();

    if dcmplt(bits, f64::from_bits(0xc3e0_0000_0000_0000).to_bits()) & FLAGS_GREATER == 0 {
        return i64::MIN;
    }
    if dcmpgt(bits, f64::from_bits(0x43e0_0000_0000_0000).to_bits()) & FLAGS_GREATER == 0 {
        return i64::MIN;
    }
    d2ll(bits)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::f64_to_i64;

    #[test]
    fn clamps_ordered_out_of_range_values_to_minimum() {
        for value in [
            f64::from_bits(0xc3e0_0000_0000_0001),
            f64::from_bits(0x43e0_0000_0000_0001),
            f64::INFINITY,
        ] {
            assert_eq!(unsafe { f64_to_i64(value) }, i64::MIN, "{value:e}");
        }
    }

    #[test]
    fn delegates_in_range_values_and_nan_to_d2ll() {
        for (value, expected) in [
            (f64::from_bits(0xc3e0_0000_0000_0000), i64::MIN),
            (-1.75, -1),
            (-0.0, 0),
            (0.0, 0),
            (1.75, 1),
            (f64::from_bits(0x43df_ffff_ffff_ffff), 9_223_372_036_854_774_784),
            (f64::from_bits(0x7ff8_0000_0000_0001), 0),
        ] {
            assert_eq!(unsafe { f64_to_i64(value) }, expected, "{value:e}");
        }
    }
}
