//! Q16 signed integer to IEEE-754 single bits — `FUN_082a17c8` @
//! 0x082a17c8 (100 bytes).
//!
//! True extent: `0x082a17c8..0x082a182c`; the next real function starts at
//! `0x082a182c`. Raw A32 decoding finds one plain internal `bl` to the ported
//! [`crate::util::highest_set_bit::highest_set_bit`] and no predicated `bl`.
//! Three inbound direct calls are plain `bl`; none is predicated.
//!
//! The routine treats `*value` as a signed Q16 integer, forms its wrapping
//! magnitude, finds the highest set bit, and packs a truncating IEEE-754
//! single-precision bit pattern with exponent bias 111. It deliberately
//! preserves the retail zero result (`0x3700_0000`) and wrapping `i32::MIN`
//! magnitude rather than adding IEEE zero handling or rounding.

use super::highest_set_bit::highest_set_bit;

/// q16_i32_to_f32_bits — original: `FUN_082a17c8` @ 0x082a17c8 (100 bytes).
///
/// # Safety
///
/// `value` must be non-null and point to a readable aligned `i32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn q16_i32_to_f32_bits(value: *const i32) -> u32 {
    let raw = value.read() as u32;
    let sign = raw & 0x8000_0000;
    let magnitude = if sign != 0 { raw.wrapping_neg() } else { raw };
    let highest_bit = highest_set_bit(magnitude) as u32;
    let significand = if highest_bit < 24 {
        magnitude << (23 - highest_bit)
    } else {
        let shift = highest_bit.wrapping_sub(23);
        if shift >= 32 { 0 } else { magnitude >> shift }
    };

    sign | ((highest_bit.wrapping_add(111) << 23) & 0x7f80_0000) | (significand & 0x007f_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(value: i32) -> u32 {
        unsafe { q16_i32_to_f32_bits(&value) }
    }

    #[test]
    fn preserves_retail_zero_and_unit_q16_encodings() {
        assert_eq!(convert(0), 0x3700_0000);
        assert_eq!(convert(1), 0x3780_0000);
        assert_eq!(convert(-1), 0xb780_0000);
        assert_eq!(convert(0x0001_0000), 0x3f80_0000);
        assert_eq!(convert(-0x0001_0000), 0xbf80_0000);
    }

    #[test]
    fn preserves_wrapping_minimum_and_truncates_low_significand_bits() {
        assert_eq!(convert(i32::MIN), 0xc700_0000);
        assert_eq!(convert(i32::MAX), 0x46ff_ffff);
        assert_eq!(convert(0x0100_0003), 0x4380_0001);
        assert_eq!(convert(-0x0100_0003), 0xc380_0001);
    }
}
