//! battery_adc_code_to_millivolts — original: `FUN_082e554c` @ `0x082e554c`
//! (40 bytes; 2 plain `bl` call sites, no predicated calls).
//!
//! Raw osos.dec words establish the exact ten-instruction A32 body
//! `0x082e554c..0x082e5570`; the following literal word `0x000003ff` supplies
//! the divisor and `push {r4,lr}` at `0x082e5578` begins the next real
//! function. The function wraps `adc_code * 2000`, divides it by 1023 through
//! the ported ADS unsigned-divider seam, adds 2250, then zero-extends the low
//! halfword. Complete-image direct-call decoding finds two inbound plain `bl`
//! instructions (`0x082bc4e0` and `0x082e5878`) and no predicated `bl`
//! instructions. No deliberate deviations.

use crate::runtime::rt_div::__rt_udiv;

/// Converts a 10-bit battery ADC code to the retailOS millivolt scale.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.battery_adc_code_to_millivolts")]
#[inline(never)]
pub unsafe extern "C" fn battery_adc_code_to_millivolts(adc_code: u32) -> u32 {
    let scaled = unsafe { __rt_udiv(adc_code.wrapping_mul(2_000), 1_023) };
    scaled.wrapping_add(2_250) & u16::MAX as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(adc_code: u32) -> u32 {
        (adc_code.wrapping_mul(2_000) / 1_023u32)
            .wrapping_add(2_250)
            & u16::MAX as u32
    }

    #[test]
    fn converts_adc_range_boundaries_and_quantization_edges() {
        for (adc_code, expected) in [
            (0, 2_250),
            (1, 2_251),
            (1_021, 4_246),
            (1_022, 4_248),
            (1_023, 4_250),
            (1_024, 4_251),
        ] {
            assert_eq!(unsafe { battery_adc_code_to_millivolts(adc_code) }, expected);
        }
    }

    #[test]
    fn preserves_wrapping_multiply_and_halfword_return() {
        for adc_code in [32_768, u32::MAX - 1, u32::MAX] {
            assert_eq!(unsafe { battery_adc_code_to_millivolts(adc_code) }, reference(adc_code));
        }
    }
}
