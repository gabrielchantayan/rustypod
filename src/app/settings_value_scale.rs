//! `settings_value_scale` — retailOS `FUN_080e676c` at **0x080e676c**.
//!
//! Raw ARM establishes the exact **100-byte** extent
//! (`0x080e676c..0x080e67d0`): `push {r4,r5,r6,lr}` opens the body and
//! `0x080e67cc` is its final `pop {r4,r5,r6,pc}`; the separately linked next
//! function opens at `0x080e67d0`. Decoding every ARM B/BL immediate in
//! `osos.dec` finds **six direct BL call sites**, all unconditional (none
//! predicated and no direct tail branches): `0x0816fc78`, `0x08170e3c`,
//! `0x081a5420`, `0x081bbe60`, `0x081bbea4`, and `0x081bbf08`.
//!
//! The function maps the signed 32-bit input across two linear segments:
//! inputs at or below 50 start at 6 and reach 55, while larger inputs rise
//! from 55 toward 100. Every multiply, add, and subtraction wraps to the
//! target's 32-bit register width; division is the already ported signed ADS
//! runtime helper and therefore truncates toward zero.
//!
//! ## Deliberate deviation
//!
//! The two direct callee getters are unported, but raw decoding proves they
//! return immutable constants: `FUN_080539cc` (`0x080539cc`) returns 6 and
//! `FUN_08051e30` (`0x08051e30`) returns 55. This port embeds those verified
//! values instead of adding dispatch seams for constant-return leaves. Their
//! values make the stock `upper == 100` arm unreachable.

use crate::runtime::rt_div::__rt_sdiv;

const LOWER_VALUE: i32 = 6;
const MIDPOINT_VALUE: i32 = 55;
const MIDPOINT_INPUT: i32 = 50;
const MAXIMUM_VALUE: i32 = 100;

/// Maps a settings input through the retail two-segment 6..100 curve.
///
/// The argument and result preserve the raw ARM `r0` bit pattern. In
/// particular, comparisons and division treat it as signed and arithmetic
/// wraps before division.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn settings_value_scale(value: u32) -> u32 {
    let value = value as i32;
    let result = if value > MIDPOINT_INPUT {
        let remaining_input = MAXIMUM_VALUE.wrapping_sub(value);
        let remaining_value = MAXIMUM_VALUE.wrapping_sub(MIDPOINT_VALUE);
        let quotient = unsafe { __rt_sdiv(remaining_input.wrapping_mul(remaining_value), MIDPOINT_INPUT) };
        MAXIMUM_VALUE.wrapping_sub(quotient)
    } else {
        let value_range = MIDPOINT_VALUE.wrapping_sub(LOWER_VALUE);
        let quotient = unsafe { __rt_sdiv(value.wrapping_mul(value_range), MIDPOINT_INPUT) };
        LOWER_VALUE.wrapping_add(quotient)
    };
    result as u32
}

#[cfg(test)]
mod tests {
    use super::settings_value_scale;

    #[test]
    fn maps_each_segment_boundary_with_truncating_steps() {
        for (input, expected) in [(0, 6), (1, 6), (49, 54), (50, 55), (51, 56), (99, 100), (100, 100)] {
            assert_eq!(unsafe { settings_value_scale(input) }, expected, "input={input}");
        }
    }

    #[test]
    fn preserves_signed_comparison_and_wrapping_arithmetic() {
        assert_eq!(unsafe { settings_value_scale(101) }, 100, "the upper segment truncates");
        assert_eq!(unsafe { settings_value_scale(u32::MAX) }, 6, "-1 remains on the lower segment");
        assert_eq!(unsafe { settings_value_scale((-50i32) as u32) }, (-43i32) as u32);
        assert_eq!(unsafe { settings_value_scale(i32::MIN as u32) }, 0xfd70_a3de);
        assert_eq!(unsafe { settings_value_scale(i32::MAX as u32) }, 0x028f_5c32);
    }
}
