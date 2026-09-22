//! `passkey_mask_indicator_countdown_tick` — original: `FUN_0827f2ac` @
//! `0x0827f2ac` (36 bytes, `0x0827f2ac..0x0827f2d0`; the next separately
//! linked function begins at `0x0827f2d0`).
//!
//! The function decrements the signed countdown at target object offset `+0x8c`.
//! A negative post-decrement value is reset to 3, then the four passkey mask
//! indicators are refreshed. Raw A32 decoding finds one unconditional direct
//! `bl` in the body (to `refresh_passkey_mask_indicators`) and three
//! unconditional direct callers at `0x0813fb20`, `0x08140098`, and `0x0820ea44`;
//! there are no predicated direct BL calls.
//!
//! Deliberate deviation: the enclosing object has no recovered layout, so the
//! target `+0x8c` field is addressed as word 35 rather than modeled as a host
//! struct whose pointer-sized first field would move that offset.

use super::passkey_mask_indicators::{refresh_passkey_mask_indicators, PasskeyMaskIndicatorView};

const COUNTDOWN_WORD: usize = 0x8c / 4;

#[inline(always)]
const fn next_countdown(countdown: i32) -> i32 {
    let decremented = countdown.wrapping_sub(1);
    if decremented < 0 { 3 } else { decremented }
}

/// Ticks the passkey mask-indicator refresh countdown and refreshes every
/// indicator. Neither pointer is NULL-checked, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn passkey_mask_indicator_countdown_tick(object: *mut u32) -> u32 {
    let countdown = object.add(COUNTDOWN_WORD);
    countdown.write(next_countdown(countdown.read() as i32) as u32);
    refresh_passkey_mask_indicators(object.cast::<PasskeyMaskIndicatorView>());
    1
}

#[cfg(test)]
mod tests {
    use super::next_countdown;

    #[test]
    fn decrements_positive_countdowns() {
        assert_eq!(next_countdown(3), 2);
        assert_eq!(next_countdown(1), 0);
    }

    #[test]
    fn resets_nonpositive_post_decrements() {
        assert_eq!(next_countdown(0), 3);
        assert_eq!(next_countdown(-1), 3);
    }

    #[test]
    fn preserves_signed_wrap_behavior() {
        assert_eq!(next_countdown(i32::MIN), i32::MAX);
    }
}
