//! `passkey_mask_indicator_cycle_advance` — original: `FUN_0827f284` @
//! `0x0827f284` (40 bytes, `0x0827f284..0x0827f2ac`; the next separately
//! linked function begins at `0x0827f2ac`).
//!
//! Raw A32 decoding finds one unconditional direct `bl` in the body (to
//! `refresh_passkey_mask_indicators`) and three unconditional direct callers
//! at `0x0813fafc`, `0x08140074`, and `0x0820ea20`; there are no predicated
//! direct BL calls. The function increments the signed cycle word at target
//! object offset `+0x8c`, resets only positive post-increment values above 3,
//! then refreshes all four mask indicators.
//!
//! Deliberate deviation: the enclosing object has no recovered layout, so the
//! target `+0x8c` field is addressed as word 35 rather than modeled as a host
//! struct whose pointer-sized first field would move that offset.

use super::passkey_mask_indicators::{refresh_passkey_mask_indicators, PasskeyMaskIndicatorView};

const CYCLE_WORD: usize = 0x8c / 4;

#[inline(always)]
const fn next_cycle(cycle: i32) -> i32 {
    let incremented = cycle.wrapping_add(1);
    if incremented > 3 { 0 } else { incremented }
}

/// Advances the passkey mask-indicator cycle and refreshes every indicator.
/// Neither pointer is NULL-checked, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn passkey_mask_indicator_cycle_advance(object: *mut u32) -> u32 {
    let cycle = unsafe { object.add(CYCLE_WORD) };
    unsafe { cycle.write(next_cycle(cycle.read() as i32) as u32) };
    unsafe { refresh_passkey_mask_indicators(object.cast::<PasskeyMaskIndicatorView>()) };
    1
}

#[cfg(test)]
mod tests {
    use super::next_cycle;

    #[test]
    fn increments_and_wraps_positive_cycle_values() {
        assert_eq!(next_cycle(0), 1);
        assert_eq!(next_cycle(2), 3);
        assert_eq!(next_cycle(3), 0);
    }

    #[test]
    fn preserves_negative_post_increment_values() {
        assert_eq!(next_cycle(-2), -1);
        assert_eq!(next_cycle(i32::MAX), i32::MIN);
    }

    #[test]
    fn preserves_signed_wrapping_at_the_lower_bound() {
        assert_eq!(next_cycle(i32::MIN), i32::MIN + 1);
        assert_eq!(next_cycle(-1), 0);
    }
}
