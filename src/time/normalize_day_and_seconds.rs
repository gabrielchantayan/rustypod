//! Normalize a Rata Die day-and-seconds pair: `FUN_081b4d60` @ 0x081b4d60.
//!
//! # Raw extent and call sites
//!
//! The executable body is exactly **96 bytes** (`0x081b4d60..0x081b4dc0`):
//! the following three words are this function's literal pool and the next
//! separately linked function begins at `0x081b4dcc`. Decoding the raw ARM
//! words finds **5 unconditional `bl` callers**, no predicated `bl` callers,
//! and no plain-`b` tail callers. The body itself makes two unconditional
//! `bl` calls to `__rt_sdiv`.
//!
//! # Algorithm
//!
//! Adds `seconds_delta` to the pair's seconds word, computes its Euclidean
//! quotient by 86,400 using the retail signed truncating divider, then folds
//! that quotient into the day and leaves seconds in `[0, 86_400)` when the
//! signed addition does not wrap. All word arithmetic wraps exactly as ARM's
//! flagless `add`, `sub`, and `mul` do.
//!
//! # Deliberate deviations
//!
//! None. The named [`super::current_day_and_seconds::DayAndSeconds`] layout
//! replaces the retail anonymous two-word record without changing its ABI.

use crate::runtime::rt_div::__rt_sdiv;
use super::current_day_and_seconds::DayAndSeconds;
use super::datetime::SECONDS_PER_DAY;

/// normalize_day_and_seconds — original: `FUN_081b4d60` @ `0x081b4d60`
/// (**96 bytes, `0x081b4d60..0x081b4dc0`; 5 unconditional `bl` callers, no
/// predicated `bl` or plain-`b` tail callers; two unconditional calls to
/// [`__rt_sdiv`] within the body).
///
/// Adds `seconds_delta` to `pair.seconds_since_midnight`, transferring whole
/// days to `pair.day_number`. Negative totals use floor division despite
/// `__rt_sdiv` truncating toward zero, matching the original's `-(quotient +
/// 1)` correction. Both fields are interpreted as signed ARM words during
/// arithmetic and retain their resulting bit patterns.
///
/// # Safety
///
/// `pair` must point to a writable, properly aligned [`DayAndSeconds`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn normalize_day_and_seconds(pair: *mut DayAndSeconds, day_delta: i32, seconds_delta: i32) {
    let total_seconds = ((*pair).seconds_since_midnight as i32).wrapping_add(seconds_delta);
    let divisor = if total_seconds < 0 { SECONDS_PER_DAY.wrapping_neg() } else { SECONDS_PER_DAY };
    let quotient = __rt_sdiv(total_seconds, divisor);
    let day_carry = if total_seconds < 0 {
        quotient.wrapping_add(1).wrapping_neg()
    } else {
        quotient
    };

    (*pair).day_number = ((*pair).day_number as i32)
        .wrapping_add(day_carry)
        .wrapping_add(day_delta) as u32;
    (*pair).seconds_since_midnight = total_seconds
        .wrapping_sub(SECONDS_PER_DAY.wrapping_mul(day_carry)) as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_across_midnight_in_both_directions() {
        let mut forward = DayAndSeconds { day_number: 719_163, seconds_since_midnight: 86_399 };
        unsafe { normalize_day_and_seconds(&mut forward, 2, 1) };
        assert_eq!(forward, DayAndSeconds { day_number: 719_166, seconds_since_midnight: 0 });

        let mut backward = DayAndSeconds { day_number: 719_163, seconds_since_midnight: 0 };
        unsafe { normalize_day_and_seconds(&mut backward, -2, -1) };
        assert_eq!(backward, DayAndSeconds { day_number: 719_160, seconds_since_midnight: 86_399 });
    }

    #[test]
    fn normalizes_negative_multi_day_totals_with_a_positive_remainder() {
        let mut pair = DayAndSeconds { day_number: 10, seconds_since_midnight: 3 };
        unsafe { normalize_day_and_seconds(&mut pair, 0, -172_804) };
        assert_eq!(pair, DayAndSeconds { day_number: 7, seconds_since_midnight: 86_399 });
    }

    #[test]
    fn preserves_arm_word_wrapping_for_day_and_seconds_addition() {
        let mut pair = DayAndSeconds { day_number: u32::MAX, seconds_since_midnight: i32::MAX as u32 };
        unsafe { normalize_day_and_seconds(&mut pair, 0, 1) };
        assert_eq!(pair, DayAndSeconds { day_number: 4_294_942_439, seconds_since_midnight: 74_752 });
    }
}
