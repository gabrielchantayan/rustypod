//! Add seconds to a Rata Die day/seconds pair.
//!
//! Original: `FUN_081b4d54` @ `0x081b4d54`. Raw A32 words establish a
//! 12-byte entry shim (`mov r2,r1; mov r1,#0; mov r0,r0`) before the real
//! three-argument entry at `0x081b4d60`. Execution falls through its 96-byte
//! shared body, returning at `0x081b4dbc`; literals occupy `0x081b4dc0..cc`,
//! and the next independent body starts at `0x081b4dcc`. The full-image scan
//! finds two plain inbound BL sites (`0x0816de00`, `0x081fa638`), zero
//! predicated inbound BL sites; shared execution has two plain BL calls to
//! `__rt_sdiv` @ `0x08031568` and zero predicated BL calls.
//!
//! Supplies zero day delta to the existing normalization port. Signed word
//! addition wraps before division. Negative totals use `-(total / -86400 +
//! 1)`, deliberately leaving seconds equal to 86400 for exact negative day
//! multiples rather than correcting the retail boundary behavior.
//!
//! Deliberate deviation: a Rust tail call replaces instruction fallthrough
//! into the shared entry. The named eight-byte record preserves target ABI.
//! `match.py` verifies the argument shuffle and a final branch: LLVM emits
//! six instructions (frame setup/teardown plus the tail call) versus the
//! original three-instruction fallthrough shim; structural diff is expected.

use super::current_day_and_seconds::DayAndSeconds;
use super::normalize_day_and_seconds::normalize_day_and_seconds;

/// # Safety
/// `pair` must point to an aligned, writable day/seconds record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn day_and_seconds_add_seconds(pair: *mut DayAndSeconds, seconds_delta: i32) {
    normalize_day_and_seconds(pair, 0, seconds_delta);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_retail_boundaries_and_wrapping() {
        for &(day, seconds, delta) in &[
            (10u32, 0i32, 0i32), (10, 86_399, 1), (10, 0, -1),
            (10, 0, -86_400), (10, 0, -172_800), (10, 3, -172_804),
            (u32::MAX, 86_399, 1), (0, 0, -1),
            (10, i32::MAX, 1), (10, i32::MIN, -1),
            (10, i32::MIN, 0), (10, i32::MAX, 0),
        ] {
            let total = seconds.wrapping_add(delta) as i64;
            let carry = if total < 0 { -(total / -86_400 + 1) } else { total / 86_400 };
            let expected = DayAndSeconds {
                day_number: day.wrapping_add(carry as u32),
                seconds_since_midnight: (total - carry * 86_400) as u32,
            };
            let mut pair = DayAndSeconds { day_number: day, seconds_since_midnight: seconds as u32 };
            unsafe { day_and_seconds_add_seconds(&mut pair, delta) };
            assert_eq!(pair, expected, "day={day}, seconds={seconds}, delta={delta}");
        }
    }
}
