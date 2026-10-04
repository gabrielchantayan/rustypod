//! One-based calendar week index — original `FUN_081f7078` @ 0x081f7078.
//!
//! True extent: 32 bytes, [0x081f7078, 0x081f7098), ending in pop
//! {r4,pc} before the next function's push. Independent raw A32 BL decoding
//! finds two inbound plain calls (0x081f7034, 0x081f706c), no predicated
//! inbound calls, and one outgoing plain call (0x081f708c) to the ported
//! unsigned divider __rt_udiv @ 0x08036f14; no predicated outgoing calls.
//! Loads the first day-number word of each record, subtracts the week origin
//! modulo 2^32, divides the unsigned difference by seven, and adds one.
//! Calendar callers store this as a one-based week index for a selected day
//! and for the last day of the year. No deliberate behavioral deviations:
//! reversed dates retain the original's large unsigned result, not signed
//! division or clamping. Host pointers address aligned u32 words directly.

use crate::rt_div::__rt_udiv;

/// Both pointers must address readable, aligned day-number words; they may alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn calendar_week_index(day: *const u32, week_origin: *const u32) -> u32 {
    let elapsed_days = day.read().wrapping_sub(week_origin.read());
    __rt_udiv(elapsed_days, 7).wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::calendar_week_index;

    #[test]
    fn week_boundaries_and_unsigned_wrap() {
        let cases = [
            (100, 100, 1),
            (106, 100, 1),
            (107, 100, 2),
            (113, 100, 2),
            (114, 100, 3),
            (465, 100, 53),
            (99, 100, 613_566_757),
            (0, u32::MAX, 1),
            (6, u32::MAX, 2),
            (u32::MAX, 0, 613_566_757),
            (0x8000_0000, 0, 306_783_379),
        ];
        for (day, origin, expected) in cases {
            assert_eq!(unsafe { calendar_week_index(&day, &origin) }, expected,
                "day={day:#x}, origin={origin:#x}");
        }
    }

    #[test]
    fn aliased_day_and_origin() {
        let day = u32::MAX;
        assert_eq!(unsafe { calendar_week_index(&day, &day) }, 1);
    }
}
