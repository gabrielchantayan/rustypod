//! Strict lexicographic comparison of day-and-seconds pairs: `FUN_0829d974`
//! @ 0x0829d974.
//!
//! # Verified extent and calls
//!
//! The next separately linked function begins with `ldr r2, [r0]` at
//! 0x0829d9ac, so the raw executable extent is **56 bytes**
//! (`0x0829d974..0x0829d9ac`). Decoding its 14 ARM words finds no calls.
//! Scanning all branch-immediate instructions in `osos.dec` finds **4 plain
//! `bl` callers**, no predicated `bl` callers, and one predicated `beq` tail
//! caller at 0x0829bdc8.
//!
//! # Algorithm
//!
//! It compares the Rata Die day number first, then elapsed seconds when the
//! days match, returning one precisely when `left` is strictly earlier than
//! `right`; both comparisons are unsigned.
//!
//! # Deliberate deviations
//!
//! The retail record is represented by the existing named `DayAndSeconds`
//! layout. The function returns `u32` rather than ARM's untyped word result;
//! the observable values remain exactly zero and one.

use super::current_day_and_seconds::DayAndSeconds;

/// day_and_seconds_is_before — original: `FUN_0829d974` @ 0x0829d974
/// (**56 bytes, 0x0829d974..0x0829d9ac; 4 plain `bl` callers, no predicated
/// `bl` callers; one predicated `beq` tail caller — verified from `osos.dec`**).
///
/// Returns one when `left` precedes `right` in unsigned `(day_number,
/// seconds_since_midnight)` lexicographic order, otherwise zero.
///
/// # Safety
///
/// `left` and `right` must point to readable, properly aligned
/// [`DayAndSeconds`] records.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn day_and_seconds_is_before(left: *const DayAndSeconds, right: *const DayAndSeconds) -> u32 {
    let left = *left;
    let right = *right;
    ((left.day_number < right.day_number)
        || (left.day_number == right.day_number
            && left.seconds_since_midnight < right.seconds_since_midnight)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_day_before_seconds() {
        let late_earlier_day = DayAndSeconds { day_number: 40, seconds_since_midnight: u32::MAX };
        let early_later_day = DayAndSeconds { day_number: 41, seconds_since_midnight: 0 };

        assert_eq!(unsafe { day_and_seconds_is_before(&late_earlier_day, &early_later_day) }, 1);
        assert_eq!(unsafe { day_and_seconds_is_before(&early_later_day, &late_earlier_day) }, 0);
    }

    #[test]
    fn compares_seconds_only_when_days_match() {
        let before = DayAndSeconds { day_number: 719_163, seconds_since_midnight: 0 };
        let after = DayAndSeconds { day_number: 719_163, seconds_since_midnight: 86_399 };
        let same = DayAndSeconds { day_number: 719_163, seconds_since_midnight: 0 };

        assert_eq!(unsafe { day_and_seconds_is_before(&before, &after) }, 1);
        assert_eq!(unsafe { day_and_seconds_is_before(&after, &before) }, 0);
        assert_eq!(unsafe { day_and_seconds_is_before(&before, &same) }, 0);
    }

    #[test]
    fn uses_unsigned_word_ordering_at_wrap_boundary() {
        let high = DayAndSeconds { day_number: u32::MAX, seconds_since_midnight: 0 };
        let low = DayAndSeconds { day_number: 0, seconds_since_midnight: u32::MAX };

        assert_eq!(unsafe { day_and_seconds_is_before(&high, &low) }, 0);
        assert_eq!(unsafe { day_and_seconds_is_before(&low, &high) }, 1);
    }
}
