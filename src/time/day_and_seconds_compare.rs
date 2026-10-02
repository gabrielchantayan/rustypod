//! Three-way day/seconds comparison: `FUN_0829d820` @ 0x0829d820.
//!
//! Raw ARM establishes 56 bytes, ending at 0x0829d858 where an independently
//! called zero-pair predicate begins. There are two outgoing plain BLs and
//! zero predicated BLs; the two incoming plain BLs are at 0x0829b3bc and
//! 0x0829b484 (no predicated callers).
//!
//! Return zero for equal records, otherwise -1 when left precedes right and
//! +1 when it follows, using unsigned day-first, seconds-second ordering.
//! Deliberate deviation: inline the verified equality helper at 0x0829d8e0
//! instead of creating a new seam. Reuse the port at 0x0829d974 for ordering.

use super::current_day_and_seconds::DayAndSeconds;
use super::day_and_seconds_is_before::day_and_seconds_is_before;

/// Original: `FUN_0829d820` @ 0x0829d820 (56 bytes; 2 plain outgoing BLs,
/// 0 predicated BLs). Compare unsigned day and seconds words lexicographically.
/// Equality is inlined; the existing strict-before port remains a real call.
///
/// # Safety
/// Both pointers must address readable, aligned `DayAndSeconds` records.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn day_and_seconds_compare(left: *const DayAndSeconds, right: *const DayAndSeconds) -> i32 {
    if (*left).day_number == (*right).day_number
        && (*left).seconds_since_midnight == (*right).seconds_since_midnight {
        0
    } else if day_and_seconds_is_before(left, right) == 0 {
        1
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_unsigned_reference_across_word_boundaries() {
        let words = [0, 1, 86_399, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        for left_day in words {
            for left_seconds in words {
                let left = DayAndSeconds { day_number: left_day, seconds_since_midnight: left_seconds };
                assert_eq!(unsafe { day_and_seconds_compare(&left, &left) }, 0);
                for right_day in words {
                    for right_seconds in words {
                        let right = DayAndSeconds { day_number: right_day, seconds_since_midnight: right_seconds };
                        let left_key = ((left_day as u64) << 32) | left_seconds as u64;
                        let right_key = ((right_day as u64) << 32) | right_seconds as u64;
                        let expected = match left_key.cmp(&right_key) {
                            core::cmp::Ordering::Less => -1,
                            core::cmp::Ordering::Equal => 0,
                            core::cmp::Ordering::Greater => 1,
                        };
                        assert_eq!(unsafe { day_and_seconds_compare(&left, &right) }, expected);
                    }
                }
            }
        }
    }
}
