//! Strict overlap predicate for retail day-and-seconds ranges.

use super::current_day_and_seconds::DayAndSeconds;
use super::day_and_seconds_is_before::day_and_seconds_is_before;

/// Two consecutive retail two-word timestamps (16 bytes on host and target).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DayAndSecondsRange {
    pub start: DayAndSeconds,
    pub end: DayAndSeconds,
}

/// Original: `FUN_0829bda8` @ 0x0829bda8, **52 bytes**, ending at
/// 0x0829bddc: 1 plain outgoing BL, 0 predicated BLs, and BEQ/BNE tail
/// branches; 2 plain incoming BLs, 0 predicated incoming BLs (raw verified).
/// Compare starts unsigned, day first then seconds. If left starts earlier,
/// return left.end > right.start; otherwise return left.start < right.end.
/// Touching endpoints are excluded. Empty or reversed ranges are not validated:
/// their results follow these same retail branches.
///
/// Deliberate deviations: named repr(C) records replace anonymous words;
/// the verified strict-greater comparator at 0x0829d904 is expressed by swapping
/// arguments to the existing strict-less Rust port at 0x0829d974. No new seam.
/// Ghidra's 116-byte extent includes independent entries at 0x0829bddc and
/// 0x0829bde8; the former loads literal 0x8c80 and returns.
///
/// # Safety
/// Both pointers must address readable, aligned `DayAndSecondsRange` records.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn day_and_seconds_ranges_overlap(left: *const DayAndSecondsRange, right: *const DayAndSecondsRange) -> u32 {
    if day_and_seconds_is_before(&(*left).start, &(*right).start) == 0 {
        day_and_seconds_is_before(&(*left).start, &(*right).end)
    } else {
        day_and_seconds_is_before(&(*right).start, &(*left).end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(key: u64) -> DayAndSeconds {
        DayAndSeconds { day_number: (key >> 32) as u32, seconds_since_midnight: key as u32 }
    }

    fn range(start: u64, end: u64) -> DayAndSecondsRange {
        DayAndSecondsRange { start: timestamp(start), end: timestamp(end) }
    }

    #[test]
    fn preserves_unsigned_order_and_degenerate_range_branches() {
        let keys = [0, 1, u32::MAX as u64, 1u64 << 32, (1u64 << 32) + 1,
                    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, u64::MAX];
        for a in keys {
            for b in keys {
                for c in keys {
                    for d in keys {
                        let left = range(a, b);
                        let right = range(c, d);
                        let expected = if a < c { b > c } else { a < d };
                        assert_eq!(unsafe { day_and_seconds_ranges_overlap(&left, &right) }, expected as u32,
                                   "left=({a},{b}), right=({c},{d})");
                    }
                }
            }
        }
    }

    #[test]
    fn excludes_touching_endpoints_and_accepts_containment() {
        let left = range(10, 20);
        for (start, end, expected) in [(20, 30, 0), (0, 10, 0), (19, 30, 1),
                                      (0, 11, 1), (11, 19, 1), (0, 30, 1), (10, 20, 1)] {
            let right = range(start, end);
            assert_eq!(unsafe { day_and_seconds_ranges_overlap(&left, &right) }, expected);
            assert_eq!(unsafe { day_and_seconds_ranges_overlap(&right, &left) }, expected);
        }
        assert_eq!(unsafe { day_and_seconds_ranges_overlap(&left, &left) }, 1);
    }
}
