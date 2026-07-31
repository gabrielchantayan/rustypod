//! Clock-pair arithmetic from retailOS.
//!
//! `clock_pair_subtract` — original: `FUN_080e99a0` @ 0x080e99a0 (56 bytes),
//! recovered from `decomp/c/008/080e99a0_FUN_080e99a0.c` and the corresponding
//! `osos.asm` routine. A clock value is `{ days, seconds }`, with a signed day
//! count and a seconds-of-day word whose borrow radix is 86,400. The routine
//! stores both raw differences first; when the signed seconds difference is
//! negative, it overwrites seconds with `difference + 86_400` and days with
//! `difference - 1`.

/// A two-word clock value: signed whole days plus seconds within a day.
#[repr(C)]
pub struct ClockPair {
    pub days: i32,
    pub seconds: i32,
}

/// Subtracts one clock pair from another, preserving the firmware's
/// store-before-borrow ordering and 86,400-second borrow radix.
///
/// # Safety
///
/// `left`, `right`, and `difference` must each point to a valid aligned
/// [`ClockPair`]. `difference` must be writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clock_pair_subtract(
    left: *const ClockPair,
    right: *const ClockPair,
    difference: *mut ClockPair,
) {
    let day_difference = (*left).days.wrapping_sub((*right).days);
    let second_difference = (*left).seconds.wrapping_sub((*right).seconds);

    (*difference).days = day_difference;
    (*difference).seconds = second_difference;

    if second_difference < 0 {
        (*difference).seconds = second_difference.wrapping_add(86_400);
        (*difference).days = day_difference.wrapping_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{clock_pair_subtract, ClockPair};

    #[test]
    fn subtracts_without_borrow() {
        let left = ClockPair {
            days: 7,
            seconds: 36_000,
        };
        let right = ClockPair {
            days: 3,
            seconds: 100,
        };
        let mut difference = ClockPair {
            days: 0,
            seconds: 0,
        };

        unsafe { clock_pair_subtract(&left, &right, &mut difference) };

        assert_eq!(difference.days, 4);
        assert_eq!(difference.seconds, 35_900);
    }

    #[test]
    fn borrows_one_day_when_seconds_are_negative() {
        let left = ClockPair {
            days: 7,
            seconds: 50,
        };
        let right = ClockPair {
            days: 3,
            seconds: 100,
        };
        let mut difference = ClockPair {
            days: 0,
            seconds: 0,
        };

        unsafe { clock_pair_subtract(&left, &right, &mut difference) };

        assert_eq!(difference.days, 3);
        assert_eq!(difference.seconds, 86_350);
    }

    #[test]
    fn exact_radix_borrow_leaves_zero_seconds() {
        let left = ClockPair {
            days: 1,
            seconds: 0,
        };
        let right = ClockPair {
            days: 0,
            seconds: 86_400,
        };
        let mut difference = ClockPair {
            days: 0,
            seconds: 1,
        };

        unsafe { clock_pair_subtract(&left, &right, &mut difference) };

        assert_eq!(difference.days, 0);
        assert_eq!(difference.seconds, 0);
    }

    #[test]
    fn preserves_negative_day_difference() {
        let left = ClockPair {
            days: -2,
            seconds: 10,
        };
        let right = ClockPair {
            days: 3,
            seconds: 5,
        };
        let mut difference = ClockPair {
            days: 0,
            seconds: 0,
        };

        unsafe { clock_pair_subtract(&left, &right, &mut difference) };

        assert_eq!(difference.days, -5);
        assert_eq!(difference.seconds, 5);
    }
}
