//! Month's first weekday: FUN_080d6d68 @ 0x080d6d68, 44 bytes.
//! Raw extent [0x080d6d68,0x080d6d94) ends at the next push {r4-r10,lr}.
//! Verified raw calls: two plain inbound BLs (0x08140fc8, 0x0829b944),
//! no predicated inbound BLs; two plain body BLs, no predicated body BLs.
//!
//! Convert a Rata Die day number to DateTime, replace day-of-month with 1,
//! recompute weekday, and return Monday=1 through Sunday=7. The raw body
//! pushes r1-r3 as scratch, not as arguments; the sole input is r0.
//! Deviations: initialize unused scratch bytes instead of preserving incoming
//! register garbage. Reuse the established day_number_to_datetime seam and
//! the ported datetime_day_number; no new firmware seam.

use super::datetime::DateTime;
use super::day_number::datetime_day_number;
use super::unix_to_datetime::day_number_to_datetime;

/// Return the weekday of the first day of the input day number's month.
///
/// # Safety
/// The installed calendar converter must accept the day number and write
/// the record's year and month, as does retailOS 0x0807eafc.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn month_first_weekday(day_number: u32) -> u32 {
    let mut date = DateTime {
        second: 0, minute: 0, hour: 0, day: 0, month: 0, reserved: 0,
        year: 0, weekday: 0, reserved2: 0,
    };
    day_number_to_datetime()(day_number, &mut date);
    date.day = 1;
    datetime_day_number(&mut date);
    if date.weekday == 0 { 7 } else { date.weekday as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::unix_to_datetime::{
        DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK, DayNumberToDateTimeFn,
    };

    fn leap(year: u32) -> bool { year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) }
    fn length(year: u32, month: u32) -> u32 {
        match month { 2 => if leap(year) { 29 } else { 28 }, 4 | 6 | 9 | 11 => 30, _ => 31 }
    }
    // Independent ordinal-date model; writes only the fields retailOS writes.
    unsafe extern "C" fn calendar(mut ordinal: u32, out: *mut DateTime) {
        let mut year = 1;
        while ordinal > if leap(year) { 366 } else { 365 } {
            ordinal -= if leap(year) { 366 } else { 365 };
            year += 1;
        }
        let mut month = 1;
        while ordinal > length(year, month) {
            ordinal -= length(year, month);
            month += 1;
        }
        (*out).year = year as u16;
        (*out).month = month as u8;
        (*out).day = ordinal as u8;
        (*out).weekday = 6; // Must be recomputed, not returned from the converter.
    }

    struct Restore(DayNumberToDateTimeFn);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(self.0); } }
    }

    #[test]
    fn first_and_last_days_cover_weekdays_leap_years_and_centuries() {
        let _calendar = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _day = super::super::day_number::DAY_NUMBER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(DAY_NUMBER_TO_DATETIME).read());
            core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(calendar);
            let mut first = 1u32;
            let mut seen = [false; 7];
            for year in 1..=2400 {
                for month in 1..=12 {
                    let days = length(year, month);
                    if year == 1 || [1900, 1970, 2000, 2024, 2100, 2400].contains(&year) {
                        let expected = (first - 1) % 7 + 1;
                        seen[(expected - 1) as usize] = true;
                        for offset in [0, days / 2, days - 1] {
                            assert_eq!(month_first_weekday(first + offset), expected,
                                "year={year} month={month} offset={offset}");
                        }
                    }
                    first += days;
                }
            }
            assert_eq!(seen, [true; 7]);
        }
    }
}
