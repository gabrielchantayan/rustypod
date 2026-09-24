//! Packed calendar record -> ADS `struct tm`: `FUN_08075ff0` @ 0x08075ff0.
//!
//! # Verified extent and calls
//!
//! The next real function begins with `push {r4, lr}` at 0x08076074, making
//! the raw executable extent **132 bytes** (`0x08075ff0..0x08076074`), exactly
//! as Ghidra reports. Raw ARM decoding finds **3 unconditional `bl`** calls
//! (`__rt_memcpy`, `datetime_day_number`, and `day_number_to_datetime`) and
//! no predicated `bl` instructions.
//!
//! # Algorithm
//!
//! Copies the ten-byte packed record to stack scratch, obtains its Rata Die
//! day number (which supplies the weekday), then converts that day number back
//! to normalized calendar fields. It writes the retained time and normalized
//! date fields to the nine-word ADS `struct tm`: zero-based month, year since
//! 1900, weekday, zero yday, and -1 isdst.
//!
//! # Deliberate deviations
//!
//! The unported calendar converter is reached through the established volatile
//! `DAY_NUMBER_TO_DATETIME` seam. The ROM memcpy veneer is the existing Rust
//! `__rt_memcpy` port. Rust's initialized stack record makes the retailOS
//! scratch padding deterministic; neither callee reads those bytes.

use super::datetime::DateTime;
use super::day_number::datetime_day_number;
use super::mktime::Tm;
use super::unix_to_datetime::day_number_to_datetime;
use crate::libc::rt_memcpy::__rt_memcpy;

/// datetime_to_tm — original: `FUN_08075ff0` @ 0x08075ff0
/// (**132 bytes, 0x08075ff0..0x08076074; 3 unconditional `bl`, no predicated
/// `bl` — verified from `osos.dec`).
///
/// Converts a packed [`DateTime`] into the ADS nine-word [`Tm`] representation.
///
/// # Safety
///
/// `datetime` must point to a readable [`DateTime`], `out` must point to
/// writable [`Tm`] storage, and the installed calendar handler must initialize
/// the date fields it owns.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_to_tm(datetime: *const DateTime, out: *mut Tm) -> i32 {
    let mut normalized = DateTime {
        second: 0,
        minute: 0,
        hour: 0,
        day: 0,
        month: 0,
        reserved: 0,
        year: 0,
        weekday: 0,
        reserved2: 0,
    };
    __rt_memcpy(
        core::ptr::addr_of_mut!(normalized).cast(),
        datetime.cast(),
        core::mem::size_of::<DateTime>(),
    );
    let day_number = datetime_day_number(&mut normalized);
    day_number_to_datetime()(day_number as u32, &mut normalized);

    (*out).tm_sec = normalized.second as i32;
    (*out).tm_min = normalized.minute as i32;
    (*out).tm_hour = normalized.hour as i32;
    (*out).tm_mday = normalized.day as i32;
    (*out).tm_mon = normalized.month.wrapping_sub(1) as i32;
    (*out).tm_year = normalized.year.wrapping_sub(1900) as i32;
    (*out).tm_wday = normalized.weekday as i32;
    (*out).tm_yday = 0;
    (*out).tm_isdst = -1;
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use super::super::unix_to_datetime::{DayNumberToDateTimeFn, DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};

    static LAST_DAY_NUMBER: AtomicU32 = AtomicU32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn calendar_model(day_number: u32, out: *mut DateTime) {
        LAST_DAY_NUMBER.store(day_number, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
        (*out).day = 31;
        (*out).month = 12;
        (*out).year = 2_099;
        (*out).weekday = 6;
    }

    #[test]
    fn converts_leap_day_and_preserves_time_through_calendar_normalization() {
        let _guard = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap();
        unsafe {
            let saved: DayNumberToDateTimeFn = DAY_NUMBER_TO_DATETIME;
            DAY_NUMBER_TO_DATETIME = calendar_model;
            CALLS.store(0, Ordering::Relaxed);

            let datetime = DateTime {
                second: 59,
                minute: 58,
                hour: 23,
                day: 29,
                month: 2,
                reserved: 0xa5,
                year: 2_024,
                weekday: 0,
                reserved2: 0x5a,
            };
            let mut out = Tm {
                tm_sec: -1,
                tm_min: -1,
                tm_hour: -1,
                tm_mday: -1,
                tm_mon: -1,
                tm_year: -1,
                tm_wday: -1,
                tm_yday: -1,
                tm_isdst: 0,
            };

            assert_eq!(datetime_to_tm(&datetime, &mut out), 1);
            assert_eq!(LAST_DAY_NUMBER.load(Ordering::Relaxed), 738_945);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(
                (out.tm_sec, out.tm_min, out.tm_hour, out.tm_mday, out.tm_mon, out.tm_year, out.tm_wday, out.tm_yday, out.tm_isdst),
                (59, 58, 23, 31, 11, 199, 6, 0, -1),
            );
            DAY_NUMBER_TO_DATETIME = saved;
        }
    }

    #[test]
    fn converts_unix_epoch_midnight_with_zero_based_month() {
        let _guard = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap();
        unsafe {
            let saved: DayNumberToDateTimeFn = DAY_NUMBER_TO_DATETIME;
            DAY_NUMBER_TO_DATETIME = calendar_model;
            CALLS.store(0, Ordering::Relaxed);

            let datetime = DateTime {
                second: 0,
                minute: 0,
                hour: 0,
                day: 1,
                month: 1,
                reserved: 0,
                year: 1_970,
                weekday: 0xff,
                reserved2: 0,
            };
            let mut out = core::mem::zeroed::<Tm>();

            assert_eq!(datetime_to_tm(&datetime, &mut out), 1);
            assert_eq!(LAST_DAY_NUMBER.load(Ordering::Relaxed), 719_163);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(
                (out.tm_sec, out.tm_min, out.tm_hour, out.tm_mday, out.tm_mon, out.tm_year, out.tm_wday, out.tm_yday, out.tm_isdst),
                (0, 0, 0, 31, 11, 199, 6, 0, -1),
            );
            DAY_NUMBER_TO_DATETIME = saved;
        }
    }
}
