//! Rata Die day-and-seconds pair -> packed calendar record: `FUN_0829d874`
//! @ 0x0829d874.
//!
//! # Verified extent and calls
//!
//! The next separately linked function begins with `ldr r2, [r0]` at
//! 0x0829d8e0, so the raw executable extent is **108 bytes**
//! (`0x0829d874..0x0829d8e0`), exactly Ghidra's size. Decoding the raw ARM
//! words finds **4 unconditional `bl` instructions** (one
//! `day_number_to_datetime`, two `__rt_udiv`, and one `__rt_memcpy`) and no
//! predicated `bl`; the reported five call sites is not supported by the
//! body.
//!
//! # Algorithm
//!
//! It converts `input.day_number` through `FUN_0807eafc`, splits raw unsigned
//! `input.seconds_since_midnight` into hour, minute, and second using 3600 and
//! 60, stores those three low bytes in the resulting record, then copies all
//! ten bytes to `out` through the ROM memcpy veneer.
//!
//! # Deliberate deviations
//!
//! The port calls the existing volatile `DAY_NUMBER_TO_DATETIME` seam for the
//! unported calendar converter. The ROM memcpy veneer is represented by the
//! existing ported `__rt_memcpy`; Rust returns `()` as does the original.

use core::mem::MaybeUninit;

use super::current_day_and_seconds::DayAndSeconds;
use super::datetime::DateTime;
use super::unix_to_datetime::day_number_to_datetime;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::runtime::rt_div::__rt_udiv;

/// day_seconds_to_datetime — original: `FUN_0829d874` @ 0x0829d874
/// (**108 bytes, 0x0829d874..0x0829d8e0; 4 unconditional `bl`, no predicated
/// `bl` — verified from `osos.dec`).
///
/// Converts a Rata Die day and raw unsigned elapsed-second count into a
/// packed [`DateTime`]. The calendar portion is delegated through the
/// `FUN_0807eafc` seam; time fields are then overwritten with the quotient
/// and remainders from unsigned divisions by 3600 and 60.
///
/// # Safety
///
/// `out` must point to writable storage for a [`DateTime`], `input` must
/// point to a readable [`DayAndSeconds`], and the installed calendar handler
/// must initialize the supplied [`DateTime`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn day_seconds_to_datetime(out: *mut DateTime, input: *const DayAndSeconds) {
    let mut datetime = MaybeUninit::<DateTime>::uninit();
    let datetime = datetime.as_mut_ptr();
    let seconds = (*input).seconds_since_midnight;

    day_number_to_datetime()((*input).day_number, datetime);

    let hour = __rt_udiv(seconds, 3_600);
    let remaining = seconds.wrapping_sub(hour.wrapping_mul(3_600));
    let minute = __rt_udiv(remaining, 60);
    (*datetime).hour = hour as u8;
    (*datetime).minute = minute as u8;
    (*datetime).second = remaining.wrapping_sub(minute.wrapping_mul(60)) as u8;

    __rt_memcpy(out.cast(), datetime.cast(), core::mem::size_of::<DateTime>());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use super::super::unix_to_datetime::{DayNumberToDateTimeFn, DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};

    static LAST_DAY: AtomicU32 = AtomicU32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn calendar_model(day_number: u32, out: *mut DateTime) {
        LAST_DAY.store(day_number, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
        *out = DateTime {
            second: 0xaa,
            minute: 0xbb,
            hour: 0xcc,
            day: 17,
            month: 9,
            reserved: 0,
            year: 2001,
            weekday: 4,
            reserved2: 0,
        };
    }

    #[test]
    fn splits_seconds_and_preserves_calendar_fields() {
        let _guard = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap();
        unsafe {
            let saved: DayNumberToDateTimeFn = DAY_NUMBER_TO_DATETIME;
            DAY_NUMBER_TO_DATETIME = calendar_model;
            CALLS.store(0, Ordering::Relaxed);

            for (day_number, seconds, hour, minute, second) in [
                (1, 0, 0, 0, 0),
                (2, 59, 0, 0, 59),
                (3, 60, 0, 1, 0),
                (4, 3_599, 0, 59, 59),
                (5, 3_600, 1, 0, 0),
                (6, 86_399, 23, 59, 59),
                (u32::MAX, u32::MAX, 86, 28, 15),
            ] {
                let input = DayAndSeconds { day_number, seconds_since_midnight: seconds };
                let mut out = MaybeUninit::<DateTime>::uninit();
                day_seconds_to_datetime(out.as_mut_ptr(), &input);
                let out = out.assume_init();

                assert_eq!(LAST_DAY.load(Ordering::Relaxed), day_number);
                assert_eq!((out.hour, out.minute, out.second), (hour, minute, second));
                assert_eq!((out.day, out.month, out.year, out.weekday), (17, 9, 2001, 4));
            }

            assert_eq!(CALLS.load(Ordering::Relaxed), 7);
            DAY_NUMBER_TO_DATETIME = saved;
        }
    }
}
