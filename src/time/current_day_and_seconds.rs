//! Current normalized calendar time -> day-and-seconds pair: `FUN_081b4dcc`
//! @ 0x081b4dcc.
//!
//! # Raw extent and call sites
//!
//! The executable extent is exactly **68 bytes**
//! (`0x081b4dcc..0x081b4e10`): the next separately linked function begins
//! with `ldr r2, [r1]` at 0x081b4e10. Decoding every ARM `B`/`BL` word in
//! `work/firmware/osos.dec` (load base 0x08000000) finds **6 unconditional
//! `bl` callers**, no predicated `bl`, and no `b` tail callers.
//!
//! # Algorithm
//!
//! It obtains the current normalized [`DateTime`] record, then calculates its
//! Rata Die day number and writes that plus the seconds elapsed since midnight
//! to `out`.
//!
//! # Deliberate deviations
//!
//! The retail stack record's two padding bytes are indeterminate. This port
//! keeps its local record uninitialized and reads only fields the callee has
//! initialized, preserving that unobservable behavior.

use core::mem::MaybeUninit;

use super::datetime::DateTime;

/// A Rata Die day number and elapsed seconds within that day.
///
/// This is the two-word `out` record written by `current_datetime_to_day_seconds`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayAndSeconds {
    pub day_number: u32,
    pub seconds_since_midnight: u32,
}

/// current_datetime_to_day_seconds — original: `FUN_081b4dcc` @
/// 0x081b4dcc (**68 bytes, 0x081b4dcc..0x081b4e10; 6 unconditional `bl`
/// callers, no predicated `bl` or `b` tail callers**).
///
/// Obtains a normalized current calendar record, computes its Rata Die day
/// number, and writes the day number and `hour * 3600 + minute * 60 + second`
/// to `out`. Arithmetic wraps as the original ARM `add` instructions do.
///
/// # Safety
///
/// `out` must point to a writable, properly aligned [`DayAndSeconds`]. The
/// current-calendar and day-number-to-date-time dispatch handlers must accept
/// the buffers passed through [`super::current_datetime_to_normalized_record`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_datetime_to_day_seconds(out: *mut DayAndSeconds) {
    let mut datetime = MaybeUninit::<DateTime>::uninit();
    let datetime = datetime.as_mut_ptr();

    super::current_datetime::current_datetime_to_normalized_record(datetime);
    let day_number = super::day_number::datetime_day_number(datetime) as u32;
    let seconds_since_midnight = ((*datetime).hour as u32)
        .wrapping_mul(3_600)
        .wrapping_add(((*datetime).minute as u32).wrapping_mul(60))
        .wrapping_add((*datetime).second as u32);

    (*out).day_number = day_number;
    (*out).seconds_since_midnight = seconds_since_midnight;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut QUERY_RECORD: [u8; 20] = [0; 20];
    static mut QUERY_RESULT: bool = false;
    static mut QUERY_CALLS: u32 = 0;
    static mut NORMALIZED: DateTime = DateTime {
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
    static mut CONVERTER_DAY_NUMBER: u32 = 0;
    static mut CONVERTER_CALLS: u32 = 0;

    unsafe extern "C" fn recording_current_datetime_query(record: *mut u8) -> bool {
        ptr::copy_nonoverlapping(QUERY_RECORD.as_ptr(), record, QUERY_RECORD.len());
        QUERY_CALLS += 1;
        QUERY_RESULT
    }

    unsafe extern "C" fn recording_day_number_to_datetime(day_number: u32, out: *mut DateTime) {
        CONVERTER_DAY_NUMBER = day_number;
        CONVERTER_CALLS += 1;
        *out = NORMALIZED;
    }

    struct Mocks {
        previous_query: usize,
        previous_converter: super::super::unix_to_datetime::DayNumberToDateTimeFn,
        _query_lock: MutexGuard<'static, ()>,
        _converter_lock: MutexGuard<'static, ()>,
    }

    impl Drop for Mocks {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(
                    ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY),
                    self.previous_query,
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
                    self.previous_converter,
                );
            }
        }
    }

    unsafe fn install(query_record: [u8; 20], query_result: bool, normalized: DateTime) -> Mocks {
        let query_lock = crate::fp::fp_misc::CURRENT_DATETIME_QUERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let converter_lock = super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous_query = ptr::read_volatile(ptr::addr_of!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY));
        let previous_converter = ptr::read_volatile(
            ptr::addr_of!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
        );
        ptr::write_volatile(
            ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY),
            recording_current_datetime_query as usize,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
            recording_day_number_to_datetime,
        );
        QUERY_RECORD = query_record;
        QUERY_RESULT = query_result;
        QUERY_CALLS = 0;
        NORMALIZED = normalized;
        CONVERTER_DAY_NUMBER = 0;
        CONVERTER_CALLS = 0;
        Mocks { previous_query, previous_converter, _query_lock: query_lock, _converter_lock: converter_lock }
    }

    #[test]
    fn uses_the_normalized_leap_day_and_ignores_a_failed_query_status() {
        let normalized = DateTime {
            second: 58,
            minute: 59,
            hour: 23,
            day: 29,
            month: 2,
            reserved: 0xa5,
            year: 2000,
            weekday: 0,
            reserved2: 0x5a,
        };
        let _mocks = unsafe {
            install(
                [0xa0, 0xa1, 0, 0, 0, 1, 1, 0xa7, 0xb2, 0x07, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3],
                false,
                normalized,
            )
        };
        let mut out = DayAndSeconds { day_number: 0, seconds_since_midnight: 0 };

        unsafe { current_datetime_to_day_seconds(&mut out) };

        assert_eq!(out, DayAndSeconds { day_number: 730_179, seconds_since_midnight: 86_398 });
        unsafe {
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_DAY_NUMBER, 719_163);
        }
    }

    #[test]
    fn writes_midnight_as_zero_elapsed_seconds() {
        let normalized = DateTime {
            second: 0,
            minute: 0,
            hour: 0,
            day: 1,
            month: 1,
            reserved: 0,
            year: 1970,
            weekday: 0,
            reserved2: 0,
        };
        let _mocks = unsafe {
            install(
                [0, 0, 59, 58, 23, 31, 12, 0, 0xb1, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                true,
                normalized,
            )
        };
        let mut out = DayAndSeconds { day_number: u32::MAX, seconds_since_midnight: u32::MAX };

        unsafe { current_datetime_to_day_seconds(&mut out) };

        assert_eq!(out, DayAndSeconds { day_number: 719_163, seconds_since_midnight: 0 });
        unsafe {
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_DAY_NUMBER, 719_162);
        }
    }
}
