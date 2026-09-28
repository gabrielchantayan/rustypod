//! Current normalized calendar record -> Unix timestamp: `FUN_083942b0` @
//! 0x083942b0.
//!
//! The raw body is exactly **100 bytes** (`0x083942b0..0x08394314`); the
//! next real function starts with `push {r4, lr}` at 0x08394314. Decoding
//! `osos.dec` finds **3 unconditional `bl`** instructions (`FUN_0808e9e0`,
//! `FUN_08075ff0`, and `mktime`), and no predicated `bl` instructions.
//!
//! It obtains the current normalized packed calendar record, converts it to
//! ADS `struct tm`, then returns `mktime`'s Unix timestamp. A zero status
//! from either conversion leaves the result at -1. When non-NULL, `out`
//! receives that result regardless of success. Deliberate deviation: volatile
//! reads of both status words retain the stock failure branches even though
//! the current Rust callees each always return one.

use core::mem::MaybeUninit;

use super::current_datetime::current_datetime_to_normalized_record;
use super::datetime::DateTime;
use super::datetime_to_tm::datetime_to_tm;
use super::mktime::{mktime, Tm};

/// current_unix_timestamp — original: `FUN_083942b0` @ 0x083942b0
/// (**100 bytes, 0x083942b0..0x08394314; 3 unconditional `bl`, no predicated
/// `bl` — verified from `osos.dec`).
///
/// Returns the current normalized calendar time as a Unix timestamp. A
/// non-NULL `out` receives the returned timestamp, including -1 on either
/// conversion failure.
///
/// # Safety
///
/// `out`, when non-NULL, must be writable for one `i32`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_unix_timestamp(out: *mut i32) -> i32 {
    let mut datetime = MaybeUninit::<DateTime>::uninit();
    let mut tm = MaybeUninit::<Tm>::uninit();
    let mut timestamp = -1;

    let current_status = current_datetime_to_normalized_record(datetime.as_mut_ptr());
    if core::ptr::read_volatile(&current_status) != 0 {
        let tm_status = datetime_to_tm(datetime.as_ptr(), tm.as_mut_ptr());
        if core::ptr::read_volatile(&tm_status) != 0 {
            timestamp = mktime(tm.as_mut_ptr());
        }
    }

    if !out.is_null() {
        *out = timestamp;
    }
    timestamp
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut CALENDAR_RECORD: [u8; 20] = [0; 20];

    unsafe extern "C" fn calendar_query(out: *mut u8) -> bool {
        ptr::copy_nonoverlapping(CALENDAR_RECORD.as_ptr(), out, CALENDAR_RECORD.len());
        true
    }

    unsafe extern "C" fn normalize_day_number(_day_number: u32, out: *mut DateTime) {
        *out = DateTime {
            second: CALENDAR_RECORD[2], minute: CALENDAR_RECORD[3], hour: CALENDAR_RECORD[4],
            day: CALENDAR_RECORD[5], month: CALENDAR_RECORD[6], reserved: 0,
            year: u16::from_le_bytes([CALENDAR_RECORD[8], CALENDAR_RECORD[9]]),
            weekday: 4, reserved2: 0,
        };
    }

    struct CalendarMocks {
        previous_query: usize,
        previous_converter: super::super::unix_to_datetime::DayNumberToDateTimeFn,
        _query_lock: MutexGuard<'static, ()>,
        _converter_lock: MutexGuard<'static, ()>,
    }

    impl Drop for CalendarMocks {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY), self.previous_query);
                ptr::write_volatile(ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME), self.previous_converter);
            }
        }
    }

    unsafe fn install(record: [u8; 20]) -> CalendarMocks {
        let query_lock = crate::fp::fp_misc::CURRENT_DATETIME_QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let converter_lock = super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous_query = ptr::read_volatile(ptr::addr_of!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY));
        let previous_converter = ptr::read_volatile(ptr::addr_of!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME));
        ptr::write_volatile(ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY), calendar_query as usize);
        ptr::write_volatile(ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME), normalize_day_number);
        CALENDAR_RECORD = record;
        CalendarMocks { previous_query, previous_converter, _query_lock: query_lock, _converter_lock: converter_lock }
    }

    #[test]
    fn stores_epoch_and_unsigned_timestamp_limit() {
        unsafe {
            let _mocks = install([0, 0, 0, 0, 0, 1, 1, 0, 0xb2, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let mut out = 99;
            assert_eq!(current_unix_timestamp(&mut out), 0);
            assert_eq!(out, 0);

            CALENDAR_RECORD = [0, 0, 15, 28, 6, 7, 2, 0, 0x3a, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(current_unix_timestamp(ptr::null_mut()), -1);
        }
    }
}
