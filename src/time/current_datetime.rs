//! Current calendar query -> normalized packed record: `FUN_0808e9e0` @
//! 0x0808e9e0.
//!
//! # Raw extent and call sites
//!
//! The executable extent is exactly **108 bytes**
//! (`0x0808e9e0..0x0808ea4c`): the next separately linked function begins
//! with `push {r3, lr}` at 0x0808ea4c. Decoding every ARM B/BL word in
//! `work/firmware/osos.dec` (load base 0x08000000) finds **20 unconditional
//! `bl` callers**, no predicated `bl`, and no `b` tail callers.
//!
//! # Algorithm
//!
//! It zeroes a 20-byte local calendar-query record, calls
//! `FUN_08056524` @ 0x08056524, then copies query bytes +2..+6 and the
//! little-endian halfword at +8 into `out`'s second, minute, hour, day,
//! month, and year fields. It converts those calendar fields to a Rata Die
//! day number through `datetime_day_number` (which writes `out.weekday`),
//! then passes that day number and `out` to the unported
//! `FUN_0807eafc` converter. It returns 1 unconditionally.
//!
//! # Deliberate deviations
//!
//! `FUN_08056524` and `FUN_0807eafc` are already represented by their
//! established volatile dispatch seams. The query's 0/1 result is ignored,
//! exactly as the raw body does. The stack local is zero-initialized; this
//! is unobservable because the source reads only its assigned bytes.

use super::datetime::DateTime;

/// current_datetime_to_normalized_record — original: `FUN_0808e9e0` @
/// 0x0808e9e0 (**108 bytes, 0x0808e9e0..0x0808ea4c; 20 unconditional `bl`
/// callers, no predicated branch or tail caller**).
///
/// Queries the current calendar state, extracts its public calendar fields
/// into `out`, normalizes the date through the Rata Die round trip, and
/// returns 1. The calendar-query validity result is deliberately ignored.
///
/// # Safety
///
/// `out` must point at a writable [`DateTime`]. The installed query and
/// day-number-to-date-time handlers must accept their documented buffers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_datetime_to_normalized_record(out: *mut DateTime) -> u32 {
    let mut calendar = [0u8; 20];
    crate::fp::fp_misc::current_datetime_query(calendar.as_mut_ptr());

    (*out).second = calendar[2];
    (*out).minute = calendar[3];
    (*out).hour = calendar[4];
    (*out).day = calendar[5];
    (*out).month = calendar[6];
    (*out).year = u16::from_le_bytes([calendar[8], calendar[9]]);

    let day_number = super::day_number::datetime_day_number(out) as u32;
    super::unix_to_datetime::day_number_to_datetime()(day_number, out);
    1
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
    static mut CONVERTER_INPUT: DateTime = DateTime {
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
        CONVERTER_INPUT = *out;
        CONVERTER_DAY_NUMBER = day_number;
        CONVERTER_CALLS += 1;
        *out = DateTime {
            second: 0x01,
            minute: 0x02,
            hour: 0x03,
            day: 0x04,
            month: 0x05,
            reserved: 0x06,
            year: 0x0708,
            weekday: 0x09,
            reserved2: 0x0a,
        };
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

    unsafe fn install(query_record: [u8; 20], query_result: bool) -> Mocks {
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
        CONVERTER_CALLS = 0;
        Mocks { previous_query, previous_converter, _query_lock: query_lock, _converter_lock: converter_lock }
    }

    #[test]
    fn normalizes_extracted_calendar_despite_invalid_query_status() {
        // 1970-01-01 is Rata Die 719163 and weekday 4. Nonzero discarded
        // source bytes and output padding prove the exact field transfers.
        let _mocks = unsafe {
            install(
                [0xa0, 0xa1, 59, 58, 23, 1, 1, 0xa7, 0xb2, 0x07, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3],
                false,
            )
        };
        let mut out = DateTime {
            second: 0xff,
            minute: 0xff,
            hour: 0xff,
            day: 0xff,
            month: 0xff,
            reserved: 0xa5,
            year: 0xffff,
            weekday: 0xff,
            reserved2: 0x5a,
        };

        assert_eq!(unsafe { current_datetime_to_normalized_record(&mut out) }, 1);
        unsafe {
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_DAY_NUMBER, 719_163);
            assert_eq!(CONVERTER_INPUT, DateTime {
                second: 59,
                minute: 58,
                hour: 23,
                day: 1,
                month: 1,
                reserved: 0xa5,
                year: 1970,
                weekday: 4,
                reserved2: 0x5a,
            });
        }
        assert_eq!(out, DateTime {
            second: 0x01,
            minute: 0x02,
            hour: 0x03,
            day: 0x04,
            month: 0x05,
            reserved: 0x06,
            year: 0x0708,
            weekday: 0x09,
            reserved2: 0x0a,
        });
    }
}
