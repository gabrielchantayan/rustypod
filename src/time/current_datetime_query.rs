//! Current calendar-query builder: `FUN_08056524` @ 0x08056524.
//!
//! Raw `osos.dec` words establish the 204-byte extent
//! `0x08056524..0x080565f0`; the next real function begins at 0x080565f0.
//! The body has one plain unconditional `bl` (0x08056544 ->
//! [`super::clock_state::fetch_clock_state`]) and no predicated `bl`.
//! Four plain, non-predicated inbound `bl` sites call it: 0x0808ea00,
//! 0x080a6b10, 0x080ab574, and 0x0825b6d0.
//!
//! It fetches a 12-byte [`ClockState`], substitutes the firmware build-date
//! defaults (2002-01-01) when status bit 0 is clear, and stores a 20-byte
//! calendar record. The returned value is status bit 1 normalized to 0/1.
//! The record has deliberately unassigned padding at +7 and +13..+15; this
//! port leaves those bytes untouched, as does the retail body.

use core::ptr;

use super::clock_state::{fetch_clock_state, ClockState, STATUS_ZONE_VALID};

const DEFAULT_YEAR: u16 = 2002;
const CALENDAR_RECORD_SIZE: usize = 20;
const SECOND_OFFSET: usize = 2;
const MINUTE_OFFSET: usize = 3;
const HOUR_OFFSET: usize = 4;
const DAY_OFFSET: usize = 5;
const MONTH_OFFSET: usize = 6;
const YEAR_OFFSET: usize = 8;
const UTC_OFFSET_MINUTES_OFFSET: usize = 10;
const DAYLIGHT_SAVING_OFFSET: usize = 12;
/// current_datetime_query — original: `FUN_08056524` @ 0x08056524 (204
/// bytes including the literal pool; one outgoing plain `bl`, zero predicated
/// `bl`; four plain inbound `bl` call sites, module header).
///
/// Fill the 20-byte calendar record at `record` and return whether its
/// zone/DST fields are valid. `record` must be writable through byte +19.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_datetime_query(record: *mut u8) -> bool {
    let mut state: ClockState = core::mem::zeroed();
    fetch_clock_state(&mut state);

    if state.status & 1 == 0 {
        state.year = DEFAULT_YEAR;
        state.month = 1;
        state.day = 1;
        state.hour = 0;
        state.minute = 0;
        state.second = 0;
    }

    ptr::write(record.add(SECOND_OFFSET), state.second);
    ptr::write(record.add(MINUTE_OFFSET), state.minute);
    ptr::write(record.add(HOUR_OFFSET), state.hour);
    ptr::write(record.add(DAY_OFFSET), state.day);
    ptr::write(record.add(MONTH_OFFSET), state.month);
    ptr::write_unaligned(record.add(YEAR_OFFSET).cast::<u16>(), state.year);
    ptr::write_unaligned(
        record.add(UTC_OFFSET_MINUTES_OFFSET).cast::<i16>(),
        (state.utc_offset_quarters as i16) * 15,
    );
    ptr::write(record.add(DAYLIGHT_SAVING_OFFSET), if state.dst_active != 0 { 60 } else { 0 });
    ptr::write_unaligned(record.cast::<u16>(), 0);
    ptr::write_unaligned(record.add(16).cast::<u32>(), 0);

    state.status & STATUS_ZONE_VALID != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::clock_state::{ClockStateGetFn, CLOCK_STATE_GET, CLOCK_STATE_SHADOW, CLOCK_STATE_TEST_LOCK};

    unsafe extern "C" fn valid_get(_force: u32, state: *mut ClockState) -> i32 {
        *state = ClockState {
            year: 2024, month: 12, day: 31, yday: 0,
            utc_offset_quarters: 0, dst_active: 0,
            hour: 23, minute: 59, second: 58, status: 3,
        };
        0
    }

    unsafe extern "C" fn invalid_get(_force: u32, state: *mut ClockState) -> i32 {
        *state = ClockState {
            year: 1999, month: 9, day: 9, yday: 0,
            utc_offset_quarters: 0, dst_active: 0,
            hour: 9, minute: 9, second: 9, status: 0,
        };
        0
    }

    unsafe fn install(get: ClockStateGetFn, shadow: ClockState) -> (ClockStateGetFn, ClockState) {
        (ptr::replace(ptr::addr_of_mut!(CLOCK_STATE_GET), get), ptr::replace(ptr::addr_of_mut!(CLOCK_STATE_SHADOW), shadow))
    }

    unsafe fn restore(saved: (ClockStateGetFn, ClockState)) {
        ptr::write(ptr::addr_of_mut!(CLOCK_STATE_GET), saved.0);
        ptr::write(ptr::addr_of_mut!(CLOCK_STATE_SHADOW), saved.1);
    }

    #[test]
    fn writes_valid_calendar_zone_and_dst_without_touching_padding() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let shadow = ClockState { year: 0, month: 0, day: 0, yday: 0, utc_offset_quarters: -20, dst_active: 1, hour: 0, minute: 0, second: 0, status: 2 };
        let saved = unsafe { install(valid_get, shadow) };
        let mut record = [0xa5; CALENDAR_RECORD_SIZE];

        assert!(unsafe { current_datetime_query(record.as_mut_ptr()) });
        assert_eq!(record[0..2], [0, 0]);
        assert_eq!(&record[2..7], &[58, 59, 23, 31, 12]);
        assert_eq!(&record[8..10], &2024u16.to_le_bytes());
        assert_eq!(&record[10..12], &(-300i16).to_le_bytes());
        assert_eq!(record[12], 60);
        assert_eq!(record[7], 0xa5);
        assert_eq!(&record[13..16], &[0xa5; 3]);
        assert_eq!(&record[16..20], &[0; 4]);
        unsafe { restore(saved) };
    }

    #[test]
    fn substitutes_defaults_and_normalizes_invalid_zone_status() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let shadow = ClockState { year: 0, month: 0, day: 0, yday: 0, utc_offset_quarters: 4, dst_active: 0, hour: 0, minute: 0, second: 0, status: 0 };
        let saved = unsafe { install(invalid_get, shadow) };
        let mut record = [0; CALENDAR_RECORD_SIZE];

        assert!(!unsafe { current_datetime_query(record.as_mut_ptr()) });
        assert_eq!(&record[2..7], &[0, 0, 0, 1, 1]);
        assert_eq!(&record[8..10], &DEFAULT_YEAR.to_le_bytes());
        assert_eq!(&record[10..12], &60i16.to_le_bytes());
        assert_eq!(record[12], 0);
        unsafe { restore(saved) };
    }
}
