//! Calendar scheduling update: `FUN_080dc3e8` @ 0x080dc3e8.
//!
//! Raw ARM extent is exactly 176 bytes (`0x080dc3e8..0x080dc498`): the
//! literal word at `0x080dc498` supplies a callback table, and the next
//! separately entered function starts with `push {r4-r8,lr}` at `0x080dc49c`.
//! Raw branch decoding finds three unconditional direct `bl` callers
//! (`0x0816f7c8`, `0x0818763c`, and `0x082040a4`) and no predicated direct
//! `bl` callers. The body has seven direct `bl` instructions and one
//! predicated indirect `blx` callback.
//!
//! It obtains the normalized current time, converts it to seconds, applies
//! the signed UTC/DST offset and the two signed minute adjustments, writes the
//! input fields into a zeroed 20-byte calendar query record, updates calendar
//! state with mask `0x180`, invokes the optional +0x0c callback, converts the
//! resulting seconds back to a packed date/time, and applies that record with
//! mask `0x3f`.
//!
//! Deliberate deviations: setters `FUN_08056800` and `FUN_080985f4`, and the
//! optional callback at `DAT_080dc498 + 0x0c`, have no names.yaml identities.
//! Device builds call their verified retail addresses/table directly; tests
//! inject these opaque operations. The already ported date/time and UTC seams
//! are called directly outside tests.

use core::ptr;

use super::current_datetime::current_datetime_to_normalized_record;
use super::datetime::datetime_to_unix_seconds;
use super::unix_to_datetime::unix_seconds_to_datetime;
use super::utc_offset::current_utc_offset_query;

const CALENDAR_RECORD_SIZE: usize = 20;
const CALENDAR_SET_MASK: u32 = 0x180;
const CALENDAR_APPLY_MASK: u32 = 0x3f;
const BASE_UTC_OFFSET_OFFSET: usize = 10;
const DAYLIGHT_SAVING_OFFSET: usize = 12;

type CalendarSet = unsafe extern "C" fn(*mut u8, u32);
type CalendarApply = unsafe extern "C" fn(*mut u8, u32);
type CalendarNotification = unsafe extern "C" fn();

#[cfg(target_os = "none")]
unsafe fn set_calendar(record: *mut u8, mask: u32) {
    let set: CalendarSet = core::mem::transmute(0x0805_6800usize);
    set(record, mask);
}

#[cfg(target_os = "none")]
unsafe fn notify_calendar_change() {
    let callback = ptr::read((0x089c_a300usize as *const usize).add(3));
    if callback != 0 {
        let notify: CalendarNotification = core::mem::transmute(callback);
        notify();
    }
}

#[cfg(target_os = "none")]
unsafe fn apply_calendar(record: *mut u8, mask: u32) {
    let apply: CalendarApply = core::mem::transmute(0x0809_85f4usize);
    apply(record, mask);
}

#[cfg(test)]
type CurrentDatetime = unsafe extern "C" fn(*mut u8) -> u32;
#[cfg(test)]
type DatetimeToSeconds = unsafe extern "C" fn(*mut u8) -> i32;
#[cfg(test)]
type UtcOffset = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;
#[cfg(test)]
type SecondsToDatetime = unsafe extern "C" fn(u32, *mut u8);

#[cfg(test)]
unsafe extern "C" fn missing_current_datetime(_: *mut u8) -> u32 { panic!("install calendar schedule operations") }
unsafe extern "C" fn missing_datetime_to_seconds(_: *mut u8) -> i32 { panic!("install calendar schedule operations") }
#[cfg(test)]
unsafe extern "C" fn missing_utc_offset(_: *mut i16, _: *mut u8) -> i32 { panic!("install calendar schedule operations") }
#[cfg(test)]
unsafe extern "C" fn missing_seconds_to_datetime(_: u32, _: *mut u8) { panic!("install calendar schedule operations") }
#[cfg(test)]
unsafe extern "C" fn missing_calendar_set(_: *mut u8, _: u32) { panic!("install calendar schedule operations") }
#[cfg(test)]
unsafe extern "C" fn missing_notification() { panic!("install calendar schedule operations") }
#[cfg(test)]
unsafe extern "C" fn missing_calendar_apply(_: *mut u8, _: u32) { panic!("install calendar schedule operations") }

#[cfg(test)]
#[derive(Clone, Copy)]
struct CalendarScheduleOps {
    current_datetime: CurrentDatetime,
    datetime_to_seconds: DatetimeToSeconds,
    utc_offset: UtcOffset,
    set_calendar: CalendarSet,
    notify_calendar_change: CalendarNotification,
    seconds_to_datetime: SecondsToDatetime,
    apply_calendar: CalendarApply,
}

#[cfg(test)]
static mut CALENDAR_SCHEDULE_OPS: CalendarScheduleOps = CalendarScheduleOps {
    current_datetime: missing_current_datetime,
    datetime_to_seconds: missing_datetime_to_seconds,
    utc_offset: missing_utc_offset,
    set_calendar: missing_calendar_set,
    notify_calendar_change: missing_notification,
    seconds_to_datetime: missing_seconds_to_datetime,
    apply_calendar: missing_calendar_apply,
};

/// `schedule_calendar_update` — original: `FUN_080dc3e8` @ `0x080dc3e8`
/// (**176 bytes, `0x080dc3e8..0x080dc498`; 3 unconditional direct `bl`
/// callers, no predicated direct `bl` callers).
///
/// Schedules a calendar update relative to the current normalized timestamp.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn schedule_calendar_update(minute_adjustment: i32, second_adjustment: i32) -> u32 {
    let mut current = [0u8; 10];
    let mut base_utc_offset_minutes = 0i16;
    let mut daylight_saving_minutes = 0u8;
    let mut calendar = [0u8; CALENDAR_RECORD_SIZE];

    #[cfg(test)]
    let ops = ptr::read_volatile(ptr::addr_of!(CALENDAR_SCHEDULE_OPS));

    #[cfg(test)]
    {
        (ops.current_datetime)(current.as_mut_ptr());
    }
    #[cfg(not(test))]
    current_datetime_to_normalized_record(current.as_mut_ptr().cast());

    let now = {
        #[cfg(test)]
        { (ops.datetime_to_seconds)(current.as_mut_ptr()) }
        #[cfg(not(test))]
        { datetime_to_unix_seconds(current.as_mut_ptr().cast()) }
    } as u32;

    #[cfg(test)]
    (ops.utc_offset)(&mut base_utc_offset_minutes, &mut daylight_saving_minutes);
    #[cfg(not(test))]
    current_utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes);

    let scheduled = now
        .wrapping_sub((base_utc_offset_minutes as i32).wrapping_mul(60) as u32)
        .wrapping_sub((daylight_saving_minutes as i8 as i32).wrapping_mul(60) as u32)
        .wrapping_add(minute_adjustment.wrapping_mul(60) as u32)
        .wrapping_add(second_adjustment.wrapping_mul(60) as u32);

    calendar[BASE_UTC_OFFSET_OFFSET..BASE_UTC_OFFSET_OFFSET + 2]
        .copy_from_slice(&(minute_adjustment as i16).to_le_bytes());
    calendar[DAYLIGHT_SAVING_OFFSET] = second_adjustment as u8;

    #[cfg(test)]
    {
        (ops.set_calendar)(calendar.as_mut_ptr(), CALENDAR_SET_MASK);
        (ops.notify_calendar_change)();
        (ops.seconds_to_datetime)(scheduled, current.as_mut_ptr());
        (ops.apply_calendar)(current.as_mut_ptr(), CALENDAR_APPLY_MASK);
    }
    #[cfg(not(test))]
    {
        set_calendar(calendar.as_mut_ptr(), CALENDAR_SET_MASK);
        notify_calendar_change();
        unix_seconds_to_datetime(scheduled, current.as_mut_ptr().cast());
        apply_calendar(current.as_mut_ptr(), CALENDAR_APPLY_MASK);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut SET_RECORD: [u8; CALENDAR_RECORD_SIZE] = [0; CALENDAR_RECORD_SIZE];
    static mut APPLY_RECORD: [u8; 10] = [0; 10];

    unsafe fn event(value: u32) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn current_datetime(out: *mut u8) -> u32 { out.copy_from_nonoverlapping([1, 2, 3, 4, 5, 0, 0, 0xd1, 0x07, 0].as_ptr(), 10); event(1); 1 }
    unsafe extern "C" fn datetime_to_seconds(_: *mut u8) -> i32 { event(2); 10_000 }
    unsafe extern "C" fn utc_offset(base: *mut i16, dst: *mut u8) -> i32 { event(3); base.write(-480); dst.write(60); 0 }
    unsafe extern "C" fn set_calendar(record: *mut u8, mask: u32) { SET_RECORD.copy_from_slice(core::slice::from_raw_parts(record, CALENDAR_RECORD_SIZE)); event(0x1000_0000 | mask); }
    unsafe extern "C" fn notify() { event(5); }
    unsafe extern "C" fn seconds_to_datetime(seconds: u32, out: *mut u8) { event(seconds); out.copy_from_nonoverlapping([9, 8, 7, 6, 5, 4, 3, 2, 1, 0].as_ptr(), 10); }
    unsafe extern "C" fn apply_calendar(record: *mut u8, mask: u32) { APPLY_RECORD.copy_from_slice(core::slice::from_raw_parts(record, 10)); event(0x2000_0000 | mask); }

    #[test]
    fn applies_signed_offsets_and_preserves_exact_record_fields() { unsafe {
        EVENT_COUNT = 0;
        CALENDAR_SCHEDULE_OPS = CalendarScheduleOps { current_datetime, datetime_to_seconds, utc_offset, set_calendar, notify_calendar_change: notify, seconds_to_datetime, apply_calendar };
        assert_eq!(schedule_calendar_update(-2, 60), 1);
        assert_eq!(&SET_RECORD[10..13], &[0xfe, 0xff, 60]);
        assert_eq!(&SET_RECORD[..10], &[0; 10]);
        assert_eq!(APPLY_RECORD, [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        // 10000 - (-480 * 60) - (60 * 60) - 120 + 3600 = 38680.
        assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3, 0x1000_0180, 5, 38_680, 0x2000_003f]);
    }}
}
