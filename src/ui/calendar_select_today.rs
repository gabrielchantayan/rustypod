//! Select today's calendar day — FUN_08126910 at 0x08126910.
//! True extent: 40 bytes [0x08126910,0x08126938), ending at the next PUSH.
//! Verified raw words: three plain body BLs, zero predicated BLs; two plain
//! inbound BLs (0x08127fd0, 0x08233d00), zero predicated inbound BLs.
//! Query the normalized current DateTime, ignore query status, compute its
//! full Rata Die day number (also updating weekday), then refresh the view
//! through 0x081268dc. That helper refreshes calendar elements with mode 1
//! and dispatches vtable +0x58 with (view, 0x53747220, 0x36df).
//! Deviations: initialize unused DateTime padding instead of spilling r1-r3;
//! use the canonical Rust date ports and a verified firmware-address call
//! for the unported refresh-and-notify helper. Hosts inject that backend.

use crate::time::datetime::DateTime;
use crate::time::current_datetime::current_datetime_to_normalized_record;
use crate::time::day_number::datetime_day_number;

type Query = unsafe extern "C" fn(*mut DateTime) -> u32;
type Select = unsafe extern "C" fn(*mut u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn refresh_calendar_day_and_notify(view: *mut u32, day: u32) {
    core::mem::transmute::<usize, Select>(0x0812_68dcusize)(view, day)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn refresh_calendar_day_and_notify(_: *mut u32, _: u32) {
    panic!("calendar selection requires retailOS helper 0x081268dc")
}

/// Select the current normalized date, irrespective of the previous selection.
///
/// # Safety
/// `view` must be a live retailOS calendar object accepted by 0x081268dc;
/// installed current-calendar handlers must satisfy their buffer contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn calendar_select_today(view: *mut u32) {
    select_today_with(view, current_datetime_to_normalized_record, refresh_calendar_day_and_notify);
}

#[inline(always)]
unsafe fn select_today_with(view: *mut u32, query: Query, select: Select) {
    let mut datetime: DateTime = core::mem::zeroed();
    query(&mut datetime);
    let day = datetime_day_number(&mut datetime) as u32;
    select(view, day);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn leap_day(out: *mut DateTime) -> u32 {
        *out = DateTime { second: 59, minute: 59, hour: 23, day: 29, month: 2,
            reserved: 0, year: 2000, weekday: 255, reserved2: 0 };
        0 // Status is deliberately ignored even with a valid output record.
    }

    unsafe extern "C" fn first_day(out: *mut DateTime) -> u32 {
        *out = DateTime { second: 0, minute: 0, hour: 0, day: 1, month: 1,
            reserved: 0, year: 1, weekday: 255, reserved2: 0 };
        1
    }

    unsafe extern "C" fn last_day(out: *mut DateTime) -> u32 {
        *out = DateTime { second: 59, minute: 59, hour: 23, day: 31, month: 12,
            reserved: 0, year: 65535, weekday: 255, reserved2: 0 };
        1
    }

    unsafe extern "C" fn commit_selection(view: *mut u32, day: u32) {
        view.write(day);
    }

    #[test]
    fn selects_full_day_number_at_leap_and_year_boundaries_ignoring_status() {
        // Independent Gregorian count of all complete years and days in year.
        for (query, year, ordinal) in [(first_day as Query, 1u32, 1u32),
            (leap_day as Query, 2000, 60), (last_day as Query, 65535, 365)] {
            let complete = year - 1;
            let expected = 365 * complete + complete / 4 - complete / 100
                + complete / 400 + ordinal;
            for previous in [0, u32::MAX, 719163] {
                let mut view = [previous, 0x12345678];
                unsafe { select_today_with(view.as_mut_ptr(), query, commit_selection); }
                assert_eq!(view, [expected, 0x12345678]);
            }
        }
    }
}
