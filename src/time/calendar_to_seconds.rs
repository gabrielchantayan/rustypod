//! Expanded calendar to runtime-epoch seconds: `FUN_08048080` @ 0x08048080.
//! True extent [0x08048080,0x08048138): 184 bytes, comprising 176 code
//! bytes and two literal words; next function begins with PUSH at 0x08048138.
//! Raw aligned A32 decoding verifies two plain inbound BLs (0x080d72bc,
//! 0x080d72f4), one plain outgoing BL (0x0807ea68), no predicated BLs.
//!
//! Narrow calendar month/day/hour/minute/second to bytes, retain the year,
//! and narrow weekday minus one into a zero-initialized packed DateTime.
//! Compute its Rata Die day through the existing datetime_day_number port,
//! subtract the runtime day bias at 0x083f50a4, multiply by 86400, and add
//! hour*3600 + minute*60 + second, all modulo 2^32. Either NULL argument
//! skips all reads and calls. No deliberate behavioral deviations; retain
//! both output stores and the runtime global rather than assume an epoch.

use super::datetime::DateTime;
use super::day_number::datetime_day_number;
use super::seconds_to_calendar::Calendar;

#[inline(always)]
unsafe fn convert(calendar: *const Calendar, out: *mut u32, day_bias: *const u32) {
    if calendar.is_null() || out.is_null() { return; }
    let mut date = DateTime {
        second: (*calendar).second as u8,
        minute: (*calendar).minute as u8,
        hour: (*calendar).hour as u8,
        day: (*calendar).day as u8,
        month: (*calendar).month as u8,
        reserved: 0,
        year: (*calendar).year,
        weekday: (*calendar).weekday.wrapping_sub(1) as u8,
        reserved2: 0,
    };
    let days = (datetime_day_number(&mut date) as u32).wrapping_sub(day_bias.read_volatile());
    let midnight = days.wrapping_mul(86_400);
    out.write_volatile(midnight);
    let seconds = midnight.wrapping_add(date.hour as u32 * 3600)
        .wrapping_add(date.minute as u32 * 60).wrapping_add(date.second as u32);
    out.write_volatile(seconds);
}

/// Convert seven calendar halfwords to runtime-epoch seconds; NULL is a no-op.
///
/// # Safety
/// Non-NULL `calendar` must be aligned and readable for a Calendar, and
/// non-NULL `out` aligned and writable for a u32. The firmware runtime day
/// bias must be readable when both arguments are non-NULL. Input and output
/// may overlap: all input fields are loaded before the first output store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calendar_to_seconds(calendar: *const Calendar, out: *mut u32) {
    convert(calendar, out, 0x083f_50a4 as *const u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn null_arguments_preserve_output_without_global_reads() {
        let mut out = 0x12345678;
        unsafe {
            calendar_to_seconds(ptr::null(), &mut out);
            calendar_to_seconds(ptr::dangling(), ptr::null_mut());
        }
        assert_eq!(out, 0x12345678);
    }

    #[test]
    fn epoch_edges_leap_centuries_narrowing_and_wrapping() {
        let _lock = super::super::day_number::DAY_NUMBER_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        // Independently known Rata Die anchors, including non-leap 1900
        // and leap 2000. Upper bytes must not affect any field but year.
        for (year, month, day, rata_die) in [
            (1, 1, 1, 1u32), (1900, 3, 1, 693655),
            (1970, 1, 1, 719163), (2000, 2, 29, 730179),
            (2000, 3, 1, 730180), (2400, 2, 29, 876276),
        ] {
            for bias in [0u32, rata_die, rata_die + 1, u32::MAX] {
                for (hour, minute, second) in [(0, 0, 0), (23, 59, 59), (255, 255, 255)] {
                    let calendar = Calendar { year, month: month | 0x100,
                        day: day | 0x200, hour: hour | 0x300, minute: minute | 0x400,
                        second: second | 0x500, weekday: 0 };
                    let before = calendar;
                    let expected = ((rata_die as i64 - bias as i64) * 86400
                        + hour as i64 * 3600 + minute as i64 * 60 + second as i64) as u32;
                    let mut guarded = [0xa5a5a5a5u32; 3];
                    unsafe { convert(&calendar, guarded.as_mut_ptr().add(1), &bias); }
                    assert_eq!(guarded, [0xa5a5a5a5, expected, 0xa5a5a5a5]);
                    assert_eq!(calendar, before);
                }
            }
        }
    }

    #[test]
    fn overlapping_output_uses_original_calendar_fields() {
        let _lock = super::super::day_number::DAY_NUMBER_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut words = [0u32; 4];
        unsafe {
            let calendar = words.as_mut_ptr().cast::<Calendar>();
            calendar.write(Calendar { year: 1970, month: 1, day: 1,
                hour: 23, minute: 59, second: 58, weekday: 5 });
            convert(calendar, words.as_mut_ptr().add(2), &719163);
        }
        assert_eq!(words[2], 86398);
    }
}
