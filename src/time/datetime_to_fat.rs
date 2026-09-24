//! FAT packed date/time encoder.

use crate::time::datetime::DateTime;

/// Encodes a packed calendar record as FAT date and time — retailOS
/// `FUN_080aacc0` at `0x080aacc0` (**172 bytes**, `0x080aacc0..0x080aad6c`;
/// 3 direct `bl` call sites: 3 plain `bl`, no predicated calls, verified by
/// decoding every ARM B/BL word in `osos.dec`).
///
/// Clears each destination's low halfword, then packs `datetime` into FAT's
/// low 16-bit date (`day`, `month`, `year - 1980`) and time (`second / 2`,
/// `minute`, `hour`) fields. The target deliberately preserves each
/// destination's upper halfword: it clears only the low halfword before each
/// full-word mask-and-merge sequence. Consequently both output pointers must
/// address readable and writable aligned `u32` words. No deliberate
/// deviations.
///
/// # Safety
///
/// `datetime` must point to a readable, properly aligned [`DateTime`];
/// `fat_date` and `fat_time` must each point to readable, writable, properly
/// aligned `u32` words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_to_fat_datetime(
    datetime: *const DateTime,
    fat_date: *mut u32,
    fat_time: *mut u32,
) {
    let datetime = &*datetime;

    *fat_date &= !0xffff;
    *fat_time &= !0xffff;

    *fat_time = (*fat_time & !0x001f) | ((datetime.second as u32 & 0x3f) >> 1);
    *fat_time = (*fat_time & !0x07e0) | ((datetime.minute as u32 & 0x3f) << 5) | (*fat_time & !0xf800);
    *fat_time = (*fat_time & !0xf800) | ((datetime.hour as u32 & 0x1f) << 11) | (*fat_time & !0x07ff);

    *fat_date = (*fat_date & !0x001f) | (datetime.day as u32 & 0x1f);
    *fat_date = (*fat_date & !0x01e0) | ((datetime.month as u32 & 0x0f) << 5) | (*fat_date & !0xfe1f);
    *fat_date = (*fat_date & !0xfe00)
        | (((datetime.year.wrapping_sub(1980) as u32) << 9) & 0xfe00)
        | (*fat_date & !0xffff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_fat_fields_and_preserves_output_upper_halves() {
        let datetime = DateTime {
            second: 59,
            minute: 58,
            hour: 23,
            day: 31,
            month: 12,
            reserved: 0,
            year: 2024,
            weekday: 0,
            reserved2: 0,
        };
        let mut fat_date = 0xabcd_ffff;
        let mut fat_time = 0x1234_ffff;

        unsafe { datetime_to_fat_datetime(&datetime, &mut fat_date, &mut fat_time) };

        assert_eq!(fat_date, 0xabcd_599f);
        assert_eq!(fat_time, 0x1234_bf5d);
    }

    #[test]
    fn masks_out_of_range_fields_and_wraps_the_year_bias() {
        let datetime = DateTime {
            second: 0xff,
            minute: 0xff,
            hour: 0xff,
            day: 0xff,
            month: 0xff,
            reserved: 0,
            year: 1979,
            weekday: 0,
            reserved2: 0,
        };
        let mut fat_date = 0;
        let mut fat_time = 0;

        unsafe { datetime_to_fat_datetime(&datetime, &mut fat_date, &mut fat_time) };

        assert_eq!(fat_date, 0xffff);
        assert_eq!(fat_time, 0xffff);
    }
}
