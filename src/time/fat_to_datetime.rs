//! FAT packed date/time decoder.

use crate::time::datetime::DateTime;

/// `fat_to_datetime` — retailOS `FUN_080aa738` @ **0x080aa738**.
///
/// The raw A32 body has 132 executable bytes (`0x080aa738..0x080aa7bb`),
/// followed by its `0x000007bc` literal at `0x080aa7bc`; the next separately
/// linked function starts at `0x080aa7c0`. Decoding all A32 BL encodings in
/// `osos.dec` finds three direct inbound plain `bl` calls (0x081bcc54,
/// 0x081bcc64, and 0x081bcc74), no predicated BL calls, and no outbound calls.
///
/// Unpacks low-halfword FAT date and time fields into `datetime`. A pair of
/// zero packed fields is the FAT sentinel and becomes 1980-01-01; all other
/// field values are copied without validation. It writes seconds, minutes,
/// hours, day, month, year, and weekday (zero), deliberately preserving the
/// two padding bytes at offsets 5 and 9. Deliberate deviations: none.
///
/// # Safety
///
/// `datetime` must be valid and writable for a properly aligned [`DateTime`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_to_datetime(fat_date: u32, fat_time: u32, datetime: *mut DateTime) {
    let mut fat_date = fat_date as u16;
    let fat_time = fat_time as u16;

    if fat_date == 0 && fat_time == 0 {
        fat_date = 0x21;
    }

    let datetime = &mut *datetime;
    datetime.second = ((fat_time & 0x1f) << 1) as u8;
    datetime.minute = ((fat_time >> 5) & 0x3f) as u8;
    datetime.hour = (fat_time >> 11) as u8;
    datetime.day = (fat_date & 0x1f) as u8;
    datetime.month = ((fat_date >> 5) & 0x0f) as u8;
    datetime.year = 1980u16.wrapping_add(fat_date >> 9);
    datetime.weekday = 0;
}

#[cfg(test)]
mod tests {
    use super::fat_to_datetime;
    use crate::time::datetime::DateTime;

    #[test]
    fn decodes_each_fat_field_and_preserves_padding() {
        let mut datetime = DateTime {
            second: 0xaa,
            minute: 0xaa,
            hour: 0xaa,
            day: 0xaa,
            month: 0xaa,
            reserved: 0x5a,
            year: 0xaaaa,
            weekday: 0xaa,
            reserved2: 0xa5,
        };

        unsafe { fat_to_datetime(0x599f, 0xbf5d, &mut datetime) };

        assert_eq!(datetime.second, 58);
        assert_eq!(datetime.minute, 58);
        assert_eq!(datetime.hour, 23);
        assert_eq!(datetime.day, 31);
        assert_eq!(datetime.month, 12);
        assert_eq!(datetime.year, 2024);
        assert_eq!(datetime.weekday, 0);
        assert_eq!(datetime.reserved, 0x5a);
        assert_eq!(datetime.reserved2, 0xa5);
    }

    #[test]
    fn converts_zero_pair_to_fat_epoch_and_masks_high_words() {
        let mut datetime = DateTime {
            second: 1,
            minute: 1,
            hour: 1,
            day: 1,
            month: 1,
            reserved: 0,
            year: 1,
            weekday: 1,
            reserved2: 0,
        };

        unsafe { fat_to_datetime(0xdead_0000, 0xbeef_0000, &mut datetime) };

        assert_eq!(datetime.second, 0);
        assert_eq!(datetime.minute, 0);
        assert_eq!(datetime.hour, 0);
        assert_eq!(datetime.day, 1);
        assert_eq!(datetime.month, 1);
        assert_eq!(datetime.year, 1980);
        assert_eq!(datetime.weekday, 0);
    }

    #[test]
    fn preserves_unvalidated_maximum_field_values() {
        let mut datetime = DateTime {
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

        unsafe { fat_to_datetime(0xffff, 0xffff, &mut datetime) };

        assert_eq!(datetime.second, 62);
        assert_eq!(datetime.minute, 63);
        assert_eq!(datetime.hour, 31);
        assert_eq!(datetime.day, 31);
        assert_eq!(datetime.month, 15);
        assert_eq!(datetime.year, 2107);
    }
}
