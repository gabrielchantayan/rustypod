//! Macintosh-epoch seconds -> local packed calendar record: `FUN_080aa95c`
//! @ **0x080aa95c**.
//!
//! # Verified extent and callers
//!
//! Raw ARM has a 76-byte executable body (`0x080aa95c..0x080aa9a8`) followed
//! by its `0x83da4f80` literal at `0x080aa9a8`; the next separately linked
//! function begins at `0x080aa9ac`. The complete extent is therefore **80
//! bytes**, not Ghidra's body-only 76 bytes. Decoding every ARM B/BL word in
//! `osos.dec` with load base `0x08000000` finds **12 unconditional `bl` call
//! sites**, no predicated `bl` sites, and no direct `b` tail callers.
//!
//! # Algorithm
//!
//! When `apply_utc_offset` is nonzero, query the current base UTC offset and
//! daylight-saving adjustment. If that query returns nonzero, add their signed
//! minute sum times 60 to the incoming Macintosh-epoch timestamp. Always add
//! `-2_082_844_800` modulo 2^32 to convert from the 1904 Macintosh epoch to
//! Unix seconds, then tail-call `unix_seconds_to_datetime`.
//!
//! # Deliberate deviation
//! The target calls the already-ported `current_utc_offset_query` directly.
//! Host-only tests substitute that callee through a private volatile seam so
//! they can cover successful, failed, and skipped queries; no target dispatch
//! seam or retailOS fallback is introduced.

use super::datetime::DateTime;
use super::unix_to_datetime::unix_seconds_to_datetime;
#[cfg(not(test))]
use super::utc_offset::current_utc_offset_query;

/// `0x83da4f80` at `0x080aa9a8`: Macintosh (1904) epoch to Unix (1970) epoch
/// adjustment, represented as the original's wrapping `u32` addend.
const MAC_TO_UNIX_EPOCH_SECONDS: u32 = 0x83da_4f80;

type UtcOffsetQueryFn = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;

#[cfg(test)]
unsafe extern "C" fn missing_utc_offset_query(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
    panic!("install a UTC-offset query before testing mac_epoch_seconds_to_datetime")
}

/// Tests replace the already-ported callee only on the host. Firmware builds
/// retain the direct Rust-to-Rust call below.
#[cfg(test)]
static mut UTC_OFFSET_QUERY: UtcOffsetQueryFn = missing_utc_offset_query;

#[inline(always)]
unsafe fn utc_offset_query(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(UTC_OFFSET_QUERY))(base_utc_offset_minutes, daylight_saving_minutes)
    }

    #[cfg(not(test))]
    {
        current_utc_offset_query(base_utc_offset_minutes, daylight_saving_minutes)
    }
}

/// mac_epoch_seconds_to_datetime — original: `FUN_080aa95c` @ `0x080aa95c`
/// (**80 bytes including its trailing literal; 12 unconditional `bl` callers,
/// no predicated `bl` or direct `b` tail callers**).
///
/// Converts a `u32` timestamp measured from 1904-01-01 into a packed
/// [`DateTime`]. A nonzero `apply_utc_offset` enables the current signed
/// base-UTC and daylight-saving minute adjustment only when its provider
/// reports success. Every timestamp add wraps exactly as ARM `add` does.
///
/// # Safety
///
/// `out` must be writable as a [`DateTime`]. When `apply_utc_offset` is
/// nonzero, the installed current-UTC-offset provider must accept both output
/// pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mac_epoch_seconds_to_datetime(
    mac_epoch_seconds: u32,
    out: *mut DateTime,
    apply_utc_offset: i32,
) {
    let mut unix_seconds = mac_epoch_seconds;

    if apply_utc_offset != 0 {
        let mut base_utc_offset_minutes = 0i16;
        let mut daylight_saving_minutes = 0u8;
        if utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes) != 0 {
            let offset_minutes = (base_utc_offset_minutes as i32).wrapping_add((daylight_saving_minutes as i8) as i32);
            unix_seconds = unix_seconds.wrapping_add(offset_minutes.wrapping_mul(60) as u32);
        }
    }

    unix_seconds = unix_seconds.wrapping_add(MAC_TO_UNIX_EPOCH_SECONDS);
    unix_seconds_to_datetime(unix_seconds, out);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_COUNT: AtomicU32 = AtomicU32::new(0);
    static LAST_DAY_NUMBER: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_day_number(day_number: u32, out: *mut DateTime) {
        LAST_DAY_NUMBER.store(day_number, Ordering::Relaxed);
        *out = DateTime {
            second: 0xaa,
            minute: 0xbb,
            hour: 0xcc,
            day: 0x1d,
            month: 0x0c,
            reserved: 0x55,
            year: 0x1234,
            weekday: 0x06,
            reserved2: 0x66,
        };
    }

    unsafe extern "C" fn valid_pacific_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(-480);
        daylight_saving_minutes.write(60);
        1
    }

    unsafe extern "C" fn valid_negative_daylight_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(1);
        daylight_saving_minutes.write(0xff);
        1
    }

    unsafe extern "C" fn invalid_pacific_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(-480);
        daylight_saving_minutes.write(60);
        0
    }

    unsafe extern "C" fn unexpected_utc_offset(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        panic!("UTC-offset query must be skipped")
    }

    struct InstalledHandlers {
        _test_lock: MutexGuard<'static, ()>,
        _day_number_lock: MutexGuard<'static, ()>,
        previous_day_number: super::super::unix_to_datetime::DayNumberToDateTimeFn,
        previous_utc_offset: UtcOffsetQueryFn,
    }

    unsafe fn install(day_number: super::super::unix_to_datetime::DayNumberToDateTimeFn, utc_offset: UtcOffsetQueryFn) -> InstalledHandlers {
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let day_number_lock = super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous_day_number = ptr::read_volatile(ptr::addr_of!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME));
        let previous_utc_offset = ptr::read_volatile(ptr::addr_of!(UTC_OFFSET_QUERY));
        ptr::write_volatile(ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME), day_number);
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), utc_offset);
        QUERY_COUNT.store(0, Ordering::Relaxed);
        LAST_DAY_NUMBER.store(0, Ordering::Relaxed);
        InstalledHandlers {
            _test_lock: test_lock,
            _day_number_lock: day_number_lock,
            previous_day_number,
            previous_utc_offset,
        }
    }

    unsafe fn restore(handlers: InstalledHandlers) {
        ptr::write_volatile(
            ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
            handlers.previous_day_number,
        );
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), handlers.previous_utc_offset);
    }

    fn zero_datetime() -> DateTime {
        DateTime {
            second: 0,
            minute: 0,
            hour: 0,
            day: 0,
            month: 0,
            reserved: 0,
            year: 0,
            weekday: 0,
            reserved2: 0,
        }
    }

    fn assert_timestamp_was_converted(unix_seconds: u32, out: DateTime) {
        let whole_days = unix_seconds / 86_400;
        let seconds_of_day = unix_seconds % 86_400;
        assert_eq!(LAST_DAY_NUMBER.load(Ordering::Relaxed), whole_days + 719_163);
        assert_eq!(out.hour, (seconds_of_day / 3_600) as u8);
        assert_eq!(out.minute, ((seconds_of_day % 3_600) / 60) as u8);
        assert_eq!(out.second, (seconds_of_day % 60) as u8);
        assert_eq!((out.day, out.month, out.year, out.weekday, out.reserved, out.reserved2), (0x1d, 0x0c, 0x1234, 0x06, 0x55, 0x66));
    }

    #[test]
    fn skips_utc_query_when_disabled_and_wraps_epoch_adjustment() {
        let handlers = unsafe { install(record_day_number, unexpected_utc_offset) };
        let mac_seconds = u32::MAX;
        let mut out = zero_datetime();

        unsafe { mac_epoch_seconds_to_datetime(mac_seconds, &mut out, 0) };

        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 0);
        assert_timestamp_was_converted(mac_seconds.wrapping_add(MAC_TO_UNIX_EPOCH_SECONDS), out);
        unsafe { restore(handlers) };
    }

    #[test]
    fn adds_base_and_daylight_offsets_after_a_successful_query() {
        let handlers = unsafe { install(record_day_number, valid_pacific_offset) };
        let mac_seconds = 2_082_844_800 + 25_200;
        let mut out = zero_datetime();

        unsafe { mac_epoch_seconds_to_datetime(mac_seconds, &mut out, 1) };

        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_timestamp_was_converted(0, out);
        unsafe { restore(handlers) };
    }

    #[test]
    fn treats_daylight_saving_byte_as_signed() {
        let handlers = unsafe { install(record_day_number, valid_negative_daylight_offset) };
        let mut out = zero_datetime();

        unsafe { mac_epoch_seconds_to_datetime(2_082_844_800, &mut out, 1) };

        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_timestamp_was_converted(0, out);
        unsafe { restore(handlers) };
    }

    #[test]
    fn ignores_written_offsets_after_a_failed_query() {
        let handlers = unsafe { install(record_day_number, invalid_pacific_offset) };
        let mac_seconds = 2_082_844_800 + 25_200;
        let mut out = zero_datetime();

        unsafe { mac_epoch_seconds_to_datetime(mac_seconds, &mut out, -7) };

        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_timestamp_was_converted(25_200, out);
        unsafe { restore(handlers) };
    }
}
