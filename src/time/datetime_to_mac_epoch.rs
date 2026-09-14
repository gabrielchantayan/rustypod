//! Packed calendar record -> Macintosh-epoch seconds: `FUN_080aad6c` @
//! **0x080aad6c**.
//!
//! Raw ARM has a 76-byte executable body (`0x080aad6c..0x080aadb8`) followed
//! by its `0x7c25b080` literal at `0x080aadb8`; the next separately linked
//! function starts at `0x080aadbc`. The complete extent is therefore **80
//! bytes**. Decoding every ARM B/BL word in `osos.dec` finds **6 unconditional
//! plain `bl` callers**, no predicated `bl` callers, and no direct `b` tail
//! callers.
//!
//! # Algorithm
//!
//! Convert the packed [`DateTime`] to Unix seconds, add the 1904-to-1970
//! Macintosh epoch delta, and, if requested, subtract the current signed UTC
//! base-offset and daylight-saving minute sum times 60 when that query reports
//! success. Every arithmetic operation wraps as the original's flagless ARM
//! `add`/`sub` instructions do.
//!
//! # Deliberate deviation
//!
//! Device builds call the two existing Rust ports directly. Host-only tests
//! replace those callees through private volatile seams to cover successful,
//! failed, and skipped UTC-offset queries; no target dispatch seam or retailOS
//! fallback is introduced.
//!
//! Safe Rust zero-initializes the two stack outputs before the query, whereas
//! retailOS leaves them uninitialized and relies on
//! `current_utc_offset_query` to write both. Its already-ported implementation
//! does so even for an invalid provider result, and this function reads them
//! only after a successful result; the observable result is unchanged.

use super::datetime::DateTime;
#[cfg(not(test))]
use super::datetime::datetime_to_unix_seconds;
#[cfg(not(test))]
use super::utc_offset::current_utc_offset_query;

/// `0x7c25b080` at `0x080aadb8`: Unix (1970) epoch to Macintosh (1904) epoch
/// adjustment, represented as the original's wrapping signed addend.
const UNIX_TO_MAC_EPOCH_SECONDS: i32 = 0x7c25_b080;

type DateTimeToUnixSecondsFn = unsafe extern "C" fn(*mut DateTime) -> i32;
type UtcOffsetQueryFn = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;

#[cfg(test)]
unsafe extern "C" fn missing_datetime_to_unix_seconds(_datetime: *mut DateTime) -> i32 {
    panic!("install a datetime-to-Unix converter before testing datetime_to_mac_epoch_seconds")
}

#[cfg(test)]
unsafe extern "C" fn missing_utc_offset_query(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
    panic!("install a UTC-offset query before testing datetime_to_mac_epoch_seconds")
}

/// Tests replace the already-ported callees only on the host. Firmware builds
/// retain the direct Rust-to-Rust calls below.
#[cfg(test)]
static mut DATETIME_TO_UNIX_SECONDS: DateTimeToUnixSecondsFn = missing_datetime_to_unix_seconds;
#[cfg(test)]
static mut UTC_OFFSET_QUERY: UtcOffsetQueryFn = missing_utc_offset_query;

#[inline(always)]
unsafe fn datetime_to_unix_seconds_query(datetime: *mut DateTime) -> i32 {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(DATETIME_TO_UNIX_SECONDS))(datetime)
    }

    #[cfg(not(test))]
    {
        datetime_to_unix_seconds(datetime)
    }
}

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

/// datetime_to_mac_epoch_seconds — original: `FUN_080aad6c` @ `0x080aad6c`
/// (**80 bytes including its trailing literal; 6 unconditional `bl` callers,
/// no predicated `bl` or direct `b` tail callers**).
///
/// Converts a packed [`DateTime`] into a signed 32-bit timestamp measured from
/// 1904-01-01. A nonzero `apply_utc_offset` subtracts the signed base-UTC and
/// daylight-saving minute sum only when its provider reports success. Every
/// timestamp operation wraps exactly as ARM arithmetic does.
///
/// # Safety
///
/// `datetime` must be valid for the ported calendar converter. When
/// `apply_utc_offset` is nonzero, the installed current-UTC-offset provider
/// must accept both output pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_to_mac_epoch_seconds(datetime: *mut DateTime, apply_utc_offset: i32) -> i32 {
    let mut mac_epoch_seconds = datetime_to_unix_seconds_query(datetime).wrapping_add(UNIX_TO_MAC_EPOCH_SECONDS);

    if apply_utc_offset != 0 {
        let mut base_utc_offset_minutes = 0i16;
        let mut daylight_saving_minutes = 0u8;
        if utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes) != 0 {
            let offset_minutes = (base_utc_offset_minutes as i32).wrapping_add((daylight_saving_minutes as i8) as i32);
            mac_epoch_seconds = mac_epoch_seconds.wrapping_sub(offset_minutes.wrapping_mul(60));
        }
    }

    mac_epoch_seconds
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DATETIME_QUERY_COUNT: AtomicU32 = AtomicU32::new(0);
    static UTC_QUERY_COUNT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn unix_epoch(_datetime: *mut DateTime) -> i32 {
        DATETIME_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        0
    }

    unsafe extern "C" fn max_unix_seconds(_datetime: *mut DateTime) -> i32 {
        DATETIME_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        i32::MAX
    }

    unsafe extern "C" fn valid_pacific_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        UTC_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(-480);
        daylight_saving_minutes.write(60);
        1
    }

    unsafe extern "C" fn valid_negative_daylight_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        UTC_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(1);
        daylight_saving_minutes.write(0xff);
        1
    }

    unsafe extern "C" fn invalid_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        UTC_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(-480);
        daylight_saving_minutes.write(60);
        0
    }

    unsafe extern "C" fn unexpected_utc_offset(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
        UTC_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        panic!("UTC-offset query must be skipped")
    }

    struct InstalledHandlers {
        _test_lock: MutexGuard<'static, ()>,
        previous_datetime_to_unix_seconds: DateTimeToUnixSecondsFn,
        previous_utc_offset: UtcOffsetQueryFn,
    }

    unsafe fn install(datetime_to_unix_seconds: DateTimeToUnixSecondsFn, utc_offset: UtcOffsetQueryFn) -> InstalledHandlers {
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous_datetime_to_unix_seconds = ptr::read_volatile(ptr::addr_of!(DATETIME_TO_UNIX_SECONDS));
        let previous_utc_offset = ptr::read_volatile(ptr::addr_of!(UTC_OFFSET_QUERY));
        ptr::write_volatile(ptr::addr_of_mut!(DATETIME_TO_UNIX_SECONDS), datetime_to_unix_seconds);
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), utc_offset);
        DATETIME_QUERY_COUNT.store(0, Ordering::Relaxed);
        UTC_QUERY_COUNT.store(0, Ordering::Relaxed);
        InstalledHandlers {
            _test_lock: test_lock,
            previous_datetime_to_unix_seconds,
            previous_utc_offset,
        }
    }

    unsafe fn restore(handlers: InstalledHandlers) {
        ptr::write_volatile(
            ptr::addr_of_mut!(DATETIME_TO_UNIX_SECONDS),
            handlers.previous_datetime_to_unix_seconds,
        );
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), handlers.previous_utc_offset);
    }

    fn datetime() -> DateTime {
        DateTime {
            second: 0,
            minute: 0,
            hour: 0,
            day: 1,
            month: 1,
            reserved: 0,
            year: 1970,
            weekday: 0,
            reserved2: 0,
        }
    }

    #[test]
    fn skips_utc_query_when_disabled_and_wraps_epoch_adjustment() {
        let handlers = unsafe { install(max_unix_seconds, unexpected_utc_offset) };
        let mut datetime = datetime();

        let actual = unsafe { datetime_to_mac_epoch_seconds(&mut datetime, 0) };

        assert_eq!(DATETIME_QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(UTC_QUERY_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(actual, i32::MAX.wrapping_add(UNIX_TO_MAC_EPOCH_SECONDS));
        unsafe { restore(handlers) };
    }

    #[test]
    fn subtracts_base_and_daylight_offsets_after_a_successful_query() {
        let handlers = unsafe { install(unix_epoch, valid_pacific_offset) };
        let mut datetime = datetime();

        let actual = unsafe { datetime_to_mac_epoch_seconds(&mut datetime, 1) };

        assert_eq!(DATETIME_QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(UTC_QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(actual, UNIX_TO_MAC_EPOCH_SECONDS.wrapping_add(25_200));
        unsafe { restore(handlers) };
    }

    #[test]
    fn treats_daylight_saving_byte_as_signed() {
        let handlers = unsafe { install(unix_epoch, valid_negative_daylight_offset) };
        let mut datetime = datetime();

        let actual = unsafe { datetime_to_mac_epoch_seconds(&mut datetime, -1) };

        assert_eq!(UTC_QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(actual, UNIX_TO_MAC_EPOCH_SECONDS);
        unsafe { restore(handlers) };
    }

    #[test]
    fn ignores_written_offsets_after_a_failed_query() {
        let handlers = unsafe { install(unix_epoch, invalid_offset) };
        let mut datetime = datetime();

        let actual = unsafe { datetime_to_mac_epoch_seconds(&mut datetime, 7) };

        assert_eq!(UTC_QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(actual, UNIX_TO_MAC_EPOCH_SECONDS);
        unsafe { restore(handlers) };
    }
}
