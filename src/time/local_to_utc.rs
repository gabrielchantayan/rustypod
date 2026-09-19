//! Convert a local seconds timestamp to UTC seconds: `FUN_0807446c` @
//! **0x0807446c**.
//!
//! # Verified extent and callers
//!
//! Raw ARM is exactly 56 bytes (`0x0807446c..0x080744a4`); `stmdb sp!,
//! {r4, lr}` at `0x080744a4` begins the separately linked sibling.
//! Decoding every A32 B/BL word in `osos.dec` finds **4 unconditional plain
//! `bl` callers** and no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Zero returns unchanged without querying the calendar. Otherwise retailOS
//! obtains the signed base UTC offset and signed daylight-saving adjustment
//! from `current_utc_offset_query`, then subtracts their combined minutes times
//! 60 seconds with u32 wrapping. The query validity return is deliberately
//! ignored.
//!
//! # Deliberate deviation
//!
//! The retail body uses its own 8-byte stack spill for the two query outputs;
//! Rust uses typed locals. The observable signed loads, unconditional query,
//! ignored validity result, and wrapping arithmetic are preserved.

#[cfg(not(test))]
use super::utc_offset::current_utc_offset_query;

type UtcOffsetQueryFn = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;

#[cfg(test)]
unsafe extern "C" fn missing_utc_offset_query(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
    panic!("install a UTC-offset query before testing local_seconds_to_utc_seconds")
}

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

/// Converts nonzero local seconds to UTC seconds using the current signed UTC
/// offset. The provider validity result is intentionally ignored, matching the
/// retail `bl` followed directly by signed loads from its output spill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn local_seconds_to_utc_seconds(seconds: u32) -> u32 {
    if seconds == 0 {
        return 0;
    }

    let mut base_utc_offset_minutes = 0i16;
    let mut daylight_saving_minutes = 0u8;
    unsafe { utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes) };
    let offset_minutes = (base_utc_offset_minutes as i32).wrapping_add((daylight_saving_minutes as i8) as i32);
    seconds.wrapping_sub(offset_minutes.wrapping_mul(60) as u32)
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

    unsafe extern "C" fn pacific_daylight(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(-480);
        daylight_saving_minutes.write(60);
        0
    }

    unsafe extern "C" fn positive_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(1);
        daylight_saving_minutes.write(0);
        1
    }

    unsafe fn install(query: UtcOffsetQueryFn) -> UtcOffsetQueryFn {
        ptr::replace(ptr::addr_of_mut!(UTC_OFFSET_QUERY), query)
    }

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn subtracts_signed_offset_even_when_provider_is_invalid() {
        let _guard = lock();
        let saved = unsafe { install(pacific_daylight) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        assert_eq!(local_seconds_to_utc_seconds(1_000), 26_200);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        unsafe { install(saved) };
    }

    #[test]
    fn wraps_and_zero_skips_the_query() {
        let _guard = lock();
        let saved = unsafe { install(positive_offset) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        assert_eq!(local_seconds_to_utc_seconds(1), u32::MAX - 58);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(local_seconds_to_utc_seconds(0), 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        unsafe { install(saved) };
    }
}
