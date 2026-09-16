//! Convert a UTC seconds timestamp to local seconds: `FUN_08074be0` @
//! **0x08074be0**.
//!
//! # Verified extent and callers
//!
//! Raw ARM is exactly 56 bytes (`0x08074be0..0x08074c18`); `cmp r0, #0` at
//! `0x08074c18` begins the separately linked sibling. Decoding every A32
//! B/BL word in `osos.dec` finds **5 unconditional plain `bl` callers** and
//! no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Zero returns unchanged without querying the calendar. Otherwise retailOS
//! obtains the signed base UTC offset and signed daylight-saving adjustment
//! from `current_utc_offset_query`, then adds their combined minutes times 60
//! seconds with u32 wrapping. The query validity return is deliberately
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
    panic!("install a UTC-offset query before testing utc_seconds_to_local_seconds")
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

/// Converts nonzero UTC seconds to local seconds using the current signed UTC
/// offset. The provider validity result is intentionally ignored, matching the
/// retail `bl` followed directly by signed loads from its output spill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn utc_seconds_to_local_seconds(seconds: u32) -> u32 {
    if seconds == 0 {
        return 0;
    }

    let mut base_utc_offset_minutes = 0i16;
    let mut daylight_saving_minutes = 0u8;
    unsafe {
        utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes);
    }

    let offset_minutes = i32::from(base_utc_offset_minutes) + i32::from(daylight_saving_minutes as i8);
    seconds.wrapping_add((offset_minutes * 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static QUERY_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn invalid_western_daylight_offset(base: *mut i16, daylight: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base.write(-480);
        daylight.write(60);
        0
    }

    unsafe extern "C" fn eastern_standard_offset(base: *mut i16, daylight: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base.write(330);
        daylight.write(0);
        1
    }

    unsafe fn install(query: UtcOffsetQueryFn) -> UtcOffsetQueryFn {
        core::ptr::replace(core::ptr::addr_of_mut!(UTC_OFFSET_QUERY), query)
    }

    #[test]
    fn ignores_query_validity_and_applies_signed_daylight_minutes() {
        let _guard = QUERY_LOCK.lock();
        let saved = unsafe { install(invalid_western_daylight_offset) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        assert_eq!(utc_seconds_to_local_seconds(100_000), 74_800);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { install(saved) };
    }

    #[test]
    fn preserves_zero_without_a_query_and_wraps_positive_offsets() {
        let _guard = QUERY_LOCK.lock();
        let saved = unsafe { install(eastern_standard_offset) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        assert_eq!(utc_seconds_to_local_seconds(0), 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(utc_seconds_to_local_seconds(u32::MAX - 60), 19_739);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { install(saved) };
    }
}
