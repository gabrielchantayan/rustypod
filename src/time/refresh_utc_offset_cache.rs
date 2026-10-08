//! Refresh the retailOS UTC-offset cache.
//!
//! `FUN_081405fc` @ **0x081405fc**, 68 bytes including its literal pool
//! (next function: 0x08140640). Raw A32 words contain two outgoing plain
//! BL calls and zero predicated BL calls; inbound raw decoding finds two
//! plain BL sites (0x0812774c, 0x08128430) and no predicated BL sites.
//! Query both offsets, sign-extend
//! the i16 base and i8 daylight adjustment, multiply their sum by 60, and
//! store seconds at 0x089cfde0 before querying and storing the daylight
//! predicate byte at 0x089cfddc. Query validity is deliberately ignored.
//!
//! Deviations: initialize the daylight local instead of retaining incoming
//! r2; the verified query overwrites it. Host builds substitute the two
//! existing callees and cache storage; device builds call their Rust ports.

use core::ptr;

#[repr(C)]
struct UtcOffsetCache {
    daylight_saving: u8,
    reserved: [u8; 3],
    seconds: i32,
}

#[cfg(not(target_os = "none"))]
type OffsetQuery = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;
#[cfg(not(target_os = "none"))]
type DaylightPredicate = unsafe extern "C" fn() -> u32;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_query(_: *mut i16, _: *mut u8) -> i32 {
    panic!("install UTC-offset query before refreshing cache")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_predicate() -> u32 {
    panic!("install daylight predicate before refreshing cache")
}
#[cfg(not(target_os = "none"))]
static mut OFFSET_QUERY: OffsetQuery = missing_query;
#[cfg(not(target_os = "none"))]
static mut DAYLIGHT_PREDICATE: DaylightPredicate = missing_predicate;
#[cfg(not(target_os = "none"))]
static mut CACHE: *mut UtcOffsetCache = ptr::null_mut();

/// Refreshes the fixed retailOS timezone cache, preserving its reserved bytes.
///
/// # Safety
/// Device cache storage and calendar services must be available. Host callers
/// must install valid storage and service callbacks and serialize access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refresh_utc_offset_cache() {
    let mut base_minutes = 0i16;
    let mut daylight_minutes = 0u8;
    #[cfg(target_os = "none")]
    super::utc_offset::current_utc_offset_query(&mut base_minutes, &mut daylight_minutes);
    #[cfg(not(target_os = "none"))]
    ptr::read_volatile(ptr::addr_of!(OFFSET_QUERY))(&mut base_minutes, &mut daylight_minutes);

    #[cfg(target_os = "none")]
    let cache = 0x089cfddcusize as *mut UtcOffsetCache;
    #[cfg(not(target_os = "none"))]
    let cache = ptr::read_volatile(ptr::addr_of!(CACHE));
    let seconds = (base_minutes as i32 + daylight_minutes as i8 as i32) * 60;
    ptr::write_volatile(ptr::addr_of_mut!((*cache).seconds), seconds);

    #[cfg(target_os = "none")]
    let daylight = super::daylight_saving_offset_is_nonzero::daylight_saving_offset_is_nonzero();
    #[cfg(not(target_os = "none"))]
    let daylight = ptr::read_volatile(ptr::addr_of!(DAYLIGHT_PREDICATE))();
    ptr::write_volatile(ptr::addr_of_mut!((*cache).daylight_saving), daylight as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE: i16 = 0;
    static mut DAYLIGHT: u8 = 0;
    static mut EXPECTED_SECONDS: i32 = 0;
    static mut PREDICATE: u32 = 0;

    unsafe extern "C" fn query(base: *mut i16, daylight: *mut u8) -> i32 {
        base.write(BASE);
        daylight.write(DAYLIGHT);
        0 // Invalid provider results still update the cache.
    }
    unsafe extern "C" fn predicate() -> u32 {
        assert_eq!(ptr::read_volatile(ptr::addr_of!((*CACHE).seconds)), EXPECTED_SECONDS);
        assert_eq!((*CACHE).daylight_saving, 0xa5); // Seconds precede predicate.
        PREDICATE
    }

    #[test]
    fn signed_offsets_ignore_validity_and_preserve_padding() {
        let _guard = LOCK.lock();
        let mut cache = UtcOffsetCache { daylight_saving: 0xa5, reserved: [0x12, 0x34, 0x56], seconds: 123 };
        unsafe {
            let saved = (OFFSET_QUERY, DAYLIGHT_PREDICATE, CACHE);
            OFFSET_QUERY = query;
            DAYLIGHT_PREDICATE = predicate;
            CACHE = &mut cache;
            for (base, daylight, predicate_value) in [
                (-480i16, 60u8, 1u32), (330, 0, 0), (1, 255, 1),
                (i16::MIN, 128, 0), (i16::MAX, 127, 1), (0, 0, 1),
            ] {
                BASE = base;
                DAYLIGHT = daylight;
                PREDICATE = predicate_value;
                EXPECTED_SECONDS = (i32::from(base) + i32::from(daylight as i8)) * 60;
                cache.daylight_saving = 0xa5;
                refresh_utc_offset_cache();
                assert_eq!(cache.seconds, (i32::from(base) + i32::from(daylight as i8)) * 60);
                assert_eq!(cache.daylight_saving, predicate_value as u8);
                assert_eq!(cache.reserved, [0x12, 0x34, 0x56]);
            }
            OFFSET_QUERY = saved.0;
            DAYLIGHT_PREDICATE = saved.1;
            CACHE = saved.2;
        }
    }
}
