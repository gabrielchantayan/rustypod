//! Daylight-saving adjustment predicate from retailOS.
//!
//! `FUN_08291e24` at load address **0x08291e24** is exactly 52 bytes
//! (`0x08291e24..0x08291e57`); the next separately linked function starts at
//! `0x08291e58` with `push {r3,lr}`. Raw A32 decoding finds three inbound
//! plain `bl` call sites (0x08127730, 0x08140630, 0x081fa620), no predicated
//! inbound `bl` forms, and two direct calls in the body: class-0x6000's
//! singleton accessor then the UTC-offset query.
//!
//! The predicate returns zero if class-0x6000 is unavailable. Otherwise it
//! queries both UTC-offset outputs and returns one precisely when the
//! daylight-saving adjustment byte is nonzero; the signed base offset and the
//! query's return value are deliberately ignored. The Rust local initializes
//! the two stack outputs before the query, whereas the ARM frame contains its
//! incoming `r2`/`r3` values; `current_utc_offset_query` overwrites both
//! non-NULL outputs before either can be observed, so this is unobservable.

#[cfg(not(target_os = "none"))]
use core::ptr;

#[cfg(not(target_os = "none"))]
type Class6000Accessor = unsafe extern "C" fn() -> *mut u8;
#[cfg(not(target_os = "none"))]
type UtcOffsetQuery = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_class_6000_accessor() -> *mut u8 {
    panic!("install a class-0x6000 accessor before testing daylight-saving state")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_utc_offset_query(_: *mut i16, _: *mut u8) -> i32 {
    panic!("install a UTC-offset query before testing daylight-saving state")
}

#[cfg(not(target_os = "none"))]
static mut CLASS_6000_ACCESSOR: Class6000Accessor = missing_class_6000_accessor;
#[cfg(not(target_os = "none"))]
static mut UTC_OFFSET_QUERY: UtcOffsetQuery = missing_utc_offset_query;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn class_6000_accessor() -> Class6000Accessor {
    ptr::read_volatile(ptr::addr_of!(CLASS_6000_ACCESSOR))
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn utc_offset_query() -> UtcOffsetQuery {
    ptr::read_volatile(ptr::addr_of!(UTC_OFFSET_QUERY))
}

/// Returns whether the class-0x6000 singleton reports a nonzero daylight-
/// saving adjustment.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn daylight_saving_offset_is_nonzero() -> u32 {
    #[cfg(target_os = "none")]
    let class_6000 = crate::app::registry::instance_of_class_6000();
    #[cfg(not(target_os = "none"))]
    let class_6000 = class_6000_accessor()();

    if class_6000.is_null() {
        return 0;
    }

    let mut base_utc_offset_minutes = 0i16;
    let mut daylight_saving_minutes = 0u8;
    #[cfg(target_os = "none")]
    crate::time::utc_offset::current_utc_offset_query(
        &mut base_utc_offset_minutes,
        &mut daylight_saving_minutes,
    );
    #[cfg(not(target_os = "none"))]
    utc_offset_query()(&mut base_utc_offset_minutes, &mut daylight_saving_minutes);

    // Keep the base-offset output non-NULL as in the ARM call, even though
    // the predicate itself ignores its value.
    core::ptr::read_volatile(&base_utc_offset_minutes);

    u32::from(daylight_saving_minutes != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut DAYLIGHT_SAVING_MINUTES: u8 = 0;

    unsafe extern "C" fn unavailable_class_6000() -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn available_class_6000() -> *mut u8 { core::ptr::dangling_mut::<u8>() }
    unsafe extern "C" fn query_offset(base: *mut i16, daylight_saving: *mut u8) -> i32 {
        QUERY_CALLS.fetch_add(1, Ordering::Relaxed);
        assert!(!base.is_null());
        assert!(!daylight_saving.is_null());
        base.write(-480);
        daylight_saving.write(DAYLIGHT_SAVING_MINUTES);
        -1
    }

    unsafe fn install(class_accessor: Class6000Accessor, query: UtcOffsetQuery) -> (Class6000Accessor, UtcOffsetQuery) {
        (
            ptr::replace(ptr::addr_of_mut!(CLASS_6000_ACCESSOR), class_accessor),
            ptr::replace(ptr::addr_of_mut!(UTC_OFFSET_QUERY), query),
        )
    }

    #[test]
    fn unavailable_class_skips_offset_query() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { install(unavailable_class_6000, query_offset) };
        QUERY_CALLS.store(0, Ordering::Relaxed);

        assert_eq!(unsafe { daylight_saving_offset_is_nonzero() }, 0);
        assert_eq!(QUERY_CALLS.load(Ordering::Relaxed), 0);
        unsafe { install(saved.0, saved.1) };
    }

    #[test]
    fn normalizes_nonzero_daylight_saving_and_ignores_query_result() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { install(available_class_6000, query_offset) };
        QUERY_CALLS.store(0, Ordering::Relaxed);
        unsafe { DAYLIGHT_SAVING_MINUTES = 60 };

        assert_eq!(unsafe { daylight_saving_offset_is_nonzero() }, 1);
        assert_eq!(QUERY_CALLS.load(Ordering::Relaxed), 1);

        unsafe { DAYLIGHT_SAVING_MINUTES = 0 };
        assert_eq!(unsafe { daylight_saving_offset_is_nonzero() }, 0);
        assert_eq!(QUERY_CALLS.load(Ordering::Relaxed), 2);
        unsafe { install(saved.0, saved.1) };
    }
}
