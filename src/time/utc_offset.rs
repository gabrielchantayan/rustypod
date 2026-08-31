//! Current UTC-offset query bridge from retailOS.
//!
//! `FUN_080ab558` at load address **0x080ab558** is exactly 68 bytes
//! (`0x080ab558..0x080ab59c`); raw ARM decoding finds 27 unconditional `bl`
//! call sites and no predicated `bl` sites, plus two unconditional tail-`b`
//! sites. It clears a 20-byte aligned stack record, asks
//! `FUN_08056524` to populate it, then copies the signed little-endian
//! base UTC offset in minutes from `record[10..12]` and the daylight-saving
//! adjustment in minutes from `record[12]` to independently nullable outputs.
//! The calendar provider's `0`/`1` validity result remains in `r0` and is
//! returned unchanged. The target build calls that still-unported provider at
//! its fixed load address; host tests install a deterministic provider.
//! Deliberate code-generation deviation: LLVM emits five aligned word stores
//! for the stack clear rather than calling the IRAM memzero veneer; the
//! cleared 20-byte record and all observable behavior are unchanged.

#[cfg(not(target_os = "none"))]
use core::ptr;

const CALENDAR_QUERY_RECORD_SIZE: usize = 20;
const BASE_UTC_OFFSET_OFFSET: usize = 10;
const DAYLIGHT_SAVING_OFFSET: usize = 12;
const CURRENT_DATETIME_QUERY_ADDRESS: usize = 0x0805_6524;

/// The provider's stack record is word-aligned in the ARM frame. Keeping that
/// alignment makes the offset at +10 naturally aligned for the original
/// `ldrh` load.
#[repr(C, align(4))]
struct CalendarQueryRecord {
    bytes: [u8; CALENDAR_QUERY_RECORD_SIZE],
}

type CurrentDateTimeQueryFn = unsafe extern "C" fn(*mut CalendarQueryRecord) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_datetime_query(_record: *mut CalendarQueryRecord) -> i32 {
    panic!("install a current-datetime provider before querying the UTC offset")
}

/// The host replacement for `FUN_08056524`; device builds call its fixed
/// retailOS address directly.
#[cfg(not(target_os = "none"))]
static mut CURRENT_DATETIME_QUERY: CurrentDateTimeQueryFn = missing_current_datetime_query;

#[inline(always)]
unsafe fn current_datetime_query() -> CurrentDateTimeQueryFn {
    #[cfg(target_os = "none")]
    {
        core::mem::transmute(CURRENT_DATETIME_QUERY_ADDRESS)
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(CURRENT_DATETIME_QUERY))
    }
}

/// Queries the calendar provider's base UTC offset and daylight-saving
/// adjustment, both expressed in minutes.
///
/// # Safety
///
/// Each non-NULL output must point to writable, naturally aligned storage for
/// its declared type. NULL independently suppresses that output, exactly as
/// the predicated `ldrhne`/`strhne` and `ldrbne`/`strbne` pairs do in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_utc_offset_query(
    base_utc_offset_minutes: *mut i16,
    daylight_saving_minutes: *mut u8,
) -> i32 {
    let mut record = CalendarQueryRecord { bytes: [0; CALENDAR_QUERY_RECORD_SIZE] };
    let valid = current_datetime_query()(&mut record);

    if !base_utc_offset_minutes.is_null() {
        base_utc_offset_minutes.write(record.bytes.as_ptr().add(BASE_UTC_OFFSET_OFFSET).cast::<i16>().read());
    }
    if !daylight_saving_minutes.is_null() {
        daylight_saving_minutes.write(record.bytes.as_ptr().add(DAYLIGHT_SAVING_OFFSET).read());
    }

    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static QUERY_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn utc_minus_eight_with_dst(record: *mut CalendarQueryRecord) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        let bytes = (*record).bytes.as_mut_ptr();
        bytes.add(BASE_UTC_OFFSET_OFFSET).cast::<i16>().write(-480);
        bytes.add(DAYLIGHT_SAVING_OFFSET).write(60);
        1
    }

    unsafe extern "C" fn invalid_half_hour_offset(record: *mut CalendarQueryRecord) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        let bytes = (*record).bytes.as_mut_ptr();
        bytes.add(BASE_UTC_OFFSET_OFFSET).cast::<i16>().write(330);
        bytes.add(DAYLIGHT_SAVING_OFFSET).write(0);
        0
    }

    unsafe fn install(query: CurrentDateTimeQueryFn) -> CurrentDateTimeQueryFn {
        ptr::replace(ptr::addr_of_mut!(CURRENT_DATETIME_QUERY), query)
    }

    #[test]
    fn copies_negative_base_offset_and_daylight_saving_minutes() {
        let _guard = QUERY_LOCK.lock();
        let saved = unsafe { install(utc_minus_eight_with_dst) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        let mut base_offset = 0i16;
        let mut daylight_saving = 0u8;
        let valid = unsafe { current_utc_offset_query(&mut base_offset, &mut daylight_saving) };

        assert_eq!(valid, 1);
        assert_eq!(base_offset, -480);
        assert_eq!(daylight_saving, 60);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);
        unsafe { install(saved) };
    }

    #[test]
    fn nullable_outputs_do_not_change_provider_result() {
        let _guard = QUERY_LOCK.lock();
        let saved = unsafe { install(invalid_half_hour_offset) };
        QUERY_COUNT.store(0, Ordering::Relaxed);

        let mut daylight_saving = 0xa5u8;
        let valid = unsafe { current_utc_offset_query(ptr::null_mut(), &mut daylight_saving) };
        assert_eq!(valid, 0);
        assert_eq!(daylight_saving, 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        let valid = unsafe { current_utc_offset_query(ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(valid, 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 2);
        unsafe { install(saved) };
    }
}
