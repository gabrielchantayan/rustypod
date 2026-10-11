//! Apply current UTC offset to a seconds timestamp: `FUN_0806ba5c` @
//! **0x0806ba5c**.
//!
//! # Verified extent and callers
//!
//! Raw ARM is exactly 32 bytes (`0x0806ba5c..0x0806ba7c`); the next separately
//! linked function starts at `0x0806ba7c` with `cmp r1, #0`. Decoding every ARM
//! B/BL word in `osos.dec` with load base `0x08000000` finds **9 unconditional
//! `bl` callers** and no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Zero remains zero without querying the calendar. Otherwise retailOS calls
//! `FUN_08054fcc`, which returns zero for an invalid UTC-offset query and the
//! negated signed sum of base and daylight-saving minutes for a valid one. The
//! `sub r0, r0, r0, lsl #4` / `add r4, r4, r0, lsl #2` pair consequently adds
//! that signed minute sum times 60 to the input modulo 2^32.
//!
//! # Deliberate deviation
//!
//! The ported `current_utc_offset_minutes_negated` adapter is shared by both
//! timestamp conversions. Typed initialized locals replace retail stack slots;
//! a private host-only volatile seam substitutes the query for tests.

#[cfg(not(test))]
use super::utc_offset::current_utc_offset_query;

type UtcOffsetQueryFn = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;

#[cfg(test)]
unsafe extern "C" fn missing_utc_offset_query(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
    panic!("install a UTC-offset query before testing apply_current_utc_offset_seconds")
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

/// Negated current UTC offset in minutes: `FUN_08054fcc` @ `0x08054fcc`.
///
/// Exactly 48 bytes, ending at 0x08054ffc where the next function begins with
/// `ldr r0, [r0, #0xf00]`. Raw decoding finds two plain inbound BLs
/// (0x0805be84, 0x0806ba68), no predicated inbound BLs, and one plain outgoing
/// BL to 0x080ab558 (no predicated outgoing BLs).
///
/// Query the base and daylight-saving offsets. On any nonzero validity result,
/// sign-extend the i16 base and i8 daylight byte, add them, and negate the sum;
/// otherwise return zero regardless of the written offsets. No arguments.
/// Deliberate deviation: initialized typed locals replace saved r2/r3 stack
/// slots; both outputs are overwritten by the provider before successful reads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn current_utc_offset_minutes_negated() -> i32 {
    let mut base_utc_offset_minutes = 0i16;
    let mut daylight_saving_minutes = 0u8;
    if unsafe { utc_offset_query(&mut base_utc_offset_minutes, &mut daylight_saving_minutes) } != 0 {
        -((base_utc_offset_minutes as i32) + (daylight_saving_minutes as i8 as i32))
    } else {
        0
    }
}

/// `apply_current_utc_offset_seconds` — original: `FUN_0806ba5c` @
/// `0x0806ba5c` (**32 bytes; 9 unconditional `bl` callers and no predicated
/// `bl` callers**).
///
/// Returns zero without calling the calendar provider when `seconds` is zero.
/// Otherwise, a successful UTC-offset query adds its signed base and
/// daylight-saving minute sum times 60. A failed query leaves `seconds`
/// unchanged. The addition wraps exactly as the retail ARM arithmetic does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn apply_current_utc_offset_seconds(seconds: u32) -> u32 {
    if seconds == 0 {
        return 0;
    }

    seconds.wrapping_sub(current_utc_offset_minutes_negated().wrapping_mul(60) as u32)
}

/// `subtract_current_utc_offset_seconds` — original: `FUN_0805be78` @
/// `0x0805be78` (**32 bytes; 6 unconditional `bl` callers and no predicated
/// `bl` callers**).
///
/// Raw ARM preserves a zero timestamp without calling the calendar provider.
/// Otherwise `FUN_08054fcc` supplies the negated signed sum of the current
/// base and daylight-saving minute offsets; its `rsb`/`add` sequence adds that
/// value times 60, equivalently subtracting the signed minute sum modulo
/// `2^32`. A failed UTC-offset query therefore leaves the timestamp unchanged.
///
/// Uses the shared ported minute adapter; multiplication and addition wrap
/// modulo 2^32 exactly as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn subtract_current_utc_offset_seconds(seconds: u32) -> u32 {
    if seconds == 0 {
        return 0;
    }

    seconds.wrapping_add(current_utc_offset_minutes_negated().wrapping_mul(60) as u32)
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

    unsafe extern "C" fn valid_east_offset(base_utc_offset_minutes: *mut i16, daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        base_utc_offset_minutes.write(120);
        daylight_saving_minutes.write(0);
        1
    }

    unsafe extern "C" fn unexpected_utc_offset(_base_utc_offset_minutes: *mut i16, _daylight_saving_minutes: *mut u8) -> i32 {
        QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
        panic!("UTC-offset query must be skipped")
    }

    struct InstalledQuery {
        _test_lock: MutexGuard<'static, ()>,
        previous: UtcOffsetQueryFn,
    }

    unsafe fn install(query: UtcOffsetQueryFn) -> InstalledQuery {
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = ptr::read_volatile(ptr::addr_of!(UTC_OFFSET_QUERY));
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), query);
        QUERY_COUNT.store(0, Ordering::Relaxed);
        InstalledQuery { _test_lock: test_lock, previous }
    }

    unsafe fn restore(installed: InstalledQuery) {
        ptr::write_volatile(ptr::addr_of_mut!(UTC_OFFSET_QUERY), installed.previous);
    }

    unsafe extern "C" fn edge_offset(base: *mut i16, daylight: *mut u8) -> i32 {
        base.write(EDGE_BASE.load(Ordering::Relaxed) as i16);
        daylight.write(EDGE_DAYLIGHT.load(Ordering::Relaxed) as u8);
        EDGE_VALID.load(Ordering::Relaxed) as i32
    }

    static EDGE_BASE: AtomicU32 = AtomicU32::new(0);
    static EDGE_DAYLIGHT: AtomicU32 = AtomicU32::new(0);
    static EDGE_VALID: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn negated_minutes_respects_signed_boundaries_and_nonzero_validity() {
        let installed = unsafe { install(edge_offset) };
        for base in [i16::MIN, -480, -1, 0, 1, 330, i16::MAX] {
            for daylight in [i8::MIN, -1, 0, 60, i8::MAX] {
                for valid in [0i32, 1, 2, -1, i32::MIN] {
                    EDGE_BASE.store(base as u32, Ordering::Relaxed);
                    EDGE_DAYLIGHT.store(daylight as u32, Ordering::Relaxed);
                    EDGE_VALID.store(valid as u32, Ordering::Relaxed);
                    let expected = if valid == 0 { 0 } else { -(i32::from(base) + i32::from(daylight)) };
                    assert_eq!(current_utc_offset_minutes_negated(), expected,
                        "base={base}, daylight={daylight}, valid={valid}");
                }
            }
        }
        unsafe { restore(installed) };
    }

    #[test]
    fn zero_skips_utc_offset_query() {
        let installed = unsafe { install(unexpected_utc_offset) };

        assert_eq!(apply_current_utc_offset_seconds(0), 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 0);

        unsafe { restore(installed) };
    }

    #[test]
    fn successful_query_adds_base_and_daylight_minutes_as_seconds() {
        let installed = unsafe { install(valid_pacific_offset) };

        assert_eq!(apply_current_utc_offset_seconds(86_400), 61_200);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn daylight_saving_byte_is_signed() {
        let installed = unsafe { install(valid_negative_daylight_offset) };

        assert_eq!(apply_current_utc_offset_seconds(123), 123);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn failed_query_ignores_written_offsets() {
        let installed = unsafe { install(invalid_pacific_offset) };

        assert_eq!(apply_current_utc_offset_seconds(0xffff_ffff), 0xffff_ffff);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn successful_negative_offset_wraps_u32_timestamp() {
        let installed = unsafe { install(valid_pacific_offset) };

        assert_eq!(apply_current_utc_offset_seconds(10_000), 0xffff_c4a0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }
    #[test]
    fn subtract_zero_skips_utc_offset_query() {
        let installed = unsafe { install(unexpected_utc_offset) };

        assert_eq!(subtract_current_utc_offset_seconds(0), 0);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 0);

        unsafe { restore(installed) };
    }

    #[test]
    fn subtract_successful_query_removes_base_and_daylight_minutes_as_seconds() {
        let installed = unsafe { install(valid_pacific_offset) };

        assert_eq!(subtract_current_utc_offset_seconds(86_400), 111_600);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn subtract_treats_daylight_saving_byte_as_signed() {
        let installed = unsafe { install(valid_negative_daylight_offset) };

        assert_eq!(subtract_current_utc_offset_seconds(123), 123);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn subtract_failed_query_ignores_written_offsets() {
        let installed = unsafe { install(invalid_pacific_offset) };

        assert_eq!(subtract_current_utc_offset_seconds(0xffff_ffff), 0xffff_ffff);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }

    #[test]
    fn subtract_positive_offset_wraps_u32_timestamp() {
        let installed = unsafe { install(valid_east_offset) };

        assert_eq!(subtract_current_utc_offset_seconds(1_000), 0xffff_e7c8);
        assert_eq!(QUERY_COUNT.load(Ordering::Relaxed), 1);

        unsafe { restore(installed) };
    }
}

