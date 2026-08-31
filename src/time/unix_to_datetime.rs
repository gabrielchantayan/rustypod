//! Unsigned Unix seconds -> packed calendar record: `FUN_080964cc` @
//! 0x080964cc.
//!
//! # Verified extent and callers
//!
//! The executable body is 116 bytes (`0x080964cc..0x08096540`), exactly
//! Ghidra's reported size. Its three literal-pool words are at
//! `0x08096540..0x0809654c`; the next function begins with `push {r4-r9,lr}`
//! at `0x0809654c`, so the complete raw extent is **128 bytes**. Decoding
//! every ARM B/BL word in `osos.dec` with load base `0x08000000` finds 28
//! direct, unconditional `bl` callers and two unconditional `b` tail callers
//! (`0x080aa9a4`, `0x08271398`); no predicated branch reaches this address.
//!
//! # Algorithm
//!
//! The input is unsigned: it divides a raw `u32` count by 86400, adds Rata
//! Die day 719163 (1970-01-01), and passes that to `FUN_0807eafc` to fill the
//! date fields. It then subtracts complete days and successively divides the
//! remaining seconds by 3600 and 60, storing hour, minute, and second at
//! packed-record offsets +2, +1, and +0. The date callee runs before those
//! three stores, so those time fields are overwritten even if it writes them.
//!
//! # Deliberate deviation
//!
//! `FUN_0807eafc` is not ported. On the firmware target this calls it at its
//! verified load address; host tests replace [`DAY_NUMBER_TO_DATETIME`] with
//! a recorder. The seam is volatile so LLVM retains the target call boundary.

use super::datetime::{DateTime, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, UNIX_EPOCH_DAY_NUMBER};

/// `FUN_0807eafc`: convert a Rata Die day number into a packed calendar
/// record. Its direct, target-only address is deliberately retained until it
/// is ported separately.
pub type DayNumberToDateTimeFn = unsafe extern "C" fn(day_number: u32, out: *mut DateTime);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_day_number_to_datetime(day_number: u32, out: *mut DateTime) {
    let convert: DayNumberToDateTimeFn = core::mem::transmute(0x0807_eafcusize);
    convert(day_number, out);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_day_number_to_datetime(_day_number: u32, _out: *mut DateTime) {
    panic!("unix_seconds_to_datetime requires calendar converter 0x0807eafc")
}

/// Active `FUN_0807eafc` dispatch. The target default calls retailOS;
/// host tests must install a model before calling [`unix_seconds_to_datetime`].
#[cfg(target_os = "none")]
pub static mut DAY_NUMBER_TO_DATETIME: DayNumberToDateTimeFn = firmware_day_number_to_datetime;

/// Active `FUN_0807eafc` dispatch. The host default intentionally exposes a
/// missing calendar model rather than inventing one.
#[cfg(not(target_os = "none"))]
pub static mut DAY_NUMBER_TO_DATETIME: DayNumberToDateTimeFn = missing_day_number_to_datetime;

#[inline(always)]
unsafe fn day_number_to_datetime() -> DayNumberToDateTimeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(DAY_NUMBER_TO_DATETIME))
}

/// unix_seconds_to_datetime — original: `FUN_080964cc` @ `0x080964cc`
/// (**128 bytes including its trailing literal pool; 28 `bl`, 0 predicated
/// `bl`, and 2 direct `b` tail callers**).
///
/// Converts an unsigned Unix-seconds value into the packed [`DateTime`]
/// record. Date fields are delegated to `FUN_0807eafc`; this function writes
/// only `second`, `minute`, and `hour` after that call.
///
/// # Safety
///
/// `out` must point to a writable [`DateTime`]. The installed
/// [`DAY_NUMBER_TO_DATETIME`] handler must accept the computed Rata Die day
/// number and that output pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn unix_seconds_to_datetime(unix_seconds: u32, out: *mut DateTime) {
    let whole_days = unix_seconds / SECONDS_PER_DAY as u32;
    let day_number = whole_days + UNIX_EPOCH_DAY_NUMBER as u32;
    day_number_to_datetime()(day_number, out);

    let mut seconds = unix_seconds - whole_days * SECONDS_PER_DAY as u32;
    let hour = seconds / SECONDS_PER_HOUR as u32;
    (*out).hour = hour as u8;

    seconds -= hour * SECONDS_PER_HOUR as u32;
    let minute = seconds / SECONDS_PER_MINUTE as u32;
    (*out).minute = minute as u8;
    (*out).second = (seconds - minute * SECONDS_PER_MINUTE as u32) as u8;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LAST_DAY_NUMBER: u32 = 0;
    static mut CALL_COUNT: u32 = 0;

    unsafe extern "C" fn record_day_number(day_number: u32, out: *mut DateTime) {
        LAST_DAY_NUMBER = day_number;
        CALL_COUNT += 1;
        // Deliberately clobber time fields: the caller must overwrite them
        // after this call, as the raw store order does.
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

    unsafe fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ptr::write_volatile(
            ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME),
            record_day_number,
        );
        LAST_DAY_NUMBER = 0;
        CALL_COUNT = 0;
        guard
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>) {
        #[cfg(target_os = "none")]
        ptr::write_volatile(
            ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME),
            firmware_day_number_to_datetime,
        );
        #[cfg(not(target_os = "none"))]
        ptr::write_volatile(
            ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME),
            missing_day_number_to_datetime,
        );
        drop(guard);
    }

    #[test]
    fn converts_time_boundaries_and_preserves_date_callee_fields() {
        let guard = unsafe { install() };
        let cases = [
            0u32,
            1,
            59,
            60,
            3_599,
            3_600,
            86_399,
            86_400,
            u32::MAX,
        ];

        for seconds in cases {
            let mut out = DateTime {
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
            unsafe { unix_seconds_to_datetime(seconds, &mut out) };

            let whole_days = seconds / SECONDS_PER_DAY as u32;
            let seconds_of_day = seconds % SECONDS_PER_DAY as u32;
            assert_eq!(unsafe { LAST_DAY_NUMBER }, whole_days + UNIX_EPOCH_DAY_NUMBER as u32);
            assert_eq!(out.hour, (seconds_of_day / SECONDS_PER_HOUR as u32) as u8);
            assert_eq!(
                out.minute,
                ((seconds_of_day % SECONDS_PER_HOUR as u32) / SECONDS_PER_MINUTE as u32) as u8
            );
            assert_eq!(out.second, (seconds_of_day % SECONDS_PER_MINUTE as u32) as u8);
            assert_eq!(
                (out.day, out.month, out.year, out.weekday, out.reserved, out.reserved2),
                (0x1d, 0x0c, 0x1234, 0x06, 0x55, 0x66),
            );
        }
        assert_eq!(unsafe { CALL_COUNT }, cases.len() as u32);
        unsafe { restore(guard) };
    }
}
