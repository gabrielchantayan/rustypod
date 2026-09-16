//! Current time as Macintosh-epoch seconds, without UTC/DST correction:
//! `FUN_0805b070` @ 0x0805b070.
//!
//! # Raw extent and call sites
//!
//! The executable extent is the 88 bytes Ghidra reports
//! (`0x0805b070..0x0805b0c8`), followed by the function's `0x00015180`
//! (86400, seconds per day) literal at `0x0805b0c8`; the complete extent is
//! therefore **92 bytes** (`0x0805b070..0x0805b0cc`). The `b 0x080548ec`
//! word at `0x0805b0cc` is a separately linked veneer, and the next real
//! function begins with `stmdb sp!, {r4-r11, lr}` at `0x0805b0d0`. Decoding
//! every ARM `B`/`BL` word in `work/firmware/osos.dec` (load base
//! 0x08000000) finds **5 unconditional `bl` callers** at `0x0805e404`,
//! `0x0805e658`, `0x0806a758`, `0x080946d8`, and `0x080d7294`; there are no
//! predicated `bl` forms and no `b` tail callers.
//!
//! # Algorithm
//!
//! ```text
//! stmdb sp!, {r1,r2,r3,r4,r5,lr}
//! mov   r4, r0                     ; out
//! mov   r0, sp                     ; stack DateTime (r1-r3 spill slots)
//! bl    current_datetime_to_normalized_record   ; 0x0808e9e0
//! mov   r0, sp
//! bl    datetime_day_number                     ; 0x0807ea68
//! ldr   r1, =86400                 ; 0x00015180
//! sub   r0, r0, #0xa9000
//! sub   r0, r0, #0xb10             ; r0 = day_number - 695056 (1904-01-01)
//! mul   r0, r1, r0
//! mov   r2, #0xe10                 ; 3600
//! str   r0, [r4]                   ; dead store, overwritten below
//! ldrb  r1, [sp, #2]               ; hour
//! smulbb r1, r1, r2                ; hour * 3600
//! ldrb  r2, [sp, #1]               ; minute
//! rsb   r2, r2, r2, lsl #4         ; minute * 15
//! add   r1, r1, r2, lsl #2         ; hour*3600 + minute*60
//! ldrb  r2, [sp]                   ; second
//! add   r1, r1, r2
//! add   r0, r1, r0
//! str   r0, [r4]
//! ldmia sp!, {r1,r2,r3,r4,r5,pc}
//! ```
//!
//! It obtains the current normalized [`DateTime`] record, takes its Rata Die
//! day number, subtracts the Macintosh-epoch day number `0xa9b10` (695056,
//! Rata Die of 1904-01-01 with 0001-01-01 = day 1, matching the epoch used by
//! `datetime_to_mac_epoch_seconds`), multiplies by 86400, adds the seconds
//! elapsed since midnight, and writes the combined u32 timestamp to `*out`.
//! Unlike `datetime_to_mac_epoch_seconds` it applies no UTC or
//! daylight-saving offset. Every addition, subtraction and multiplication
//! wraps as the original's flagless ARM instructions do.
//!
//! # Deliberate deviations
//!
//! The retail stack record's padding bytes are indeterminate. This port keeps
//! its local record uninitialized and reads only fields the callees
//! initialize, preserving that unobservable behavior. The intermediate
//! `str r0, [r4]` (day-part store) is dead in the original — the final
//! `str` overwrites the same word — and is omitted; LLVM would discard it
//! regardless.

use core::mem::MaybeUninit;

use super::datetime::DateTime;

/// `0xa9000 + 0xb10` from the two `sub` instructions: Rata Die day number of
/// the Macintosh epoch, 1904-01-01.
const MAC_EPOCH_DAY_NUMBER: i32 = 0xa9b10;

/// current_mac_epoch_seconds_raw — original: `FUN_0805b070` @ 0x0805b070
/// (**92-byte extent, 0x0805b070..0x0805b0cc, including the 86400 literal;
/// 5 unconditional `bl` callers, no predicated `bl` or `b` tail callers**).
///
/// Writes the current time as seconds since 1904-01-01 00:00:00 (Macintosh
/// epoch), without any UTC or daylight-saving correction, to `*out`.
/// Arithmetic wraps as the original ARM `add`/`sub`/`mul` instructions do.
///
/// # Safety
///
/// `out` must point to a writable, properly aligned `u32`. The
/// current-calendar dispatch handler must accept the buffers passed through
/// [`super::current_datetime::current_datetime_to_normalized_record`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_mac_epoch_seconds_raw(out: *mut u32) {
    let mut datetime = MaybeUninit::<DateTime>::uninit();
    let datetime = datetime.as_mut_ptr();

    super::current_datetime::current_datetime_to_normalized_record(datetime);
    let day_number = super::day_number::datetime_day_number(datetime);

    let day_seconds = day_number
        .wrapping_sub(MAC_EPOCH_DAY_NUMBER)
        .wrapping_mul(super::datetime::SECONDS_PER_DAY);
    let seconds_since_midnight = ((*datetime).hour as i32)
        .wrapping_mul(3_600)
        .wrapping_add(((*datetime).minute as i32).wrapping_mul(60))
        .wrapping_add((*datetime).second as i32);

    *out = seconds_since_midnight.wrapping_add(day_seconds) as u32;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut QUERY_RECORD: [u8; 20] = [0; 20];
    static mut QUERY_RESULT: bool = false;
    static mut QUERY_CALLS: u32 = 0;
    static mut NORMALIZED: DateTime = DateTime {
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
    static mut CONVERTER_CALLS: u32 = 0;

    unsafe extern "C" fn recording_current_datetime_query(record: *mut u8) -> bool {
        ptr::copy_nonoverlapping(QUERY_RECORD.as_ptr(), record, QUERY_RECORD.len());
        QUERY_CALLS += 1;
        QUERY_RESULT
    }

    unsafe extern "C" fn recording_day_number_to_datetime(_day_number: u32, out: *mut DateTime) {
        CONVERTER_CALLS += 1;
        *out = NORMALIZED;
    }

    struct Mocks {
        previous_query: usize,
        previous_converter: super::super::unix_to_datetime::DayNumberToDateTimeFn,
        _query_lock: MutexGuard<'static, ()>,
        _converter_lock: MutexGuard<'static, ()>,
    }

    impl Drop for Mocks {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(
                    ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY),
                    self.previous_query,
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
                    self.previous_converter,
                );
            }
        }
    }

    unsafe fn install(query_record: [u8; 20], query_result: bool, normalized: DateTime) -> Mocks {
        let query_lock = crate::fp::fp_misc::CURRENT_DATETIME_QUERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let converter_lock = super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous_query = ptr::read_volatile(ptr::addr_of!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY));
        let previous_converter = ptr::read_volatile(
            ptr::addr_of!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
        );
        ptr::write_volatile(
            ptr::addr_of_mut!(crate::fp::fp_misc::CURRENT_DATETIME_QUERY),
            recording_current_datetime_query as usize,
        );
        ptr::write_volatile(
            ptr::addr_of_mut!(super::super::unix_to_datetime::DAY_NUMBER_TO_DATETIME),
            recording_day_number_to_datetime as super::super::unix_to_datetime::DayNumberToDateTimeFn,
        );
        QUERY_RECORD = query_record;
        QUERY_RESULT = query_result;
        QUERY_CALLS = 0;
        NORMALIZED = normalized;
        CONVERTER_CALLS = 0;
        Mocks {
            previous_query,
            previous_converter,
            _query_lock: query_lock,
            _converter_lock: converter_lock,
        }
    }

    fn dt(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> DateTime {
        DateTime {
            second,
            minute,
            hour,
            day,
            month,
            reserved: 0,
            year,
            weekday: 0,
            reserved2: 0,
        }
    }

    /// Reference computation straight from the ARM listing, using the real
    /// Rata Die day-number port.
    fn reference(normalized: &DateTime) -> u32 {
        let mut copy = *normalized;
        let day_number = unsafe { super::super::day_number::datetime_day_number(&mut copy) };
        day_number
            .wrapping_sub(0xa9000)
            .wrapping_sub(0xb10)
            .wrapping_mul(0x15180)
            .wrapping_add((normalized.hour as i32) * 0xe10)
            .wrapping_add((normalized.minute as i32) * 60)
            .wrapping_add(normalized.second as i32) as u32
    }

    #[test]
    fn mac_epoch_midnight_is_zero() {
        let _mocks = unsafe { install([0; 20], true, dt(1904, 1, 1, 0, 0, 0)) };
        let mut out = 0xffff_ffffu32;
        unsafe { current_mac_epoch_seconds_raw(&mut out) };
        assert_eq!(out, 0, "1904-01-01 is Rata Die 695056 = 0xa9b10");
        assert_eq!(unsafe { QUERY_CALLS }, 1);
        assert_eq!(unsafe { CONVERTER_CALLS }, 1);
    }

    #[test]
    fn combines_day_and_time_of_day() {
        for normalized in [
            dt(1904, 1, 1, 0, 0, 1),
            dt(1904, 1, 2, 0, 0, 0),
            dt(2009, 10, 13, 23, 59, 59),
            dt(2026, 9, 16, 12, 34, 56),
            dt(1970, 1, 1, 0, 0, 0),
        ] {
            let _mocks = unsafe { install([0; 20], true, normalized) };
            let mut out = 0;
            unsafe { current_mac_epoch_seconds_raw(&mut out) };
            assert_eq!(out, reference(&normalized), "for {normalized:?}");
        }
    }

    #[test]
    fn arithmetic_wraps_for_far_future_dates() {
        // Year 65535 pushes day_number*86400 far past u32::MAX; the original
        // mul/add have no flags, so the result wraps modulo 2^32.
        let normalized = dt(65535, 12, 31, 23, 59, 59);
        let _mocks = unsafe { install([0; 20], true, normalized) };
        let mut out = 0;
        unsafe { current_mac_epoch_seconds_raw(&mut out) };
        assert_eq!(out, reference(&normalized));
    }

    #[test]
    fn pre_epoch_dates_wrap_negative() {
        // Day numbers below the 1904 epoch make the sub borrow; wrapping
        // reproduces the original's flagless sub.
        let normalized = dt(1903, 12, 31, 23, 59, 59);
        let _mocks = unsafe { install([0; 20], true, normalized) };
        let mut out = 0;
        unsafe { current_mac_epoch_seconds_raw(&mut out) };
        assert_eq!(out, reference(&normalized));
        assert_eq!(out, (-1i32) as u32, "one second before the Mac epoch");
    }

    #[test]
    fn failed_query_still_uses_returned_record() {
        // The original ignores current_datetime_to_normalized_record's
        // return value entirely; only the written record matters.
        let normalized = dt(2009, 1, 1, 1, 2, 3);
        let _mocks = unsafe { install([0; 20], false, normalized) };
        let mut out = 0;
        unsafe { current_mac_epoch_seconds_raw(&mut out) };
        assert_eq!(out, reference(&normalized));
    }
}
