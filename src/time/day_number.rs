//! Packed-record Rata Die day number with weekday side effect:
//! `FUN_0807ea68` @ 0x0807ea68, called `datetime_day_number` here.
//!
//! # Verified extent and callers
//!
//! The next function opens with `push {r1-r9, lr}` at **0x0807eafc**, so
//! the raw extent is **148 bytes** (`0x0807ea68..0x0807eafc`), not the 140
//! Ghidra reports: the reported size stops at the `pop` @ 0x0807eaf0 and
//! drops the two literal-pool words the function's own `ldr rN, [pc, ...]`
//! instructions reach — 365 @ 0x0807eaf4 and 367 @ 0x0807eaf8. Decoding
//! every ARM B/BL word in `osos.dec` (load base 0x08000000) finds **25
//! unconditional `bl` callers and no predicated branch or `b` tail call**,
//! matching the stated count exactly.
//!
//! # Algorithm (from the raw words)
//!
//! ```text
//! ldrh  r7, [r0, #6]        ; year   (u16)
//! ldrb  r6, [r0, #4]        ; month  (1 = January)
//! ldrb  r8, [r0, #3]        ; day
//! r5 = year - 1                       ; wraps as u32
//! r9 = 365*r5 + (r5 >> 2)             ; mla with the 365 pool literal
//! r9 -= __rt_udiv(r5, 100)            ; UNSIGNED divides @ 0x08036f14
//! r5  = r9 + __rt_udiv(r5, 400)
//! r5 += __rt_udiv((month*367 - 256 - 106), 12)   ; smulbb, 367 pool literal
//! r5 += FUN_08086e00(year, month)     ; February correction
//! r5 += day
//! __rt_udiv(r5, 7)                    ; quotient discarded, rem in r1
//! strb  r1, [r0, #8]                  ; weekday = day_number % 7
//! return r0 = r5                      ; the FULL day number (mov r0, r5)
//! ```
//!
//! That is proleptic-Gregorian Rata Die with 0001-01-01 = day 1:
//! `365*(y-1) + (y-1)/4 - (y-1)/100 + (y-1)/400 + (367*m - 362)/12
//! + feb_correction + d`. Weekday 1 = Monday, so 1970-01-01 (Rata Die
//! 719163, see `time/datetime.rs`'s `UNIX_EPOCH_DAY_NUMBER`) lands on
//! weekday 4 — Thursday. Every divide is the UNSIGNED `__rt_udiv`: the
//! fields are raw bytes/halfwords with no validation, so out-of-range
//! inputs wrap through the unsigned arithmetic rather than faulting.
//!
//! # Deliberate deviation
//!
//! `FUN_08086e00` @ 0x08086e00 (28 bytes) — the February correction, 0
//! for `month <= 2` else -1 in a leap year / -2 in a common year via
//! `is_leap_year` @ 0x080aabac — is not ported. Its body is fully
//! decoded, so the wired host default of [`LEAP_MONTH_CORRECTION`]
//! reproduces it exactly on the ported `is_leap_year` (the
//! `month_length.rs` "wired default is the real port" precedent); on
//! the firmware target the default calls retailOS at its verified load
//! address. The seam is volatile so LLVM retains the call boundary (the
//! `unix_to_datetime.rs` precedent). The divisions call the
//! ported `__rt_udiv`/`__rt_udivmod` (runtime/rt_div.rs) so the four `bl`
//! boundaries survive for match.py review.

use super::datetime::DateTime;

/// `FUN_08086e00`: February leap correction for a (year, month) pair —
/// 0 for January/February, -1 after February in a leap year, -2 after
/// February in a common year. Its direct, target-only address is
/// deliberately retained until it is ported separately.
pub type LeapMonthCorrectionFn = unsafe extern "C" fn(year: u32, month: u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_leap_month_correction(year: u32, month: u32) -> i32 {
    let correct: LeapMonthCorrectionFn = core::mem::transmute(0x0808_6e00usize);
    correct(year, month)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn modeled_leap_month_correction(year: u32, month: u32) -> i32 {
    // FUN_08086e00's raw words: `cmp r1, #2; movls r0, #0` for
    // January/February, otherwise `is_leap_year` and
    // `mvneq r0, #1` (common, -2) / `mvnne r0, #0` (leap, -1).
    if month <= 2 {
        0
    } else if crate::time::leap_year::is_leap_year(year) != 0 {
        -1
    } else {
        -2
    }
}

/// Active `FUN_08086e00` dispatch. The target default calls retailOS;
/// host tests may install a recorder to observe the delegation.
#[cfg(target_os = "none")]
pub static mut LEAP_MONTH_CORRECTION: LeapMonthCorrectionFn = firmware_leap_month_correction;

/// Active `FUN_08086e00` dispatch. The host default is the exact model
/// above — the callee's body is fully decoded, so nothing is invented.
#[cfg(not(target_os = "none"))]
pub static mut LEAP_MONTH_CORRECTION: LeapMonthCorrectionFn = modeled_leap_month_correction;

#[inline(always)]
unsafe fn leap_month_correction() -> LeapMonthCorrectionFn {
    core::ptr::read_volatile(core::ptr::addr_of!(LEAP_MONTH_CORRECTION))
}

/// datetime_day_number — original: `FUN_0807ea68` @ 0x0807ea68
/// (**148 bytes, 0x0807ea68..0x0807eafc**, including the 365/367
/// literal-pool words; 25 `bl`, 0 predicated `bl`, 0 `b` — verified by
/// decoding every branch word in `osos.dec`, module header).
///
/// Returns the proleptic-Gregorian Rata Die day number (0001-01-01 = 1)
/// of the record's year/month/day and stores that number mod 7 into
/// `dt->weekday` (1 = Monday, 0 = Sunday). All arithmetic wraps like the
/// original's flagless ARM adds/multiplies; the divides are unsigned.
///
/// # Safety
///
/// `dt` must point at a readable, writable [`DateTime`]. The installed
/// [`LEAP_MONTH_CORRECTION`] handler runs once per call with the record's
/// zero-extended year and month.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_day_number(dt: *mut DateTime) -> i32 {
    let record = &mut *dt;
    let year = record.year as u32;
    let month = record.month as u32;
    let day = record.day as u32;

    let y = year.wrapping_sub(1);
    let mut days = 365u32.wrapping_mul(y).wrapping_add(y >> 2);
    days = days.wrapping_sub(crate::runtime::rt_div::__rt_udiv(y, 100));
    days = days.wrapping_add(crate::runtime::rt_div::__rt_udiv(y, 400));
    // smulbb month*367, then the two strength-split subs: -256, -106.
    days = days.wrapping_add(crate::runtime::rt_div::__rt_udiv(
        month.wrapping_mul(367).wrapping_sub(256).wrapping_sub(106),
        12,
    ));
    days = days.wrapping_add(leap_month_correction()(year, month) as u32);
    days = days.wrapping_add(day);

    // The original divides by 7 and stores only the r1 remainder; the
    // quotient dies and r0 is reloaded with the full day number.
    let mut remainder = 0u32;
    crate::runtime::rt_div::__rt_udivmod(days, 7, &mut remainder);
    record.weekday = remainder as u8;
    days as i32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CORRECTION_CALLS: u32 = 0;
    static mut LAST_YEAR: u32 = 0;
    static mut LAST_MONTH: u32 = 0;

    /// Faithful model of `FUN_08086e00` @ 0x08086e00, fully decoded from
    /// its raw words: `cmp r1,#2; movls r0,#0` then `is_leap_year` and
    /// `mvneq r0,#1` / `mvnne r0,#0` (-2 common / -1 leap).
    fn reference_correction(year: u32, month: u32) -> i32 {
        if month <= 2 {
            0
        } else if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
            -1
        } else {
            -2
        }
    }

    unsafe extern "C" fn recording_correction(year: u32, month: u32) -> i32 {
        CORRECTION_CALLS += 1;
        LAST_YEAR = year;
        LAST_MONTH = month;
        reference_correction(year, month)
    }

    unsafe fn install() -> MutexGuard<'static, ()> {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ptr::write_volatile(
            ptr::addr_of_mut!(LEAP_MONTH_CORRECTION),
            recording_correction,
        );
        CORRECTION_CALLS = 0;
        LAST_YEAR = 0;
        LAST_MONTH = 0;
        guard
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>) {
        #[cfg(target_os = "none")]
        ptr::write_volatile(
            ptr::addr_of_mut!(LEAP_MONTH_CORRECTION),
            firmware_leap_month_correction,
        );
        #[cfg(not(target_os = "none"))]
        ptr::write_volatile(
            ptr::addr_of_mut!(LEAP_MONTH_CORRECTION),
            modeled_leap_month_correction,
        );
        drop(guard);
    }

    fn dt(year: u16, month: u8, day: u8) -> DateTime {
        DateTime {
            second: 0,
            minute: 0,
            hour: 0,
            day,
            month,
            reserved: 0,
            year,
            weekday: 0xff,
            reserved2: 0,
        }
    }

    /// Independent oracle: Hinnant's `days_from_civil` (days since
    /// 1970-01-01) shifted by the Rata Die epoch day. Shares no code with
    /// the port's 365/367/udiv formula.
    fn oracle_day_number(year: i64, month: i64, day: i64) -> i64 {
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468 + 719163
    }

    fn is_leap(year: i64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }

    /// Days in month, February corrected; the oracle input stays valid.
    fn month_len(year: i64, month: i64) -> i64 {
        const LEN: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if month == 2 && is_leap(year) {
            29
        } else {
            LEN[(month - 1) as usize]
        }
    }

    /// Every day of ordinary, century-common, century-leap and epoch
    /// years against the independent civil oracle, weekday included.
    #[test]
    fn rata_die_and_weekday_match_an_independent_civil_oracle() {
        let guard = unsafe { install() };
        for year in [1i64, 4, 100, 400, 1582, 1600, 1700, 1800, 1900, 1970, 2000, 2038, 2100, 2400] {
            for month in 1..=12i64 {
                for day in 1..=month_len(year, month) {
                    let mut d = dt(year as u16, month as u8, day as u8);
                    let want = oracle_day_number(year, month, day);
                    assert_eq!(unsafe { datetime_day_number(&mut d) }, want as i32, "{year}-{month}-{day}");
                    assert_eq!(d.weekday, (want % 7) as u8, "weekday {year}-{month}-{day}");
                }
            }
        }
        assert_eq!(
            unsafe { CORRECTION_CALLS },
            [1i64, 4, 100, 400, 1582, 1600, 1700, 1800, 1900, 1970, 2000, 2038, 2100, 2400]
                .iter()
                .map(|&y| (1..=12).map(|m| month_len(y, m)).sum::<i64>())
                .sum::<i64>() as u32,
            "one February-correction call per record"
        );
        unsafe { restore(guard) };
    }

    /// Anchor weekdays under this scheme (1 = Monday, 0 = Sunday):
    /// 0001-01-01 is a Monday, 1970-01-01 a Thursday, 2000-01-01 a
    /// Saturday.
    #[test]
    fn known_anchor_weekdays() {
        let guard = unsafe { install() };
        for (year, month, day, want_days, want_weekday) in [
            (1u16, 1u8, 1u8, 1i32, 1u8),
            (1970, 1, 1, 719163, 4),
            (2000, 1, 1, 730120, 6),
        ] {
            let mut d = dt(year, month, day);
            assert_eq!(unsafe { datetime_day_number(&mut d) }, want_days);
            assert_eq!(d.weekday, want_weekday);
        }
        unsafe { restore(guard) };
    }

    /// The original reloads r0 with the full day number after the mod-7
    /// divide (`mov r0, r5`): the return is the day number, not the
    /// quotient.
    #[test]
    fn returns_the_day_number_not_the_quotient() {
        let guard = unsafe { install() };
        let mut d = dt(1970, 1, 1);
        let days = unsafe { datetime_day_number(&mut d) };
        assert_eq!(days, 719163);
        assert_eq!(d.weekday, 4);
        assert_ne!(days, 719163 / 7);
        unsafe { restore(guard) };
    }

    /// The February correction is delegated once per call with the
    /// record's zero-extended year and month, in the original's
    /// (r0 = year, r1 = month) register order.
    #[test]
    fn february_correction_is_delegated_with_year_and_month() {
        let guard = unsafe { install() };
        let mut d = dt(0x9abc, 6, 15);
        unsafe { datetime_day_number(&mut d) };
        assert_eq!(unsafe { CORRECTION_CALLS }, 1);
        assert_eq!(unsafe { (LAST_YEAR, LAST_MONTH) }, (0x9abc, 6));
        unsafe { restore(guard) };
    }

    /// No validation anywhere: raw byte/halfword fields wrap through the
    /// UNSIGNED divides exactly like the ARM original. Expected values
    /// computed word-by-word from the disassembly (u32 wrapping, udiv):
    /// year=0 makes y = 0xffff_ffff; month=0 makes the smulbb term
    /// 0xffff_fe96 before its udiv-by-12.
    #[test]
    fn out_of_range_fields_wrap_like_the_arm_original() {
        let guard = unsafe { install() };
        for (year, month, day, want_days, want_weekday) in [
            (0u16, 1u8, 1u8, 0x3e14_7975u32, 3u8),
            (0, 0, 0, 0x5369_ceab, 0),
            (1970, 13, 1, 719528, 5),
            (0xffff, 12, 31, 23936166, 2),
        ] {
            let mut d = dt(year, month, day);
            assert_eq!(
                unsafe { datetime_day_number(&mut d) },
                want_days as i32,
                "{year}-{month}-{day}"
            );
            assert_eq!(d.weekday, want_weekday, "weekday {year}-{month}-{day}");
        }
        unsafe { restore(guard) };
    }
}
