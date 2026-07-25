//! Ports of the ARM ADS 1.0.1 localtime/gmtime pair and the unsigned
//! divide-by-10 helper from osos.
//!
//! Originals:
//! - `localtime` veneer @ 0x080312a0 (12 bytes): `ldr r1, =0x08b2f9f4`
//!   (the static `struct tm`), then a tail-branch to the core. It adds
//!   NOTHING else — no timezone offset, no DST lookup — so on this device
//!   `localtime` and `gmtime` are the same function. The binary contains
//!   no separate gmtime veneer; both Rust entry points below share the
//!   one core, matching the original's semantics.
//! - localtime/gmtime core @ 0x08033590 (260 bytes): decomposes a
//!   32-bit `time_t` into tm fields by repeated division. All division is
//!   UNSIGNED (`__rt_udiv` @ 0x08036f14, called with the raw loaded value
//!   and no sign handling), so any `time_t` other than exactly -1 is
//!   treated as a huge unsigned count of seconds — negative inputs wrap
//!   into dates in 2038..2106 rather than pre-1970 dates. `time_t == -1`
//!   is special-cased: the tm is zeroed (memset @ 0x08037db8, 36 bytes)
//!   and `tm_mday` set to 1.
//! - `__rt_udiv10` @ 0x08033694 (44 bytes): unsigned divide-by-10 via the
//!   classic shift-add magic multiply, quotient in r0, remainder in r1.
//!
//! Core algorithm (mirrored from the disassembly):
//! 1. Peel seconds/minutes/hours with successive divmod by 60, 60, 24.
//! 2. `days = quot + 0x63e0` — days since 1900-01-01 plus one; the extra
//!    day is the classic ADS trick that pushes the (non-leap) century
//!    year 1900 out of the 4-year-cycle math. `tm_wday = days % 7`
//!    (1970-01-01 = Thursday = 4 falls out of 25568 % 7).
//! 3. Split `days` into 1461-day cycles: `year = 4*cycles`, and for a
//!    remainder >= 366 add `(rem-1)/365` more years with
//!    `yday = (rem-1)%365`; otherwise `yday = rem`.
//! 4. Month/day: walk a LEAP-year month-length table ([31,29,31,...],
//!    12 bytes @ 0x08986001). For non-leap years (`year & 3 != 0`) the
//!    yday is first bumped by one when >= 59 so the leap table lines up.
//! 5. `tm_isdst = -1` always.
//!
//! Known quirks of the original, faithfully reproduced:
//! - Dates in the year 1900 (very negative `time_t`) come out one day
//!    too high in `tm_yday` — the +1 offset shifts year 0's numbering.
//! - The 4-year-cycle math treats EVERY year divisible by 4 as leap, so
//!    wrapped negative inputs landing past 2100-02-28 drift one day off
//!    the true Gregorian calendar (2100 is not really a leap year).
//! - Not thread-safe and not reentrant: both entry points return the
//!    same static tm, exactly like the original's struct at 0x08b2f9f4.
//!    A second call overwrites the first result.
//!
//! Simplifications: the `time_t == -1` path's `memset` call is a loop of
//! volatile word stores (keeps LLVM from lowering it to an
//! `__aeabi_memclr4` libcall); the repeated `__rt_udiv` calls are a local
//! restoring-division helper (bit-identical outputs, no `__aeabi`
//! libcalls). Division by constants never reaches the div-by-zero path,
//! so `__rt_div0` is not modelled.
//!
//! NOTE: [`Tm`] is a local copy of the `#[repr(C)] struct tm` layout
//! also defined in `mktime.rs` (ported by another agent); the two should
//! be unified into a shared type once both land.

/// Broken-down time, `#[repr(C)]`, 9 x i32 = 36 bytes (the size the
/// original memsets on the `time_t == -1` path). Field order and offsets
/// match the original's stores (sec@0 .. isdst@32).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

const TM_ZERO: Tm = Tm {
    tm_sec: 0,
    tm_min: 0,
    tm_hour: 0,
    tm_mday: 0,
    tm_mon: 0,
    tm_year: 0,
    tm_wday: 0,
    tm_yday: 0,
    tm_isdst: 0,
};

/// The single static broken-down-time struct both entry points return —
/// original: 36 bytes in .bss @ 0x08b2f9f4, zeroed by startup. NOT
/// thread-safe, like the original: every call overwrites it.
static mut STATIC_TM: Tm = TM_ZERO;

/// Leap-year month lengths — original: 12-byte table @ 0x08986001.
/// Non-leap years are handled by shifting the day-of-year past the
/// phantom Feb 29 before the walk (see module doc, step 4).
const MONTH_LEN_LEAP: [u8; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days in a 4-year cycle (365*4 + 1).
const DAYS_PER_4_YEARS: u32 = 1461;

/// `localtime` — original veneer @ 0x080312a0: load the static tm and
/// tail-call the core. Returns the shared static struct; a later call
/// (via either entry point) overwrites it. `t` must point to a valid
/// `time_t`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn localtime(t: *const i32) -> *mut Tm {
    time_to_tm(t, core::ptr::addr_of_mut!(STATIC_TM))
}

/// `gmtime` — the original binary has no gmtime veneer; the localtime
/// core applies no timezone/DST adjustment, so gmtime is the same
/// function returning the same static struct.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gmtime(t: *const i32) -> *mut Tm {
    time_to_tm(t, core::ptr::addr_of_mut!(STATIC_TM))
}

/// Shared core — original @ 0x08033590. Decomposes `*t` into `*tm` and
/// returns `tm`. See the module doc for the algorithm and its quirks.
unsafe fn time_to_tm(t: *const i32, tm: *mut Tm) -> *mut Tm {
    let time = *t;
    if time == -1 {
        // Original: memset(tm, 0, 36) @ 0x08037db8, then tm_mday = 1.
        // Volatile word stores keep LLVM's memset-idiom recognition from
        // lowering this to an __aeabi_memclr4 libcall.
        let words = tm as *mut u32;
        for i in 0..(core::mem::size_of::<Tm>() / core::mem::size_of::<u32>()) {
            core::ptr::write_volatile(words.add(i), 0);
        }
        (*tm).tm_mday = 1;
        return tm;
    }

    // All division below is UNSIGNED in the original (__rt_udiv on the
    // raw loaded word): negative inputs other than -1 wrap into the far
    // future, they do not produce pre-1970 dates.
    let (minutes, tm_sec) = udivmod(time as u32, 60);
    let (hours, tm_min) = udivmod(minutes, 60);
    let (day_count, tm_hour) = udivmod(hours, 24);
    (*tm).tm_sec = tm_sec as i32;
    (*tm).tm_min = tm_min as i32;
    (*tm).tm_hour = tm_hour as i32;

    // Days since 1900-01-01, plus one so the non-leap century year 1900
    // stays out of the 4-year-cycle math (wrapping, as the original's
    // 32-bit adds).
    let days = day_count.wrapping_add(0x63e0);

    let (_, tm_wday) = udivmod(days, 7);
    (*tm).tm_wday = tm_wday as i32;

    let (cycles, day_in_cycle) = udivmod(days, DAYS_PER_4_YEARS);
    let mut year = cycles * 4;
    let mut yday = day_in_cycle;
    if day_in_cycle >= 366 {
        // Past the first (leap-slot) year of the cycle: (rem-1)/365 more
        // full years, day-of-year is the remainder.
        let (extra_years, day_in_year) = udivmod(day_in_cycle - 1, 365);
        year += extra_years;
        yday = day_in_year;
    }
    (*tm).tm_year = year as i32;
    (*tm).tm_yday = yday as i32;

    // Non-leap years: shift the day-of-year past the leap table's Feb 29
    // (original: `cmp yday,#59; adc yday,yday,#0`).
    let mut day = yday;
    if year & 3 != 0 {
        day += (day >= 59) as u32;
    }
    let mut month = 0usize;
    // The walk provably stops by month 11 (day <= 365 on entry, and the
    // table sums to 366), but LLVM cannot see that — index via `get` so
    // no core::panic_bounds_check call is pulled in. The original's walk
    // has no bounds check at all (plain `ldrb [r2, r5]`).
    loop {
        let len = MONTH_LEN_LEAP.get(month).copied().unwrap_or(1) as u32;
        if len > day {
            break;
        }
        day -= len;
        month += 1;
    }
    (*tm).tm_mday = day as i32 + 1;
    (*tm).tm_mon = month as i32;
    (*tm).tm_isdst = -1;

    tm
}

/// `__rt_udiv10` — original @ 0x08033694. Quotient-only entry point
/// matching the original's r0 return (the remainder comes back in r1,
/// which the plain C ABI cannot express; use [`udiv10_full`]).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_udiv10(num: u32) -> u32 {
    udiv10_full(num).0
}

/// Full divide: returns `(num / 10, num % 10)`. Mirrors the original's
/// shift-add magic multiply (`x = n - n/4; x += x>>4; x += x>>8;
/// x += x>>16; q = x>>3`) and the single-step fix-up seeded from
/// `n - 10` — plain shifts/adds on armv5te, no `__aeabi` libcall.
pub fn udiv10_full(num: u32) -> (u32, u32) {
    let mut quot = num - (num >> 2);
    quot = quot.wrapping_add(quot >> 4);
    quot = quot.wrapping_add(quot >> 8);
    quot = quot.wrapping_add(quot >> 16);
    quot >>= 3;
    // rem = (num - 10) - quot*10; if it underflowed, quot was exact and
    // the true remainder is rem + 10, else quot was one low.
    let mut rem = num.wrapping_sub(10).wrapping_sub(quot.wrapping_mul(10));
    if (rem as i32) < 0 {
        rem = rem.wrapping_add(10);
    } else {
        quot += 1;
    }
    (quot, rem)
}

/// Restoring long division standing in for the original's `__rt_udiv`
/// calls @ 0x08036f14: returns `(num / den, num % den)`. Bit-identical
/// outputs; the u64 remainder keeps the 33rd bit explicit and lowers to
/// inline shifts/subs on armv5te (no `__aeabi_uidivmod` libcall).
/// Callers here never pass `den == 0`. Kept out-of-line so the core
/// calls it once per step, mirroring the original's `bl __rt_udiv`
/// structure instead of inlining five unrolled division loops.
#[inline(never)]
fn udivmod(num: u32, den: u32) -> (u32, u32) {
    let den = den as u64;
    let mut rem: u64 = 0;
    let mut quot: u32 = 0;
    for bit in (0..32).rev() {
        rem = (rem << 1) | ((num >> bit) & 1) as u64;
        if rem >= den {
            rem -= den;
            quot |= 1 << bit;
        }
    }
    (quot, rem as u32)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::string::String;
    use std::sync::Mutex;

    /// The static tm is process-global and tests run on parallel threads:
    /// every test that calls localtime/gmtime must hold this lock.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Read out a copy of the current static-struct contents.
    fn break_down(t: i32) -> Tm {
        unsafe { *localtime(&t) }
    }

    fn assert_fields(tm: &Tm, expect: &Tm, ctx: String) {
        assert_eq!(tm, expect, "field mismatch: {ctx}");
    }

    #[test]
    fn epoch_zero() {
        let _guard = TEST_LOCK.lock().unwrap();
        let tm = break_down(0);
        assert_fields(
            &tm,
            &Tm {
                tm_sec: 0,
                tm_min: 0,
                tm_hour: 0,
                tm_mday: 1,
                tm_mon: 0,
                tm_year: 70,
                tm_wday: 4, // Thursday
                tm_yday: 0,
                tm_isdst: -1,
            },
            format!("epoch: {tm:?}"),
        );
    }

    /// `time_t == -1` is the original's error sentinel: memset(tm,0,36)
    /// then tm_mday = 1 — note tm_isdst ends up 0, NOT -1.
    #[test]
    fn minus_one_is_special() {
        let _guard = TEST_LOCK.lock().unwrap();
        let tm = break_down(-1);
        assert_eq!(
            tm,
            Tm {
                tm_mday: 1,
                ..TM_ZERO
            }
        );
    }

    #[test]
    fn known_date_2009_12_11() {
        let _guard = TEST_LOCK.lock().unwrap();
        // 2009-12-11 00:00:00 UTC = 1230768000 + 344*86400, a Friday.
        let tm = break_down(1260489600);
        assert_eq!(
            tm,
            Tm {
                tm_sec: 0,
                tm_min: 0,
                tm_hour: 0,
                tm_mday: 11,
                tm_mon: 11,
                tm_year: 109,
                tm_wday: 5,
                tm_yday: 344,
                tm_isdst: -1,
            }
        );
    }

    #[test]
    fn leap_years() {
        let _guard = TEST_LOCK.lock().unwrap();
        // 2000-02-29 12:00:00 UTC (2000 IS a leap year — divisible by 400
        // and, for the original's 4-year-cycle math, simply by 4).
        let tm = break_down(951825600);
        assert_eq!(
            tm,
            Tm {
                tm_sec: 0,
                tm_min: 0,
                tm_hour: 12,
                tm_mday: 29,
                tm_mon: 1,
                tm_year: 100,
                tm_wday: 2, // Tuesday
                tm_yday: 59,
                tm_isdst: -1,
            }
        );
        // The day after: 2000-03-01.
        let tm = break_down(951825600 + 86400);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday), (100, 2, 1, 60));
        // 2008-02-29 23:59:59 UTC -> 2008-03-01 00:00:00 a second later.
        let tm = break_down(1204329599);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday), (108, 1, 29, 59));
        let tm = break_down(1204329600);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday), (108, 2, 1, 60));
        // Non-leap year: 2009-02-28 23:59:59 -> 2009-03-01.
        let tm = break_down(1235865599);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday), (109, 1, 28, 58));
        let tm = break_down(1235865600);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday), (109, 2, 1, 59));
        // Year-end boundary: the month walk enters with day <= 365 and
        // must stop at month 11 / mday 31 (365 - 335 = 30 < 31), never
        // running off the 12-byte table. 2000-12-31 (leap, Sunday) and
        // 2009-12-31 (non-leap, Thursday).
        let tm = break_down(978220800);
        assert_eq!(
            (tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday, tm.tm_wday),
            (100, 11, 31, 365, 0)
        );
        let tm = break_down(1262217600);
        assert_eq!(
            (tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_yday, tm.tm_wday),
            (109, 11, 31, 364, 4)
        );
    }

    #[test]
    fn year_2038_boundary() {
        let _guard = TEST_LOCK.lock().unwrap();
        // i32::MAX = 2038-01-19 03:14:07 UTC, a Tuesday.
        let tm = break_down(i32::MAX);
        assert_eq!(
            tm,
            Tm {
                tm_sec: 7,
                tm_min: 14,
                tm_hour: 3,
                tm_mday: 19,
                tm_mon: 0,
                tm_year: 138,
                tm_wday: 2,
                tm_yday: 18,
                tm_isdst: -1,
            }
        );
        // One second earlier and the day boundary before that.
        let tm = break_down(i32::MAX - 1);
        assert_eq!((tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday), (6, 14, 3, 19));
        let tm = break_down(i32::MAX - (3 * 3600 + 14 * 60 + 7));
        assert_eq!((tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_mday, tm.tm_yday), (0, 0, 0, 19, 18));
    }

    /// Independent reference: Howard Hinnant's civil_from_days on the
    /// day count. Agrees with the original for every NON-NEGATIVE input
    /// (the original's quirks only show in year 1900 and past 2100-02-28,
    /// both unreachable from t >= 0).
    fn reference_civil(t: i32) -> Tm {
        let u = t as u32;
        let tm_sec = (u % 60) as i32;
        let tm_min = ((u / 60) % 60) as i32;
        let tm_hour = ((u / 3600) % 24) as i32;
        let days = (u / 86400) as u64;
        let tm_wday = ((days + 4) % 7) as i32; // 1970-01-01 = Thursday
        let z = days + 719468;
        let era = z / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if m <= 2 { y + 1 } else { y };
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let mlens = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let yday: u64 = mlens[..(m - 1) as usize].iter().sum::<u64>() + d - 1;
        Tm {
            tm_sec,
            tm_min,
            tm_hour,
            tm_mday: d as i32,
            tm_mon: (m - 1) as i32,
            tm_year: (year - 1900) as i32,
            tm_wday,
            tm_yday: yday as i32,
            tm_isdst: -1,
        }
    }

    /// Field-by-field sweep across the whole non-negative range.
    #[test]
    fn matches_reference_across_range() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut t: i64 = 0;
        while t <= i32::MAX as i64 {
            let got = break_down(t as i32);
            let want = reference_civil(t as i32);
            assert_eq!(got, want, "mismatch at t={t}");
            t += 9973; // odd step: hits varied sec/min/hour and every weekday
        }
        // Dense sweep over a full leap-year February/March boundary.
        for t in 951696000..=952041600i64 {
            if t % 3600 != 0 {
                continue;
            }
            let got = break_down(t as i32);
            let want = reference_civil(t as i32);
            assert_eq!(got, want, "mismatch at t={t}");
        }
    }

    /// Negative inputs other than -1: the original divides the raw word
    /// UNSIGNED, so they wrap into 2038..2106 — NOT pre-1970 dates.
    #[test]
    fn negative_values_wrap_unsigned() {
        let _guard = TEST_LOCK.lock().unwrap();
        // t = -2 -> u32 4294967294 s = 49710 days + 6:28:14.
        // Under the original's every-4th-year-leap math that lands on
        // 2106-02-06 (true Gregorian would be 2106-02-07: 2100 is not a
        // leap year — an original-firmware quirk we reproduce).
        let tm = break_down(-2);
        assert_eq!(
            tm,
            Tm {
                tm_sec: 14,
                tm_min: 28,
                tm_hour: 6,
                tm_mday: 6,
                tm_mon: 1,
                tm_year: 206,
                tm_wday: 0, // weekday stays calendar-correct (days mod 7)
                tm_yday: 36,
                tm_isdst: -1,
            }
        );
        // i32::MIN wraps to u32 0x80000000 = 2147483648 s = i32::MAX + 1:
        // 24855 days + 3:14:08 -> 2038-01-19, one second after the
        // positive boundary.
        let tm = break_down(i32::MIN);
        assert_eq!(
            (tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_yday),
            (138, 0, 19, 3, 14, 8, 18)
        );
    }

    /// Both entry points return THE static struct: a second call
    /// overwrites the first result, and gmtime aliases localtime.
    #[test]
    fn static_struct_return_semantics() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            let first = localtime(&0);
            assert_eq!((*first).tm_year, 70);
            let second = gmtime(&1260489600);
            assert!(core::ptr::eq(first, second), "gmtime must alias localtime's struct");
            // The first pointer now sees the second call's contents.
            assert_eq!((*first).tm_year, 109);
            assert_eq!((*first).tm_mday, 11);
            let third = localtime(&-1);
            assert!(core::ptr::eq(first, third));
            assert_eq!((*first).tm_year, 0);
            assert_eq!((*first).tm_mday, 1);
        }
    }

    #[test]
    fn udiv10_edges() {
        for n in [0u32, 1, 9, 10, 11, 19, 20, 99, 100, 101, u32::MAX - 1, u32::MAX] {
            assert_eq!(udiv10_full(n), (n / 10, n % 10), "udiv10({n})");
        }
        // Pseudo-random sweep (xorshift) across the whole u32 range.
        let mut x: u32 = 0x12345678;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            assert_eq!(udiv10_full(x), (x / 10, x % 10), "udiv10({x})");
        }
    }

    #[test]
    fn udivmod_matches_native() {
        let mut x: u32 = 0xdeadbeef;
        for den in [3u32, 7, 24, 60, 365, 366, 1461, 0x8000_0001] {
            for _ in 0..10_000 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                assert_eq!(udivmod(x, den), (x / den, x % den), "udivmod({x}, {den})");
            }
        }
    }
}
