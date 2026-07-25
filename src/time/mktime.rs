//! Port of the ARM ADS 1.0.1 `mktime` and its field-normalization helper.
//!
//! Originals:
//! - normalize helper @ 0x080312ac (100 bytes): `carry = norm(&field, carry,
//!   base)`. Splits `field + carry` into two 16-bit limbs (signed high,
//!   unsigned low) and divides by `base` with two `__rt_sdiv` calls — the
//!   classic no-64-bit-arithmetic carry propagation. The low division's
//!   remainder is then forced non-negative (`while r < 0 { r += base;
//!   q -= 1 }`), so the net effect is Euclidean division: `field` becomes
//!   the remainder in `[0, base)` and the quotient (total carry) is
//!   returned.
//! - `mktime` @ 0x08031310 (584 bytes): normalizes sec/min/hour through
//!   bases 60/60/24, then mday through base 1461 (!) — out-of-range days are
//!   folded into the year four years at a time — and mon through base 12.
//!   A walk over the days-in-month table @ 0x08986001 ({31,29,...}, Feb=29)
//!   reduces the remaining 0..1460 day count, compensating by one day when
//!   crossing February in a year with `(year & 3) != 0`, plus an explicit
//!   Feb-29-in-non-leap-year -> Mar-1 fixup. Days since 1900 are computed as
//!   `1461*(year/4) + 365*(year%4) - (year%4==0) + yday`, minutes via
//!   Horner, the 1900->1970 epoch offset (0x0231c660 = 36,816,480 minutes)
//!   subtracted, and seconds folded in with the same 16-bit-limb trick.
//!   Returns the timestamp, or -1 on range error.
//!
//! struct tm layout (confirmed from the disassembly): 9 x i32 at offsets
//! 0x00..0x20 — sec, min, hour, mday, mon, year, wday, yday, isdst. The
//! original never touches anything past offset 0x20 (no gmtoff/zone), and
//! time_t is a 32-bit int.
//!
//! Quirks of the original, mirrored faithfully:
//! - Leap rule is simply `(tm_year % 4) == 0`. tm_year 200 (2100) is
//!   therefore treated as a LEAP year (Feb 29 2100 is accepted); tm_year 0
//!   (1900) would also be "leap" but is unreachable — after normalization
//!   the year must satisfy `70 <= year <= 208` (1970..2108) or the function
//!   returns -1.
//! - The pre-normalization `tm_year` must lie in [-0x40000000, 0x40000000].
//! - The timestamp must fit in an UNSIGNED 32-bit range: dates before
//!   1970-01-01 00:00:00 UTC fail, and the effective upper bound is
//!   2106-02-07 06:28:15. Timestamps past 2038-01-19 03:14:07 are returned
//!   as negative i32 (plain two's-complement wrap), and a genuine success
//!   value of 0xffffffff is indistinguishable from the -1 error return —
//!   both behaviors are in the original.
//! - On every error path the caller's struct is left untouched; on success
//!   all nine fields are written back (mday 1-based, wday 0=Sunday, yday
//!   0-based) with isdst forced to -1.
//!
//! Simplifications: division/remainder use Rust `/` and `%`, which have the
//! same C truncation semantics as the original's `__rt_sdiv` calls. The
//! 16-bit-limb arithmetic is kept exactly (with explicit wrapping ops) so
//! extreme inputs wrap the same way the ARM registers do.

/// Days-in-month table @ 0x08986001 (bytes `1f 1d 1f 1e ...`): February is
/// stored as 29; non-leap years are compensated inside the algorithm.
const DAYS_IN_MONTH: [i32; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// 0x0231c660 — minutes from 1900-01-01 00:00 to the 1970-01-01 epoch
/// (25,567 days; the formula counts 1900 as a leap year, see module docs).
const MINUTES_1900_TO_EPOCH: i32 = 0x0231_c660;

/// struct tm as the original sees it: nine 32-bit ints, offsets 0x00..0x20.
#[repr(C)]
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

/// Days-in-month lookup, mirroring the original's unchecked `ldrb`. The
/// index is always in 0..12: normalize() leaves mon in [0, 12) and the walk
/// loop resets 12 -> 0 before the next lookup. debug_assert keeps host tests
/// honest; release code has no bounds check (and no panic path), like the
/// original.
fn month_days(idx: i32) -> i32 {
    debug_assert!((0..12).contains(&idx));
    unsafe { *DAYS_IN_MONTH.get_unchecked(idx as usize) }
}

/// Normalize helper @ 0x080312ac: Euclidean-divide `*field + carry` by
/// `base`, store the non-negative remainder back to `*field`, return the
/// quotient. The original computes this on 16-bit limbs with two
/// `__rt_sdiv` calls; the limb split is kept so wrap behavior matches.
fn normalize(field: &mut i32, carry: i32, base: i32) -> i32 {
    let value = *field;
    // High limbs (sign-extended) and low limbs (zero-extended) summed
    // separately — value + carry == hi*65536 + lo exactly.
    let hi = (value >> 16).wrapping_add(carry >> 16);
    let lo = (value & 0xffff).wrapping_add(carry & 0xffff);
    let q1 = hi / base;
    let r1 = hi % base;
    // Fold the high remainder into the low limb and divide again.
    let low_total = lo.wrapping_add(r1 << 16);
    let mut q2 = low_total / base;
    let mut r2 = low_total % base;
    // Force the remainder into [0, base) (Euclidean result).
    while r2 < 0 {
        r2 += base;
        q2 -= 1;
    }
    *field = r2;
    q2.wrapping_add(q1 << 16)
}

/// mktime @ 0x08031310 — normalize `tm`, fill in wday/yday/isdst, and
/// return seconds since 1970-01-01 00:00:00 UTC, or -1 on range error.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mktime(tm: *mut Tm) -> i32 {
    let t = &mut *tm;
    // The original snapshots all input fields up front.
    let mut sec = t.tm_sec;
    let mut min = t.tm_min;
    let mut hour = t.tm_hour;
    let mut mday = t.tm_mday;
    let mut mon = t.tm_mon;
    let tm_year = t.tm_year;

    if tm_year > 0x4000_0000 || tm_year < -0x4000_0000 {
        return -1;
    }

    let carry = normalize(&mut sec, 0, 60);
    let carry = normalize(&mut min, carry, 60);
    let carry = normalize(&mut hour, carry, 24);
    // mday is 1-based: fold the -1 into the carry, then normalize against a
    // 4-year cycle (1461 days) — the quotient moves whole quadrennia.
    let day_carry = normalize(&mut mday, carry.wrapping_sub(1), 1461);
    let mon_carry = normalize(&mut mon, 0, 12);
    let mut year = mon_carry
        .wrapping_add(day_carry.wrapping_mul(4))
        .wrapping_add(tm_year);

    // Reduce the remaining day count (0..1460) against the month table.
    while month_days(mon) <= mday {
        mday -= month_days(mon);
        mon += 1;
        if mon == 2 {
            // Table Feb is 29 days; give the extra day back in non-leap years.
            if year & 3 != 0 {
                mday += 1;
            }
        } else if mon == 12 {
            year = year.wrapping_add(1);
            mon = 0;
        }
    }
    // Feb 29 in a non-leap year rolls over to Mar 1.
    if mon == 1 && mday == 28 && year & 3 != 0 {
        mon = 2;
        mday = 0;
    }

    // Year must be 1970..2108 (further trimmed by the timestamp check below).
    if (year.wrapping_sub(70)) as u32 >= 139 {
        return -1;
    }

    // Day of year, 0-based.
    let mut yday = mday;
    for m in 0..mon {
        yday += month_days(m);
    }
    if mon > 1 && year & 3 != 0 {
        yday -= 1;
    }

    // Days since 1900-01-01 with the (year % 4 == 0) leap rule.
    let mut days = 1461i32
        .wrapping_mul(year / 4)
        .wrapping_add(365i32.wrapping_mul(year & 3))
        .wrapping_add(yday);
    if year & 3 == 0 {
        days = days.wrapping_sub(1);
    }
    let wday = (days.wrapping_add(1)) % 7;

    // Total minutes relative to the epoch, then seconds folded in via the
    // same 16-bit-limb split the normalize helper uses.
    let minutes = min
        .wrapping_add(hour.wrapping_add(days.wrapping_mul(24)).wrapping_mul(60))
        .wrapping_sub(MINUTES_1900_TO_EPOCH);
    let low = sec.wrapping_add((minutes & 0xffff).wrapping_mul(60));
    let high = (minutes >> 16)
        .wrapping_mul(60)
        .wrapping_add(((low as u32) >> 16) as i32);
    // Timestamp must fit in 32 bits as an unsigned value.
    if (high as u32) >> 16 != 0 {
        return -1;
    }
    let timestamp = (((high as u32) << 16) | ((low as u32) & 0xffff)) as i32;

    t.tm_sec = sec;
    t.tm_min = min;
    t.tm_hour = hour;
    t.tm_mday = mday + 1;
    t.tm_mon = mon;
    t.tm_year = year;
    t.tm_wday = wday;
    t.tm_yday = yday;
    t.tm_isdst = -1;
    timestamp
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn tm(sec: i32, min: i32, hour: i32, mday: i32, mon: i32, year: i32) -> Tm {
        Tm {
            tm_sec: sec,
            tm_min: min,
            tm_hour: hour,
            tm_mday: mday,
            tm_mon: mon,
            tm_year: year,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
        }
    }

    fn call(t: &mut Tm) -> i32 {
        unsafe { mktime(t) }
    }

    // ---- Independent reference implementation (naive, loop-based) ----
    // Same leap rule as the original (leap iff tm_year % 4 == 0) but built
    // from plain day-by-day walking, sharing no logic with the port.

    fn ref_leap(year: i32) -> bool {
        year % 4 == 0
    }

    fn ref_dim(year: i32, mon: i32) -> i32 {
        const D: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        D[mon as usize] + i32::from(mon == 1 && ref_leap(year))
    }

    /// Returns ((timestamp as u32, wday, yday), normalized
    /// (sec, min, hour, mday, mon, year)) or None on range error.
    fn ref_mktime(t: &Tm) -> Option<((u32, i32, i32), (i32, i32, i32, i32, i32, i32))> {
        if t.tm_year > 0x4000_0000 || t.tm_year < -0x4000_0000 {
            return None;
        }
        let mut sec = t.tm_sec;
        let mut min = t.tm_min;
        let mut hour = t.tm_hour;
        let mut mday = t.tm_mday;
        let mut mon = t.tm_mon;
        let mut year = t.tm_year;

        min += sec.div_euclid(60);
        sec = sec.rem_euclid(60);
        hour += min.div_euclid(60);
        min = min.rem_euclid(60);
        mday += hour.div_euclid(24);
        hour = hour.rem_euclid(24);
        year += mon.div_euclid(12);
        mon = mon.rem_euclid(12);

        while mday < 1 {
            mon -= 1;
            if mon < 0 {
                mon = 11;
                year -= 1;
            }
            mday += ref_dim(year, mon);
        }
        while mday > ref_dim(year, mon) {
            mday -= ref_dim(year, mon);
            mon += 1;
            if mon > 11 {
                mon = 0;
                year += 1;
            }
        }

        if !(70..=208).contains(&year) {
            return None;
        }

        let mut days1900: i64 = 0;
        for y in 0..year {
            // The original's 1461*(y/4) + 365*(y%4) - (y%4==0) day count
            // matches a calendar where 1900 itself is NOT a leap year, even
            // though month lengths inside a year use the plain y%4 rule.
            days1900 += 365 + i64::from(ref_leap(y) && y != 0);
        }
        let mut yday = 0i32;
        for m in 0..mon {
            yday += ref_dim(year, m);
        }
        yday += mday - 1;
        days1900 += i64::from(yday);

        let days_epoch = days1900 - 25567; // 1900 -> 1970
        let total = days_epoch * 86400
            + i64::from(hour) * 3600
            + i64::from(min) * 60
            + i64::from(sec);
        if !(0..=u32::MAX as i64).contains(&total) {
            return None;
        }
        let wday = ((days_epoch + 4) % 7) as i32; // 1970-01-01 = Thursday
        Some(((total as u32, wday, yday), (sec, min, hour, mday, mon, year)))
    }

    fn assert_matches_ref(t: &Tm) {
        let mut got = tm(t.tm_sec, t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon, t.tm_year);
        let ret = call(&mut got);
        match ref_mktime(t) {
            None => assert_eq!(ret, -1, "expected -1 for {t:?}"),
            Some(((ts, wday, yday), (sec, min, hour, mday, mon, year))) => {
                assert_eq!(ret as u32, ts, "timestamp for {t:?}");
                assert_eq!(got.tm_wday, wday, "wday for {t:?}");
                assert_eq!(got.tm_yday, yday, "yday for {t:?}");
                assert_eq!(
                    (got.tm_sec, got.tm_min, got.tm_hour, got.tm_mday, got.tm_mon, got.tm_year),
                    (sec, min, hour, mday, mon, year),
                    "normalized fields for {t:?}"
                );
                assert_eq!(got.tm_isdst, -1);
            }
        }
    }

    impl core::fmt::Debug for Tm {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                self.tm_year + 1900, self.tm_mon + 1, self.tm_mday, self.tm_hour, self.tm_min,
                self.tm_sec
            )
        }
    }

    #[test]
    fn known_timestamps() {
        // Epoch.
        let mut t = tm(0, 0, 0, 1, 0, 70);
        assert_eq!(call(&mut t), 0);
        assert_eq!((t.tm_wday, t.tm_yday, t.tm_isdst), (4, 0, -1));

        // 2000-01-01 00:00:00 UTC = 946684800, a Saturday.
        let mut t = tm(0, 0, 0, 1, 0, 100);
        assert_eq!(call(&mut t), 946_684_800);
        assert_eq!(t.tm_wday, 6);

        // Firmware build date 2009-12-11 00:00:00 UTC = 1260489600, a Friday.
        let mut t = tm(0, 0, 0, 11, 11, 109);
        assert_eq!(call(&mut t), 1_260_489_600);
        assert_eq!(t.tm_wday, 5);
        assert_eq!(t.tm_yday, 344);

        // 2038 boundary: 2038-01-19 03:14:07 = i32::MAX ...
        let mut t = tm(7, 14, 3, 19, 0, 138);
        assert_eq!(call(&mut t), i32::MAX);
        assert_eq!(t.tm_wday, 2);
        // ... and one second later wraps to i32::MIN (mirrors the original).
        let mut t = tm(8, 14, 3, 19, 0, 138);
        assert_eq!(call(&mut t), i32::MIN);
    }

    #[test]
    fn normalization_cases() {
        // mon = 13 -> February of the next year.
        let mut t = tm(0, 0, 0, 1, 13, 109);
        let r = call(&mut t);
        assert_eq!((t.tm_year, t.tm_mon, t.tm_mday), (110, 1, 1));
        assert_eq!(r as u32, ref_mktime(&tm(0, 0, 0, 1, 1, 110)).unwrap().0.0);

        // mday = 0 -> last day of the previous month.
        let mut t = tm(0, 0, 0, 0, 2, 109);
        let r = call(&mut t);
        assert_eq!((t.tm_year, t.tm_mon, t.tm_mday), (109, 1, 28));
        assert_eq!(r as u32, ref_mktime(&tm(0, 0, 0, 28, 1, 109)).unwrap().0.0);

        // sec = -1 -> 59 seconds into the previous minute.
        let mut t = tm(-1, 30, 12, 15, 5, 100);
        let r = call(&mut t);
        assert_eq!((t.tm_hour, t.tm_min, t.tm_sec), (12, 29, 59));
        assert_eq!(r as u32, ref_mktime(&tm(59, 29, 12, 15, 5, 100)).unwrap().0.0);

        // A pile of out-of-range fields at once.
        assert_matches_ref(&tm(90, -5, 30, 35, 14, 109));
        assert_matches_ref(&tm(-1, -1, -1, 0, -1, 109));
        assert_matches_ref(&tm(0, 0, 0, 2000, 0, 100));
        assert_matches_ref(&tm(0, 0, 0, -2000, 0, 100));
    }

    #[test]
    fn leap_years() {
        // 2000 is leap (tm_year 100, 100 % 4 == 0): Feb 29 valid, Tuesday.
        let mut t = tm(0, 0, 0, 29, 1, 100);
        let r = call(&mut t);
        assert_ne!(r, -1);
        assert_eq!((t.tm_mon, t.tm_mday, t.tm_wday, t.tm_yday), (1, 29, 2, 59));

        // 2001 is not leap: Feb 29 rolls to Mar 1.
        let mut t = tm(0, 0, 0, 29, 1, 101);
        let r = call(&mut t);
        assert_ne!(r, -1);
        assert_eq!((t.tm_mon, t.tm_mday, t.tm_yday), (2, 1, 59));

        // 1900 is out of range entirely (year must be >= 70).
        let mut t = tm(0, 0, 0, 29, 1, 0);
        assert_eq!(call(&mut t), -1);

        // 2100 is treated as LEAP by the original (200 % 4 == 0) — Feb 29
        // 2100 is accepted. POSIX disagrees; we mirror the firmware.
        let mut t = tm(0, 0, 0, 29, 1, 200);
        let r = call(&mut t);
        assert_ne!(r, -1);
        assert_eq!((t.tm_mon, t.tm_mday), (1, 29));

        // 2104 Feb 29 — last quadrennial year fully in range.
        assert_matches_ref(&tm(0, 0, 0, 29, 1, 204));
    }

    #[test]
    fn range_errors() {
        // 1969-12-31 23:59:59 — one second before the epoch.
        let mut t = tm(59, 59, 23, 31, 11, 69);
        assert_eq!(call(&mut t), -1);

        // Beyond the unsigned 32-bit timestamp ceiling (2106-02-07 06:28:16).
        let mut t = tm(16, 28, 6, 7, 1, 206);
        assert_eq!(call(&mut t), -1);
        // ... while one second earlier is the largest representable
        // timestamp, 0xffffffff — returned as -1, yet a SUCCESS (fields are
        // written back). This ambiguity exists in the original.
        let mut t = tm(15, 28, 6, 7, 1, 206);
        assert_eq!(call(&mut t), -1);
        assert_eq!(t.tm_year, 206); // success: fields were written back

        // Absurd tm_year values are rejected before any normalization.
        for year in [0x4000_0001, i32::MAX, -0x4000_0001, i32::MIN] {
            let mut t = tm(0, 0, 0, 1, 0, year);
            assert_eq!(call(&mut t), -1, "year {year}");
        }

        // Error paths must not modify the caller's struct.
        let mut t = tm(1, 2, 3, 4, 5, 6);
        assert_eq!(call(&mut t), -1);
        assert_eq!(
            (t.tm_sec, t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon, t.tm_year, t.tm_wday, t.tm_yday,
             t.tm_isdst),
            (1, 2, 3, 4, 5, 6, 0, 0, 0)
        );
    }

    /// Exhaustive-ish sweep: every month of years 1970..2105, several days,
    /// several times of day, checked against the naive reference.
    #[test]
    fn reference_sweep() {
        for year in (70..=205).step_by(1) {
            for mon in 0..12 {
                for mday in [1, 10, 28] {
                    for (hour, min, sec) in [(0, 0, 0), (12, 34, 56), (23, 59, 59)] {
                        assert_matches_ref(&tm(sec, min, hour, mday, mon, year));
                    }
                }
            }
        }
        // Every day of February across leap and non-leap years.
        for year in [100, 101, 102, 103, 104, 200, 201, 204] {
            for mday in 1..=31 {
                assert_matches_ref(&tm(0, 0, 0, mday, 1, year));
            }
        }
        // Month-boundary mday spillover in both directions.
        for mon in 0..12 {
            assert_matches_ref(&tm(0, 0, 0, 0, mon, 109));
            assert_matches_ref(&tm(0, 0, 0, 33, mon, 109));
        }
    }
}
