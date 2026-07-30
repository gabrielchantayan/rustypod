//! BCD datetime block -> (days, seconds-of-day): the Hinnant
//! civil-to-days converter shared by every wall-clock consumer.
//!
//! Original: `FUN_0809e3e8` @ 0x0809e3e8 (228 bytes, excluding the 365
//! literal pool word @ 0x0809e4cc; 5 `bl` call sites: @ 0x08056174 in
//! rtc_read_time, @ 0x080641f0 in FUN_0806418c, and @ 0x0806e850 /
//! 0x0806e8a4 / 0x0806e8b0 in FUN_0806e7e4).
//!
//! Algorithm (mirrored from the disassembly): `buf` is the 7-byte RTC
//! register image (sec, min, hour, weekday, day, month, year; weekday
//! is ignored). Each field goes through the BCD decode FUN_080ed424
//! (`v - 6*(v>>4)` for `v < 0x9a`, else 99 — reproduced inline as
//! [`bcd_to_bin`]; the month byte is decoded TWICE, once for the year
//! adjustment and once for the month pipeline). The day count is
//! Hinnant's days_from_civil over the 2-digit year:
//! `adj = (14 - month) / 12` — an UNSIGNED `__rt_udiv` @ 0x08036f14,
//! so a month above 14 wraps the subtraction to a huge quotient;
//! `y = year - adj + 0x1a90` (0x1a90 = 6800, a multiple of 400, so the
//! 2-digit year's leap pattern is undisturbed); `mp = month + 12*adj -
//! 3`; `days = 365*y + day + (153*mp + 2)/5 + y/4 - y/100 + y/400 -
//! 0x7d2d` (365 via `mla` from the pool literal; the /5, /100, /400
//! are signed truncating `__rt_sdiv` @ 0x08031568; the /4 is the
//! compiler's add-3-and-asr truncating idiom, which LLVM emits for a
//! native i32 divide-by-4). Seconds-of-day is `hour*0xe10 + min*60 +
//! sec` (the *60 strength-reduced to `(min*15) << 2` in the original).
//! Both results are stored through the out-pair (days at [0], seconds
//! at [1]); the function returns void.
//!
//! The port calls the ported `__rt_udiv`/`__rt_sdiv`
//! (runtime/rt_div.rs, `#[inline(never)]`) so the original's `bl`
//! boundaries survive for match.py review; all adds/multiplies wrap to
//! match ARM flag-less arithmetic. The inline `bcd_to_bin` stands in
//! for the unported FUN_080ed424 and is likewise kept out-of-line so
//! the seven decode calls remain visible.

/// BCD byte to binary: `v - 6*(v>>4)` for `v < 0x9a`, else clamped to
/// 99 (stock FUN_080ed424 @ 0x080ed424, reproduced inline — that
/// function is not yet ported in its own right).
#[inline(never)]
pub(crate) fn bcd_to_bin(v: u8) -> i32 {
    if (v as u32) < 0x9a {
        (v as i32).wrapping_sub(6 * (v as i32 >> 4))
    } else {
        99
    }
}

/// bcd_datetime_to_days_secs @ 0x0809e3e8 — convert a 7-byte BCD
/// datetime block (sec, min, hour, weekday, day, month, year) into a
/// day count and a seconds-of-day count, stored to `out[0]` / `out[1]`.
/// All arithmetic wraps like the ARM original; the divisions carry the
/// exact signed/unsigned flavor of the original's __rt_sdiv/__rt_udiv
/// calls.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bcd_datetime_to_days_secs(out: *mut i32, buf: *const u8) {
    let month = bcd_to_bin(*buf.add(5));
    // Jan/Feb year adjustment — UNSIGNED divide in the original, so a
    // month above 14 wraps the subtraction to a huge quotient.
    let adj = crate::runtime::rt_div::__rt_udiv(14u32.wrapping_sub(month as u32), 12) as i32;
    let year = bcd_to_bin(*buf.add(6))
        .wrapping_sub(adj)
        .wrapping_add(0x1a90);
    // The original decodes the month byte a second time here.
    let month = bcd_to_bin(*buf.add(5));
    let mp = month
        .wrapping_add(adj.wrapping_mul(12))
        .wrapping_sub(3);
    let day = bcd_to_bin(*buf.add(4));
    let month_days = crate::runtime::rt_div::__rt_sdiv(mp.wrapping_mul(0x99).wrapping_add(2), 5);
    let days = 365i32
        .wrapping_mul(year)
        .wrapping_add(day.wrapping_add(month_days))
        // Native i32 divide-by-4: LLVM emits the original's
        // add-3-and-asr truncating idiom.
        .wrapping_add(year / 4)
        .wrapping_sub(crate::runtime::rt_div::__rt_sdiv(year, 100))
        .wrapping_add(crate::runtime::rt_div::__rt_sdiv(year, 400))
        .wrapping_sub(0x7d2d);
    *out = days;
    let secs = bcd_to_bin(*buf.add(2))
        .wrapping_mul(0xe10)
        .wrapping_add(bcd_to_bin(*buf.add(1)).wrapping_mul(60))
        .wrapping_add(bcd_to_bin(*buf.add(0)));
    *out.add(1) = secs;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(buf: &[u8; 8]) -> (i32, i32) {
        let mut pair = [0i32; 2];
        unsafe { bcd_datetime_to_days_secs(pair.as_mut_ptr(), buf.as_ptr()) };
        (pair[0], pair[1])
    }

    fn to_bcd(v: i32) -> u8 {
        (((v / 10) << 4) | (v % 10)) as u8
    }

    fn regs(y: i32, m: i32, d: i32) -> [u8; 8] {
        [0, 0, 0, 0, to_bcd(d), to_bcd(m), to_bcd(y), 0]
    }

    /// Naive proleptic-Gregorian day counter over the 2-digit RTC year,
    /// days since 0000-03-01 (the Hinnant epoch), computed by loops.
    fn is_leap(y: i32) -> bool {
        y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
    }

    fn ref_days_since_mar1_year0(y: i32, m: i32, d: i32) -> i32 {
        let yy = if m <= 2 { y - 1 } else { y };
        let mp = if m <= 2 { m + 9 } else { m - 3 };
        const MLEN: [i32; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 28];
        let mut days = d - 1;
        for len in MLEN.iter().take(mp as usize) {
            days += len;
        }
        if yy >= 0 {
            for year in 0..yy {
                days += if is_leap(year + 1) { 366 } else { 365 };
            }
        } else {
            for year in yy..0 {
                days -= if is_leap(year + 1) { 366 } else { 365 };
            }
        }
        days
    }

    /// Offset between the port's day count and the naive reference,
    /// from the formula at 0000-03-01:
    /// 365*6800 + 1 + 0 + 1700 - 68 + 17 - 32045 = 2451605.
    const EPOCH_OFFSET: i32 = 2451605;

    fn check_date(y: i32, m: i32, d: i32) {
        let (days, secs) = convert(&regs(y, m, d));
        assert_eq!(secs, 0);
        assert_eq!(
            days,
            ref_days_since_mar1_year0(y, m, d) + EPOCH_OFFSET,
            "day count mismatch for {y:02}-{m:02}-{d:02}"
        );
    }

    #[test]
    fn epoch_boundary() {
        // The Hinnant epoch itself: 0000-03-01 -> EPOCH_OFFSET.
        check_date(0, 3, 1);
        // One day either side of it.
        check_date(0, 3, 2);
        check_date(0, 2, 28);
    }

    #[test]
    fn jan_feb_year_adjustment() {
        // Jan/Feb belong to the previous March-year: Dec 31 -> Jan 1
        // is a single day step, as is Jan 31 -> Feb 1.
        let (dec31, _) = convert(&regs(24, 12, 31));
        let (jan1, _) = convert(&regs(25, 1, 1));
        assert_eq!(jan1 - dec31, 1);
        let (jan31, _) = convert(&regs(24, 1, 31));
        let (feb1, _) = convert(&regs(24, 2, 1));
        assert_eq!(feb1 - jan31, 1);
        // Exhaustive spot-check against the naive reference across the
        // adjustment boundary.
        for &(y, m, d) in &[
            (0, 1, 1),
            (0, 2, 1),
            (24, 1, 1),
            (24, 2, 28),
            (24, 3, 1),
            (99, 1, 1),
            (99, 2, 28),
        ] {
            check_date(y, m, d);
        }
    }

    #[test]
    fn leap_centuries() {
        // The 0x1a90 = 6800 bias is a multiple of 400, so 2-digit year
        // 0 lands on a 400-leap century: year 0 IS leap.
        let (feb28, _) = convert(&regs(0, 2, 28));
        let (feb29, _) = convert(&regs(0, 2, 29));
        let (mar1, _) = convert(&regs(0, 3, 1));
        assert_eq!(feb29 - feb28, 1);
        assert_eq!(mar1 - feb29, 1);
        // Year 24 is an ordinary 4-leap.
        let (feb28, _) = convert(&regs(24, 2, 28));
        let (mar1, _) = convert(&regs(24, 3, 1));
        assert_eq!(mar1 - feb28, 2);
        // Year 23 is not leap.
        let (feb28, _) = convert(&regs(23, 2, 28));
        let (mar1, _) = convert(&regs(23, 3, 1));
        assert_eq!(mar1 - feb28, 1);
    }

    #[test]
    fn two_digit_year_bias() {
        // The 2-digit year is biased by 6800, NOT 2000: identical
        // month/day in years 24 and 25 is exactly 365 days apart (no
        // leap day inside the span), while a span containing Feb 29 of
        // leap year 24 is 366.
        let (a, _) = convert(&regs(24, 6, 15));
        let (b, _) = convert(&regs(25, 6, 15));
        assert_eq!(b - a, 365);
        let (a, _) = convert(&regs(23, 3, 1));
        let (b, _) = convert(&regs(24, 3, 1));
        assert_eq!(b - a, 366); // Feb 29 of leap year 24 is inside
        // The full 2-digit range stays positive and ordered.
        check_date(0, 1, 1);
        check_date(99, 12, 31);
        check_date(70, 1, 1);
        check_date(24, 12, 31);
    }

    #[test]
    fn seconds_of_day() {
        let (_, secs) = convert(&[0x58, 0x59, 0x23, 0x04, 0x29, 0x02, 0x24, 0]);
        assert_eq!(secs, 23 * 3600 + 59 * 60 + 58);
        let (_, secs) = convert(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x24, 0]);
        assert_eq!(secs, 0);
        // Weekday byte (buf[3]) is ignored.
        let (da, sa) = convert(&[0x30, 0x15, 0x10, 0x00, 0x15, 0x06, 0x24, 0]);
        let (db, sb) = convert(&[0x30, 0x15, 0x10, 0x06, 0x15, 0x06, 0x24, 0]);
        assert_eq!((da, sa), (db, sb));
    }

    #[test]
    fn bcd_clamp() {
        assert_eq!(bcd_to_bin(0x99), 99);
        assert_eq!(bcd_to_bin(0x9a), 99);
        assert_eq!(bcd_to_bin(0xff), 99);
        assert_eq!(bcd_to_bin(0x59), 59);
    }

    #[test]
    fn wild_bcd_does_not_panic() {
        // Months above 14 wrap the unsigned (14 - month) / 12 into a
        // huge quotient; all arithmetic must wrap, not trip debug
        // overflow checks.
        for m in [0x00u8, 0x13, 0x32, 0x99, 0x9a, 0xff] {
            let buf = [0xff, 0xff, 0xff, 0xff, 0xff, m, 0xff, 0xff];
            let _ = convert(&buf);
        }
    }
}
