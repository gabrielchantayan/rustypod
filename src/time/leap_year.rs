//! Proleptic-Gregorian leap-year test: `FUN_080aabac` @ 0x080aabac
//! (52 bytes, 0x080aabac..0x080aabe0).
//!
//! Nine `bl` call sites in osos.asm: @ 0x08076090 in FUN_08076074
//! (`datetime_days_in_month`, ported in `time/month_length.rs`), @
//! 0x0807ebb4 in FUN_0807eafc, @ 0x08086e10 in FUN_08086e00, @
//! 0x080d6d40 in FUN_080d6d1c, @ 0x080ff55c / 0x080ff5e8 / 0x080ff788
//! in FUN_080ff4e4, @ 0x08158bec in FUN_08158ba0, and @ 0x08271338 in
//! FUN_082710e0. Three of the callers (FUN_080d6d1c, FUN_080ff4e4,
//! FUN_08158ba0) are the calendar helpers that share the days-in-month
//! table literal with `datetime_days_in_month` (see its module header).
//! The best-known callers hand in the `ldrh` year field of the packed
//! `DateTime` record (0..=0xffff), but the register-level signature is
//! a full 32-bit unsigned year.
//!
//! # Algorithm
//!
//! Leap iff `year % 4 == 0` AND `year % 400` is not one of the three
//! non-leap century residues — a century year is common unless it is a
//! 400-year (2000 and 1600 leap; 1900, 2100 common):
//!
//! ```arm
//! stmdb sp!, {r4, lr}
//! mov  r4, r0             ; year
//! mov  r1, #0x190         ; 400
//! bl   0x08036f14         ; __rt_udiv: r1 = year % 400 (unconditional)
//! tst  r4, #0x3
//! bne  -> return 0        ; not divisible by 4
//! cmp  r1, #0x64          ; 100
//! cmpne r1, #0xc8         ; 200
//! cmpne r1, #0x12c        ; 300
//! movne r0, #0x1          ; leap iff year % 400 not in {100, 200, 300}
//! ```
//!
//! Returns 1 for leap, 0 for common. Year 0 is leap (0 % 4 == 0 and
//! 0 % 400 == 0); the unsigned `% 400` bounds every residue to
//! 0..=399, so the residue compares are sign-agnostic and "negative"
//! years are simply large unsigned values.
//!
//! The divide is unconditional in the original (the `bl` precedes the
//! `tst`), and the remainder is the r1 output of `__rt_udiv` @
//! 0x08036f14 — reached here through the ported `__rt_udivmod` wrapper
//! (`runtime/rt_div.rs`, the btree_parse_cell_ptr precedent), which
//! keeps the `bl` call boundary for match.py.

use crate::runtime::rt_div::__rt_udivmod;

/// is_leap_year — original: `FUN_080aabac` @ 0x080aabac (52 bytes;
/// 9 `bl` call sites, module header).
///
/// Returns 1 if `year` is a leap year under the proleptic Gregorian
/// rule, 0 otherwise: `year % 4 == 0` and `year % 400` not in
/// {100, 200, 300}. The divide runs before the divisibility-by-4
/// short-circuit exactly as in the original.
// `#[inline(never)]`: the one intra-crate caller (the IS_LEAP_YEAR
// seam default in `time/month_length.rs`) keeps the original's `bl`
// call boundary for match.py review (the __rt_udiv precedent).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn is_leap_year(year: u32) -> i32 {
    let mut residue: u32 = 0;
    __rt_udivmod(year, 400, &mut residue);
    if year & 3 != 0 {
        return 0;
    }
    if residue != 100 && residue != 200 && residue != 300 {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Textbook Gregorian reference, formulated independently of the
    /// port's three-residue test: leap iff divisible by 4, except
    /// century years that are not 400-years.
    fn reference_leap(year: u32) -> i32 {
        if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            1
        } else {
            0
        }
    }

    /// The divisibility-by-4 gate (`tst r4, #0x3`): any year with a
    /// nonzero low two bits is common, whatever its % 400 residue.
    #[test]
    fn not_divisible_by_4_is_common() {
        for year in [1u32, 2, 3, 1901, 2001, 2002, 2003, 0xffff] {
            assert_eq!(unsafe { is_leap_year(year) }, 0, "year {year}");
        }
    }

    /// Divisible by 4 with a % 400 residue outside {100, 200, 300}
    /// is leap — the `movne r0, #0x1` path.
    #[test]
    fn ordinary_leap_years() {
        for year in [4u32, 1996, 2004, 2024, 2096] {
            assert_eq!(unsafe { is_leap_year(year) }, 1, "year {year}");
        }
    }

    /// Century years with % 400 residues 100, 200, 300 are common —
    /// the three `cmp`/`cmpne` filters.
    #[test]
    fn century_residues_are_common() {
        for year in [1700u32, 1800, 1900, 2100, 2200, 2300, 2500, 2600] {
            assert_eq!(unsafe { is_leap_year(year) }, 0, "year {year}");
        }
    }

    /// 400-year centuries (residue 0) stay leap.
    #[test]
    fn four_century_years_are_leap() {
        for year in [400u32, 1200, 1600, 2000, 2400] {
            assert_eq!(unsafe { is_leap_year(year) }, 1, "year {year}");
        }
    }

    /// Year zero as the ARM computes it: 0 & 3 == 0 and 0 % 400 == 0,
    /// so leap.
    #[test]
    fn year_zero_is_leap() {
        assert_eq!(unsafe { is_leap_year(0) }, 1);
    }

    /// The register-level input is an unsigned 32-bit year: values with
    /// the sign bit set are just large years. u32::MAX fails the
    /// div-by-4 gate; u32::MAX - 3 has residue 92 (leap); the largest
    /// residue-100 year 0xfffffe74 = 400*10737417 + 100 is common.
    #[test]
    fn large_unsigned_years() {
        assert_eq!(unsafe { is_leap_year(u32::MAX) }, 0);
        assert_eq!(unsafe { is_leap_year(u32::MAX - 3) }, 1);
        assert_eq!(unsafe { is_leap_year(0xfffffe74) }, 0);
    }

    /// Every representable DateTime year, plus a wide stride over the
    /// full u32 range, against the independent textbook formulation.
    #[test]
    fn exhaustive_against_reference() {
        for year in 0..=0xffffu32 {
            assert_eq!(
                unsafe { is_leap_year(year) },
                reference_leap(year),
                "year {year}"
            );
        }
        let mut year = 0x1_0000u32;
        while year <= u32::MAX - 999_983 {
            assert_eq!(
                unsafe { is_leap_year(year) },
                reference_leap(year),
                "year {year}"
            );
            year += 999_983; // odd stride, coprime with 400
        }
    }
}
