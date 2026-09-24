//! Convert a zero-based ordinal day to packed month/day fields: `FUN_080d7038`
//! @ `0x080d7038`.
//!
//! # Verified extent and calls
//!
//! Raw `osos.dec` has a 108-byte executable body
//! (`0x080d7038..0x080d70a4`), then its one-word table-pointer literal at
//! `0x080d70a4`; `0x080d70a8` begins the next independently entered function.
//! Thus the complete function extent is 112 bytes. The body has one plain
//! direct `bl` (to `FUN_08074410`) and no predicated `bl` instructions. A full
//! A32 caller scan finds two plain direct callers (`0x0803be80`, `0x080d5f9c`)
//! and one predicated direct caller (`bleq` at `0x080674ac`).
//!
//! # Algorithm
//!
//! It walks the runtime days-in-month table `[31, 29, 31, ...]` using the
//! record's zero-based ordinal day. For a common year it consumes 28 rather
//! than the table's 29-day February, then writes one-based month and day.
//!
//! # Deliberate deviations
//!
//! The table lives in scatterloaded RAM at `0x089caaa0`, outside `osos.dec`,
//! so this port uses its recovered immutable contents. `FUN_08074410` has no
//! names.yaml entry; its decoded `% 100` / low-two-bit predicate is exactly
//! the existing proleptic-Gregorian `is_leap_year` port, which is called here
//! instead of creating an unverified seam for that address.

use super::leap_year::is_leap_year;

const DAYS_IN_MONTH: [u8; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Target-layout calendar scratch record used by `FUN_080d7038`.
///
/// The input year and ordinal day remain untouched; only `month` and `day`
/// are written.
#[repr(C)]
pub struct OrdinalDayRecord {
    /// +0x00: proleptic-Gregorian year.
    pub year: u16,
    /// +0x02: output one-based month.
    pub month: u8,
    /// +0x03: output one-based day of month.
    pub day: u8,
    /// +0x04: input zero-based ordinal day.
    pub ordinal_day: u16,
}

const _: () = assert!(core::mem::size_of::<OrdinalDayRecord>() == 6);
const _: () = assert!(core::mem::offset_of!(OrdinalDayRecord, ordinal_day) == 4);

/// ordinal_day_to_month_day — original: `FUN_080d7038` @ `0x080d7038`
/// (**108-byte executable body; 112 bytes including its literal pool; one
/// plain direct `bl`, no predicated `bl` — module header**).
///
/// Converts `record.ordinal_day` from a zero-based day-of-year to one-based
/// `record.month` and `record.day`, using the record's u16 year for February.
///
/// # Safety
///
/// `record` must point to writable [`OrdinalDayRecord`] storage. As in the
/// retail routine, callers must supply an ordinal day valid for its year.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ordinal_day_to_month_day(record: *mut OrdinalDayRecord) {
    let mut remaining_days = (*record).ordinal_day as u32;
    let mut month_index = 0usize;
    let leap = is_leap_year((*record).year as u32);
    let days_in_month = DAYS_IN_MONTH.as_ptr();

    while days_in_month.add(month_index).read() as u32 <= remaining_days {
        if month_index == 1 && leap == 0 {
            month_index = 2;
            remaining_days -= 28;
        } else {
            remaining_days -= days_in_month.add(month_index).read() as u32;
            month_index += 1;
        }
    }

    if month_index == 1 && leap == 0 && remaining_days == 28 {
        month_index = 2;
        remaining_days = 0;
    }

    (*record).month = (month_index + 1) as u8;
    (*record).day = (remaining_days + 1) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(year: u16, ordinal_day: u16) -> (u8, u8) {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let mut remaining = ordinal_day as u32;
        for (index, &days) in DAYS_IN_MONTH.iter().enumerate() {
            let days = if index == 1 && !leap { 28 } else { days };
            if remaining < days as u32 {
                return ((index + 1) as u8, (remaining + 1) as u8);
            }
            remaining -= days as u32;
        }
        unreachable!("test inputs are valid ordinal days")
    }

    #[test]
    fn converts_calendar_boundaries_for_common_and_leap_years() {
        for (year, ordinal_day) in [
            (1900, 0),
            (1900, 30),
            (1900, 31),
            (1900, 58),
            (1900, 59),
            (1900, 364),
            (2000, 59),
            (2000, 60),
            (2000, 365),
            (2024, 59),
            (2024, 60),
            (2024, 365),
        ] {
            let mut record = OrdinalDayRecord { year, month: 0xaa, day: 0xbb, ordinal_day };
            unsafe { ordinal_day_to_month_day(&mut record) };
            assert_eq!((record.month, record.day), reference(year, ordinal_day), "{year} day {ordinal_day}");
            assert_eq!((record.year, record.ordinal_day), (year, ordinal_day));
        }
    }
}
