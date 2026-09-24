//! Clock-record ordering: `FUN_0808cde4` @ `0x0808cde4`.
//!
//! # Verified original
//!
//! The true extent is **120 bytes**, `0x0808cde4..0x0808ce5c`: raw
//! `osos.dec` words end with `ldr pc,[sp],#4` at `0x0808ce58`, and the
//! `stmdb sp!,{r4,lr}` at `0x0808ce5c` begins the next function. Full A32
//! decoding finds three unconditional direct `bl` callers (`0x08044a80`,
//! `0x080caa5c`, and `0x080e1d58`) and no predicated direct `bl` callers.
//! The leaf body has no direct calls.
//!
//! # Algorithm
//!
//! Compare clock records lexicographically by the 32-bit date key formed from
//! little-endian halfwords at offsets 0 and 4, then by the 24-bit time key at
//! offsets 8, 9, and 10. Return -1, 0, or 1.
//!
//! # Deliberate deviations
//!
//! None. The caller-facing record pointers are halfword-aligned, matching the
//! original `ldrh` accesses.

use core::ptr;

/// compare_clock_records — original: `FUN_0808cde4` @ `0x0808cde4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn compare_clock_records(left: *const u8, right: *const u8) -> i32 {
    let left_date = (ptr::read(left.cast::<u16>()) as u32) << 16 | ptr::read(left.add(4).cast::<u16>()) as u32;
    let right_date = (ptr::read(right.cast::<u16>()) as u32) << 16 | ptr::read(right.add(4).cast::<u16>()) as u32;
    if left_date != right_date { return if left_date < right_date { -1 } else { 1 }; }

    let left_time = (ptr::read(left.add(8)) as u32) << 16 | (ptr::read(left.add(9)) as u32) << 8 | ptr::read(left.add(10)) as u32;
    let right_time = (ptr::read(right.add(8)) as u32) << 16 | (ptr::read(right.add(9)) as u32) << 8 | ptr::read(right.add(10)) as u32;
    if left_time < right_time { -1 } else if left_time > right_time { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(2))]
    struct Record([u8; 11]);

    fn record(date_high: u16, date_low: u16, hour: u8, minute: u8, second: u8) -> Record {
        let mut record = Record([0; 11]);
        record.0[0..2].copy_from_slice(&date_high.to_le_bytes());
        record.0[4..6].copy_from_slice(&date_low.to_le_bytes());
        record.0[8..11].copy_from_slice(&[hour, minute, second]);
        record
    }

    #[test]
    fn compares_date_before_time() {
        let earlier_date = record(2024, 0x1234, 23, 59, 59);
        let later_date = record(2025, 0, 0, 0, 0);
        unsafe { assert_eq!(compare_clock_records(earlier_date.0.as_ptr(), later_date.0.as_ptr()), -1); }
    }

    #[test]
    fn compares_time_when_date_keys_match() {
        let earlier = record(2025, 0x1234, 12, 34, 55);
        let later = record(2025, 0x1234, 12, 34, 56);
        unsafe {
            assert_eq!(compare_clock_records(earlier.0.as_ptr(), later.0.as_ptr()), -1);
            assert_eq!(compare_clock_records(later.0.as_ptr(), earlier.0.as_ptr()), 1);
        }
    }

    #[test]
    fn ignores_uncompared_record_bytes_and_returns_zero_for_equal_keys() {
        let mut left = record(2025, 0x1234, 1, 2, 3);
        let mut right = record(2025, 0x1234, 1, 2, 3);
        left.0[2] = 0xaa;
        left.0[3] = 0xbb;
        left.0[6] = 0xcc;
        right.0[2] = 0x11;
        right.0[3] = 0x22;
        right.0[6] = 0x33;
        unsafe { assert_eq!(compare_clock_records(left.0.as_ptr(), right.0.as_ptr()), 0); }
    }
}
