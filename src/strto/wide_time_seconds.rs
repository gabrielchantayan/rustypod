//! parse_wide_time_seconds — `FUN_0820fd6c` @ 0x0820fd6c, 188 bytes.
//!
//! Raw extent ends at the next prologue, 0x0820fe28. Verified outgoing calls:
//! three plain BLs to parse_wide_decimal_counted, zero predicated BLs; two
//! incoming BLs. Read an optional sign, then up to three two-unit unchecked
//! decimal fields, and return sign * (hours * 3600 + minutes * 60 + seconds)
//! with wrapping word arithmetic. Only each field's starting cursor is checked
//! against the end; odd ranges deliberately read one code unit beyond it.
//!
//! Deliberate ABI clarification: a repr(C) pair of native pointers represents
//! the original two ARM pointer words, widening naturally on the host. No
//! validation or clamping is added, and the caller's range is not advanced.

use super::wide_decimal_counted::parse_wide_decimal_counted;

#[repr(C)]
pub struct WideTimeRange {
    pub start: *const u16,
    pub end: *const u16,
}

/// # Safety
/// `range` must be readable. Its start must be readable even for an empty
/// range. Every started two-unit field must have both units readable, including
/// padding past an odd end; an initial sign must permit advancing one unit.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_wide_time_seconds(range: *const WideTimeRange) -> i32 {
    let mut cursor = (*range).start;
    let first = cursor.read();
    let negative = first == b'-' as u16;
    if negative || first == b'+' as u16 {
        cursor = cursor.add(1);
    }
    let hours = if (cursor as usize) < ((*range).end as usize) {
        parse_wide_decimal_counted(&mut cursor, 2)
    } else { 0 };
    let minutes = if (cursor as usize) < ((*range).end as usize) {
        parse_wide_decimal_counted(&mut cursor, 2)
    } else { 0 };
    let seconds = if (cursor as usize) < ((*range).end as usize) {
        parse_wide_decimal_counted(&mut cursor, 2)
    } else { 0 };
    let value = hours.wrapping_mul(3600)
        .wrapping_add(minutes.wrapping_mul(60)).wrapping_add(seconds);
    if negative { value.wrapping_neg() as i32 } else { value as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(input: &[u16], length: usize) {
        let range = WideTimeRange { start: input.as_ptr(), end: unsafe { input.as_ptr().add(length) } };
        let mut offset = usize::from(input[0] == b'-' as u16 || input[0] == b'+' as u16);
        let mut expected = 0u32;
        for weight in [3600u32, 60, 1] {
            if offset < length {
                let field = (input[offset] as u32).wrapping_sub(48).wrapping_mul(10)
                    .wrapping_add(input[offset + 1] as u32).wrapping_sub(48);
                expected = expected.wrapping_add(field.wrapping_mul(weight));
                offset += 2;
            }
        }
        if input[0] == b'-' as u16 { expected = expected.wrapping_neg(); }
        assert_eq!(unsafe { parse_wide_time_seconds(&range) }, expected as i32);
        assert_eq!(range.start, input.as_ptr());
        assert_eq!(range.end, unsafe { input.as_ptr().add(length) });
    }

    #[test]
    fn signs_partial_fields_and_ignored_suffix() {
        for input in [
            [49, 50, 51, 52, 53, 54, 57, 57],
            [43, 49, 50, 51, 52, 53, 54, 57],
            [45, 49, 50, 51, 52, 53, 54, 57],
        ] {
            for length in 0..=input.len() { check(&input, length); }
        }
        let input = [49, 50, 51, 52, 53, 54];
        let range = WideTimeRange { start: input.as_ptr(), end: unsafe { input.as_ptr().add(6) } };
        assert_eq!(unsafe { parse_wide_time_seconds(&range) }, 45296);
    }

    #[test]
    fn unchecked_units_and_wrapping_signed_result() {
        for input in [
            [0, 47, 58, 65535, 0, 65535, 0, 0],
            [45, 65535, 65535, 65535, 65535, 65535, 65535, 0],
            [65535; 8],
        ] {
            for length in 0..=input.len() { check(&input, length); }
        }
    }

    #[test]
    fn reversed_range_returns_zero_after_initial_read() {
        let input = [49, 50, 51];
        let range = WideTimeRange { start: unsafe { input.as_ptr().add(2) }, end: input.as_ptr() };
        assert_eq!(unsafe { parse_wide_time_seconds(&range) }, 0);
    }
}
