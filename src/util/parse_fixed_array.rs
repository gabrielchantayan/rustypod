//! Fixed-number array parsing from the retail text/font parser.
//!
//! Original `FUN_08091434` @ `0x08091434`, 208 bytes, ending at the
//! next function at `0x08091504`. Whole-image A32 decoding verifies two
//! inbound plain BLs (0x080b81cc, 0x080d47cc), zero predicated BLs;
//! two outbound plain BLs and zero predicated BLs.
//! Accepts an optional '[' or '{', skips whitespace/comments before each
//! value, and parses at most capacity 16.16 numbers with a decimal exponent.
//! Unbracketed input produces at most one value. Retail compares the INITIAL
//! byte against the closing delimiter, not the current byte: preserve this
//! bug, including repeated parses without progress until capacity is reached.
//! An initial NUL equals the unbracketed zero delimiter after skipping.
//! Deliberate deviations: call the existing Rust whitespace skipper; retain
//! the verified decimal parser at 0x0808e2e8 via a typed seam. Host callers
//! can supply that seam explicitly; the firmware entry is unavailable on hosts.

use super::skip_ascii_whitespace_and_comments::skip_ascii_whitespace_and_comments;

/// Verified retail decimal-to-16.16 parser ABI, with decimal exponent in r2.
pub type ParseDecimalFixed = unsafe extern "C" fn(*mut *mut u8, *const u8, i32) -> i32;

/// # Safety
/// `cursor` is writable and points into a readable range ending at `end`.
/// `values` holds at least max(capacity, 0) writable words. The input must
/// satisfy the retail decimal parser's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_fixed_array(
    cursor: *mut *mut u8, end: *const u8, capacity: i32,
    values: *mut i32, exponent: i32,
) -> i32 {
    #[cfg(target_os = "none")]
    let parse: ParseDecimalFixed = core::mem::transmute(0x0808_e2e8usize);
    #[cfg(not(target_os = "none"))]
    let parse: ParseDecimalFixed = missing_decimal_parser;
    parse_fixed_array_with(cursor, end, capacity, values, exponent, parse)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decimal_parser(_: *mut *mut u8, _: *const u8, _: i32) -> i32 {
    panic!("parse_fixed_array requires the retail decimal parser seam on hosts")
}

/// Same safety contract as `parse_fixed_array`; `parse` must implement the
/// verified decimal parser ABI and preserve a valid cursor for subsequent scans.
pub unsafe fn parse_fixed_array_with(
    cursor: *mut *mut u8, end: *const u8, capacity: i32,
    values: *mut i32, exponent: i32, parse: ParseDecimalFixed,
) -> i32 {
    let mut current = cursor.read();
    let mut count = 0;
    if (current as usize) < end as usize {
        let initial = current.read();
        let closing = match initial { b'[' => b']', b'{' => b'}', _ => 0 };
        if closing != 0 { current = current.add(1); }
        while (current as usize) < end as usize {
            skip_ascii_whitespace_and_comments(&mut current, end);
            if current as usize >= end as usize || count >= capacity { break; }
            if initial == closing {
                current = current.add(1);
                break;
            }
            values.add(count as usize).write(parse(&mut current, end, exponent));
            count += 1;
            if closing == 0 { break; }
        }
    }
    cursor.write(current);
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    // Restricted independent reference for integer tokens. A nondigit leaves
    // the cursor unchanged, as the real decimal parser does for ']' and '}'.
    unsafe extern "C" fn integer_fixed(cursor: *mut *mut u8, end: *const u8, exponent: i32) -> i32 {
        let mut p = cursor.read();
        let mut value = 0i32;
        while (p as usize) < end as usize && p.read().is_ascii_digit() {
            value = value * 10 + (p.read() - b'0') as i32;
            p = p.add(1);
        }
        cursor.write(p);
        for _ in 0..exponent { value *= 10; }
        value << 16
    }

    #[test]
    fn bounded_arrays_and_retail_delimiter_bug() {
        for (input, capacity, exponent, expected, offset) in [
            (&b"[1 2]"[..], 4, 0, & [65536, 131072, 0, 0][..], 4),
            (&b"{3}"[..], 2, 1, & [1966080, 0][..], 2),
            (&b"7 8"[..], 4, 0, & [458752][..], 1),
            (&b"[ 1 2]"[..], 1, 0, & [65536][..], 4),
            (&b"[ %x\n 9]"[..], 0, 0, & [][..], 6),
            (&b"[ 1]"[..], -1, 0, & [][..], 2),
            (&b"[ \t"[..], 3, 0, & [][..], 3),
            (&b""[..], 3, 0, & [][..], 0),
            (&b"\0 X!"[..], 3, 0, & [][..], 3),
        ] {
            let mut bytes = input.to_vec();
            let base = bytes.as_mut_ptr();
            let mut cursor = base;
            let mut values = [0x12345678; 5];
            let count = unsafe {
                parse_fixed_array_with(&mut cursor, base.add(bytes.len()), capacity,
                    values.as_mut_ptr(), exponent, integer_fixed)
            };
            assert_eq!(count as usize, expected.len(), "{input:?}");
            assert_eq!(&values[..expected.len()], expected, "{input:?}");
            assert_eq!(values[expected.len()], 0x12345678);
            assert_eq!(cursor as usize - base as usize, offset, "{input:?}");
        }
    }

    #[test]
    fn exported_entry_empty_range_requires_no_decimal_parser() {
        let mut bytes = [b'9'];
        let mut cursor = bytes.as_mut_ptr();
        let count = unsafe { parse_fixed_array(&mut cursor, bytes.as_ptr(), 1, core::ptr::null_mut(), 0) };
        assert_eq!(count, 0);
        assert_eq!(cursor, bytes.as_mut_ptr());
    }
}
