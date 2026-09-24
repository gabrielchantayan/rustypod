//! `bdf_parse_i32` — original: `FUN_080f3c80` @ `0x080f3c80`.
//!
//! Raw osos.dec establishes a 188-byte extent, `0x080f3c80..0x080f3d3c`:
//! 172 bytes of instructions followed by four literal-pool words. The next
//! distinct function starts at `0x080f3d3c`. The function has no outbound
//! plain or predicated `bl` instructions; whole-image decoding finds three
//! inbound plain `bl` sites and no predicated ones.
//!
//! Algorithm: parse an optional leading `-`, select base 8, 10, or 16 (other
//! requested bases become 10), unconditionally recognize a `0x`/`0X` prefix,
//! then accumulate valid base digits with wrapping i32 arithmetic. A non-null
//! cursor output receives the first unparsed byte. Null or empty input returns zero
//! without touching that output. Deliberate deviations: none.

/// Parses the signed integer syntax used by the BDF font-property reader.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bdf_parse_i32(text: *const u8, end: *mut *const u8, base: i32) -> i32 {
    if text.is_null() || *text == 0 {
        return 0;
    }

    let negative = *text == b'-';
    let mut cursor = if negative { text.add(1) } else { text };
    let mut radix = match base {
        8 | 16 => base,
        _ => 10,
    };

    if *cursor == b'0' && (*cursor.add(1) == b'x' || *cursor.add(1) == b'X') {
        radix = 16;
        cursor = cursor.add(2);
    }

    let mut value = 0i32;
    while let Some(digit) = digit_in_radix(*cursor, radix) {
        value = value.wrapping_mul(radix).wrapping_add(digit);
        cursor = cursor.add(1);
    }

    if !end.is_null() {
        *end = cursor;
    }
    if negative { value.wrapping_neg() } else { value }
}

#[inline]
fn digit_in_radix(byte: u8, radix: i32) -> Option<i32> {
    let digit = match byte {
        b'0'..=b'9' => (byte - b'0') as i32,
        b'a'..=b'f' => (byte - b'a' + 10) as i32,
        b'A'..=b'F' => (byte - b'A' + 10) as i32,
        _ => return None,
    };
    (digit < radix).then_some(digit)
}

#[cfg(test)]
mod tests {
    use super::bdf_parse_i32;

    unsafe fn parse(input: &[u8], base: i32) -> (i32, usize) {
        let mut end = core::ptr::null();
        let value = bdf_parse_i32(input.as_ptr(), &mut end, base);
        (value, end.offset_from(input.as_ptr()) as usize)
    }

    #[test]
    fn selects_only_the_three_firmware_radices() {
        unsafe {
            assert_eq!(parse(b"77z\0", 8), (63, 2));
            assert_eq!(parse(b"1f\0", 16), (31, 2));
            assert_eq!(parse(b"19x\0", 2), (19, 2));
            assert_eq!(parse(b"19x\0", 0), (19, 2));
        }
    }

    #[test]
    fn prefix_overrides_requested_base_and_sign_wraps() {
        unsafe {
            assert_eq!(parse(b"0Xf!\0", 8), (15, 3));
            assert_eq!(parse(b"-0x80000000?\0", 10), (i32::MIN, 11));
            assert_eq!(parse(b"-12x\0", 10), (-12, 3));
        }
    }

    #[test]
    fn retains_firmware_null_and_empty_input_behavior() {
        unsafe {
            let mut untouched = b"sentinel\0".as_ptr();
            assert_eq!(bdf_parse_i32(core::ptr::null(), &mut untouched, 10), 0);
            assert_eq!(bdf_parse_i32(b"\0".as_ptr(), &mut untouched, 10), 0);
            assert_eq!(untouched, b"sentinel\0".as_ptr());
            assert_eq!(parse(b"0x\0", 10), (0, 2));
        }
    }
}
