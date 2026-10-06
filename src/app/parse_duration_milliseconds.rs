//! Parse colon-separated duration fields into milliseconds.
//!
//! `parse_duration_milliseconds` — original: `FUN_08178914` @ 0x08178914.
//! True extent: 144 bytes, 0x08178914..0x081789a4; the next function begins
//! at 0x081789a4. Raw firmware has two incoming plain BL calls (0x08178558,
//! 0x081785d0), zero incoming predicated BL calls, and one outgoing plain BL
//! to the existing `string_object_c_str` @ 0x082a50b0.
//!
//! Decimal digits accumulate the current field. Each colon folds that field
//! into a base-60 prefix and resets the field; all other non-NUL bytes are
//! ignored. At NUL, the prefix and final field are combined and multiplied
//! by 1000. Every operation wraps at 32 bits, including malformed/large input.
//! Deliberate deviations: no semantic deviations; Rust replaces the eleven-
//! entry ARM jump table with digit/colon branches. The existing StringObject
//! accessor models the shared empty string for a NULL payload.

use crate::cxx::string_object::{string_object_c_str, StringObject};

/// The leading context word is unused, as in retailOS. `text` must point to a
/// valid StringObject whose non-NULL payload is readable through its first NUL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_duration_milliseconds(
    _context: u32,
    text: *const StringObject,
) -> u32 {
    let mut cursor = string_object_c_str(text);
    let mut prefix = 0u32;
    let mut field = 0u32;
    loop {
        let byte = *cursor;
        if byte == 0 {
            return prefix.wrapping_mul(60).wrapping_add(field).wrapping_mul(1000);
        }
        if byte >= b'0' && byte <= b'9' {
            field = field.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
        } else if byte == b':' {
            prefix = prefix.wrapping_mul(60).wrapping_add(field);
            field = 0;
        }
        cursor = cursor.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn parse(bytes: &[u8]) -> u32 {
        assert!(bytes.contains(&0));
        let text = StringObject { vtable: ptr::null(), payload: bytes.as_ptr() as *mut u8 };
        unsafe { parse_duration_milliseconds(0x12345678, &text) }
    }

    #[test]
    fn duration_fields_and_empty_fields() {
        for (text, expected) in [
            (&b"\0"[..], 0),
            (&b"7\0"[..], 7000),
            (&b"01:02\0"[..], 62000),
            (&b"1:02:03\0"[..], 3723000),
            (&b"1:2:3:4\0"[..], 223384000),
            (&b":5\0"[..], 5000),
            (&b"5:\0"[..], 300000),
            (&b"1::2\0"[..], 3602000),
            (&b"::\0"[..], 0),
            (&b"1:99\0"[..], 159000),
        ] {
            assert_eq!(parse(text), expected, "{text:?}");
        }
    }

    #[test]
    fn ignores_non_digits_without_terminating_or_resetting() {
        assert_eq!(parse(b" -1x2.3 \xff:4/5\0"), 7425000);
        assert_eq!(parse(b"junk\0"), 0);
        assert_eq!(parse(b"12\0:99\0"), 12000);
    }

    #[test]
    fn wraps_field_prefix_and_final_scaling() {
        assert_eq!(parse(b"4294967296\0"), 0);
        assert_eq!(parse(b"4294967295\0"), u32::MAX - 999);
        assert_eq!(parse(b"4294967295:1\0"), 0u32.wrapping_sub(59000));
        assert_eq!(parse(b"4294967295::1\0"), 0u32.wrapping_sub(3599000));
    }

    #[test]
    fn null_payload_uses_existing_empty_string_accessor() {
        let text = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
        assert_eq!(unsafe { parse_duration_milliseconds(0, &text) }, 0);
    }
}
