//! Skip spaces and tabs — retailOS `FUN_0817808c` @ `0x0817808c`.
//!
//! True extent: [0x0817808c, 0x081780c4), 56 bytes, all instructions.
//! Raw A32 decoding verifies one plain outbound BL to
//! `string_object_codepoint_at` @ 0x082a52c8, no predicated BLs, and two
//! plain inbound BLs at 0x081786cc and 0x08178718 (no predicated inbound BLs).
//! Read the codepoint at the caller's index; increment the stored index while
//! it is ASCII space or tab. Other whitespace, NUL and invalid indices stop
//! the scan. The first ABI argument is unused. No deliberate deviations;
//! integer addition wraps as on ARM and the existing decoder is reused.

use crate::cxx::string_object::{string_object_codepoint_at, StringObject};

/// # Safety
/// `index` must be readable and writable. `string` and its payload must meet
/// the preconditions of `string_object_codepoint_at` for the supplied index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_skip_blanks(
    _context: *const core::ffi::c_void,
    string: *const StringObject,
    index: *mut i32,
) {
    loop {
        let codepoint = string_object_codepoint_at(string, index.read());
        if codepoint != 0x20 && codepoint != 9 { break; }
        index.write(index.read().wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_only_spaces_and_tabs_from_codepoint_index() {
        let cases: &[(&[u8], i32, i32)] = &[
            (b"\0", 0, 0),
            (b" \t \t\0", 0, 4),
            (b"x \tq\0", 0, 0),
            (b"x \tq\0", 1, 3),
            (b" \n\t\0", 0, 1),
            (b"\r \0", 0, 0),
            (b"\x0b \0", 0, 0),
            (b"\x0c \0", 0, 0),
            (b"\xc2\xa0 \0", 0, 0),
            (b"\xc3\xa9 \tq\0", 1, 3),
            (b" \0", -1, -1),
            (b" \0", 8, 8),
            (b" \0", i32::MAX, i32::MAX),
        ];
        for &(payload, start, expected) in cases {
            let string = StringObject {
                vtable: core::ptr::null(),
                payload: payload.as_ptr() as *mut u8,
            };
            let mut index = start;
            unsafe { parser_skip_blanks(core::ptr::null(), &string, &mut index); }
            assert_eq!(index, expected, "payload={payload:?}, start={start}");
        }
    }

    #[test]
    fn null_payload_and_negative_index_stop_without_increment() {
        let string = StringObject {
            vtable: core::ptr::null(), payload: core::ptr::null_mut(),
        };
        let mut index = 0;
        unsafe { parser_skip_blanks(core::ptr::null(), &string, &mut index); }
        assert_eq!(index, 0);
        index = i32::MIN;
        unsafe { parser_skip_blanks(core::ptr::null(), core::ptr::null(), &mut index); }
        assert_eq!(index, i32::MIN);
    }
}
