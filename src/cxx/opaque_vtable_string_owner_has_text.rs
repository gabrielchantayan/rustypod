//! Owner string predicate — original: `FUN_0829c468` @ `0x0829c468`.
//! True extent: 24 bytes, `0x0829c468..0x0829c47f`; the next function
//! starts at `0x0829c480`. Raw-word scanning verifies two incoming plain
//! BL calls (0x081dc6ac, 0x081dcae4), one outgoing plain BL to
//! `utf8_codepoint_count_safe` @ 0x082770e0, and zero predicated BL calls.
//!
//! Loads the embedded StringObject payload at target offset +0x18, counts
//! decoded codepoints, and returns exactly zero or one. NULL, empty, and
//! decoder-zero malformed payloads return zero; this is not a byte-empty
//! check. The complete decoder walk is retained, including its reads after
//! the first character. Deviations: none; the existing repr(C) owner model
//! uses native pointer fields so host fixtures do not assume ARM offsets.

use super::opaque_vtable_string_owner_destroy::OpaqueVtableStringOwner;
use super::string_object::utf8_codepoint_count_safe;

/// # Safety
/// `this` must point to a readable owner. A non-NULL string payload must
/// satisfy `utf8_codepoint_count_safe`'s readable-sequence contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_string_owner_has_text(
    this: *const OpaqueVtableStringOwner,
) -> u32 {
    (utf8_codepoint_count_safe((*this).string.payload) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object::StringObject;
    use core::ptr;

    #[test]
    fn decoder_termination_and_nonzero_normalization() {
        let cases: &[(*const u8, u32)] = &[
            (ptr::null(), 0),
            (b"\0".as_ptr(), 0),
            (b"ASCII\0".as_ptr(), 1),
            (b"\xc2\xa2\xe2\x82\xac\0".as_ptr(), 1),
            (b"\xc0\x80\0".as_ptr(), 0), // Overlong decoded NUL.
            (b"\xf0\x90\x80\x80\0".as_ptr(), 0), // Unsupported lead.
            (b"a\xf0\x90\x80\x80\0".as_ptr(), 1),
            (b"\0ignored\0".as_ptr(), 0),
        ];
        for &(payload, expected) in cases {
            let owner = OpaqueVtableStringOwner {
                vtable: usize::MAX,
                opaque_words: [u32::MAX; 4],
                string: StringObject {
                    vtable: ptr::null(),
                    payload: payload.cast_mut(),
                },
                trailing_pair: [u32::MAX; 2],
            };
            assert_eq!(unsafe { opaque_vtable_string_owner_has_text(&owner) }, expected);
        }
    }
}
