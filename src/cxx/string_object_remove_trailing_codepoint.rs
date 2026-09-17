//! Removes repeated trailing codepoints from a StringObject payload.

use crate::cxx::string_object::{
    utf8_next_codepoint, utf8_prev_codepoint, StringObject,
};
use crate::cxx::string_object_truncate_codepoints::string_object_truncate_codepoints;

/// `string_object_remove_trailing_codepoint` — original: `FUN_082771e0` @
/// 0x082771e0.
///
/// True extent: 128 bytes (0x082771e0..0x08277260), ending at the next push
/// instruction. Raw decoding finds two plain `bl` instructions and one
/// predicated `blgt` in the body. It forward-counts decoded codepoints in the
/// non-NULL payload, reverse-decodes and counts a matching suffix, then calls
/// the ported truncation helper at 0x08277044 to retain the remaining
/// codepoints. The function returns the number removed.
///
/// # Safety
///
/// `this` must point to a valid StringObject. A non-NULL payload must be a
/// readable NUL-terminated byte sequence, with the same decoder preconditions
/// as the retail code.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_remove_trailing_codepoint(
    this: *mut StringObject,
    codepoint: u32,
) -> i32 {
    let payload = unsafe { (*this).payload };
    if payload.is_null() {
        return 0;
    }

    let mut cursor = payload.cast_const();
    let mut codepoint_count = 0i32;
    while unsafe { *cursor } != 0 {
        unsafe { utf8_next_codepoint(&mut cursor) };
        codepoint_count = codepoint_count.wrapping_add(1);
    }

    let mut removed = 0i32;
    while payload.cast_const() < cursor && unsafe { utf8_prev_codepoint(&mut cursor) } == codepoint {
        removed = removed.wrapping_add(1);
    }

    if removed > 0 {
        unsafe { string_object_truncate_codepoints(this, codepoint_count.wrapping_sub(removed)) };
    }
    removed
}

