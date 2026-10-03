//! Removes a suffix selected by retailOS's byte-class table or U+3000.

use super::string_object::{utf8_next_codepoint, utf8_prev_codepoint, StringObject};
use super::string_object_truncate_codepoints::string_object_truncate_codepoints;

#[inline(always)]
unsafe fn suffix_class(codepoint: u32) -> bool {
    if codepoint >= 0x100 {
        return codepoint == 0x3000;
    }
    #[cfg(target_os = "none")]
    { core::ptr::read_volatile((0x083ecfdd as *const u8).add(codepoint as usize)) & 6 != 0 }
    #[cfg(not(target_os = "none"))]
    {
        // Exact mask-6 bitmap of osos.dec's 256 bytes at 0x083ecfdd.
        const CLASS_BITS: [u32; 8] = [
            0x787c6081, 0xe1cece91, 0x44f809e1, 0x17e7860c,
            0xde081008, 0xe4ecc668, 0xce0c44e0, 0xc40c6660,
        ];
        CLASS_BITS[(codepoint >> 5) as usize] & (1 << (codepoint & 31)) != 0
    }
}

/// Original: FUN_08277264 at 0x08277264. True extent 160 bytes through
/// 0x08277304: 156 code bytes and the table-pointer literal at 0x08277300.
/// Raw words verify two internal plain BLs and one predicated BLGT, plus
/// two plain inbound BLs and no predicated inbound calls.
///
/// Forward-counts UTF-8 codepoints, reverse-counts the suffix whose decoded
/// values have table mask 6 set (below 256) or equal U+3000, truncates to
/// the remaining count, and returns the removed count. NULL payload returns
/// zero. The table is deliberately NOT replaced by a guessed whitespace
/// set: static bytes include non-whitespace classes. Target reads the actual
/// retail address; host uses its raw-image mask bitmap, so runtime changes
/// to that table are visible only on target. No other deliberate deviations.
///
/// # Safety
/// `this` must be a valid StringObject; its non-NULL payload must satisfy
/// both retail UTF-8 decoders' readable-buffer requirements. Its vtable
/// must support the truncation helper's resize and clear slots.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_remove_trailing_classified_codepoints(this: *mut StringObject) -> i32 {
    let payload = (*this).payload;
    if payload.is_null() { return 0; }
    let mut cursor = payload.cast_const();
    let mut count = 0i32;
    while *cursor != 0 {
        utf8_next_codepoint(&mut cursor);
        count = count.wrapping_add(1);
    }
    let mut removed = 0i32;
    while payload.cast_const() < cursor && suffix_class(utf8_prev_codepoint(&mut cursor)) {
        removed = removed.wrapping_add(1);
    }
    if removed > 0 {
        string_object_truncate_codepoints(this, count.wrapping_sub(removed));
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object_truncate_codepoints::StringObjectTruncateVtable;
    use core::ptr;

    unsafe extern "C" fn resize(this: *mut StringObject, _len: i32, flag: i32) -> *mut u8 {
        assert_eq!(flag, 1);
        (*this).payload
    }
    unsafe extern "C" fn clear(this: *mut StringObject) { *(*this).payload = 0; }

    #[test]
    fn preserves_raw_classes_and_multibyte_boundaries() {
        let vtable = StringObjectTruncateVtable { slots_below: [0; 2], resize, clear };
        for (input, expected, removed) in [
            (&b"\0"[..], &b"\0"[..], 0),
            (&b"A\t\0"[..], &b"A\t\0"[..], 0),
            (&b"A \0"[..], &b"A\0"[..], 1),
            (&b"Ab\0"[..], &b"A\0"[..], 1),
            (&b" A\0"[..], &b" A\0"[..], 0),
            (&b"A\xe3\x80\x80 \0"[..], &b"A\0"[..], 2),
            (&b"\xe2\x82\xac \0"[..], &b"\xe2\x82\xac\0"[..], 1),
            (&b" \xe3\x80\x80\0"[..], &b"\0"[..], 2),
        ] {
            let mut bytes = input.to_vec();
            let mut object = StringObject { vtable: (&vtable as *const StringObjectTruncateVtable).cast(), payload: bytes.as_mut_ptr() };
            assert_eq!(unsafe { string_object_remove_trailing_classified_codepoints(&mut object) }, removed, "{input:?}");
            assert_eq!(&bytes[..expected.len()], expected, "{input:?}");
        }
        let mut object = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
        assert_eq!(unsafe { string_object_remove_trailing_classified_codepoints(&mut object) }, 0);
    }
}
