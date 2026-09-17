//! Removes repeated trailing codepoints from a StringObject payload.

use crate::cxx::string_object::{utf8_next_codepoint, utf8_prev_codepoint, StringObject};

/// ABI of the unported StringObject truncation helper at 0x08277044.
pub type StringObjectTruncateCodepoints = unsafe extern "C" fn(*mut StringObject, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn target_truncate_codepoints(this: *mut StringObject, count: i32) {
    let function: StringObjectTruncateCodepoints =
        unsafe { core::mem::transmute(0x0827_7044usize) };
    unsafe { function(this, count) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn target_truncate_codepoints(_this: *mut StringObject, _count: i32) {}

/// The one remaining retail boundary used to resize the StringObject payload.
pub static mut STRING_OBJECT_TRUNCATE_CODEPOINTS_OP: StringObjectTruncateCodepoints =
    target_truncate_codepoints;

#[inline]
unsafe fn truncate_codepoints(this: *mut StringObject, count: i32) {
    let operation = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_TRUNCATE_CODEPOINTS_OP))
    };
    unsafe { operation(this, count) };
}

/// `string_object_remove_trailing_codepoint` — original: `FUN_082771e0` @
/// 0x082771e0.
///
/// True extent: 128 bytes (0x082771e0..0x08277260), ending at the next push
/// instruction. Raw decoding finds two plain `bl` instructions and one
/// predicated `blgt` in the body. It forward-counts decoded codepoints in the
/// non-NULL payload, reverse-decodes and counts a matching suffix, then asks
/// the unported truncation helper at 0x08277044 to retain the remaining
/// codepoints. The function returns the number removed.
///
/// Deliberate deviation: the resizing helper remains an explicit typed seam;
/// its virtual allocation/truncation protocol is not duplicated here.
///
/// # Safety
///
/// `this` must point to a valid StringObject. A non-NULL payload must be a
/// readable NUL-terminated byte sequence, with the same decoder preconditions
/// as the retail code. The installed truncation operation must accept `this`.
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
        unsafe { truncate_codepoints(this, codepoint_count.wrapping_sub(removed)) };
    }
    removed
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_THIS: *mut StringObject = ptr::null_mut();
    static mut SEEN_COUNT: i32 = i32::MIN;

    unsafe extern "C" fn record_truncate(this: *mut StringObject, count: i32) {
        unsafe {
            SEEN_THIS = this;
            SEEN_COUNT = count;
        }
    }

    unsafe fn run(payload: *mut u8, codepoint: u32) -> (i32, *mut StringObject, i32) {
        let mut object = StringObject { vtable: ptr::null(), payload };
        let previous = unsafe { STRING_OBJECT_TRUNCATE_CODEPOINTS_OP };
        unsafe {
            SEEN_THIS = ptr::null_mut();
            SEEN_COUNT = i32::MIN;
            STRING_OBJECT_TRUNCATE_CODEPOINTS_OP = record_truncate;
        }
        let removed = unsafe { string_object_remove_trailing_codepoint(&mut object, codepoint) };
        unsafe { STRING_OBJECT_TRUNCATE_CODEPOINTS_OP = previous };
        unsafe { (removed, SEEN_THIS, SEEN_COUNT) }
    }

    #[test]
    fn removes_the_complete_ascii_suffix_and_retains_its_codepoint_length() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut payload = *b"path///\0";
        let (removed, this, retained) = unsafe { run(payload.as_mut_ptr(), b'/' as u32) };
        assert_eq!(removed, 3);
        assert!(!this.is_null());
        assert_eq!(retained, 4);
    }

    #[test]
    fn reverse_decoder_removes_multibyte_codepoints_by_character_not_byte() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut payload = *b"a\xc2\xa2\xc2\xa2\0";
        let (removed, _this, retained) = unsafe { run(payload.as_mut_ptr(), 0x00a2) };
        assert_eq!(removed, 2);
        assert_eq!(retained, 1);
    }

    #[test]
    fn null_and_nonmatching_payloads_do_not_call_the_truncation_seam() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (removed, this, retained) = unsafe { run(ptr::null_mut(), b'/' as u32) };
        assert_eq!((removed, this, retained), (0, ptr::null_mut(), i32::MIN));

        let mut payload = *b"path/\0";
        let (removed, this, retained) = unsafe { run(payload.as_mut_ptr(), b'\\' as u32) };
        assert_eq!((removed, this, retained), (0, ptr::null_mut(), i32::MIN));
    }
}
