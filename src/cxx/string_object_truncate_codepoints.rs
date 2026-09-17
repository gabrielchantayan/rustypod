//! Truncates a StringObject payload at a UTF-8 codepoint boundary.

use crate::cxx::string_object::{utf8_next_codepoint, StringObject};

/// The two virtual slots used by `string_object_truncate_codepoints`.
///
/// The first two words preserve the target's +0x08 and +0x0c slot offsets
/// on ARM. Pointer-width fields keep the corresponding word indices usable
/// in host fixtures.
#[repr(C)]
pub struct StringObjectTruncateVtable {
    pub slots_below: [usize; 2],
    pub resize: unsafe extern "C" fn(*mut StringObject, i32, i32) -> *mut u8,
    pub clear: unsafe extern "C" fn(*mut StringObject),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::offset_of!(StringObjectTruncateVtable, resize)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 12] = [0; core::mem::offset_of!(StringObjectTruncateVtable, clear)];

/// `string_object_truncate_codepoints` — original: `FUN_08277044` @
/// `0x08277044` (120 bytes, `0x08277044..0x082770bc`).
///
/// Raw ARM has two plain `bl` instructions in the body (to the UTF-8
/// codepoint counter and index walker), zero predicated `bl` instructions,
/// one unpredicated virtual `blx`, and a predicated virtual tail dispatch.
/// Four direct callers were decoded independently: one plain `bl` and three
/// predicated forms (`blhi`, two `blgt`). It leaves a string unchanged when
/// its codepoint count does not exceed `index`; otherwise a non-positive
/// index tail-dispatches vtable slot +0x0c, while a positive index advances
/// through UTF-8 sequences, requests `byte_offset + 1` bytes through slot
/// +0x08 with flag 1, and NUL-terminates a successful result.
///
/// Deliberate deviations: the two decoded virtual slots are represented by a
/// typed vtable rather than concrete callee identities; their serialized ARM
/// offsets and arguments are preserved.
///
/// # Safety
///
/// `this` must be a valid StringObject with a readable NUL-terminated payload
/// when non-NULL. Its vtable must provide the decoded resize and clear slots.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_truncate_codepoints(this: *mut StringObject, index: i32) {
    let payload = unsafe { (*this).payload };
    let mut cursor = payload.cast_const();
    let mut count = 0i32;
    if !cursor.is_null() {
        while unsafe { *cursor } != 0 {
            unsafe { utf8_next_codepoint(&mut cursor) };
            count = count.wrapping_add(1);
        }
    }

    if count <= index {
        return;
    }

    let vtable = unsafe { (*this).vtable.cast::<StringObjectTruncateVtable>() };
    if index <= 0 {
        unsafe { ((*vtable).clear)(this) };
        return;
    }

    cursor = payload.cast_const();
    for _ in 0..index {
        unsafe { utf8_next_codepoint(&mut cursor) };
    }
    let byte_len = unsafe { cursor.offset_from(payload.cast_const()) as i32 }.wrapping_add(1);
    let resized = unsafe { ((*vtable).resize)(this, byte_len, 1) };
    if !resized.is_null() {
        unsafe { *resized.add(byte_len as usize - 1) = 0 };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RESIZE_RESULT: *mut u8 = ptr::null_mut();
    static mut SEEN_LEN: i32 = i32::MIN;
    static mut SEEN_FLAG: i32 = i32::MIN;
    static mut CLEAR_CALLS: u32 = 0;

    unsafe extern "C" fn resize(_this: *mut StringObject, len: i32, flag: i32) -> *mut u8 {
        unsafe { SEEN_LEN = len; SEEN_FLAG = flag; RESIZE_RESULT }
    }

    unsafe extern "C" fn clear(_this: *mut StringObject) {
        unsafe { CLEAR_CALLS += 1 }
    }

    fn run(payload: *mut u8, index: i32, result: *mut u8) -> (i32, i32, u32) {
        let vtable = StringObjectTruncateVtable { slots_below: [0; 2], resize, clear };
        let mut object = StringObject { vtable: (&vtable as *const StringObjectTruncateVtable).cast(), payload };
        unsafe { RESIZE_RESULT = result; SEEN_LEN = i32::MIN; SEEN_FLAG = i32::MIN; CLEAR_CALLS = 0; }
        unsafe { string_object_truncate_codepoints(&mut object, index) };
        unsafe { (SEEN_LEN, SEEN_FLAG, CLEAR_CALLS) }
    }

    #[test]
    fn truncates_at_a_multibyte_codepoint_boundary() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut source = *b"a\xc2\xa2z\0";
        let mut destination = [0xff; 8];
        let seen = run(source.as_mut_ptr(), 2, destination.as_mut_ptr());
        assert_eq!(seen, (4, 1, 0));
        assert_eq!(destination[3], 0);
    }

    #[test]
    fn nonpositive_index_clears_only_nonempty_strings() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut source = *b"x\0";
        assert_eq!(run(source.as_mut_ptr(), 0, ptr::null_mut()), (i32::MIN, i32::MIN, 1));
        let mut empty = *b"\0";
        assert_eq!(run(empty.as_mut_ptr(), 0, ptr::null_mut()), (i32::MIN, i32::MIN, 0));
    }

    #[test]
    fn out_of_range_index_does_not_dispatch() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut source = *b"x\0";
        assert_eq!(run(source.as_mut_ptr(), 1, ptr::null_mut()), (i32::MIN, i32::MIN, 0));
    }
}
