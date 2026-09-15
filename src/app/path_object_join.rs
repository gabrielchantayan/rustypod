//! PathObject join helper recovered from retailOS.

use crate::cxx::string_object::{
    string_object_codepoint_at, string_object_c_str, string_object_destroy,
    string_object_insert_cstr, string_object_is_empty, string_object_suffix, StringObject,
};

/// `path_object_join` — original: `FUN_08279374` @ 0x08279374.
///
/// True extent: 180 bytes (0x08279374..0x08279428), ending before the next
/// separately linked function. Raw-image branch decoding finds five incoming
/// plain `bl` calls (0x08149e90, 0x081bd52c, 0x081bde9c, 0x08279358, and
/// 0x082a5630), zero predicated calls. The body takes the destination's
/// one-codepoint suffix, removes all trailing `:`, `/`, or `\\` when that
/// suffix is a delimiter, then appends `/` only when a nonempty source is
/// joined onto an empty destination, and finally appends the source C string.
///
/// Deliberate deviation: `string_object_remove_trailing_codepoint` remains an
/// unported target helper at 0x082771e0, so this port retains that exact call
/// boundary rather than duplicating its virtual truncation protocol. Host
/// tests install a replacement through `PATH_REMOVE_TRAILING_OP`.
pub type PathRemoveTrailingOp = unsafe extern "C" fn(*mut StringObject, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn target_remove_trailing(this: *mut StringObject, codepoint: u32) -> i32 {
    let function: PathRemoveTrailingOp = core::mem::transmute(0x0827_71e0usize);
    function(this, codepoint)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn target_remove_trailing(_this: *mut StringObject, _codepoint: u32) -> i32 { 0 }

pub static mut PATH_REMOVE_TRAILING_OP: PathRemoveTrailingOp = target_remove_trailing;

#[inline]
unsafe fn remove_trailing(this: *mut StringObject, codepoint: u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_REMOVE_TRAILING_OP))(this, codepoint)
}

/// Joins `source` onto `this` according to retailOS PathObject rules.
///
/// # Safety
///
/// Both pointers must be valid StringObject storage. Their payloads and the
/// target object's virtual allocation slots must meet the contracts of the
/// directly called StringObject operations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_join(
    this: *mut StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    if !string_object_is_empty(this) {
        let mut suffix = core::mem::MaybeUninit::<StringObject>::uninit();
        string_object_suffix(suffix.as_mut_ptr(), this, 1);
        let delimiter = string_object_codepoint_at(suffix.as_ptr(), 0);
        string_object_destroy(suffix.as_mut_ptr());
        if delimiter == b':' as u32 || delimiter == b'/' as u32 || delimiter == b'\\' as u32 {
            remove_trailing(this, delimiter);
        }
    }
    if !string_object_is_empty(source) {
        if string_object_is_empty(this) {
            let slash = [b'/', 0];
            string_object_insert_cstr(this, i32::MAX, slash.as_ptr());
        }
        string_object_insert_cstr(this, i32::MAX, string_object_c_str(source));
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn empty_objects_return_the_destination_without_touching_payload_words() {
        let mut destination = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        assert_eq!(unsafe { path_object_join(&mut destination, &source) as usize }, &mut destination as *mut _ as usize);
        assert!(destination.payload.is_null());
    }

    #[test]
    fn an_empty_source_does_not_require_a_destination_payload() {
        let mut destination = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let source_bytes = [0u8];
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: source_bytes.as_ptr() as *mut u8,
        };
        unsafe { path_object_join(&mut destination, &source); }
        assert!(destination.payload.is_null());
    }
}
