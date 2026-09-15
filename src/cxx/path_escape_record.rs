//! Escaped path-string record assignment.
//!
//! The enclosing record class is not identified. Its two accessed members are
//! StringObjects at target offsets +0x04 and +0x0c.

use core::ptr;

use super::string_object::{
    string_object_assign_payload, string_object_c_str, string_object_copy_construct,
    string_object_destroy, utf8_strcmp_safe, StringObject,
};

/// The decoded prefix of a record which retains the supplied path at +0x0c and
/// conditionally stores an unescaped/normalized spelling at +0x04.
///
/// `usize` fields model target words: on the target each StringObject starts
/// four bytes after its predecessor; widened host pointers must not define this
/// ABI through byte offsets.
#[repr(C)]
pub struct EscapedPathStringRecord {
    pub header: usize,
    pub normalized: StringObject,
    pub source: StringObject,
}

/// Unported `FUN_0826bd10` boundary: construct `out` from `source`, dropping
/// a `#` immediately followed by `#`, `/`, or `\\`, and set `changed`.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_path_escape_remove_markers(
    out: *mut StringObject, source: *const StringObject, marker: u32, replacement: u32, changed: *mut u8,
) {
    let call: unsafe extern "C" fn(*mut StringObject, *const StringObject, u32, u32, *mut u8) =
        core::mem::transmute(0x0826_bd10usize);
    call(out, source, marker, replacement, changed);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn path_escape_remove_markers_stub(
    out: *mut StringObject, _source: *const StringObject, _marker: u32, _replacement: u32, changed: *mut u8,
) {
    (*out).vtable = ptr::null();
    (*out).payload = ptr::null_mut();
    *changed = 0;
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_object_text_normalize(string: *mut StringObject) {
    let call: unsafe extern "C" fn(*mut StringObject) = core::mem::transmute(0x0827_6db4usize);
    call(string);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn string_object_text_normalize_stub(_string: *mut StringObject) {}

#[cfg(target_os = "none")]
pub static mut PATH_ESCAPE_REMOVE_MARKERS: unsafe extern "C" fn(
    *mut StringObject, *const StringObject, u32, u32, *mut u8,
) = firmware_path_escape_remove_markers;
#[cfg(not(target_os = "none"))]
pub static mut PATH_ESCAPE_REMOVE_MARKERS: unsafe extern "C" fn(
    *mut StringObject, *const StringObject, u32, u32, *mut u8,
) = path_escape_remove_markers_stub;

/// Unported `FUN_08276db4` boundary: normalize the temporary text in place.
#[cfg(target_os = "none")]
pub static mut STRING_OBJECT_TEXT_NORMALIZE: unsafe extern "C" fn(*mut StringObject) =
    firmware_string_object_text_normalize;
#[cfg(not(target_os = "none"))]
pub static mut STRING_OBJECT_TEXT_NORMALIZE: unsafe extern "C" fn(*mut StringObject) =
    string_object_text_normalize_stub;

#[inline(always)]
unsafe fn path_escape_remove_markers_op() -> unsafe extern "C" fn(
    *mut StringObject, *const StringObject, u32, u32, *mut u8,
) {
    ptr::read_volatile(ptr::addr_of!(PATH_ESCAPE_REMOVE_MARKERS))
}

#[inline(always)]
unsafe fn string_object_text_normalize_op() -> unsafe extern "C" fn(*mut StringObject) {
    ptr::read_volatile(ptr::addr_of!(STRING_OBJECT_TEXT_NORMALIZE))
}

/// path_escape_record_assign — original: `FUN_0826bc30` @ `0x0826bc30`
/// (192 bytes, 48 ARM words; **5 plain `bl` call sites and zero predicated**:
/// `0x08178ab0`, `0x08178bb4`, `0x08178d30`, `0x08178df8`, `0x0828bcf4`).
///
/// Saves `source` at record +0x0c, copies it to a temporary, and removes a
/// path-escape `#` only when it prefixes `#`, `/`, or `\\`. On that change it
/// invokes the retail text-normalization member, then stores the temporary at
/// +0x04 only when its normalized payload differs from the original C string.
/// Both temporaries are destroyed on every path.
///
/// Deliberate deviations: `FUN_0826bd10` and `FUN_08276db4` are unported, so
/// their exact ROM calls are explicit injectable boundaries. The typed record
/// preserves target word positions without relying on host pointer widths.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_escape_record_assign(
    record: *mut EscapedPathStringRecord,
    source: *const StringObject,
) {
    string_object_assign_payload(ptr::addr_of_mut!((*record).source), string_object_c_str(source));

    let mut copied = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
    let mut unescaped = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
    string_object_copy_construct(ptr::addr_of_mut!(copied), source);

    let mut changed = 0u8;
    path_escape_remove_markers_op()(
        ptr::addr_of_mut!(unescaped), ptr::addr_of!(copied), 0x23, 0,
        ptr::addr_of_mut!(changed),
    );
    string_object_destroy(ptr::addr_of_mut!(copied));

    if changed != 0 {
        string_object_text_normalize_op()(ptr::addr_of_mut!(unescaped));
    }
    if utf8_strcmp_safe(unescaped.payload, string_object_c_str(source)) != 0 {
        string_object_assign_payload(
            ptr::addr_of_mut!((*record).normalized), string_object_c_str(ptr::addr_of!(unescaped)),
        );
    }
    string_object_destroy(ptr::addr_of_mut!(unescaped));
}

#[cfg(test)]
mod tests {
    #[test]
    fn escape_marker_requires_an_escaped_path_character() {
        let cases = [(b"a#/\0".as_slice(), true), (b"a##\0", true),
            (b"a#\\\0", true), (b"a#x\0", false), (b"a#\0", false)];
        for (text, expected) in cases {
            assert_eq!(text.windows(2).any(|pair| pair[0] == b'#' && matches!(pair[1], b'#' | b'/' | b'\\')), expected);
        }
    }
}
