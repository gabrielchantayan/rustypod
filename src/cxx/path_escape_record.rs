//! Escaped path-string record assignment.
//!
//! The enclosing record class is not identified. Its two accessed members are
//! StringObjects at target offsets +0x04 and +0x0c.

use core::ptr;

use super::string_object::{
    string_default_construct, string_object_append_code_unit_returning_this,
    string_object_assign_payload, string_object_c_str, string_object_codepoint_at,
    string_object_copy_construct, string_object_destroy, utf8_codepoint_count_safe,
    utf8_strcmp_safe, StringObject,
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

/// path_escape_remove_markers — original: `FUN_0826bd10` @ `0x0826bd10`
/// (200 bytes, `0x0826bd10..0x0826bdd7`; the next real function begins at
/// `0x0826bdd8`). **3 inbound plain `bl` call sites and zero predicated**,
/// verified by decoding every ARM branch word in `osos.dec`.
///
/// Default-constructs `out`, then scans `source` by decoded codepoint. A
/// `marker` is omitted only when its following codepoint is `\\`, `/`, or the
/// marker itself; the following codepoint is appended, optionally preceded by
/// `replacement` when it is nonzero, and `changed` is set to one. Every other
/// codepoint is appended unchanged. `changed`, when non-NULL, is cleared
/// before construction. The source's codepoint count is captured before the
/// scan, so the loop's two-codepoint consumption retains the ARM index flow.
///
/// The raw body makes seven direct calls: six plain `bl` instructions
/// (`string_default_construct`, `utf8_codepoint_count_safe`, two
/// `string_object_codepoint_at`, and two
/// `string_object_append_code_unit_returning_this`) plus one predicated
/// `blne` to the same append helper. All callees are ported directly; there
/// are no deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_escape_remove_markers(
    out: *mut StringObject,
    source: *const StringObject,
    marker: u32,
    replacement: u32,
    changed: *mut u8,
) {
    if !changed.is_null() {
        *changed = 0;
    }
    string_default_construct(out);
    let count = utf8_codepoint_count_safe((*source).payload);
    let mut index = 0u32;
    while index < count as u32 {
        let codepoint = string_object_codepoint_at(source, index as i32);
        if codepoint == marker {
            let next = string_object_codepoint_at(source, index.wrapping_add(1) as i32);
            if next == b'\\' as u32 || next == b'/' as u32 || next == marker {
                if replacement != 0 {
                    string_object_append_code_unit_returning_this(out, replacement);
                }
                string_object_append_code_unit_returning_this(out, next);
                if !changed.is_null() {
                    *changed = 1;
                }
                index = index.wrapping_add(1);
            } else {
                string_object_append_code_unit_returning_this(out, codepoint);
            }
        } else {
            string_object_append_code_unit_returning_this(out, codepoint);
        }
        index = index.wrapping_add(1);
    }
}

/// Unported `FUN_08276db4` boundary: normalize the temporary text in place.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_object_text_normalize(string: *mut StringObject) {
    let call: unsafe extern "C" fn(*mut StringObject) = core::mem::transmute(0x0827_6db4usize);
    call(string);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn string_object_text_normalize_stub(_string: *mut StringObject) {}

#[cfg(target_os = "none")]
pub static mut STRING_OBJECT_TEXT_NORMALIZE: unsafe extern "C" fn(*mut StringObject) =
    firmware_string_object_text_normalize;
#[cfg(not(target_os = "none"))]
pub static mut STRING_OBJECT_TEXT_NORMALIZE: unsafe extern "C" fn(*mut StringObject) =
    string_object_text_normalize_stub;

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
/// Deliberate deviation: `FUN_08276db4` remains an explicit injectable
/// boundary. The typed record preserves target word positions without relying
/// on host pointer widths.
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
    path_escape_remove_markers(
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
    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use parking_lot::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OUTPUT: [u8; 64] = [0; 64];

    unsafe extern "C" fn output_allocator(
        this: *mut StringObject, _requested_size: usize, _flags: u32,
    ) -> *mut u8 {
        (*this).payload = core::ptr::addr_of_mut!(OUTPUT).cast();
        (*this).payload
    }

    unsafe extern "C" fn output_clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }

    fn run(text: &[u8], replacement: u32) -> ([u8; 64], u8) {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let previous: StringObjectAssignCstrOps =
                core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS));
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: output_allocator,
                clear_payload: output_clear,
            };
            OUTPUT = [0; 64];
            let source = StringObject {
                vtable: core::ptr::null(),
                payload: text.as_ptr() as *mut u8,
            };
            let mut out = StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            };
            let mut changed = 0;
            path_escape_remove_markers(&mut out, &source, b'#' as u32, replacement, &mut changed);
            let result = OUTPUT;
            STRING_OBJECT_ASSIGN_CSTR_OPS = previous;
            (result, changed)
        }
    }

    #[test]
    fn escape_marker_requires_an_escaped_path_character() {
        for (text, expected, replacement) in [
            (b"a#/\0".as_slice(), b"a/\0".as_slice(), 0),
            (b"a##\0".as_slice(), b"a#\0".as_slice(), 0),
            (b"a#\\\0".as_slice(), b"a\\\0".as_slice(), 0),
            (b"a#x\0".as_slice(), b"a#x\0".as_slice(), 0),
            (b"a#\0".as_slice(), b"a#\0".as_slice(), 0),
            (b"#/\0".as_slice(), b"_/\0".as_slice(), b'_' as u32),
        ] {
            let (out, changed) = run(text, replacement);
            assert_eq!(&out[..expected.len()], expected);
            assert_eq!(changed, u8::from(expected != text));
        }
    }
}
