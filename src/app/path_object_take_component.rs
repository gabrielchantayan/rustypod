//! Destructive path component extraction from retailOS.

use crate::app::path_object_construct::path_object_construct_from_string_object;
use crate::cxx::string_object::{StringObject, string_object_c_str, string_object_destroy,
    string_object_erase, string_object_prefix, utf8_next_codepoint, utf8_prev_codepoint};

/// Original `FUN_082790a0` @ 0x082790a0; true extent 204 bytes,
/// 0x082790a0..0x0827916c (next function starts with push).
/// Raw words verify ten outgoing plain BLs and zero predicated BLs;
/// whole-image decoding finds two incoming plain BLs, zero predicated BLs.
/// Scans decoded codepoints up to NUL, ':', '/', or '\\', constructs a
/// PathObject from that prefix, then erases the prefix and one separator.
/// With escaping enabled, '\\/' and '\\\\' remove the escape backslash
/// in place and include the escaped separator in the component. Other
/// backslashes terminate the component. The cursor is deliberately retained
/// across erase calls, including any allocator effects, just as in ARM.
/// Deliberate deviations: repr(C) pointer fields widen on hosts and
/// MaybeUninit models the temporary stack object. Existing virtual allocation
/// seams remain required; this port does not make those callees hook-ready.
/// Codegen review: 64 versus 51 instructions; LLVM adds a frame and removes
/// the reverse decode whose cursor result is unused on the terminating path.
/// The original final erase has no specified return value.
///
/// # Safety
/// `out` must be writable uninitialized StringObject storage distinct from
/// `remaining`. `remaining` must satisfy the existing string allocation,
/// decoder padding, erase and release contracts. Escaping requires storage
/// to remain readable at the retained cursor after each erase.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_take_component(
    out: *mut StringObject, remaining: *mut StringObject, escaping: u32,
) {
    let mut cursor = string_object_c_str(remaining);
    let mut length = 0i32;
    loop {
        let codepoint = utf8_next_codepoint(&mut cursor);
        if codepoint == 0 { break; }
        if escaping != 0 && codepoint == b'\\' as u32 {
            let escaped = utf8_next_codepoint(&mut cursor);
            if escaped != b'/' as u32 && escaped != b'\\' as u32 {
                utf8_prev_codepoint(&mut cursor);
                break;
            }
            string_object_erase(remaining, length, 1);
            utf8_prev_codepoint(&mut cursor);
        } else if codepoint == b':' as u32 || codepoint == b'/' as u32
            || codepoint == b'\\' as u32 {
            break;
        }
        length = length.wrapping_add(1);
    }
    let mut prefix = core::mem::MaybeUninit::<StringObject>::uninit();
    string_object_prefix(prefix.as_mut_ptr(), remaining, length);
    path_object_construct_from_string_object(out, prefix.as_ptr());
    string_object_destroy(prefix.as_mut_ptr());
    string_object_erase(remaining, 0, length.wrapping_add(1));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::*;
    use std::vec::Vec;

    static mut BUFFERS: Vec<std::boxed::Box<[u8; 128]>> = Vec::new();

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size <= 128);
        if flags == 1 { return (*this).payload; }
        let mut buffer = std::boxed::Box::new([0u8; 128]);
        let pointer = buffer.as_mut_ptr();
        (*this).payload = pointer;
        (*core::ptr::addr_of_mut!(BUFFERS)).push(buffer);
        pointer
    }
    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                .write(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
            core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write(DEFAULT_STRING_OBJECT_OPS);
            (*core::ptr::addr_of_mut!(BUFFERS)).clear();
        } }
    }
    unsafe fn text(object: &StringObject) -> Vec<u8> {
        std::ffi::CStr::from_ptr(string_object_c_str(object).cast()).to_bytes().to_vec()
    }

    #[test]
    fn extracts_components_and_consumes_exactly_one_separator() {
        let _assign = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap();
        let _release = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _restore = Restore;
        unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write(
                StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear });
            core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write(StringObjectOps { release_payload: clear });
            for (input, escaping, component, rest) in [
                ("", 0, "", ""), ("abc", 0, "abc", ""),
                ("/abc", 0, "", "abc"), ("a//b", 0, "a", "/b"),
                ("a:b", 0, "a", "b"), ("a\\b", 0, "a", "b"),
                ("a\\/b/c", 1, "a/b", "c"), ("a\\\\b:c", 1, "a\\b", "c"),
                ("a\\x", 1, "a", "x"), ("a\\", 1, "a", ""),
                // Retained byte cursor lands inside 中 after the in-place shift.
                ("é\\/中/z", 1, "é/", "/z"),
                ("\\/\\\\/tail", 1, "/\\", "tail"),
            ] {
                let mut storage = [0u8; 128];
                storage[..input.len()].copy_from_slice(input.as_bytes());
                let mut remaining = StringObject { vtable: core::ptr::null(), payload: storage.as_mut_ptr() };
                let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
                path_object_take_component(out.as_mut_ptr(), &mut remaining, escaping);
                let out = out.assume_init();
                assert_eq!(text(&out), component.as_bytes(), "{input:?}");
                assert_eq!(text(&remaining), rest.as_bytes(), "{input:?}");
                assert_eq!(out.vtable as usize,
                    crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS);
            }
        }
    }
}
