//! `string_object_construct_from_resource_or_cstr` — original: `FUN_080c6308`
//! at load address `0x080c6308` (60 bytes, through the tail branch at
//! `0x080c6340`; the next real function begins at `0x080c6348`). Raw ARM
//! decoding finds three inbound plain `bl` call sites and zero predicated
//! `bl` call sites.
//!
//! The constructor takes an output `StringObject`, a source word, and a
//! selector. When the selector is zero, the source word is already a C-string
//! pointer. Otherwise it is a string-resource id: the current task's resource
//! chain is obtained and queried for that id. It then tail-calls the embedded
//! string-owner initializer with the selected C string. Deliberate deviations:
//! the stock tail branch is an ordinary Rust call, which preserves all
//! observable effects and return value.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{string_object_construct_from_cstr, StringObject};
use crate::util::context_field::task_ctx_field_0x30;

/// `string_object_construct_from_resource_or_cstr` — original:
/// `FUN_080c6308` @ `0x080c6308` (60 bytes; 3 plain `bl` call sites, 0
/// predicated).
///
/// Initializes `out` from `source`: a C-string pointer when `use_resource` is
/// zero, otherwise a resource id resolved through the current task's provider
/// chain. The constructor's saved output pointer is returned.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_object_construct_from_resource_or_cstr")]
#[inline(never)]
pub unsafe extern "C" fn string_object_construct_from_resource_or_cstr(
    out: *mut StringObject,
    source: usize,
    use_resource: u32,
) -> *mut StringObject {
    let source = if use_resource == 0 {
        source as *const u8
    } else {
        let chain = task_ctx_field_0x30() as usize as *mut ResourceProvider;
        resource_chain_find_string(chain, source as u32)
    };
    string_object_construct_from_cstr(out, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn c_string_selector_passes_null_source_to_the_constructor() {
        let mut out = StringObject {
            vtable: core::ptr::null(),
            payload: 1usize as *mut u8,
        };

        let result = unsafe {
            string_object_construct_from_resource_or_cstr(
                core::ptr::addr_of_mut!(out),
                0,
                0,
            )
        };

        assert_eq!(result, core::ptr::addr_of_mut!(out));
        assert!(core::ptr::eq(out.vtable, &STRING_OBJECT_VTABLE));
        assert!(out.payload.is_null());
    }

    #[test]
    fn c_string_selector_passes_an_empty_source_unchanged() {
        let mut out = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let empty = *b"\0";

        let result = unsafe {
            string_object_construct_from_resource_or_cstr(
                core::ptr::addr_of_mut!(out),
                empty.as_ptr() as usize,
                0,
            )
        };

        assert_eq!(result, core::ptr::addr_of_mut!(out));
    }
}
