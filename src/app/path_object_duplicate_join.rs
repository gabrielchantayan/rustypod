//! PathObject duplicate-and-join helper recovered from retailOS.
//!
//! The helper has an ABI-only second argument: the raw ARM body never reads
//! r1. It copy-constructs a temporary from r2, joins that same source onto the
//! temporary, copy-constructs the destination from it, then destroys it.

use crate::app::path_object_construct::path_object_copy_construct;
use crate::app::path_object_join::path_object_join;
use crate::cxx::string_object::{string_object_destroy, StringObject};

/// `path_object_duplicate_join` — original: `FUN_082a5618` @ `0x082a5618`.
///
/// True extent: 52 bytes (`0x082a5618..0x082a564c`); the next separately
/// linked function starts with `push {r4, lr}` at `0x082a564c`. Raw-image
/// decoding finds four plain incoming `bl` calls and zero predicated calls.
/// The function creates a stack PathObject copy of `source`, joins `source`
/// onto it, copies that result to `this`, and destroys the temporary.
///
/// Deliberate deviation: Rust expresses the ARM stack pair as `MaybeUninit`;
/// the final destructor result remains the function return even though every
/// observed caller ignores it. The unused ABI argument is retained because
/// retailOS receives it in r1.
///
/// # Safety
///
/// `this` must be writable two-word StringObject storage and `source` must be
/// a readable PathObject/StringObject. `_unused` is ABI-preserved only.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_duplicate_join(
    this: *mut StringObject,
    _unused: *const StringObject,
    source: *const StringObject,
) -> *mut StringObject {
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let temporary = path_object_copy_construct(temporary.as_mut_ptr(), source);
    path_object_join(temporary, source);
    path_object_copy_construct(this, temporary);
    string_object_destroy(temporary)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS;

    #[test]
    fn empty_source_constructs_an_empty_path_destination() {
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let mut destination = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };

        unsafe {
            path_object_duplicate_join(&mut destination, core::ptr::null(), &source);
        }

        assert_eq!(destination.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
        assert!(destination.payload.is_null());
        assert!(source.payload.is_null());
    }

    #[test]
    fn ignored_second_argument_does_not_change_empty_source_result() {
        let source = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let unused = StringObject {
            vtable: PATH_OBJECT_VTABLE_ADDRESS as *const _,
            payload: b"unused\0".as_ptr() as *mut u8,
        };
        let mut destination = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };

        unsafe {
            path_object_duplicate_join(&mut destination, &unused, &source);
        }

        assert_eq!(destination.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
        assert!(destination.payload.is_null());
    }
}
