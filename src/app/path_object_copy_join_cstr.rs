//! Copy-and-join PathObject construction recovered from retailOS.

use crate::app::path_object_construct::{path_object_copy_construct, path_object_join_cstr};
use crate::cxx::string_object::{string_object_destroy, StringObject};

/// `path_object_copy_join_cstr` — original: `FUN_082a55e4` @ `0x082a55e4`.
///
/// True extent: 52 bytes (`0x082a55e4..0x082a5618`), ending with the pop
/// at 0x082a5614 before the next function's push. Raw ARM words verify four
/// outgoing plain BLs, zero predicated BLs; whole-image decoding finds two
/// incoming plain BLs, zero predicated BLs (0x0815e8a8 and 0x082857b0).
/// Copy-constructs a temporary from `source` (r1), joins `suffix` (r2) onto
/// it, copy-constructs `this` from the join result, then destroys the temporary.
///
/// Deliberate deviations: `MaybeUninit<StringObject>` models the stack pair;
/// host pointer fields widen through the existing repr(C) object. All callees
/// use existing ports and their virtual-method boundaries. Preserve the final
/// destructor's r0 result, not `this`: it points at expired temporary storage
/// and must not be dereferenced. Observed retailOS callers ignore this result.
///
/// # Safety
///
/// `this` must be writable StringObject storage, `source` a readable object,
/// and `suffix` NULL or readable through its NUL terminator. The existing
/// StringObject allocation, insertion, and release contracts must hold.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_object_copy_join_cstr(
    this: *mut StringObject,
    source: *const StringObject,
    suffix: *const u8,
) -> *mut StringObject {
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let temporary = path_object_copy_construct(temporary.as_mut_ptr(), source);
    let joined = path_object_join_cstr(temporary, suffix);
    path_object_copy_construct(this, joined);
    string_object_destroy(temporary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS;

    #[test]
    fn null_and_nul_only_inputs_construct_empty_independent_destination() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock();
        for payload in [core::ptr::null_mut(), b"\0".as_ptr() as *mut u8] {
            for suffix in [core::ptr::null(), b"\0".as_ptr()] {
                let source = StringObject { vtable: core::ptr::null(), payload };
                let mut destination = StringObject {
                    vtable: core::ptr::null(), payload: 1usize as *mut u8,
                };
                unsafe { path_object_copy_join_cstr(&mut destination, &source, suffix); }
                assert_eq!(destination.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
                assert!(destination.payload.is_null());
                assert_eq!(source.payload, payload);
                assert!(source.vtable.is_null());
            }
        }
    }

    #[test]
    fn aliased_empty_source_is_copied_before_destination_construction() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock();
        let mut object = StringObject {
            vtable: core::ptr::null(), payload: b"\0".as_ptr() as *mut u8,
        };
        let pointer = &mut object as *mut StringObject;
        unsafe { path_object_copy_join_cstr(pointer, pointer, core::ptr::null()); }
        assert_eq!(object.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
        assert!(object.payload.is_null());
    }
}
