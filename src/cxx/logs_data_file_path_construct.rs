//! Constructor for the fixed `/Logs/Data File` `StringObject`.
//!
//! Original: `FUN_08264c2c` at load address **0x08264c2c**. Raw `osos.dec`
//! words establish an 88-byte A32 body from `0x08264c2c` through the return
//! at `0x08264c80`; its four-word literal pool starts at `0x08264c84`.
//! There is one outgoing plain `bl` (to `string_object_construct_from_cstr`
//! at `0x08277304`) and no predicated call. Three incoming call sites are
//! plain `bl`s, with none predicated.
//!
//! The retail body materializes four encoded words on its stack, shifts each
//! right once, clears the high byte of the last word, and constructs `this`
//! from the resulting `/Logs/Data File` C string. This port uses the decoded
//! static byte string rather than reproducing stack-local word transforms;
//! the resulting callee arguments and object state are identical.

use crate::cxx::string_object::{string_object_construct_from_cstr, StringObject};

const LOGS_DATA_FILE_PATH: &[u8; 16] = b"/Logs/Data File\0";

/// Construct `this` from the retailOS fixed `/Logs/Data File` path.
///
/// `this` must point to writable `StringObject` storage; as in the retail
/// constructor, it is not NULL-guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn logs_data_file_path_construct(
    this: *mut StringObject,
) -> *mut StringObject {
    string_object_construct_from_cstr(this, LOGS_DATA_FILE_PATH.as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectVtable, STRING_OBJECT_VTABLE};

    #[test]
    fn constructs_the_exact_fixed_path_from_uninitialized_object_words() {
        let mut object = StringObject {
            vtable: 0xdead_beefusize as *const StringObjectVtable,
            payload: 0xcafe_f00dusize as *mut u8,
        };
        let this = core::ptr::addr_of_mut!(object);

        assert_eq!(unsafe { logs_data_file_path_construct(this) }, this);
        assert_eq!(LOGS_DATA_FILE_PATH, b"/Logs/Data File\0");
        assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(object.payload.is_null(), "the default host allocation seam fails cleanly");
    }
}
