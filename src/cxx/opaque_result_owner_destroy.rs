//! Plain destructor for an unidentified owner of an [`OpaqueResult`].
//!
//! The target layout starts with a vtable word and one opaque word, then the
//! 80-byte `OpaqueResult` at +0x08, one more opaque word, and a StringObject
//! at +0x5c.
use crate::cxx::opaque_result_destroy::{opaque_result_destroy, OpaqueResult};
use crate::cxx::string_object::{string_object_destroy, StringObject};

/// Vtable literal written by the original destructor.
pub const OPAQUE_RESULT_OWNER_VTABLE: usize = 0x0898_0a08;

/// Target layout of the otherwise unidentified owning object.
#[repr(C)]
pub struct OpaqueResultOwner {
    /// +0x00 on target — overwritten with `OPAQUE_RESULT_OWNER_VTABLE`.
    pub vtable: usize,
    /// +0x04 on target — untouched.
    pub leading_opaque_word: u32,
    /// +0x08..+0x57 on target — destroyed after `trailing_string`.
    pub result: OpaqueResult,
    /// +0x58 on target — untouched.
    pub trailing_opaque_word: u32,
    /// +0x5c on target — destroyed first.
    pub trailing_string: StringObject,
}

/// `opaque_result_owner_destroy` — original: `FUN_08104974` @ `0x08104974`
/// (32 bytes; two plain direct `bl` calls, zero predicated direct `bl` calls).
///
/// Raw `osos.dec` establishes the eight-instruction body at
/// `0x08104974..0x08104993`: it loads literal `0x08980a08`, saves registers,
/// stores that vtable with post-index +0x5c, destroys the trailing StringObject
/// @ `0x08277484`, subtracts 0x54, destroys the embedded OpaqueResult @
/// `0x082679f8`, subtracts 8, and returns. The literal pool is at
/// `0x08104994`; the next real function starts at `0x08104998` with
/// `ldrb r0,[r0,#0x34]`. The raw body has two unconditional direct BL calls
/// and no predicated BL calls.
///
/// It re-installs the owner vtable, destroys the trailing string before the
/// embedded result, and returns the original owner pointer. Deliberate host
/// deviation: the target vtable is a 32-bit ROM literal, represented as `usize`
/// so `#[repr(C)]` preserves the ARM layout while safely accommodating host
/// pointers in the embedded StringObjects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_result_owner_destroy(
    this: *mut OpaqueResultOwner,
) -> *mut OpaqueResultOwner {
    (*this).vtable = OPAQUE_RESULT_OWNER_VTABLE;
    string_object_destroy(&mut (*this).trailing_string);
    opaque_result_destroy(&mut (*this).result);
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn reinitializes_destroyed_members_and_preserves_opaque_words() {
        let mut owner: OpaqueResultOwner = unsafe { core::mem::zeroed() };
        owner.vtable = usize::MAX;
        owner.leading_opaque_word = 0x1234_5678;
        owner.trailing_opaque_word = 0x8765_4321;
        owner.result.secondary.payload = 0xcafe_f00d as *mut u8;

        let returned = unsafe { opaque_result_owner_destroy(&mut owner) };

        assert!(core::ptr::eq(returned, &mut owner));
        assert_eq!(owner.vtable, OPAQUE_RESULT_OWNER_VTABLE);
        assert_eq!(owner.leading_opaque_word, 0x1234_5678);
        assert_eq!(owner.trailing_opaque_word, 0x8765_4321);
        assert!(core::ptr::eq(owner.trailing_string.vtable, &STRING_OBJECT_VTABLE));
        assert!(owner.trailing_string.payload.is_null());
        assert!(core::ptr::eq(owner.result.primary.vtable, &STRING_OBJECT_VTABLE));
        assert!(owner.result.primary.payload.is_null());
        assert_eq!(owner.result.secondary.payload, 0xcafe_f00d as *mut u8);
    }
}
