//! Plain destructor for an unidentified vtable-bearing StringObject owner.
//!
//! Original: `FUN_0816de54` at load address `0x0816de54` (24 bytes).
//! Raw `osos.dec` words establish the exact body from `ldr r1, [pc, #16]`
//! through `pop {r4,pc}` at `0x0816de68`; `0x0816de6c` is its literal pool,
//! followed by a one-word veneer at `0x0816de70` and the next real function at
//! `0x0816de74`. Whole-image A32 branch decoding finds three inbound direct
//! plain `bl` calls (0x0815fb9c, 0x081dc6d4, 0x081dcb18) and zero predicated
//! `bl` calls. Its body has one plain `bl`, to `string_object_destroy`, and no
//! predicated calls.
//!
//! It installs vtable literal `0x08988958`, destroys the embedded StringObject
//! at target offset +0x14, and returns the enclosing object. The owner class
//! remains unidentified, so this structural name deliberately makes no claim
//! about its other four words.
//!
//! Deliberate host deviation: the target's vtable word is `usize`, so the
//! embedded StringObject follows it at +0x14 on ARM but may be padded on a
//! 64-bit host. `#[repr(C)]` preserves the target layout while keeping host
//! fixtures aligned for StringObject's native pointers.

use crate::cxx::string_object::{string_object_destroy, StringObject};

/// Vtable literal written by the original destructor.
pub const OPAQUE_VTABLE_STRING_OWNER_VTABLE: usize = 0x0898_8958;

/// Target layout: vtable, four opaque words, then an embedded StringObject.
#[repr(C)]
pub struct OpaqueVtableStringOwner {
    /// +0x00 on target — overwritten with `OPAQUE_VTABLE_STRING_OWNER_VTABLE`.
    pub vtable: usize,
    /// +0x04..+0x13 on target — untouched by this destructor.
    pub opaque_words: [u32; 4],
    /// +0x14 on target — destroyed in place.
    pub string: StringObject,
}

/// opaque_vtable_string_owner_destroy — original: `FUN_0816de54` @ `0x0816de54`
/// (24 bytes; three inbound direct plain `bl` call sites, zero predicated).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_string_owner_destroy(
    this: *mut OpaqueVtableStringOwner,
) -> *mut OpaqueVtableStringOwner {
    (*this).vtable = OPAQUE_VTABLE_STRING_OWNER_VTABLE;
    string_object_destroy(&mut (*this).string);
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn reinstalls_vtables_preserves_opaque_words_and_returns_owner() {
        let mut owner = OpaqueVtableStringOwner {
            vtable: usize::MAX,
            opaque_words: [0, u32::MAX, 0x1234_5678, 0x8765_4321],
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
        };

        let returned = unsafe { opaque_vtable_string_owner_destroy(&mut owner) };

        assert!(core::ptr::eq(returned, &mut owner));
        assert_eq!(owner.vtable, OPAQUE_VTABLE_STRING_OWNER_VTABLE);
        assert_eq!(owner.opaque_words, [0, u32::MAX, 0x1234_5678, 0x8765_4321]);
        assert!(core::ptr::eq(owner.string.vtable, &STRING_OBJECT_VTABLE));
        assert!(owner.string.payload.is_null());
    }
}
