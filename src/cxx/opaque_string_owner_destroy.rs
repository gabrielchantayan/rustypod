//! Plain destructor for an unidentified one-word-header StringObject owner.
//!
//! Original: `FUN_0826c994` at load address `0x0826c994` (20 bytes).
//! Raw `osos.dec` words establish the full extent through `pop {r4,pc}` at
//! `0x0826c9a4`; the next separately linked function begins with
//! `push {r0,r1,r2,r3,r4,lr}` at `0x0826c9a8`. The body has one plain `bl`
//! (to [`string_object_destroy`] @ `0x08277484`) and no predicated `bl`.
//!
//! It destroys the embedded StringObject one target word past `this`, then
//! subtracts that word from the returned pointer to return the enclosing
//! object. The header is untouched. The owner class remains unidentified, so
//! this structural name deliberately makes no claim about its header.
//!
//! Deliberate host deviation: `usize` represents the target's one-word
//! header, so the embedded field is eight bytes after the header on 64-bit
//! hosts. Subtracting `size_of::<usize>()` preserves the ARM return dataflow
//! for host fixtures without making host pointer width part of the ABI.

use crate::cxx::string_object::{string_object_destroy, StringObject};

/// Target layout: an opaque word followed by an embedded StringObject.
#[repr(C)]
pub struct OpaqueStringOwner {
    /// +0x00 on target — not read or written by this destructor.
    pub header: usize,
    /// +0x04 on target — destroyed in place.
    pub string: StringObject,
}

/// opaque_string_owner_destroy — original: `FUN_0826c994` @ `0x0826c994`
/// (20 bytes; four inbound direct `bl` call sites, all unconditional).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_string_owner_destroy(
    this: *mut OpaqueStringOwner,
) -> *mut OpaqueStringOwner {
    let string = string_object_destroy(&mut (*this).string);
    (string as *mut u8).sub(core::mem::size_of::<usize>()) as *mut OpaqueStringOwner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn preserves_header_reinstalls_string_vtable_and_returns_owner() {
        let mut owner = OpaqueStringOwner {
            header: usize::MAX,
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
        };

        let returned = unsafe { opaque_string_owner_destroy(&mut owner) };

        assert!(core::ptr::eq(returned, &mut owner));
        assert_eq!(owner.header, usize::MAX);
        assert!(core::ptr::eq(owner.string.vtable, &STRING_OBJECT_VTABLE));
        assert!(owner.string.payload.is_null());
    }

    #[test]
    fn preserves_nonzero_header_at_pointer_width_boundary() {
        let mut owner = OpaqueStringOwner {
            header: 1usize << (usize::BITS - 1),
            string: StringObject {
                vtable: &STRING_OBJECT_VTABLE,
                payload: core::ptr::null_mut(),
            },
        };

        assert!(core::ptr::eq(
            unsafe { opaque_string_owner_destroy(&mut owner) },
            &mut owner,
        ));
        assert_eq!(owner.header, 1usize << (usize::BITS - 1));
    }
}
