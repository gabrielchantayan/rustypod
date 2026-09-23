//! Constructor for an unidentified vtable-bearing StringObject owner.
//!
//! Original: `FUN_0816de24` at load address `0x0816de24` (40 bytes). Raw
//! `osos.dec` words establish the exact body from `push {r4,lr}` through
//! `pop {r4,pc}` at `0x0816de4c`; the literal-pool vtable word is at
//! `0x0816de50`, and the next real function begins at `0x0816de54`.
//! Decoding the body finds exactly three plain `bl` calls and zero predicated
//! `bl` calls.
//!
//! The constructor first builds the common 20-byte two-pair base, replaces its
//! vtable with `0x08988958`, default-constructs the embedded StringObject at
//! target offset +0x14, clears the trailing pair at +0x1c, and returns `this`.
//!
//! Deliberate deviation: target builds call the existing Rust ports for all
//! three direct BL targets. The native-host fixture copies the two base pairs
//! into semantic fields because its native-width vtable makes target byte
//! offsets unsuitable there; both layouts preserve the ARM fields.

use super::opaque_vtable_string_owner_destroy::{
    OpaqueVtableStringOwner, OPAQUE_VTABLE_STRING_OWNER_VTABLE,
};
use super::string_object::string_default_construct;
use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;
use crate::util::u32_pair_store::store_u32_pair;

/// Constructs an opaque vtable-bearing owner with an empty embedded string.
///
/// # Safety
///
/// `this` must be writable as an [`OpaqueVtableStringOwner`]. Both source
/// pairs must be readable for eight aligned bytes. The retail constructor has
/// no null, alignment, or bounds guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_vtable_string_owner_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_string_owner_construct(
    this: *mut OpaqueVtableStringOwner,
    src_pair_at_4: *const u8,
    src_pair_at_12: *const u8,
) -> *mut OpaqueVtableStringOwner {
    unsafe {
        #[cfg(target_os = "none")]
        vtable_two_pair_base_construct(this.cast(), src_pair_at_4, src_pair_at_12);

        #[cfg(not(target_os = "none"))]
        {
            (*this).opaque_words[0] = src_pair_at_4.cast::<u32>().read_volatile();
            (*this).opaque_words[1] = src_pair_at_4.add(4).cast::<u32>().read_volatile();
            (*this).opaque_words[2] = src_pair_at_12.cast::<u32>().read_volatile();
            (*this).opaque_words[3] = src_pair_at_12.add(4).cast::<u32>().read_volatile();
        }

        (*this).vtable = OPAQUE_VTABLE_STRING_OWNER_VTABLE;
        string_default_construct(&mut (*this).string);

        #[cfg(target_os = "none")]
        store_u32_pair(this.cast::<u8>().add(28).cast(), 0, 0);

        #[cfg(not(target_os = "none"))]
        store_u32_pair((*this).trailing_pair.as_mut_ptr(), 0, 0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn constructs_base_empty_string_and_zero_pair() {
        let mut owner = OpaqueVtableStringOwner {
            vtable: usize::MAX,
            opaque_words: [u32::MAX; 4],
            string: super::super::string_object::StringObject {
                vtable: core::ptr::null(),
                payload: 1usize as *mut u8,
            },
            trailing_pair: [u32::MAX; 2],
        };
        let pair_at_4: [u32; 2] = [0xdead_beef, 0x0bad_f00d];
        let pair_at_12: [u32; 2] = [0x1234_5678, 0x9abc_def0];

        let returned = unsafe {
            opaque_vtable_string_owner_construct(
                &mut owner,
                pair_at_4.as_ptr().cast(),
                pair_at_12.as_ptr().cast(),
            )
        };

        assert!(core::ptr::eq(returned, &mut owner));
        assert_eq!(owner.vtable, OPAQUE_VTABLE_STRING_OWNER_VTABLE);
        assert_eq!(owner.opaque_words, [0xdead_beef, 0x0bad_f00d, 0x1234_5678, 0x9abc_def0]);
        assert!(core::ptr::eq(owner.string.vtable, &STRING_OBJECT_VTABLE));
        assert!(owner.string.payload.is_null());
        assert_eq!(owner.trailing_pair, [0, 0]);
    }

}
