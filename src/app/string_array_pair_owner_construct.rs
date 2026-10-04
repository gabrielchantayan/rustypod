//! Composite string/observable-array owner constructor, FUN_082107f0 @ 0x082107f0.
//! True extent: 84 bytes, 0x082107f0..0x08210844 (80 code bytes plus
//! vtable literal 0x089928d4). The next function begins at 0x08210844.
//! Whole-image A32 decoding finds two inbound plain BLs at 0x08210494 and
//! 0x082104d0; the body has six plain BLs. No predicated BLs in either direction.
//! Install the vtable, clear the owned-member word, construct strings at +0x0c,
//! +0x50, +0x58 and array pairs at +0x28, +0x70 in that order, then reset
//! through resident 0x08210528. Each member return determines the next base.
//! Deliberate deviations: native string pointers expand host layout; repr(C)
//! fields and offset differences preserve target layout and return rebasing.
//! The unported reset has a host injection seam, but target calls resident code.
//! Concrete class identity is not recovered; the name describes its members.

use crate::cxx::observable_array_pair::{observable_array_pair_construct, ObservableArrayPair};
use crate::cxx::string_object::{string_default_construct, StringObject};
use core::mem::offset_of;
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct StringArrayPairOwner {
    pub vtable: u32,
    pub opaque_word: u32,
    pub owned_member: u32,
    pub primary_string: StringObject,
    pub primary_state: [u32; 5],
    pub first_pair: ObservableArrayPair,
    pub secondary_string: StringObject,
    pub tertiary_string: StringObject,
    pub secondary_state: [u32; 4],
    pub second_pair: ObservableArrayPair,
}

#[cfg(target_os = "none")]
const _: [u8; 0x98] = [0; core::mem::size_of::<StringArrayPairOwner>()];
#[cfg(target_os = "none")]
const _: [u8; 0x70] = [0; offset_of!(StringArrayPairOwner, second_pair)];

pub type StringArrayPairOwnerReset = unsafe extern "C" fn(*mut StringArrayPairOwner);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reset(_: *mut StringArrayPairOwner) {
    panic!("install resident string/array-pair owner reset");
}
#[cfg(not(target_os = "none"))]
pub static mut STRING_ARRAY_PAIR_OWNER_RESET: StringArrayPairOwnerReset = missing_reset;

/// # Safety
/// `owner` must be aligned writable storage for the whole object. The resident
/// reset routine's requirements apply; hosts must install an equivalent reset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_array_pair_owner_construct(
    owner: *mut StringArrayPairOwner,
) -> *mut StringArrayPairOwner {
    #[cfg(target_os = "none")]
    let reset: StringArrayPairOwnerReset = core::mem::transmute(0x0821_0528usize);
    #[cfg(not(target_os = "none"))]
    let reset = core::ptr::addr_of!(STRING_ARRAY_PAIR_OWNER_RESET).read_volatile();
    construct(owner, reset)
}

unsafe fn construct(mut owner: *mut StringArrayPairOwner, reset: StringArrayPairOwnerReset)
    -> *mut StringArrayPairOwner {
    addr_of_mut!((*owner).vtable).write_volatile(0x0899_28d4);
    addr_of_mut!((*owner).owned_member).write_volatile(0);
    let string = string_default_construct(addr_of_mut!((*owner).primary_string));
    owner = string.cast::<u8>().sub(offset_of!(StringArrayPairOwner, primary_string)).cast();
    let pair = observable_array_pair_construct(addr_of_mut!((*owner).first_pair));
    owner = pair.cast::<u8>().sub(offset_of!(StringArrayPairOwner, first_pair)).cast();
    let string = string_default_construct(addr_of_mut!((*owner).secondary_string));
    owner = string.cast::<u8>().sub(offset_of!(StringArrayPairOwner, secondary_string)).cast();
    let string = string_default_construct(addr_of_mut!((*owner).tertiary_string));
    owner = string.cast::<u8>().sub(offset_of!(StringArrayPairOwner, tertiary_string)).cast();
    let pair = observable_array_pair_construct(addr_of_mut!((*owner).second_pair));
    owner = pair.cast::<u8>().sub(offset_of!(StringArrayPairOwner, second_pair)).cast();
    reset(owner);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    unsafe extern "C" fn check_before_reset(owner: *mut StringArrayPairOwner) {
        let owner = &mut *owner;
        assert_eq!(owner.vtable, 0x0899_28d4);
        assert_eq!(owner.owned_member, 0);
        for string in [&owner.primary_string, &owner.secondary_string, &owner.tertiary_string] {
            assert!(core::ptr::eq(string.vtable, &STRING_OBJECT_VTABLE));
            assert!(string.payload.is_null());
        }
        for pair in [&owner.first_pair, &owner.second_pair] {
            assert_eq!(pair.leading_words, [0, 0]);
            // Verify all four words of each target-width array, including vtable.
            for array in [&pair.first, &pair.second] {
                let words = core::slice::from_raw_parts(core::ptr::from_ref(array).cast::<u32>(), 4);
                assert_eq!(words, &[0x089a_5d0c, 0, 0, 0]);
            }
        }
        owner.owned_member = 0x1234;
    }

    #[test]
    fn initializes_dirty_members_without_clearing_unowned_state() {
        for fill in [0u8, 0x55, 0xff] {
            let mut storage = core::mem::MaybeUninit::<StringArrayPairOwner>::uninit();
            unsafe {
                storage.as_mut_ptr().cast::<u8>().write_bytes(fill, core::mem::size_of::<StringArrayPairOwner>());
                let owner = storage.as_mut_ptr();
                assert_eq!(construct(owner, check_before_reset), owner);
                let owner = &*owner;
                let word = u32::from_ne_bytes([fill; 4]);
                assert_eq!(owner.opaque_word, word);
                assert_eq!(owner.primary_state, [word; 5]);
                assert_eq!(owner.secondary_state, [word; 4]);
                assert_eq!(owner.owned_member, 0x1234);
            }
        }
    }
}
