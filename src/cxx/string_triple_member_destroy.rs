//! Three-string member destructor — `FUN_082a95f0` @ `0x082a95f0`.
//!
//! True extent: 44 bytes, `0x082a95f0..0x082a961c`; the next independent
//! function starts at `0x082a961c`. Raw A32 words verify three unconditional
//! outbound BLs to `cxx_string_release` @ `0x083d8b04`, zero predicated BLs,
//! and two unconditional inbound BLs at `0x082a7d44` and `0x082a95e4`.
//! Releases the COW string slots at +0x1c, +0x18, then +0x14 and returns
//! the original object pointer without modifying its prefix or string slots.
//! No NULL guard, vtable store, or object deallocation occurs.
//!
//! Deliberate deviations: none on target. Host pointer fields widen naturally
//! through `repr(C)` rather than overlapping at four-byte byte offsets.

use crate::cxx::string::cxx_string_release;

/// Only the layout observed by this destructor; the prefix remains opaque.
#[repr(C)]
pub struct CxxStringTripleMemberObject {
    pub prefix: [u32; 5],
    pub first: *mut u8,
    pub second: *mut u8,
    pub third: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(CxxStringTripleMemberObject, first)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(CxxStringTripleMemberObject, second)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(CxxStringTripleMemberObject, third)];

/// Releases the three members in reverse order, preserving the object address.
///
/// # Safety
/// `object` must be writable and contain three valid owned COW string slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_triple_member_destroy(
    object: *mut CxxStringTripleMemberObject,
) -> *mut CxxStringTripleMemberObject {
    unsafe {
        cxx_string_release(core::ptr::addr_of_mut!((*object).third));
        cxx_string_release(core::ptr::addr_of_mut!((*object).second));
        cxx_string_release(core::ptr::addr_of_mut!((*object).first));
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::{empty_rep_data, StringRep};

    #[repr(C)]
    struct SharedString {
        rep: StringRep,
        bytes: [u8; 4],
    }

    fn shared(refcount: i32) -> SharedString {
        SharedString { rep: StringRep { refcount, capacity: 3, length: 3 }, bytes: *b"abc\0" }
    }

    #[test]
    fn releases_distinct_members_without_changing_object_storage() {
        let mut first = shared(1);
        let mut second = shared(4);
        let mut third = shared(2);
        let slots = [first.bytes.as_mut_ptr(), second.bytes.as_mut_ptr(), third.bytes.as_mut_ptr()];
        let mut object = CxxStringTripleMemberObject {
            prefix: [0x12345678, 2, 3, 4, 0xabcdef01],
            first: slots[0], second: slots[1], third: slots[2],
        };
        let prefix = object.prefix;
        let address = &mut object as *mut _;
        assert_eq!(unsafe { cxx_string_triple_member_destroy(address) }, address);
        assert_eq!([first.rep.refcount, second.rep.refcount, third.rep.refcount], [0, 3, 1]);
        assert_eq!(object.prefix, prefix);
        assert_eq!([object.first, object.second, object.third], slots);
    }

    #[test]
    fn aliasing_members_each_release_a_reference() {
        let mut shared = shared(3);
        let data = shared.bytes.as_mut_ptr();
        let mut object = CxxStringTripleMemberObject {
            prefix: [0; 5], first: data, second: data, third: data,
        };
        unsafe { cxx_string_triple_member_destroy(&mut object); }
        assert_eq!(shared.rep.refcount, 0);
        assert_eq!(shared.bytes, *b"abc\0");
    }

    #[test]
    fn shared_empty_members_are_not_modified() {
        let empty = empty_rep_data();
        let mut object = CxxStringTripleMemberObject {
            prefix: [7; 5], first: empty, second: empty, third: empty,
        };
        unsafe { cxx_string_triple_member_destroy(&mut object); }
        assert_eq!([object.first, object.second, object.third], [empty; 3]);
        assert_eq!(object.prefix, [7; 5]);
    }
}
