//! Image-format descriptor owner teardown; concrete C++ class name unresolved.
//!
//! Original `FUN_081fd0c0` @ `0x081fd0c0`: 56 bytes through the next real
//! boundary `0x081fd0f8` (52 instruction bytes plus vtable literal at +52).
//! Raw whole-image decoding finds two inbound plain BLs (0x0822bb48 and
//! 0x0822bb6c), zero predicated inbound BLs, and three outbound plain BLs.
//! Install vtable 0x08990e7c, release the handle at +0x2b0 using the slot-1
//! destructor template, invoke the empty descriptor-slots destructor at +0x1c,
//! recover the owner from its returned pointer, delete its mutex at +4, and
//! return the owner. No behavioral deviations. repr(C) expands pointer-bearing
//! fields on hosts; enclosing-object recovery uses the corresponding field
//! offset rather than assuming target byte offsets on a 64-bit host.
//! Codegen deviation: LLVM proves the existing empty destructor is identity
//! and removes its call and pointer recovery, despite inline(never). The two
//! emitted BL relocations retain the release-before-mutex-delete ordering.

use core::ptr::addr_of_mut;
use crate::cxx::empty_destructor_1d6030::empty_destructor_1d6030;
use crate::cxx::handle::{RefcountedBody, refcounted_body_release_slot1_copy};
use crate::kernel::sync_mutex::{Mutex, mutex_delete};

#[repr(C)]
pub struct ImageFormatDescriptorOwner {
    pub vtable: u32,
    pub mutex: Mutex,
    pub opaque_prefix: [u32; 4],
    pub descriptor_slots: [u32; 165],
    pub body: *mut RefcountedBody,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ImageFormatDescriptorOwner, mutex) == 4);
    assert!(core::mem::offset_of!(ImageFormatDescriptorOwner, descriptor_slots) == 0x1c);
    assert!(core::mem::offset_of!(ImageFormatDescriptorOwner, body) == 0x2b0);
};

/// # Safety
/// `owner` must be a valid writable owner, with a handle and mutex satisfying
/// the existing release/delete contracts. Destruction callbacks must leave the
/// enclosing owner alive. No NULL or bounds checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn image_format_descriptor_owner_destroy(
    owner: *mut ImageFormatDescriptorOwner,
) -> *mut ImageFormatDescriptorOwner {
    addr_of_mut!((*owner).vtable).write(0x0899_0e7c);
    refcounted_body_release_slot1_copy(addr_of_mut!((*owner).body));
    let slots = empty_destructor_1d6030(addr_of_mut!((*owner).descriptor_slots).cast());
    let owner = slots.cast::<u8>().sub(
        core::mem::offset_of!(ImageFormatDescriptorOwner, descriptor_slots),
    ).cast::<ImageFormatDescriptorOwner>();
    mutex_delete(addr_of_mut!((*owner).mutex));
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_shared_or_null_body_without_touching_descriptor_storage() {
        for count in [None, Some(2), Some(i32::MIN)] {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: count.unwrap_or(17),
                mutex: core::ptr::null_mut(),
            };
            let mut owner = ImageFormatDescriptorOwner {
                vtable: 0xdead_beef,
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0xaabb_ccdd },
                opaque_prefix: [0x1122_3344; 4],
                descriptor_slots: [0x5566_7788; 165],
                body: if count.is_some() { &mut body } else { core::ptr::null_mut() },
            };
            let expected = &mut owner as *mut ImageFormatDescriptorOwner;
            assert_eq!(unsafe { image_format_descriptor_owner_destroy(expected) }, expected);
            assert_eq!(owner.vtable, 0x0899_0e7c);
            assert!(owner.body.is_null());
            assert!(owner.mutex.sem_cell.is_null());
            assert_eq!(owner.mutex.unused, 0xaabb_ccdd);
            assert_eq!(owner.opaque_prefix, [0x1122_3344; 4]);
            assert_eq!(owner.descriptor_slots, [0x5566_7788; 165]);
            assert_eq!(body.refcount, count.map_or(17, |n| n.wrapping_sub(1)));
        }
    }
}
