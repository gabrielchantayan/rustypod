//! Clears resource-registration state and registers its six reserved IDs.
//!
//! `resource_registration_reset` — original: `FUN_081a45c4` @ `0x081a45c4`.
//! Raw ARM establishes the true 188-byte extent `0x081a45c4..0x081a4680`:
//! the final `bx r3` tail dispatch is at `0x081a467c` and its literal pool
//! begins at `0x081a4680`. Raw whole-image decoding finds four inbound direct
//! unconditional `bl` calls (0x081a3160, 0x081a3ab4, 0x081a3e34, 0x081a5048)
//! and no predicated forms. The body has five unconditional indirect `blx`
//! calls and one unconditional indirect `bx` tail dispatch.
//!
//! # Algorithm
//!
//! Clear bytes `+0x80..+0x84` and the halfword at `+0x86`, then invoke vtable
//! slot `+0x58` six times with the group marker `0x2a2a2a2a` and consecutive
//! resource IDs `0x3d0a..=0x3d0f`.
//!
//! # Deliberate deviation
//!
//! Firmware pointers and vtable words are 32 bits. Host fixtures use native
//! pointers, so their physical field offsets differ; the target-only
//! assertions preserve the verified ARM offsets.

use core::ptr::{addr_of, read_volatile};

const RESOURCE_GROUP_MARKER: u32 = 0x2a2a_2a2a;
const FIRST_RESOURCE_ID: u32 = 0x3d0a;
const REGISTER_RESOURCE_SLOT: usize = 0x58 / core::mem::size_of::<usize>();

pub type RegisterResource = unsafe extern "C" fn(*mut ResourceRegistrationObject, u32, u32);

#[repr(C)]
pub struct ResourceRegistrationVtable {
    pub unresolved_00: [usize; REGISTER_RESOURCE_SLOT],
    pub register_resource: RegisterResource,
}

#[repr(C)]
pub struct ResourceRegistrationObject {
    pub vtable: *const ResourceRegistrationVtable,
    pub unresolved_04_to_7f: [u8; 0x7c],
    pub state_80_to_84: [u8; 5],
    pub unresolved_85: u8,
    pub state_86: u16,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x58] = [0; core::mem::offset_of!(ResourceRegistrationVtable, register_resource)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x80] = [0; core::mem::offset_of!(ResourceRegistrationObject, state_80_to_84)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x86] = [0; core::mem::offset_of!(ResourceRegistrationObject, state_86)];
#[inline(always)]
unsafe fn register_resource(object: *mut ResourceRegistrationObject, resource_id: u32) {
    let vtable = read_volatile(addr_of!((*object).vtable));
    let callback = read_volatile(addr_of!((*vtable).register_resource));
    callback(object, RESOURCE_GROUP_MARKER, resource_id);
}


/// Clears registration state and registers the six fixed resource IDs.
///
/// # Safety
/// `object` must point to a writable firmware object with a valid vtable and
/// callable `register_resource` slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_registration_reset(object: *mut ResourceRegistrationObject) {
    (*object).state_80_to_84 = [0; 5];
    (*object).state_86 = 0;

    register_resource(object, FIRST_RESOURCE_ID);
    register_resource(object, FIRST_RESOURCE_ID + 1);
    register_resource(object, FIRST_RESOURCE_ID + 2);
    register_resource(object, FIRST_RESOURCE_ID + 3);
    register_resource(object, FIRST_RESOURCE_ID + 4);
    register_resource(object, FIRST_RESOURCE_ID + 5);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(*mut ResourceRegistrationObject, u32, u32)> = Vec::new();

    unsafe extern "C" fn record_registration(
        object: *mut ResourceRegistrationObject,
        group: u32,
        resource_id: u32,
    ) {
        CALLS.push((object, group, resource_id));
    }

    #[test]
    fn clears_all_state_bytes_and_registers_consecutive_fixed_ids() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALLS.clear();
            let vtable = ResourceRegistrationVtable {
                unresolved_00: [0; REGISTER_RESOURCE_SLOT],
                register_resource: record_registration,
            };
            let mut object = ResourceRegistrationObject {
                vtable: &vtable,
                unresolved_04_to_7f: [0xa5; 0x7c],
                state_80_to_84: [0xff; 5],
                unresolved_85: 0x5a,
                state_86: 0xffff,
            };

            resource_registration_reset(&mut object);

            assert_eq!(object.state_80_to_84, [0; 5]);
            assert_eq!(object.state_86, 0);
            assert_eq!(object.unresolved_85, 0x5a);
            assert_eq!(object.unresolved_04_to_7f, [0xa5; 0x7c]);
            assert_eq!(CALLS.len(), 6);
            for (index, &(seen_object, group, resource_id)) in CALLS.iter().enumerate() {
                assert!(core::ptr::eq(seen_object, &mut object));
                assert_eq!(group, RESOURCE_GROUP_MARKER);
                assert_eq!(resource_id, FIRST_RESOURCE_ID + index as u32);
            }
        }
    }
}
