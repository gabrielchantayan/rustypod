//! `owner_link_register` — FUN_0816874c @ 0x0816874c, true size 12 bytes.
//!
//! Raw words e1a01000 e5900004 eaffff7f move receiver to r1, load its
//! owner at +4 into r0, and tail-branch to 0x08168558. The next real
//! function starts at 0x08168758. Full-image aligned A32 decoding verifies
//! two inbound plain BL calls (0x0813b014, 0x081e2384), zero predicated
//! BL calls; the wrapper has zero outbound BLs and one tail branch.
//! Register the receiver with its owner. The unported destination locks
//! owner+4, checks membership, appends a missing receiver to the vector at
//! owner+0x14, conditionally dispatches it when owner+0x10 is nonzero, then
//! unlocks. Ghidra incorrectly expands that destination into this wrapper.
//! Deliberate deviations: host execution injects the destination; firmware
//! retains the verified retail address. No additional validation or guards.

use super::owner_link_base_construct::OwnerLinkBase;

type OwnerLinkRegistration = unsafe extern "C" fn(u32, *mut OwnerLinkBase);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_link_registration(_: u32, _: *mut OwnerLinkBase) {
    panic!("install owner-link registration for host execution")
}

/// Host dispatch for unported registration at 0x08168558.
/// Install only while no other thread is using this module.
#[cfg(not(target_os = "none"))]
pub static mut OWNER_LINK_REGISTRATION: OwnerLinkRegistration = missing_owner_link_registration;

/// # Safety
/// `receiver` must be readable and aligned, and its owner and derived object
/// must satisfy the retail registration destination's lifetime requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_link_register(receiver: *mut OwnerLinkBase) {
    #[cfg(target_os = "none")]
    let register: OwnerLinkRegistration = core::mem::transmute(0x0816_8558usize);
    #[cfg(not(target_os = "none"))]
    let register = core::ptr::read_volatile(core::ptr::addr_of!(OWNER_LINK_REGISTRATION));
    register((*receiver).owner, receiver);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn consume_owner(owner: u32, receiver: *mut OwnerLinkBase) {
        assert_eq!(owner, (*receiver).owner);
        // A real destination may modify the object; the wrapper must neither
        // copy it nor overwrite changes after returning from registration.
        (*receiver).owner = !owner;
    }

    // Explicit wrapper edge-case tests requested by the port assignment.
    #[test]
    fn preserves_target_width_owner_and_destination_mutations() {
        #[repr(C)]
        struct Derived { base: OwnerLinkBase, trailing: [u32; 2] }
        unsafe {
            let previous = OWNER_LINK_REGISTRATION;
            OWNER_LINK_REGISTRATION = consume_owner;
            for owner in [0, 1, 0x0800_0000, 0x8000_0000, u32::MAX] {
                let mut object = Derived {
                    base: OwnerLinkBase { vtable: 0x089a_746c, owner },
                    trailing: [0x1234_5678, 0x8765_4321],
                };
                owner_link_register(&mut object.base);
                assert_eq!(object.base.owner, !owner);
                assert_eq!(object.base.vtable, 0x089a_746c);
                assert_eq!(object.trailing, [0x1234_5678, 0x8765_4321]);
            }
            OWNER_LINK_REGISTRATION = previous;
        }
    }
}
