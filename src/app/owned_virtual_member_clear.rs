//! Clear an owned member through its virtual release method.
//!
//! retailOS `FUN_08186dc4` at `0x08186dc4`, true size 48 bytes:
//! [0x08186dc4,0x08186df4). The next function starts with push {r4-r6,lr}.
//! Whole-image raw A32 decoding verifies two inbound plain BLs at
//! 0x0839c3b4 and 0x0839c3f8, zero predicated inbound BLs. The body has
//! zero plain/predicated BLs and one register BLX at 0x08186de0.
//! If owner word 1 is non-NULL, call that object's vtable word 1 with the
//! object as r0, then clear owner word 1. Return the original owner pointer.
//! Callers subsequently delete the returned owner. The virtual method's
//! concrete identity and class identity are not established.
//!
//! Deliberate deviations: repr(C) pointers widen on hosts, retaining field
//! and vtable word order instead of host byte offsets. No target deviations.

#[repr(C)]
pub struct OwnedVirtualMemberVtable {
    pub reserved: usize,
    pub release: unsafe extern "C" fn(*mut OwnedVirtualMember),
}

#[repr(C)]
pub struct OwnedVirtualMember {
    pub vtable: *const OwnedVirtualMemberVtable,
}

#[repr(C)]
pub struct VirtualMemberOwner {
    pub opaque_header: usize,
    pub member: *mut OwnedVirtualMember,
}

/// The owner must be writable. A non-NULL member must have a valid vtable
/// with a callable release slot; release must leave the owner writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_virtual_member_clear(owner: *mut VirtualMemberOwner) -> *mut VirtualMemberOwner {
    let member = (*owner).member;
    if !member.is_null() {
        ((*(*member).vtable).release)(member);
        (*owner).member = core::ptr::null_mut();
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct FixtureMember {
        base: OwnedVirtualMember,
        owner: *mut VirtualMemberOwner,
        calls: u32,
        observed_live_member: bool,
    }

    unsafe extern "C" fn release(member: *mut OwnedVirtualMember) {
        let fixture = member.cast::<FixtureMember>();
        (*fixture).calls += 1;
        let owner = (*fixture).owner;
        (*fixture).observed_live_member = (*owner).member == member;
        // A release callback may change the slot; the stock final store must
        // still clear it rather than preserving the callback's replacement.
        (*owner).member = core::ptr::dangling_mut::<OwnedVirtualMember>();
    }

    #[test]
    fn absent_member_preserves_header_and_returns_owner() {
        for header in [0, usize::MAX, 0x12345678] {
            let mut owner = VirtualMemberOwner { opaque_header: header, member: core::ptr::null_mut() };
            let result = unsafe { owned_virtual_member_clear(&mut owner) };
            assert_eq!(result, &mut owner as *mut _);
            assert_eq!(owner.opaque_header, header);
            assert!(owner.member.is_null());
        }
    }

    #[test]
    fn releases_before_clearing_overwrites_callback_replacement_and_is_idempotent() {
        let vtable = OwnedVirtualMemberVtable { reserved: usize::MAX, release };
        let mut owner = VirtualMemberOwner { opaque_header: 0x87654321, member: core::ptr::null_mut() };
        let mut member = FixtureMember {
            base: OwnedVirtualMember { vtable: &vtable }, owner: &mut owner,
            calls: 0, observed_live_member: false,
        };
        owner.member = &mut member.base;
        let result = unsafe { owned_virtual_member_clear(&mut owner) };
        assert_eq!(result, &mut owner as *mut _);
        assert!(member.observed_live_member);
        assert_eq!(member.calls, 1);
        assert!(owner.member.is_null());
        assert_eq!(owner.opaque_header, 0x87654321);
        unsafe { owned_virtual_member_clear(&mut owner); }
        assert_eq!(member.calls, 1);
        assert!(owner.member.is_null());
    }
}
