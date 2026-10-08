//! Reset profile members — retailOS `0x0812b6a8`.
//!
//! True extent: 60 bytes, [0x0812b6a8, 0x0812b6e4), ending POP {r4,pc};
//! the next entry is a branch veneer. Whole-image A32 decoding verifies one
//! plain incoming BL (0x0812af48), one BLNE (0x081299a4), zero outgoing
//! BLs, and two outgoing BLXNE register calls. Dispatch virtual slot +0x30
//! on non-null members +0xa8 then +0xac, loading the latter after the first
//! callback. Clear the active member word +0xb0 only after both calls.
//! Callers reset profile state or change its selected mode. The concrete
//! virtual method identity is unknown; no fixed-address seam is introduced.
//!
//! Deliberate deviations: repr(C) pointers widen on hosts; ARM offsets are
//! checked below. Incidental return-register contents are not exposed.

#[repr(C)]
pub struct ProfileMemberVtable {
    pub reserved: [usize; 12],
    pub reset: unsafe extern "C" fn(*mut ProfileMember),
}

#[repr(C)]
pub struct ProfileMember {
    pub vtable: *const ProfileMemberVtable,
}

#[repr(C)]
pub struct ProfileMembers {
    pub reserved: [u32; 42],
    pub first: *mut ProfileMember,
    pub second: *mut ProfileMember,
    pub active: u32,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ProfileMemberVtable, reset) == 0x30);
    assert!(core::mem::offset_of!(ProfileMembers, first) == 0xa8);
    assert!(core::mem::offset_of!(ProfileMembers, second) == 0xac);
    assert!(core::mem::offset_of!(ProfileMembers, active) == 0xb0);
};

/// # Safety
/// The profile must be live and aligned. Each non-null member must have a
/// live vtable whose slot +0x30 implements this ABI. Callbacks must leave
/// the profile live and the subsequently loaded member valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn profile_members_reset(profile: *mut ProfileMembers) {
    let first = (*profile).first;
    if !first.is_null() {
        ((*(*first).vtable).reset)(first);
    }
    let second = (*profile).second;
    if !second.is_null() {
        ((*(*second).vtable).reset)(second);
    }
    (*profile).active = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[repr(C)]
    struct Member {
        base: ProfileMember,
        owner: *mut ProfileMembers,
        replacement: *mut ProfileMember,
        replace_second: bool,
        count: u32,
        payload: u32,
    }

    unsafe extern "C" fn reset(member: *mut ProfileMember) {
        let member = member.cast::<Member>();
        let owner = (*member).owner;
        assert_ne!((*owner).active, 0);
        (*member).count += 1;
        (*member).payload = 0;
        if (*member).replace_second {
            (*owner).second = (*member).replacement;
        }
        (*owner).active = 0x12345678;
    }

    fn profile() -> ProfileMembers {
        ProfileMembers { reserved: [0xdeadbeef; 42], first: null_mut(),
            second: null_mut(), active: u32::MAX }
    }

    fn member(vtable: &ProfileMemberVtable, owner: &mut ProfileMembers) -> Member {
        Member { base: ProfileMember { vtable }, owner, replacement: null_mut(),
            replace_second: false, count: 0, payload: u32::MAX }
    }

    #[test]
    fn null_combinations_preserve_members_and_opaque_words() {
        let vtable = ProfileMemberVtable { reserved: [0; 12], reset };
        for mask in 0..4 {
            let mut owner = profile();
            let mut first = member(&vtable, &mut owner);
            let mut second = member(&vtable, &mut owner);
            if mask & 1 != 0 { owner.first = &mut first.base; }
            if mask & 2 != 0 { owner.second = &mut second.base; }
            let pointers = (owner.first, owner.second);
            unsafe { profile_members_reset(&mut owner); }
            assert_eq!(first.count, mask & 1);
            assert_eq!(second.count, (mask >> 1) & 1);
            assert_eq!(first.payload, if mask & 1 != 0 { 0 } else { u32::MAX });
            assert_eq!(second.payload, if mask & 2 != 0 { 0 } else { u32::MAX });
            assert_eq!(owner.active, 0);
            assert_eq!((owner.first, owner.second), pointers);
            assert_eq!(owner.reserved, [0xdeadbeef; 42]);
        }
    }

    #[test]
    fn first_callback_replaces_or_clears_second_before_it_is_loaded() {
        let vtable = ProfileMemberVtable { reserved: [0; 12], reset };
        for clear in [false, true] {
            let mut owner = profile();
            let mut first = member(&vtable, &mut owner);
            let mut stale = member(&vtable, &mut owner);
            let mut replacement = member(&vtable, &mut owner);
            first.replace_second = true;
            first.replacement = if clear { null_mut() } else { &mut replacement.base };
            owner.first = &mut first.base;
            owner.second = &mut stale.base;
            unsafe { profile_members_reset(&mut owner); }
            assert_eq!(first.count, 1);
            assert_eq!(stale.count, 0);
            assert_eq!(stale.payload, u32::MAX);
            assert_eq!(replacement.count, if clear { 0 } else { 1 });
            assert_eq!(owner.second, first.replacement);
            assert_eq!(owner.active, 0);
        }
    }

    #[test]
    fn aliased_members_are_dispatched_twice() {
        let vtable = ProfileMemberVtable { reserved: [0; 12], reset };
        let mut owner = profile();
        let mut shared = member(&vtable, &mut owner);
        owner.first = &mut shared.base;
        owner.second = &mut shared.base;
        unsafe { profile_members_reset(&mut owner); }
        assert_eq!(shared.count, 2);
        assert_eq!(shared.payload, 0);
        assert_eq!(owner.active, 0);
    }
}
