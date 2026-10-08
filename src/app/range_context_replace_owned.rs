//! `range_context_replace_owned` — `FUN_08140534` @ 0x08140534.
//!
//! True extent: 8 bytes [0x08140534,0x0814053c), words e2800034 ea0a9bad.
//! Zero outgoing plain or predicated BLs; two incoming plain BLs at
//! 0x081dcdf0 and 0x081dce20, zero predicated incoming BLs. The next real
//! function begins with push {r4,r5,r6,lr}. The wrapper adds +0x34 and
//! tail-branches to 0x083e73f4 (48 bytes, ending before 0x083e7424).
//! That helper leaves an identical pointer alone, otherwise invokes a
//! non-NULL old object's virtual slot +4 before publishing the replacement.
//! Its sole call is a predicated register BLX, not a direct BL.
//!
//! Deliberate deviations: inline the verified tail helper rather than add
//! an unported seam; use the existing owned-member types. repr(C) pointers
//! widen on hosts, preserving field order rather than literal host offsets.
//! No concrete identity is claimed for the virtual release method.

use super::owned_virtual_member_clear::OwnedVirtualMember;

#[repr(C)]
pub struct RangeOwnedContext {
    pub opaque_prefix: [u32; 13],
    pub owned: *mut OwnedVirtualMember,
}

/// # Safety
/// Context must be writable. A different non-NULL old member must have a
/// valid release slot, whose callback must leave the context writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn range_context_replace_owned(
    context: *mut RangeOwnedContext, replacement: *mut OwnedVirtualMember,
) {
    let slot = core::ptr::addr_of_mut!((*context).owned);
    let old = slot.read_volatile();
    if old == replacement {
        return;
    }
    if !old.is_null() {
        ((*(*old).vtable).release)(old);
    }
    slot.write_volatile(replacement);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::owned_virtual_member_clear::OwnedVirtualMemberVtable;

    #[repr(C)]
    struct Member {
        base: OwnedVirtualMember,
        owner: *mut RangeOwnedContext,
        calls: u32,
        saw_old: bool,
    }

    unsafe extern "C" fn release(old: *mut OwnedVirtualMember) {
        let member = old.cast::<Member>();
        (*member).calls += 1;
        (*member).saw_old = (*(*member).owner).owned == old;
        (*(*member).owner).owned = core::ptr::dangling_mut();
    }

    #[test]
    fn null_and_identical_members_do_not_dispatch() {
        let mut owner = RangeOwnedContext { opaque_prefix: [0x12345678; 13], owned: core::ptr::null_mut() };
        // An identical pointer need not even have a readable vtable.
        for pointer in [core::ptr::null_mut(), core::ptr::dangling_mut()] {
            owner.owned = pointer;
            unsafe { range_context_replace_owned(&mut owner, pointer); }
            assert_eq!(owner.owned, pointer);
            assert_eq!(owner.opaque_prefix, [0x12345678; 13]);
        }
        owner.owned = core::ptr::null_mut();
        let replacement = core::ptr::dangling_mut();
        unsafe { range_context_replace_owned(&mut owner, replacement); }
        assert_eq!(owner.owned, replacement);
    }

    #[test]
    fn releases_old_before_publishing_even_when_callback_changes_slot() {
        for clear in [false, true] {
            let vtable = OwnedVirtualMemberVtable { reserved: 0, release };
            let mut owner = RangeOwnedContext { opaque_prefix: [0x87654321; 13], owned: core::ptr::null_mut() };
            let mut old = Member { base: OwnedVirtualMember { vtable: &vtable }, owner: &mut owner, calls: 0, saw_old: false };
            let mut new = Member { base: OwnedVirtualMember { vtable: &vtable }, owner: &mut owner, calls: 0, saw_old: false };
            owner.owned = &mut old.base;
            let replacement = if clear { core::ptr::null_mut() } else { &mut new.base };
            unsafe { range_context_replace_owned(&mut owner, replacement); }
            assert_eq!(old.calls, 1);
            assert!(old.saw_old);
            assert_eq!(new.calls, 0);
            assert_eq!(owner.owned, replacement);
            assert_eq!(owner.opaque_prefix, [0x87654321; 13]);
            unsafe { range_context_replace_owned(&mut owner, replacement); }
            assert_eq!(old.calls, 1);
            assert_eq!(new.calls, 0);
        }
    }
}
