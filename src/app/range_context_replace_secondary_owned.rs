//! `range_context_replace_secondary_owned` — `FUN_08140514` @ 0x08140514.
//!
//! True extent: 8 bytes [0x08140514,0x0814051c), words e2800038 ea0a9bb5.
//! Two incoming plain BLs (0x081dcd5c, 0x081dcea4), zero predicated BLs;
//! zero outgoing BLs. The independently called function at 0x0814051c
//! begins with ldr r2,[r0,#0x40]. Add +0x38 and tail-branch to the verified
//! 48-byte helper at 0x083e73f4: return on pointer identity, release a
//! non-NULL old member through vtable slot +4, then publish replacement.
//! The helper has one BLXNE and no direct BLs; it ends at 0x083e7424.
//!
//! Deliberate deviations: inline the verified helper, matching the existing
//! +0x34 owned-context port, without inventing a virtual callee identity.
//! repr(C) preserves target offsets and widens pointers on hosts. Volatile
//! slot accesses preserve publication after a callback that mutates the slot.

use super::owned_virtual_member_clear::OwnedVirtualMember;

#[repr(C)]
pub struct RangeSecondaryOwnedContext {
    pub opaque_prefix: [u32; 14],
    pub owned: *mut OwnedVirtualMember,
}

/// # Safety
/// Context must be writable. A different non-NULL old member must have a
/// valid release slot, whose callback must leave the context writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn range_context_replace_secondary_owned(
    context: *mut RangeSecondaryOwnedContext, replacement: *mut OwnedVirtualMember,
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
        owner: *mut RangeSecondaryOwnedContext,
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
    fn identity_needs_no_readable_vtable_and_empty_slot_accepts_replacement() {
        let mut owner = RangeSecondaryOwnedContext { opaque_prefix: [0x12345678; 14], owned: core::ptr::null_mut() };
        for pointer in [core::ptr::null_mut(), core::ptr::dangling_mut()] {
            owner.owned = pointer;
            unsafe { range_context_replace_secondary_owned(&mut owner, pointer); }
            assert_eq!(owner.owned, pointer);
            assert_eq!(owner.opaque_prefix, [0x12345678; 14]);
        }
        owner.owned = core::ptr::null_mut();
        let replacement = core::ptr::dangling_mut();
        unsafe { range_context_replace_secondary_owned(&mut owner, replacement); }
        assert_eq!(owner.owned, replacement);
    }

    #[test]
    fn release_observes_old_and_callback_mutation_does_not_override_replacement() {
        for clear in [false, true] {
            let vtable = OwnedVirtualMemberVtable { reserved: 0, release };
            let mut owner = RangeSecondaryOwnedContext { opaque_prefix: [0x87654321; 14], owned: core::ptr::null_mut() };
            let mut old = Member { base: OwnedVirtualMember { vtable: &vtable }, owner: &mut owner, calls: 0, saw_old: false };
            let mut new = Member { base: OwnedVirtualMember { vtable: &vtable }, owner: &mut owner, calls: 0, saw_old: false };
            owner.owned = &mut old.base;
            let replacement = if clear { core::ptr::null_mut() } else { &mut new.base };
            unsafe { range_context_replace_secondary_owned(&mut owner, replacement); }
            assert_eq!(old.calls, 1);
            assert!(old.saw_old);
            assert_eq!(new.calls, 0);
            assert_eq!(owner.owned, replacement);
            assert_eq!(owner.opaque_prefix, [0x87654321; 14]);
            unsafe { range_context_replace_secondary_owned(&mut owner, replacement); }
            assert_eq!(old.calls, 1);
            assert_eq!(new.calls, 0);
        }
    }
}
