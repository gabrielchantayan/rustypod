//! Reset the string-and-child owner, FUN_0818bf34 @ 0x0818bf34.
//!
//! True extent: 92 bytes through 0x0818bf90 (88 code, 4-byte empty
//! string). Raw aligned A32 scan: two inbound plain BLs at 0x0818bf1c
//! and 0x0818cb1c, no predicated BLs. Body: one plain BL to
//! string_object_assign_cstr @ 0x0827639c, no predicated BLs, two BLXNE.
//! Assign the empty string, clear state and flag, release and clear each
//! derived child in order, then clear trailing state.
//!
//! Deliberate deviations: the constant-empty assignment is lowered to its
//! verified virtual slot +0xc directly, avoiding the existing assignment
//! port's unwired no-op boundary. repr(C) pointers widen on hosts; virtual
//! slot indices retain target layout. No concrete class identity is inferred.

use super::string_child_owner_destruct::StringChildOwner;

/// Reset a live owner, preserving all unowned fields and flag padding.
///
/// # Safety
/// `owner`, its string vtable slot 3, and each non-NULL child release slot
/// must be valid. Callbacks must obey the original ownership protocol.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_child_owner_reset(owner: *mut StringChildOwner) {
    let string = core::ptr::addr_of_mut!((*owner).string);
    let clear: unsafe extern "C" fn(*mut crate::cxx::string_object::StringObject) =
        core::mem::transmute((*(*string).vtable).slots[3]);
    clear(string);
    (*owner).state = 0;
    (*owner).flag = 0;
    let first = (*owner).derived_first;
    if !first.is_null() {
        ((*(*first).vtable).release)(first);
    }
    (*owner).derived_first = core::ptr::null_mut();
    let second = (*owner).derived_second;
    if !second.is_null() {
        ((*(*second).vtable).release)(second);
    }
    (*owner).derived_second = core::ptr::null_mut();
    (*owner).trailing_state = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::buffer_pool_owner_destruct::{ReleaseObject, ReleaseVtable};
    use crate::cxx::string_object::{StringObject, StringObjectVtable};
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    static OWNER: AtomicPtr<StringChildOwner> = AtomicPtr::new(core::ptr::null_mut());
    static RELEASES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn clear(string: *mut StringObject) {
        let owner = OWNER.load(Ordering::Relaxed);
        assert_eq!(string, core::ptr::addr_of_mut!((*owner).string));
        assert_eq!((*owner).state, 7);
        assert_eq!((*owner).flag, 1);
        (*string).payload = core::ptr::null_mut();
    }
    unsafe extern "C" fn release(child: *mut ReleaseObject) {
        let owner = OWNER.load(Ordering::Relaxed);
        assert!((*owner).string.payload.is_null());
        assert_eq!((*owner).state, 0);
        assert_eq!((*owner).flag, 0);
        assert_eq!((*owner).trailing_state, 9);
        if child == (*owner).derived_second {
            assert!((*owner).derived_first.is_null());
        } else {
            assert_eq!(child, (*owner).derived_first);
        }
        RELEASES.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn optional_children_release_in_order_without_touching_unowned_fields() {
        let vtable = StringObjectVtable { slots: [0, 0, 0, clear as *const () as usize, 0, 0] };
        let release_vtable = ReleaseVtable { primary: 0, release };
        for mask in 0..4 {
            let mut first = ReleaseObject { vtable: &release_vtable };
            let mut second = ReleaseObject { vtable: &release_vtable };
            let mut payload = 42u8;
            let mut owner = StringChildOwner {
                vtable: 0x1234, reserved: [0xfeed; 4],
                base_first: &mut first, base_second: &mut second,
                string: StringObject { vtable: &vtable, payload: &mut payload },
                unknown_24: 0x5678, state: 7, flag: 1, padding: [0xab; 3],
                derived_first: if mask & 1 != 0 { &mut first } else { core::ptr::null_mut() },
                derived_second: if mask & 2 != 0 { &mut second } else { core::ptr::null_mut() },
                trailing_state: 9,
            };
            OWNER.store(&mut owner, Ordering::Relaxed);
            RELEASES.store(0, Ordering::Relaxed);
            unsafe { string_child_owner_reset(&mut owner); }
            assert_eq!(RELEASES.load(Ordering::Relaxed), (mask as u32).count_ones() as usize);
            assert!(owner.derived_first.is_null() && owner.derived_second.is_null());
            assert_eq!((owner.state, owner.flag, owner.trailing_state), (0, 0, 0));
            assert_eq!(owner.vtable, 0x1234);
            assert_eq!(owner.reserved, [0xfeed; 4]);
            assert_eq!(owner.unknown_24, 0x5678);
            assert_eq!(owner.padding, [0xab; 3]);
            assert_eq!(owner.base_first, &mut first as *mut _);
            assert_eq!(owner.base_second, &mut second as *mut _);
        }
    }
}
