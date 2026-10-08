//! Reset a selection/context owner: FUN_0812f6ec @ 0x0812f6ec.
//!
//! Raw A32 extent [0x0812f6ec, 0x0812f754): 104 bytes, six plain
//! outgoing BLs, no predicated BLs. Whole-image word decoding finds two
//! plain incoming BLs (0x0811512c, 0x081304b8), no predicated callers.
//! Delete enabled container elements, clear the observable array, clear
//! two state words and two flag bytes, reset the value pair via the verified
//! helper at 0x0812f6b4, then copy a null-owner context into the member token.
//! The member's vtable and all unowned bytes remain unchanged.
//!
//! Deviations: repr(C) native pointers widen the host model; target offsets
//! remain exact. The value-pair reset uses the ported refcounted-handle helpers.
//! The empty context destructor may fold away; no incidental register return
//! is promised.

use super::scoped_context::{ScopedContext, scoped_context_construct,
    scoped_context_copy_fields, scoped_context_destroy};
#[cfg(not(target_arch = "arm"))]
use crate::cxx::observable_array::observable_array_clear;
use crate::cxx::templates::scoped_context_container_delete_enabled_elements;
#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn observable_array_clear(this: *mut crate::cxx::observable_array::ObservableArray);
}
use crate::cxx::handle::{RefcountedBody, refcounted_handle_construct,
    refcounted_handle_copy_assign, refcounted_body_release_dtor};

/// Container head shared by deletion and observable-array clear.
#[repr(C)]
pub struct SelectionContextArray {
    pub vtable: *const usize,
    pub count: i32,
    pub unknown_08: u32,
    pub unknown_0c: u32,
    pub delete_enabled: u8,
    pub unknown_11_17: [u8; 7],
}

#[repr(C)]
pub struct SelectionContextOwner {
    pub prefix: [u32; 6],
    pub array: SelectionContextArray,
    pub state_30: u32,
    pub state_34: u32,
    pub unknown_38_3a: [u8; 3],
    pub flag_3b: u8,
    pub unknown_3c_41: [u8; 6],
    pub flag_42: u8,
    pub unknown_43_73: [u8; 49],
    pub value_state: u32,
    pub value_pair: *mut RefcountedBody,
    pub context: ScopedContext,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(SelectionContextOwner, array) == 0x18);
    assert!(core::mem::offset_of!(SelectionContextOwner, state_30) == 0x30);
    assert!(core::mem::offset_of!(SelectionContextOwner, flag_3b) == 0x3b);
    assert!(core::mem::offset_of!(SelectionContextOwner, flag_42) == 0x42);
    assert!(core::mem::offset_of!(SelectionContextOwner, value_state) == 0x74);
    assert!(core::mem::offset_of!(SelectionContextOwner, value_pair) == 0x78);
    assert!(core::mem::offset_of!(SelectionContextOwner, context) == 0x7c);
};

/// Reset the selected value handle — FUN_0812f6b4 @ 0x0812f6b4.
///
/// Raw A32 extent [0x0812f6b4, 0x0812f6ec): 56 bytes. Whole-image
/// aligned-word decoding finds two plain incoming BLs (0x08125e70,
/// 0x0812f724), no predicated incoming BLs, and three plain outgoing BLs,
/// no predicated outgoing BLs. Construct a null temporary handle, assign it
/// to the member at +0x78 (releasing its previous body), destroy the
/// temporary, then zero the state word at +0x74.
///
/// Deviations: native pointers widen the repr(C) host owner; target member
/// offsets are asserted above. The Ghidra r1/r2/r3 arguments are not inputs:
/// the saved r3 stack slot is overwritten by the null-handle constructor.
/// Incidental r0=0 on return is not exposed by this void API.
///
/// # Safety
/// Owner must be live and its value_pair must satisfy the release helper's
/// body, mutex, implementation and virtual-destructor requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_value_pair_reset(owner: *mut SelectionContextOwner) {
    let mut temporary = core::mem::MaybeUninit::<*mut RefcountedBody>::uninit();
    let source = refcounted_handle_construct(temporary.as_mut_ptr(), 0, 0);
    refcounted_handle_copy_assign(core::ptr::addr_of_mut!((*owner).value_pair), source);
    refcounted_body_release_dtor(temporary.as_mut_ptr());
    (*owner).value_state = 0;
}

/// # Safety
/// Owner must be live; its array vtable, elements, and context must satisfy
/// the called deletion/clear helpers. Target value-pair member must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_context_reset(owner: *mut SelectionContextOwner) {
    let array = core::ptr::addr_of_mut!((*owner).array);
    scoped_context_container_delete_enabled_elements(array.cast());
    observable_array_clear(array.cast());
    (*owner).flag_3b = 0;
    (*owner).state_30 = 0;
    (*owner).state_34 = 0;
    (*owner).flag_42 = 0;
    selection_value_pair_reset(owner);
    let mut temporary = core::mem::MaybeUninit::<ScopedContext>::uninit();
    let source = scoped_context_construct(temporary.as_mut_ptr(), core::ptr::null_mut(), 0);
    scoped_context_copy_fields(core::ptr::addr_of_mut!((*owner).context), source);
    scoped_context_destroy(temporary.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{ObservableArray, ObservableArrayClearHost,
        ObservableArrayClearVtable};

    unsafe extern "C" fn remove_tail(array: *mut ObservableArray, amount: i32) {
        let array = array.cast::<ObservableArrayClearHost>();
        assert_eq!(amount, (*array).len.wrapping_neg() as i32);
        (*array).len = 0;
    }

    #[test]
    fn reset_preserves_unowned_bytes_and_context_vtable_for_empty_and_wrapping_counts() {
        let vtable = ObservableArrayClearVtable {
            unresolved_00_b8: [0; 47], remove_tail,
        };
        for count in [0, 1, -1, i32::MIN, i32::MAX] {
            let mut owner = SelectionContextOwner {
                prefix: [0xfeed; 6],
                array: SelectionContextArray {
                    vtable: (&vtable as *const ObservableArrayClearVtable).cast(),
                    count, unknown_08: 7, unknown_0c: 9, delete_enabled: 0,
                    unknown_11_17: [0xa5; 7],
                },
                state_30: u32::MAX, state_34: 17,
                unknown_38_3a: [0xa5; 3], flag_3b: 0xff,
                unknown_3c_41: [0xa5; 6], flag_42: 0xff,
                unknown_43_73: [0xa5; 49], value_state: 8, value_pair: core::ptr::null_mut(),
                context: ScopedContext {
                    vtable: core::ptr::null(), owner_valid: 0x1234,
                    owner: core::ptr::dangling_mut(),
                    service_context: core::ptr::dangling_mut(),
                    registry_token: core::ptr::dangling_mut(), mode: 0xff,
                },
            };
            unsafe { selection_context_reset(&mut owner); }
            assert_eq!((owner.state_30, owner.state_34, owner.value_state), (0, 0, 0));
            assert!(owner.value_pair.is_null());
            assert_eq!((owner.flag_3b, owner.flag_42, owner.context.mode), (0, 0, 0));
            assert_eq!(owner.context.owner_valid, 0);
            assert!(owner.context.owner.is_null());
            assert!(owner.context.service_context.is_null());
            assert!(owner.context.registry_token.is_null());
            assert!(owner.context.vtable.is_null());
            assert_eq!(owner.prefix, [0xfeed; 6]);
            assert_eq!((owner.array.unknown_08, owner.array.unknown_0c), (7, 9));
            assert_eq!(owner.array.unknown_11_17, [0xa5; 7]);
            assert_eq!(owner.unknown_38_3a, [0xa5; 3]);
            assert_eq!(owner.unknown_3c_41, [0xa5; 6]);
            assert_eq!(owner.unknown_43_73, [0xa5; 49]);
        }
    }

    #[test]
    fn value_reset_releases_shared_body_and_preserves_neighboring_fields() {
        let mut owner: SelectionContextOwner = unsafe { core::mem::zeroed() };
        let mut body = RefcountedBody {
            opaque0: 0, refcount: 2, mutex: core::ptr::null_mut(),
        };
        owner.prefix = [0xfeed; 6];
        owner.value_state = u32::MAX;
        owner.value_pair = &mut body;
        owner.unknown_43_73 = [0xa5; 49];
        owner.context.owner_valid = 0x1234;
        unsafe { selection_value_pair_reset(&mut owner); }
        assert_eq!(body.refcount, 1);
        assert!(owner.value_pair.is_null());
        assert_eq!(owner.value_state, 0);
        assert_eq!(owner.prefix, [0xfeed; 6]);
        assert_eq!(owner.unknown_43_73, [0xa5; 49]);
        assert_eq!(owner.context.owner_valid, 0x1234);
        owner.value_state = 17;
        unsafe { selection_value_pair_reset(&mut owner); }
        assert_eq!(body.refcount, 1);
        assert!(owner.value_pair.is_null());
        assert_eq!(owner.value_state, 0);
    }
}
