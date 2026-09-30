//! Opaque retaining constructor — `FUN_082a8b18` @ `0x082a8b18`.
//!
//! True extent: 56 bytes to the next function at 0x082a8b50: 52 bytes of
//! instructions through pop {r4,pc}, then holder literal 0x08a0fbcc. Raw A32
//! decoding verifies two inbound plain BLs (0x082a7408, 0x082a8ae8), no
//! predicated inbound BLs, no outbound plain BLs and one outbound BLEQ to
//! lazy_string_tables_initialize at 0x082a89e0.
//!
//! Store the object in dst, initialize the lazy string tables if holder word
//! +0x10 is zero, reload dst, wrapping-increment its object's +0x1c reference
//! count, and return dst. No release, NULL guard or equality shortcut.
//! Deliberate deviations: native-width host pointer slots, unchanged target
//! eight-word object prefix; reuse the existing Rust initializer and holder.

use super::opaque_refcounted_assign::OpaqueRefcountedObject;
use super::lazy_string_tables_initialize::{holder, lazy_string_tables_initialize};

#[inline(always)]
unsafe fn construct_with_initializer(
    dst: *mut *mut OpaqueRefcountedObject,
    object: *mut OpaqueRefcountedObject,
    state: *const u32,
    initialize: impl FnOnce(),
) -> *mut *mut OpaqueRefcountedObject {
    dst.write(object);
    if core::ptr::read_volatile(state.add(4)) == 0 { initialize(); }
    let retained = dst.read();
    (*retained).references = (*retained).references.wrapping_add(1);
    dst
}

/// # Safety
/// dst must be writable and its pointee after initialization non-NULL and
/// writable through +0x1c. The existing lazy-table initializer's safety
/// requirements apply. dst must not overlap the retained reference count.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_refcounted_construct(
    dst: *mut *mut OpaqueRefcountedObject,
    object: *mut OpaqueRefcountedObject,
) -> *mut *mut OpaqueRefcountedObject {
    construct_with_initializer(dst, object, holder(), || lazy_string_tables_initialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialized_holder_retains_without_release_and_wraps() {
        let state = [0, 0, 0, 0, 1];
        for count in [0, 1, 41, u32::MAX] {
            let mut object = OpaqueRefcountedObject { unresolved_00_18: [0x12345678; 7], references: count };
            let mut old = OpaqueRefcountedObject { unresolved_00_18: [0xabcdef01; 7], references: 9 };
            let pointer = &mut object as *mut _;
            let mut slot = &mut old as *mut _;
            let dst = &mut slot as *mut _;
            unsafe { assert_eq!(construct_with_initializer(dst, pointer, state.as_ptr(), || panic!("already initialized")), dst); }
            assert_eq!(slot, pointer);
            assert_eq!(object.references, count.wrapping_add(1));
            assert_eq!(object.unresolved_00_18, [0x12345678; 7]);
            assert_eq!(old.references, 9);
            assert_eq!(old.unresolved_00_18, [0xabcdef01; 7]);
        }
    }

    #[test]
    fn cold_holder_publishes_before_initializing_and_reloads_afterwards() {
        let state = [0; 5];
        let mut original = OpaqueRefcountedObject { unresolved_00_18: [0; 7], references: 12 };
        let mut replacement = OpaqueRefcountedObject { unresolved_00_18: [7; 7], references: u32::MAX };
        let pointer = &mut original as *mut _;
        let replacement_pointer = &mut replacement as *mut _;
        let mut slot = core::ptr::null_mut();
        let dst = &mut slot as *mut _;
        unsafe {
            assert_eq!(construct_with_initializer(dst, pointer, state.as_ptr(), || {
                assert_eq!(dst.read(), pointer);
                assert_eq!((*pointer).references, 12);
                dst.write(replacement_pointer);
            }), dst);
        }
        assert_eq!(slot, replacement_pointer);
        assert_eq!(original.references, 12);
        assert_eq!(replacement.references, 0);
        assert_eq!(replacement.unresolved_00_18, [7; 7]);
    }
}
