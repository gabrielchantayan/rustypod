//! Opaque handle copy constructor — `FUN_082a8b50` @ `0x082a8b50`.
//!
//! True extent: 24 bytes, six A32 words through mov pc,lr at 0x082a8b64;
//! the next independently entered function begins at 0x082a8b68. Whole-image
//! word decoding verifies two inbound plain BLs (0x082a7d6c, 0x083e7938),
//! zero predicated inbound BLs and zero outbound BLs of either kind.
//!
//! Copy the source pointee into destination, then wrapping-increment its
//! reference count at +0x1c. Return destination (r0 is unchanged in stock).
//! No NULL guard, equality shortcut or release of the previous destination.
//! Deliberate deviation: native-width host pointer slots; the shared object
//! prefix retains the target's eight-word layout. No inferred class identity.

use super::opaque_refcounted_assign::OpaqueRefcountedObject;

/// # Safety
/// src must be readable, dst writable, and the source pointee non-NULL and
/// writable through its reference count. Slots may alias each other, but must
/// not overlap the object's count. This is construction, not assignment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_refcounted_copy_construct(
    dst: *mut *mut OpaqueRefcountedObject,
    src: *const *mut OpaqueRefcountedObject,
) -> *mut *mut OpaqueRefcountedObject {
    let object = src.read();
    dst.write(object);
    (*object).references = (*object).references.wrapping_add(1);
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_preserves_prefix_source_and_old_object_and_wraps_count() {
        for count in [0, 1, 41, u32::MAX] {
            let mut object = OpaqueRefcountedObject { unresolved_00_18: [0x12345678; 7], references: count };
            let mut old = OpaqueRefcountedObject { unresolved_00_18: [0xabcdef01; 7], references: 9 };
            let src = &mut object as *mut _;
            let mut dst = &mut old as *mut _;
            let slot = &mut dst as *mut _;
            unsafe { assert_eq!(opaque_refcounted_copy_construct(slot, &src), slot); }
            assert_eq!(dst, src);
            assert_eq!(src, &mut object as *mut _);
            assert_eq!(object.references, count.wrapping_add(1));
            assert_eq!(object.unresolved_00_18, [0x12345678; 7]);
            assert_eq!(old.references, 9);
            assert_eq!(old.unresolved_00_18, [0xabcdef01; 7]);
        }
    }

    #[test]
    fn aliased_slots_and_equal_pointees_still_retain() {
        let mut object = OpaqueRefcountedObject { unresolved_00_18: [0; 7], references: 7 };
        let mut slot = &mut object as *mut _;
        let address = &mut slot as *mut _;
        unsafe { assert_eq!(opaque_refcounted_copy_construct(address, address), address); }
        assert_eq!(object.references, 8);
        let src = slot;
        unsafe { opaque_refcounted_copy_construct(address, &src); }
        assert_eq!(object.references, 9);
        assert_eq!(slot, src);
    }
}
