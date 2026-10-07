//! Virtual dispatch then clear active — retailOS `0x08149f20`.
//!
//! True extent: 36 bytes, [0x08149f20, 0x08149f44); next entry is BX LR.
//! Raw aligned A32 decoding verifies two incoming plain BLs at 0x081bdfc0
//! and 0x081bfa2c, zero predicated BLs. Body: zero plain/predicated BLs,
//! one BLX through vtable slot +0x30. Invoke the slot with the original
//! object, then clear only byte +8, even when initially inactive. Both
//! callers ignore r0; the virtual method's concrete identity is unresolved.
//! Deliberate deviations: repr(C) pointers and vtable slots widen on hosts;
//! incidental r0 contents are not exposed as a return contract. No target
//! algorithmic deviations or fixed-address callee seams.

#[repr(C)]
pub struct ActiveDispatchVtable {
    pub reserved: [usize; 12],
    pub slot_30: unsafe extern "C" fn(*mut ActiveDispatchObject),
}

#[repr(C)]
pub struct ActiveDispatchObject {
    pub vtable: *const ActiveDispatchVtable,
    pub payload: u32,
    pub active: u8,
    pub adjacent: [u8; 3],
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ActiveDispatchObject, active) == 8);
    assert!(core::mem::offset_of!(ActiveDispatchVtable, slot_30) == 0x30);
};

/// # Safety
/// Object and vtable must be live and aligned, and slot +0x30 must implement
/// the declared ABI. The callback must leave the object writable and live.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn virtual_dispatch_clear_active(object: *mut ActiveDispatchObject) {
    ((*(*object).vtable).slot_30)(object);
    core::ptr::addr_of_mut!((*object).active).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        object: ActiveDispatchObject,
        expected_active: u8,
        calls: u32,
        replacement: *const ActiveDispatchVtable,
    }

    unsafe extern "C" fn dispatch(object: *mut ActiveDispatchObject) {
        let fixture = object.cast::<Fixture>();
        assert_eq!((*object).active, (*fixture).expected_active);
        (*fixture).calls += 1;
        (*object).active = 0xff;
        (*object).payload = 0x12345678;
        (*object).adjacent = [0x91, 0x82, 0x73];
        (*object).vtable = (*fixture).replacement;
    }

    unsafe extern "C" fn replacement_dispatch(object: *mut ActiveDispatchObject) {
        let fixture = object.cast::<Fixture>();
        assert_eq!((*object).active, 0);
        (*fixture).calls += 10;
        (*object).active = 7;
    }

    #[test]
    fn dispatch_precedes_byte_clear_and_preserves_callback_changes() {
        let replacement = ActiveDispatchVtable { reserved: [0; 12], slot_30: replacement_dispatch };
        let original = ActiveDispatchVtable { reserved: [0; 12], slot_30: dispatch };
        for active in [0, 1, 0x80, 0xff] {
            let mut fixture = Fixture {
                object: ActiveDispatchObject {
                    vtable: &original, payload: 0xdeadbeef,
                    active, adjacent: [0xa5; 3],
                },
                expected_active: active, calls: 0, replacement: &replacement,
            };
            unsafe { virtual_dispatch_clear_active(&mut fixture.object); }
            assert_eq!(fixture.calls, 1);
            assert_eq!(fixture.object.active, 0);
            assert_eq!(fixture.object.payload, 0x12345678);
            assert_eq!(fixture.object.adjacent, [0x91, 0x82, 0x73]);
            assert_eq!(fixture.object.vtable, &replacement as *const _);
            unsafe { virtual_dispatch_clear_active(&mut fixture.object); }
            assert_eq!(fixture.calls, 11);
            assert_eq!(fixture.object.active, 0);
            assert_eq!(fixture.object.adjacent, [0x91, 0x82, 0x73]);
        }
    }
}
