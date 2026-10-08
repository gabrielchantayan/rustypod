//! Dispatch zero to an object's virtual method — retailOS `0x08130a98`.
//!
//! True extent: 16 bytes, [0x08130a98, 0x08130aa8). Raw A32 words are
//! e5901000, e591214c, e3a01000, e12fff12; the next entry starts with a
//! push {r0-r6,lr}. Independent whole-image decoding verifies two inbound
//! plain BLs (0x0813094c, 0x081312d8), zero predicated BLs, and no outbound
//! BLs. Load the receiver's vtable, load slot +0x14c (word 83), and tail-
//! dispatch with the unchanged receiver and zero. Both direct callers ignore
//! the result; neither establishes the concrete virtual method's identity.
//!
//! Deliberate deviations: repr(C) pointers and reserved vtable words widen
//! on hosts while preserving word indices. Incidental r0 contents are not
//! exposed as a return contract. No fixed-address seam or null checks.

#[repr(C)]
pub struct ZeroDispatchVtable {
    pub reserved: [usize; 83],
    pub slot_14c: unsafe extern "C" fn(*mut ZeroDispatchObject, u32),
}

#[repr(C)]
pub struct ZeroDispatchObject {
    pub vtable: *const ZeroDispatchVtable,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ZeroDispatchVtable, slot_14c) == 0x14c);
    assert!(core::mem::size_of::<ZeroDispatchObject>() == 4);
};

/// # Safety
/// The receiver and vtable must be live and aligned, and slot +0x14c must
/// implement the declared ABI for this receiver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn virtual_dispatch_zero(object: *mut ZeroDispatchObject) {
    ((*(*object).vtable).slot_14c)(object, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        object: ZeroDispatchObject,
        replacement: *const ZeroDispatchVtable,
        state: u32,
        adjacent: u32,
    }

    unsafe extern "C" fn replace(object: *mut ZeroDispatchObject, value: u32) {
        let fixture = object.cast::<Fixture>();
        assert_eq!(value, 0);
        assert_eq!((*fixture).state, u32::MAX);
        (*fixture).state = value;
        (*object).vtable = (*fixture).replacement;
    }

    unsafe extern "C" fn advance(object: *mut ZeroDispatchObject, value: u32) {
        let fixture = object.cast::<Fixture>();
        assert_eq!(value, 0);
        (*fixture).state += 1;
    }

    #[test]
    fn reloads_replaced_vtable_and_preserves_receiver_mutations() {
        let replacement = ZeroDispatchVtable { reserved: [0; 83], slot_14c: advance };
        let original = ZeroDispatchVtable { reserved: [0; 83], slot_14c: replace };
        let mut fixture = Fixture {
            object: ZeroDispatchObject { vtable: &original },
            replacement: &replacement, state: u32::MAX, adjacent: 0xdeadbeef,
        };
        unsafe { virtual_dispatch_zero(&mut fixture.object); }
        assert_eq!(fixture.state, 0);
        assert_eq!(fixture.object.vtable, &replacement as *const _);
        for expected in 1..=3 {
            unsafe { virtual_dispatch_zero(&mut fixture.object); }
            assert_eq!(fixture.state, expected);
            assert_eq!(fixture.adjacent, 0xdeadbeef);
        }
    }
}
