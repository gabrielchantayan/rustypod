//! Replace an object's associated interface through virtual notifications.
//!
//! Original: FUN_08110be4 at 0x08110be4, 96 bytes, ending before the
//! prologue at 0x08110c44. Raw whole-image decoding verifies two incoming
//! plain BLs (0x08111224, 0x081112c8), zero predicated BLs. The body has
//! zero direct BLs, one BLX, one BLXNE, and a final BXNE tail dispatch.
//! Query receiver slot +0x1c; if unchanged, return without touching state.
//! Notify the old nonnull association through +0x3c, reload receiver +0x0c,
//! store the replacement at state +4, and notify it through +0x38 if nonnull.
//! Concrete virtual method identities remain unresolved; no fixed-address seams.
//! Deliberate deviations: repr(C) pointer fields and vtable entries widen on
//! hosts, preserving target word indices. The final tail dispatch is expressed
//! as a final void call; no verified caller consumes a return value.

#[repr(C)]
pub struct AssociationReceiverVtable {
    pub reserved: [usize; 7],
    pub query_association: unsafe extern "C" fn(*mut AssociationReceiver) -> *mut AssociatedObject,
}

#[repr(C)]
pub struct AssociatedObjectVtable {
    pub reserved: [usize; 14],
    pub association_added: unsafe extern "C" fn(*mut AssociatedObject, *mut AssociationReceiver),
    pub association_removed: unsafe extern "C" fn(*mut AssociatedObject, *mut AssociationReceiver),
}

#[repr(C)]
pub struct AssociatedObject {
    pub vtable: *const AssociatedObjectVtable,
}

#[repr(C)]
pub struct AssociationState {
    pub reserved: usize,
    pub associated: *mut AssociatedObject,
}

#[repr(C)]
pub struct AssociationReceiver {
    pub vtable: *const AssociationReceiverVtable,
    pub reserved: [usize; 2],
    pub state: *mut AssociationState,
}

/// # Safety
/// Receiver, its query slot, and the state selected after removal must be valid.
/// Nonnull associations must have callable notification slots. Notifications
/// must preserve the receiver and replacement object's lifetime.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn associated_object_replace(
    receiver: *mut AssociationReceiver, replacement: *mut AssociatedObject,
) {
    let old = unsafe { ((*(*receiver).vtable).query_association)(receiver) };
    if old == replacement {
        return;
    }
    if !old.is_null() {
        unsafe { ((*(*old).vtable).association_removed)(old, receiver); }
    }
    unsafe { (*(*receiver).state).associated = replacement; }
    if !replacement.is_null() {
        unsafe { ((*(*replacement).vtable).association_added)(replacement, receiver); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Fixture {
        receiver: AssociationReceiver,
        queried: *mut AssociatedObject,
        redirected: *mut AssociationState,
        expected: *mut AssociatedObject,
        events: [u8; 3],
        count: usize,
    }

    unsafe fn event(receiver: *mut AssociationReceiver, code: u8) {
        let fixture = unsafe { &mut *receiver.cast::<Fixture>() };
        fixture.events[fixture.count] = code;
        fixture.count += 1;
    }

    unsafe extern "C" fn query(receiver: *mut AssociationReceiver) -> *mut AssociatedObject {
        unsafe { event(receiver, 1); (*receiver.cast::<Fixture>()).queried }
    }

    unsafe extern "C" fn removed(object: *mut AssociatedObject, receiver: *mut AssociationReceiver) {
        unsafe {
            let fixture = &mut *receiver.cast::<Fixture>();
            assert_eq!(object, fixture.queried);
            assert_eq!((*fixture.receiver.state).associated, object);
            fixture.receiver.state = fixture.redirected;
            event(receiver, 2);
        }
    }

    unsafe extern "C" fn added(object: *mut AssociatedObject, receiver: *mut AssociationReceiver) {
        unsafe {
            let fixture = &mut *receiver.cast::<Fixture>();
            assert_eq!(object, fixture.expected);
            assert_eq!((*fixture.receiver.state).associated, object);
            event(receiver, 3);
        }
    }

    #[test]
    fn replacement_transitions_and_removal_redirected_state() {
        let receiver_vtable = AssociationReceiverVtable { reserved: [0; 7], query_association: query };
        let object_vtable = AssociatedObjectVtable { reserved: [0; 14], association_added: added, association_removed: removed };
        let mut old = AssociatedObject { vtable: &object_vtable };
        let mut new = AssociatedObject { vtable: &object_vtable };
        for has_old in [false, true] {
            for has_new in [false, true] {
                let previous = if has_old { &mut old as *mut _ } else { ptr::null_mut() };
                let replacement = if has_new { &mut new as *mut _ } else { ptr::null_mut() };
                let mut initial = AssociationState { reserved: 0x1234, associated: previous };
                let mut redirected = AssociationState { reserved: 0x5678, associated: previous };
                let mut fixture = Fixture {
                    receiver: AssociationReceiver { vtable: &receiver_vtable, reserved: [11, 22], state: &mut initial },
                    queried: previous, redirected: &mut redirected, expected: replacement,
                    events: [0; 3], count: 0,
                };
                unsafe { associated_object_replace(&mut fixture.receiver, replacement); }
                let expected_events: &[u8] = match (has_old, has_new) {
                    (false, false) => &[1], (false, true) => &[1, 3],
                    (true, false) => &[1, 2], (true, true) => &[1, 2, 3],
                };
                assert_eq!(&fixture.events[..fixture.count], expected_events);
                assert_eq!(initial.associated, if has_old { previous } else { replacement });
                assert_eq!(redirected.associated, if has_old { replacement } else { previous });
                assert_eq!((initial.reserved, redirected.reserved), (0x1234, 0x5678));
                assert_eq!(fixture.receiver.reserved, [11, 22]);
            }
        }
    }

    #[test]
    fn identical_association_does_not_require_state_or_notify() {
        let receiver_vtable = AssociationReceiverVtable { reserved: [0; 7], query_association: query };
        // An unusable object vtable and state prove the identity exit precedes both.
        let mut object = AssociatedObject { vtable: ptr::null() };
        for association in [ptr::null_mut(), &mut object as *mut _] {
            let mut fixture = Fixture {
                receiver: AssociationReceiver { vtable: &receiver_vtable, reserved: [0; 2], state: ptr::null_mut() },
                queried: association, redirected: ptr::null_mut(), expected: association,
                events: [0; 3], count: 0,
            };
            unsafe { associated_object_replace(&mut fixture.receiver, association); }
            assert_eq!(fixture.events, [1, 0, 0]);
            assert!(fixture.receiver.state.is_null());
        }
    }
}
