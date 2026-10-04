//! Optional delegate event dispatch in the retailOS UI hierarchy.

#[repr(C)]
pub struct EventDelegateOwner {
    pub vtable: *const EventDelegateOwnerVtable,
}

#[repr(C)]
pub struct EventDelegateOwnerVtable {
    pub preceding_slots: [usize; 51],
    pub get_delegate: unsafe extern "C" fn(*mut EventDelegateOwner) -> *mut EventDelegate,
}

#[repr(C)]
pub struct EventDelegate {
    pub vtable: *const EventDelegateVtable,
}

#[repr(C)]
pub struct EventDelegateVtable {
    pub preceding_slots: [usize; 12],
    pub handle_event: unsafe extern "C" fn(*mut EventDelegate, *mut u8) -> u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xcc] = [0; core::mem::offset_of!(EventDelegateOwnerVtable, get_delegate)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x30] = [0; core::mem::offset_of!(EventDelegateVtable, handle_event)];

/// event_forward_to_delegate — original `FUN_0820457c` @ `0x0820457c`.
///
/// True size: 48 bytes, ending at the next prologue at 0x082045ac.
/// Whole-image raw ARM decoding finds two plain BL callers (0x081d2550,
/// 0x082856ec), zero predicated BL callers. Body: zero plain/predicated BLs,
/// one BLX through owner slot +0xcc and one conditional tail BX through
/// delegate slot +0x30. Obtain the optional delegate, return zero if absent,
/// otherwise forward the original event and return the handler's full word.
/// Both callers consume r0 despite Ghidra declaring this wrapper void.
/// Delegate is a role name, not a recovered concrete class identity.
/// Deviations: host vtables use native-width slots; target layout is unchanged.
///
/// # Safety
/// `owner` must have a valid vtable and getter. A non-null getter result must
/// have a valid handler vtable. `event` must satisfy that handler's contract;
/// the wrapper itself does not dereference it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_forward_to_delegate(
    owner: *mut EventDelegateOwner,
    event: *mut u8,
) -> u32 {
    let delegate = ((*(*owner).vtable).get_delegate)(owner);
    if delegate.is_null() { return 0; }
    ((*(*delegate).vtable).handle_event)(delegate, event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct OwnerFixture {
        base: EventDelegateOwner,
        delegate: *mut EventDelegate,
        lookups: u32,
    }

    #[repr(C)]
    struct DelegateFixture {
        base: EventDelegate,
        result: u32,
        handled: u32,
    }

    unsafe extern "C" fn get_delegate(owner: *mut EventDelegateOwner) -> *mut EventDelegate {
        let fixture = &mut *owner.cast::<OwnerFixture>();
        fixture.lookups += 1;
        fixture.delegate
    }

    unsafe extern "C" fn handle_event(delegate: *mut EventDelegate, event: *mut u8) -> u32 {
        let fixture = &mut *delegate.cast::<DelegateFixture>();
        fixture.handled += 1;
        if !event.is_null() { *event = (*event).wrapping_add(1); }
        fixture.result
    }

    #[test]
    fn absent_delegate_returns_zero_without_touching_event() {
        let table = EventDelegateOwnerVtable { preceding_slots: [0; 51], get_delegate };
        let mut owner = OwnerFixture {
            base: EventDelegateOwner { vtable: &table },
            delegate: core::ptr::null_mut(), lookups: 0,
        };
        let mut event = 0xff;
        assert_eq!(unsafe { event_forward_to_delegate(&mut owner.base, &mut event) }, 0);
        assert_eq!(event, 0xff);
        assert_eq!(owner.lookups, 1);
        assert_eq!(unsafe { event_forward_to_delegate(&mut owner.base, core::ptr::null_mut()) }, 0);
        assert_eq!(owner.lookups, 2);
    }

    #[test]
    fn dispatch_preserves_full_result_and_handler_mutations() {
        let owner_table = EventDelegateOwnerVtable { preceding_slots: [0; 51], get_delegate };
        let delegate_table = EventDelegateVtable { preceding_slots: [0; 12], handle_event };
        let mut delegate = DelegateFixture {
            base: EventDelegate { vtable: &delegate_table }, result: 0, handled: 0,
        };
        let mut owner = OwnerFixture {
            base: EventDelegateOwner { vtable: &owner_table },
            delegate: &mut delegate.base, lookups: 0,
        };
        for result in [0, 1, 0x8000_0000, u32::MAX] {
            delegate.result = result;
            let mut event = 0xff;
            assert_eq!(unsafe { event_forward_to_delegate(&mut owner.base, &mut event) }, result);
            assert_eq!(event, 0);
            assert_eq!(unsafe { event_forward_to_delegate(&mut owner.base, core::ptr::null_mut()) }, result);
        }
        assert_eq!(owner.lookups, 8);
        assert_eq!(delegate.handled, 8);
    }
}
