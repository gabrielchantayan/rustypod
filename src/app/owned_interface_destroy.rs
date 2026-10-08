//! Owned-interface destruction — `FUN_0811ee44` @ `0x0811ee44`.
//!
//! True executable size: 44 bytes, [0x0811ee44, 0x0811ee70); the
//! four-byte vtable literal follows, then a real function at 0x0811ee74.
//! Raw whole-image A32 decoding finds two inbound plain BLs (0x0811ee38,
//! 0x08224224), zero predicated BLs. The body has no direct BL and one
//! predicated register BLX, through the owned interface's slot +0x1c.
//!
//! Install vtable 0x08982ecc, dispatch slot +0x1c with the non-NULL interface
//! at owner+8 as receiver, and return owner. Do not clear the interface or
//! modify the word at +4. The class and concrete virtual method are unknown.
//! Deliberate deviations: repr(C) native pointers widen on hosts; vtable
//! entries preserve word indices rather than host byte offsets. No new
//! fixed-address callee seam is introduced.

#[repr(C)]
pub struct OwnedInterfaceVtable {
    pub reserved: [usize; 7],
    pub destroy: unsafe extern "C" fn(*mut OwnedInterface),
}

#[repr(C)]
pub struct OwnedInterface {
    pub vtable: *const OwnedInterfaceVtable,
}

#[repr(C)]
pub struct InterfaceOwner {
    pub vtable: u32,
    pub state: u32,
    pub interface: *mut OwnedInterface,
}

const OWNER_VTABLE: u32 = 0x0898_2ecc;

/// # Safety
/// `owner` must be writable. Its optional interface must have a readable
/// vtable with a callable slot +0x1c accepting that interface as receiver.
/// The virtual method must leave the owner allocation valid for return.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_interface_destroy(owner: *mut InterfaceOwner) -> *mut InterfaceOwner {
    core::ptr::addr_of_mut!((*owner).vtable).write_volatile(OWNER_VTABLE);
    let interface = core::ptr::addr_of!((*owner).interface).read();
    if !interface.is_null() {
        let vtable = core::ptr::addr_of!((*interface).vtable).read();
        ((*vtable).destroy)(interface);
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct ObservedInterface {
        interface: OwnedInterface,
        owner: *mut InterfaceOwner,
        calls: u32,
        seen_vtable: u32,
        seen_state: u32,
        seen_interface: *mut OwnedInterface,
    }

    unsafe extern "C" fn observe(interface: *mut OwnedInterface) {
        let observed = &mut *interface.cast::<ObservedInterface>();
        observed.calls += 1;
        observed.seen_vtable = (*observed.owner).vtable;
        observed.seen_state = (*observed.owner).state;
        observed.seen_interface = (*observed.owner).interface;
    }

    #[test]
    fn absent_interface_preserves_state_and_returns_owner() {
        for state in [0, 1, 2, u32::MAX] {
            let mut owner = InterfaceOwner { vtable: 0xdead_beef, state, interface: core::ptr::null_mut() };
            let pointer = &mut owner as *mut InterfaceOwner;
            assert_eq!(unsafe { owned_interface_destroy(pointer) }, pointer);
            assert_eq!(owner.vtable, OWNER_VTABLE);
            assert_eq!(owner.state, state);
            assert!(owner.interface.is_null());
        }
    }

    #[test]
    fn dispatch_observes_restored_vtable_and_retains_interface() {
        let vtable = OwnedInterfaceVtable { reserved: [0; 7], destroy: observe };
        let mut observed = ObservedInterface {
            interface: OwnedInterface { vtable: &vtable },
            owner: core::ptr::null_mut(), calls: 0, seen_vtable: 0,
            seen_state: 0, seen_interface: core::ptr::null_mut(),
        };
        let interface = &mut observed.interface as *mut OwnedInterface;
        let mut owner = InterfaceOwner { vtable: 0xdead_beef, state: u32::MAX, interface };
        let pointer = &mut owner as *mut InterfaceOwner;
        observed.owner = pointer;
        assert_eq!(unsafe { owned_interface_destroy(pointer) }, pointer);
        assert_eq!(observed.calls, 1);
        assert_eq!(observed.seen_vtable, OWNER_VTABLE);
        assert_eq!(observed.seen_state, u32::MAX);
        assert_eq!(observed.seen_interface, interface);
        assert_eq!(owner.interface, interface);
        assert_eq!(owner.state, u32::MAX);
        assert_eq!(owner.vtable, OWNER_VTABLE);
    }
}
