//! Query the state code of an application context's owned interface.
//!
//! Original `FUN_081145f0` at `0x081145f0`, true size 16 bytes, ending at
//! `0x08114600` (the next independently called function's push). Raw A32
//! words: e5900430 e5901000 e59110cc e12fff11. Verified inbound calls:
//! two plain BLs (0x08115338, 0x0819e274), zero predicated BLs. Outbound:
//! zero plain/predicated BLs and zero BLX; one BX virtual tail dispatch.
//! Load the interface at context +0x430, then its vtable slot +0xcc, and
//! invoke it with the interface as receiver. Preserve the entire returned
//! word. Callers distinguish codes 0, 1, 2 and 3; their domain meanings and
//! the concrete virtual method's identity are not established.
//!
//! Deliberate deviations: repr(C) host pointers widen, preserving field and
//! vtable word indices. Rust expresses the tail dispatch as a final call;
//! no fixed-address callee seam, null checks or result normalization.

#[repr(C)]
pub struct OwnedStateVtable {
    pub reserved: [usize; 0xcc / 4],
    pub state: unsafe extern "C" fn(*mut OwnedStateInterface) -> u32,
}

#[repr(C)]
pub struct OwnedStateInterface {
    pub vtable: *const OwnedStateVtable,
}

#[repr(C)]
pub struct OwnedInterfaceStateContext {
    pub reserved: [u32; 0x430 / 4],
    pub interface: *mut OwnedStateInterface,
}

/// The context, owned interface and state slot must be valid. The virtual
/// method may mutate its receiver; its full word result is returned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_owned_interface_state(context: *mut OwnedInterfaceStateContext) -> u32 {
    let interface = (*context).interface;
    ((*(*interface).vtable).state)(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct StateMachine {
        interface: OwnedStateInterface,
        state: u32,
    }

    unsafe extern "C" fn advance(interface: *mut OwnedStateInterface) -> u32 {
        let machine = &mut *interface.cast::<StateMachine>();
        let previous = machine.state;
        machine.state = previous.wrapping_add(1);
        previous
    }

    #[test]
    fn virtual_state_transitions_preserve_word_boundaries_and_receiver_identity() {
        let vtable = OwnedStateVtable { reserved: [0; 0xcc / 4], state: advance };
        let mut first = StateMachine {
            interface: OwnedStateInterface { vtable: &vtable }, state: 0,
        };
        let mut second = StateMachine {
            interface: OwnedStateInterface { vtable: &vtable }, state: u32::MAX,
        };
        let mut context = OwnedInterfaceStateContext {
            reserved: [0x12345678; 0x430 / 4], interface: &mut first.interface,
        };
        for expected in 0..=3 {
            assert_eq!(unsafe { context_owned_interface_state(&mut context) }, expected);
            assert_eq!(first.state, expected + 1);
        }
        context.interface = &mut second.interface;
        assert_eq!(unsafe { context_owned_interface_state(&mut context) }, u32::MAX);
        assert_eq!(second.state, 0);
        second.state = 0x80000000;
        assert_eq!(unsafe { context_owned_interface_state(&mut context) }, 0x80000000);
        assert_eq!(second.state, 0x80000001);
        assert_eq!(first.state, 4);
        assert_eq!(context.reserved, [0x12345678; 0x430 / 4]);
    }
}
