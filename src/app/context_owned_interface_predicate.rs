//! Gated predicate on an application context's owned interface.
//!
//! Original FUN_08113994 at 0x08113994, true size 52 bytes, ending at
//! 0x081139c8 (the next function's push). Verified inbound calls: two plain
//! BLs at 0x081119f0 and 0x0811327c, zero predicated BLs. Outbound: no
//! immediate BLs, one BLX through vtable slot +0x9c. If byte +0x4cc is
//! nonzero, return zero without accessing the interface. Otherwise load
//! the interface at +0x430, invoke its slot +0x9c with that receiver, and
//! return one iff the entire returned word is nonzero. Callers use this
//! predicate to select property values; the domain meaning is unresolved.
//!
//! Deliberate deviations: repr(C) pointers widen on hosts, preserving
//! target field/slot word indices. No guessed callee seam or null checks.

#[repr(C)]
pub struct OwnedPredicateVtable {
    pub reserved: [usize; 0x9c / 4],
    pub predicate: unsafe extern "C" fn(*mut OwnedPredicateInterface) -> u32,
}

#[repr(C)]
pub struct OwnedPredicateInterface {
    pub vtable: *const OwnedPredicateVtable,
}

#[repr(C)]
pub struct OwnedInterfacePredicateContext {
    pub reserved: [u32; 0x430 / 4],
    pub interface: *mut OwnedPredicateInterface,
    pub between_interface_and_gate: [u32; (0x4cc - 0x434) / 4],
    pub gate: u8,
}

/// Context must be valid. Only when gate is zero must the interface,
/// vtable and predicate slot be valid; the method may mutate its receiver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_owned_interface_predicate(context: *mut OwnedInterfacePredicateContext) -> u32 {
    if (*context).gate != 0 {
        return 0;
    }
    let interface = (*context).interface;
    (((*(*interface).vtable).predicate)(interface) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct PredicateMachine {
        interface: OwnedPredicateInterface,
        result: u32,
        calls: u32,
    }

    unsafe extern "C" fn query(interface: *mut OwnedPredicateInterface) -> u32 {
        let machine = &mut *interface.cast::<PredicateMachine>();
        machine.calls += 1;
        machine.result
    }

    fn context(interface: *mut OwnedPredicateInterface) -> OwnedInterfacePredicateContext {
        OwnedInterfacePredicateContext {
            reserved: [0; 0x430 / 4], interface,
            between_interface_and_gate: [0; (0x4cc - 0x434) / 4], gate: 0,
        }
    }

    #[test]
    fn every_nonzero_gate_short_circuits_an_invalid_interface() {
        let mut owner = context(core::ptr::null_mut());
        for gate in 1..=u8::MAX {
            owner.gate = gate;
            assert_eq!(unsafe { context_owned_interface_predicate(&mut owner) }, 0);
        }
    }

    #[test]
    fn gate_transitions_suppress_calls_and_normalize_full_word_results() {
        let vtable = OwnedPredicateVtable { reserved: [0; 0x9c / 4], predicate: query };
        let mut machine = PredicateMachine {
            interface: OwnedPredicateInterface { vtable: &vtable }, result: 0, calls: 0,
        };
        let mut owner = context(&mut machine.interface);
        for (index, result) in [0, 1, 0x100, 0x80000000, u32::MAX, 0].into_iter().enumerate() {
            machine.result = result;
            owner.gate = 0;
            assert_eq!(unsafe { context_owned_interface_predicate(&mut owner) }, (result != 0) as u32);
            assert_eq!(machine.calls, index as u32 + 1);
            owner.gate = 0x80;
            assert_eq!(unsafe { context_owned_interface_predicate(&mut owner) }, 0);
            assert_eq!(machine.calls, index as u32 + 1);
        }
    }
}
