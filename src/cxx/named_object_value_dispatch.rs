//! Named-object embedded-interface value dispatch.
//!
//! Original: `FUN_08284910` @ `0x08284910`, 28 bytes, ending at the
//! independently decoded function prologue at `0x0828492c`. Raw words verify
//! two unconditional inbound BLs (0x0816c8cc, 0x082847f4), zero predicated
//! inbound BLs, and zero direct BLs / one unconditional indirect BLX in the body.
//!
//! Copies the incoming word to a stack local, adjusts the receiver to its
//! embedded interface at +0x4c, and calls that interface's vtable slot +0x1c
//! with the local's address. The slot's semantic identity is unresolved.
//! Deliberate deviations: host pointer fields and vtable slots widen naturally
//! under repr(C); the embedded receiver's host offset is not a firmware byte
//! offset. The incidental saved-r3/saved-lr stack words are not exposed. Unlike
//! Ghidra's void prototype, the raw r0 result is retained as a u32; both known
//! callers ignore it. No ownership or NULL handling is invented.

/// Recovered interface prefix; additional fields belong to the concrete type.
#[repr(C)]
pub struct NamedObjectValueInterface {
    pub vtable: *const NamedObjectValueVtable,
}

/// Slot +0x1c is the only method resolved structurally by this wrapper.
#[repr(C)]
pub struct NamedObjectValueVtable {
    pub unresolved_00_18: [usize; 7],
    pub dispatch_value: unsafe extern "C" fn(*mut NamedObjectValueInterface, *mut u32) -> u32,
}

/// Target layout has nineteen words preceding the embedded interface.
#[repr(C)]
pub struct NamedObjectValueOwner {
    pub unresolved_00_48: [u32; 19],
    pub value_interface: NamedObjectValueInterface,
}

/// # Safety
/// `owner` must contain the embedded interface and any concrete fields its
/// method uses. Its vtable slot must accept a synchronous, temporary u32
/// pointer; it must not retain that pointer beyond the call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn named_object_dispatch_value(
    owner: *mut NamedObjectValueOwner,
    mut value: u32,
) -> u32 {
    let receiver = core::ptr::addr_of_mut!((*owner).value_interface);
    let vtable = core::ptr::addr_of!((*receiver).vtable).read();
    ((*vtable).dispatch_value)(receiver, &mut value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        owner: NamedObjectValueOwner,
        observed: u32,
        calls: u32,
    }

    unsafe extern "C" fn consume(receiver: *mut NamedObjectValueInterface, value: *mut u32) -> u32 {
        let state = receiver.cast::<u8>().add(core::mem::size_of::<NamedObjectValueInterface>()).cast::<u32>();
        state.write(value.read());
        state.add(1).write(state.add(1).read() + 1);
        value.write(0x1357_9bdf);
        0x2468_ace0
    }

    unsafe extern "C" fn alternate(receiver: *mut NamedObjectValueInterface, value: *mut u32) -> u32 {
        consume(receiver, value) ^ u32::MAX
    }

    #[test]
    fn dispatches_selected_slot_with_mutable_local_and_embedded_receiver() {
        for method in [consume as unsafe extern "C" fn(_, _) -> _, alternate] {
            let vtable = NamedObjectValueVtable { unresolved_00_18: [0; 7], dispatch_value: method };
            let mut fixture = Fixture {
                owner: NamedObjectValueOwner {
                    unresolved_00_48: [0xa5a5_a5a5; 19],
                    value_interface: NamedObjectValueInterface { vtable: &vtable },
                },
                observed: 0,
                calls: 0,
            };
            for value in [0, 1, 0x8000_0000, u32::MAX] {
                let result = unsafe { named_object_dispatch_value(&mut fixture.owner, value) };
                assert_eq!(fixture.observed, value);
                assert_eq!(result, if method as usize == consume as usize { 0x2468_ace0 } else { 0xdb97_531f });
                assert_eq!(fixture.owner.unresolved_00_48, [0xa5a5_a5a5; 19]);
                assert_eq!(fixture.owner.value_interface.vtable, &vtable as *const _);
            }
            assert_eq!(fixture.calls, 4);
        }
    }
}
