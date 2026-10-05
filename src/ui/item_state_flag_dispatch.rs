//! Item state flag dispatch — retailOS `0x081bac88`.
//!
//! True extent: 104 bytes, [0x081bac88, 0x081bacf0), next entry starts
//! with push {r0-r4,lr}. Raw aligned A32 scan: two inbound plain BLs
//! (0x081bae04, 0x081bb004), zero predicated BLs. Body: zero plain or
//! predicated BLs, two BLX calls and one conditional tail BX.
//! Skip when owner flag 0x02000000 is set. Obtain state through slot +0x5c,
//! clear state bit 0x40, dispatch receiver slot +0xd8, then reload the
//! receiver and dispatch slot +0x88 if the captured state's bit was set.
//! Virtual identities and wider class identity remain unresolved.
//! Deliberate deviations: native repr(C) pointers/slots widen on hosts;
//! final tail dispatch is expressed as a call. Both verified callers ignore
//! r0, so incidental register results are not exposed as a return contract.

#[repr(C)]
pub struct ItemState {
    pub reserved: [u32; 18],
    pub flags: u32,
}

#[repr(C)]
pub struct ItemOwnerVtable {
    pub reserved: [usize; 23],
    pub state: unsafe extern "C" fn(*mut ItemOwner) -> *mut ItemState,
}

#[repr(C)]
pub struct ItemReceiverVtable {
    pub reserved_00: [usize; 34],
    pub slot_88: unsafe extern "C" fn(*mut ItemReceiver),
    pub reserved_8c: [usize; 19],
    pub slot_d8: unsafe extern "C" fn(*mut ItemReceiver),
}

#[repr(C)]
pub struct ItemReceiver {
    pub vtable: *const ItemReceiverVtable,
}

#[repr(C)]
pub struct ItemOwner {
    pub vtable: *const ItemOwnerVtable,
    pub reserved_04: [u32; 17],
    pub flags: u32,
    pub reserved_4c: [u32; 40],
    pub receiver: *mut ItemReceiver,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ItemOwner, flags) == 0x48);
    assert!(core::mem::offset_of!(ItemOwner, receiver) == 0xec);
    assert!(core::mem::offset_of!(ItemState, flags) == 0x48);
    assert!(core::mem::offset_of!(ItemOwnerVtable, state) == 0x5c);
    assert!(core::mem::offset_of!(ItemReceiverVtable, slot_88) == 0x88);
    assert!(core::mem::offset_of!(ItemReceiverVtable, slot_d8) == 0xd8);
};

/// # Safety
/// Owner, returned state and receiver must be live and suitably aligned.
/// All invoked virtual slots must implement the declared ABI. Callbacks may
/// mutate state and replace the owner's receiver; the captured state must live
/// through the first receiver dispatch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_state_flag_dispatch(owner: *mut ItemOwner) {
    if core::ptr::addr_of!((*owner).flags).read_volatile() & 0x0200_0000 != 0 {
        return;
    }
    let state = ((*(*owner).vtable).state)(owner);
    let flags = core::ptr::addr_of_mut!((*state).flags);
    flags.write_volatile(flags.read_volatile() & !0x40);
    let receiver = core::ptr::addr_of!((*owner).receiver).read();
    ((*(*receiver).vtable).slot_d8)(receiver);
    if flags.read_volatile() & 0x40 != 0 {
        let receiver = core::ptr::addr_of!((*owner).receiver).read();
        ((*(*receiver).vtable).slot_88)(receiver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        owner: ItemOwner,
        state: ItemState,
        first: ReceiverFixture,
        second: ReceiverFixture,
        set_bit: bool,
        replace: bool,
        queries: u32,
    }

    #[repr(C)]
    struct ReceiverFixture {
        receiver: ItemReceiver,
        fixture: *mut Fixture,
        updates: u32,
        followups: u32,
    }

    unsafe extern "C" fn state(owner: *mut ItemOwner) -> *mut ItemState {
        let fixture = owner.cast::<Fixture>();
        (*fixture).queries += 1;
        core::ptr::addr_of_mut!((*fixture).state)
    }

    unsafe extern "C" fn update(receiver: *mut ItemReceiver) {
        let receiver = receiver.cast::<ReceiverFixture>();
        let fixture = (*receiver).fixture;
        assert_eq!((*fixture).state.flags, 0xa5a5_0001);
        (*receiver).updates += 1;
        if (*fixture).set_bit { (*fixture).state.flags |= 0x40; }
        if (*fixture).replace {
            (*fixture).owner.receiver = core::ptr::addr_of_mut!((*fixture).second.receiver);
        }
    }

    unsafe extern "C" fn followup(receiver: *mut ItemReceiver) {
        let receiver = receiver.cast::<ReceiverFixture>();
        assert_ne!((*(*receiver).fixture).state.flags & 0x40, 0);
        (*receiver).followups += 1;
    }

    #[test]
    fn callback_flag_and_receiver_replacement_control_followup() {
        let owner_vtable = ItemOwnerVtable { reserved: [0; 23], state };
        let receiver_vtable = ItemReceiverVtable {
            reserved_00: [0; 34], slot_88: followup,
            reserved_8c: [0; 19], slot_d8: update,
        };
        for skip in [false, true] {
            for set_bit in [false, true] {
                for replace in [false, true] {
                    for initial_bit in [0, 0x40] {
                        let mut fixture = Fixture {
                            owner: ItemOwner {
                                vtable: &owner_vtable, reserved_04: [0; 17],
                                flags: if skip { 0x0200_0000 } else { 0x0100_0000 },
                                reserved_4c: [0; 40], receiver: core::ptr::null_mut(),
                            },
                            state: ItemState { reserved: [0x12345678; 18], flags: 0xa5a5_0001 | initial_bit },
                            first: ReceiverFixture { receiver: ItemReceiver { vtable: &receiver_vtable }, fixture: core::ptr::null_mut(), updates: 0, followups: 0 },
                            second: ReceiverFixture { receiver: ItemReceiver { vtable: &receiver_vtable }, fixture: core::ptr::null_mut(), updates: 0, followups: 0 },
                            set_bit, replace, queries: 0,
                        };
                        fixture.first.fixture = &mut fixture;
                        fixture.second.fixture = &mut fixture;
                        if !skip { fixture.owner.receiver = &mut fixture.first.receiver; }
                        unsafe { item_state_flag_dispatch(&mut fixture.owner); }
                        assert_eq!(fixture.queries, u32::from(!skip));
                        assert_eq!(fixture.first.updates, u32::from(!skip));
                        assert_eq!(fixture.second.updates, 0);
                        assert_eq!(fixture.first.followups, u32::from(!skip && set_bit && !replace));
                        assert_eq!(fixture.second.followups, u32::from(!skip && set_bit && replace));
                        assert_eq!(fixture.state.flags, 0xa5a5_0001 | if skip { initial_bit } else if set_bit { 0x40 } else { 0 });
                        assert_eq!(fixture.state.reserved, [0x12345678; 18]);
                    }
                }
            }
        }
    }
}
