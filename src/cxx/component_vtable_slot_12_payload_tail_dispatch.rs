//! Tail-dispatching an opaque component's payload method.
//!
//! `component_vtable_slot_12_payload_tail_dispatch` — original: `FUN_0829f288`
//! @ **0x0829f288** (20 bytes). Raw ARM establishes the exact body from
//! `0x0829f288` through the `bx r2` at `0x0829f298`; the independently linked
//! next function begins at `0x0829f29c`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly four
//! inbound direct calls, all unconditional `bl` at `0x0820daa4`, `0x0820db00`,
//! `0x0820db3c`, and `0x0820dbc8`. There are no predicated `bl` forms or direct
//! tail branches.
//!
//! # Algorithm
//!
//! Loads the owner's opaque component pointer at `+0xc0`, reads the payload at
//! `+0x1d8`, and tail-dispatches the component through its vtable's `+0x0c`
//! slot. The component replaces the owner in `r0`, the payload remains in `r1`,
//! and the virtual method's `u32` result is returned unchanged.
//!
//! # Deliberate deviation
//!
//! The component and virtual method are not identified, so this port models
//! only their verified dispatch contract. Host vtable cells use native-width
//! pointers; `repr(C)` and target-only offset assertions preserve their ARM word
//! positions. Rust expresses the terminal `bx` as a typed call.

/// ARMv5TE word index of the component pointer in its owner.
const COMPONENT_WORD: usize = 0xc0 / 4;
/// ARMv5TE vtable word index for byte offset `+0x0c`.
const COMPONENT_DISPATCH_SLOT: usize = 0x0c / 4;
/// ARMv5TE word index of the payload in its owner.
const PAYLOAD_WORD: usize = 0x1d8 / 4;

/// ABI of the unrecovered component method at vtable slot `+0x0c`.
pub type ComponentVtableSlot12PayloadDispatch = unsafe extern "C" fn(*mut ComponentVtableSlot12Payload, u32) -> u32;

/// Prefix of the opaque component vtable consumed by the wrapper.
#[repr(C)]
pub struct ComponentVtableSlot12PayloadVtable {
    /// `+0x00..+0x08`: unresolved virtual entries.
    pub opaque_00_08: [usize; COMPONENT_DISPATCH_SLOT],
    /// `+0x0c`: method invoked by the retail tail wrapper.
    pub dispatch: ComponentVtableSlot12PayloadDispatch,
}

/// Component reached through the owner's `+0xc0` field.
#[repr(C)]
pub struct ComponentVtableSlot12Payload {
    /// `+0x00`: virtual method table.
    pub vtable: *const ComponentVtableSlot12PayloadVtable,
}

/// Owner prefix consumed by [`component_vtable_slot_12_payload_tail_dispatch`].
#[repr(C)]
pub struct ComponentVtableSlot12PayloadOwner {
    /// `+0x00..+0xbc`: opaque owner state.
    pub opaque_00_bc: [u32; COMPONENT_WORD],
    /// `+0xc0`: component selected as the virtual receiver.
    pub component: *mut ComponentVtableSlot12Payload,
    /// `+0xc4..+0x1d4`: opaque owner state.
    pub opaque_c4_1d4: [u32; PAYLOAD_WORD - COMPONENT_WORD - 1],
    /// `+0x1d8`: payload forwarded as the virtual method's second argument.
    pub payload: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ComponentVtableSlot12PayloadVtable, dispatch)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc0] = [0; core::mem::offset_of!(ComponentVtableSlot12PayloadOwner, component)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1d8] = [0; core::mem::offset_of!(ComponentVtableSlot12PayloadOwner, payload)];

/// Tail-dispatches the owner's component through vtable slot `+0x0c`.
///
/// # Safety
///
/// `owner` must designate a readable [`ComponentVtableSlot12PayloadOwner`] with
/// a non-NULL component, vtable, and callable slot-`+0x0c` method. The retail
/// wrapper validates none of those pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.component_vtable_slot_12_payload_tail_dispatch")]
pub unsafe extern "C" fn component_vtable_slot_12_payload_tail_dispatch(
    owner: *mut ComponentVtableSlot12PayloadOwner,
) -> u32 {
    let payload = unsafe { (*owner).payload };
    let component = unsafe { (*owner).component };
    let dispatch = unsafe { (*(*component).vtable).dispatch };
    unsafe { dispatch(component, payload) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut FORWARDED_COMPONENT: *mut ComponentVtableSlot12Payload = ptr::null_mut();
    static mut FORWARDED_PAYLOAD: u32 = 0;

    unsafe extern "C" fn wrong_slot(_component: *mut ComponentVtableSlot12Payload, _payload: u32) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(component: *mut ComponentVtableSlot12Payload, payload: u32) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_COMPONENT = component;
            FORWARDED_PAYLOAD = payload;
        }
        0xcafe_babe
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            FORWARDED_COMPONENT = ptr::null_mut();
            FORWARDED_PAYLOAD = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_the_owner_component_payload_through_only_slot_0x0c() {
        let _bench = bench();
        let mut vtable = ComponentVtableSlot12PayloadVtable {
            opaque_00_08: [wrong_slot as usize; COMPONENT_DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut component = ComponentVtableSlot12Payload { vtable: &mut vtable };
        let mut owner = ComponentVtableSlot12PayloadOwner {
            opaque_00_bc: [0; COMPONENT_WORD],
            component: &mut component,
            opaque_c4_1d4: [0; PAYLOAD_WORD - COMPONENT_WORD - 1],
            payload: 0x1234_5678,
        };

        let result = unsafe { component_vtable_slot_12_payload_tail_dispatch(&mut owner) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0x0c slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_COMPONENT, &mut component), "the component replaces owner in r0");
            assert_eq!(FORWARDED_PAYLOAD, 0x1234_5678, "the owner payload remains in r1");
        }
    }
}
