//! Tail-dispatching an opaque component's no-argument method.
//!
//! `component_vtable_slot_08_tail_dispatch` — original: `FUN_0829f278`
//! @ **0x0829f278** (16 bytes). Raw ARM establishes the exact body from
//! `0x0829f278` through the `bx r1` at `0x0829f284`; the independently linked
//! next function begins at `0x0829f288`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly three
//! inbound direct calls, all unconditional `bl` at `0x0820db78`, `0x0820dbf8`,
//! and `0x0820dc10`. There are no predicated `bl` forms or direct tail branches.
//!
//! # Algorithm
//!
//! Loads the owner's opaque component pointer at `+0xc0` and tail-dispatches it
//! through vtable slot `+0x08`. The component replaces the owner in `r0`, and
//! the virtual method's `u32` result is returned unchanged.
//!
//! # Deliberate deviation
//!
//! The component and virtual method are not identified, so this port models
//! only their verified dispatch contract. Host vtable cells use native-width
//! pointers; `repr(C)` and target-only offset assertions preserve their ARM word
//! positions. Rust expresses the terminal `bx` as a typed call.

/// ARMv5TE word index of the component pointer in its owner.
const COMPONENT_WORD: usize = 0xc0 / 4;
/// ARMv5TE vtable word index for byte offset `+0x08`.
const COMPONENT_DISPATCH_SLOT: usize = 0x08 / 4;

/// ABI of the unrecovered component method at vtable slot `+0x08`.
pub type ComponentVtableSlot08Dispatch = unsafe extern "C" fn(*mut ComponentVtableSlot08) -> u32;

/// Prefix of the opaque component vtable consumed by the wrapper.
#[repr(C)]
pub struct ComponentVtableSlot08Vtable {
    /// `+0x00..+0x04`: unresolved virtual entries.
    pub opaque_00_04: [usize; COMPONENT_DISPATCH_SLOT],
    /// `+0x08`: method invoked by the retail tail wrapper.
    pub dispatch: ComponentVtableSlot08Dispatch,
}

/// Component reached through the owner's `+0xc0` field.
#[repr(C)]
pub struct ComponentVtableSlot08 {
    /// `+0x00`: virtual method table.
    pub vtable: *const ComponentVtableSlot08Vtable,
}

/// Owner prefix consumed by [`component_vtable_slot_08_tail_dispatch`].
#[repr(C)]
pub struct ComponentVtableSlot08Owner {
    /// `+0x00..+0xbc`: opaque owner state.
    pub opaque_00_bc: [u32; COMPONENT_WORD],
    /// `+0xc0`: component selected as the virtual receiver.
    pub component: *mut ComponentVtableSlot08,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ComponentVtableSlot08Vtable, dispatch)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc0] = [0; core::mem::offset_of!(ComponentVtableSlot08Owner, component)];

/// Tail-dispatches the owner's component through vtable slot `+0x08`.
///
/// # Safety
///
/// `owner` must designate a readable [`ComponentVtableSlot08Owner`] with a
/// non-NULL component, vtable, and callable slot-`+0x08` method. The retail
/// wrapper validates none of those pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.component_vtable_slot_08_tail_dispatch")]
pub unsafe extern "C" fn component_vtable_slot_08_tail_dispatch(
    owner: *mut ComponentVtableSlot08Owner,
) -> u32 {
    let component = unsafe { (*owner).component };
    let dispatch = unsafe { (*(*component).vtable).dispatch };
    unsafe { dispatch(component) }
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
    static mut FORWARDED_COMPONENT: *mut ComponentVtableSlot08 = ptr::null_mut();

    unsafe extern "C" fn wrong_slot(_component: *mut ComponentVtableSlot08) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(component: *mut ComponentVtableSlot08) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_COMPONENT = component;
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
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_the_owner_component_through_only_slot_0x08() {
        let _bench = bench();
        let mut vtable = ComponentVtableSlot08Vtable {
            opaque_00_04: [wrong_slot as usize; COMPONENT_DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut component = ComponentVtableSlot08 { vtable: &mut vtable };
        let mut owner = ComponentVtableSlot08Owner {
            opaque_00_bc: [0; COMPONENT_WORD],
            component: &mut component,
        };

        let result = unsafe { component_vtable_slot_08_tail_dispatch(&mut owner) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0x08 slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_COMPONENT, &mut component), "the component replaces owner in r0");
        }
    }
}
