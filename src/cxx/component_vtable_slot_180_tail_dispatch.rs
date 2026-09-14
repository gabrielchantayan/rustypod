//! Tail-dispatching an opaque component's vtable slot.
//!
//! `component_vtable_slot_180_tail_dispatch` — original: `FUN_081159bc` @
//! **0x081159bc** (16 bytes). Raw ARM establishes the exact body from
//! `0x081159bc` through the `bx r1` at `0x081159c8`; the independently linked
//! next function begins at `0x081159cc`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly six
//! inbound direct calls, all unconditional `bl` at `0x0812eecc`, `0x0812f174`,
//! `0x0812f4f4`, `0x0819e250`, `0x0819e2f0`, and `0x08289814`. There are no
//! predicated forms or direct tail branches. No aligned raw image word references
//! this wrapper, so it is statically called rather than virtual-dispatched.
//!
//! # Algorithm
//!
//! Loads the owner's opaque component pointer at `+0x430`, then tail-dispatches
//! that component through its vtable's `+0xb4` slot. The component becomes the
//! virtual method's receiver and its `u32` result is returned unchanged. Neither
//! the owner, component, vtable, nor slot has a NULL guard.
//!
//! # Deliberate deviation
//!
//! The component and its virtual method are not identified, so this port models
//! only their verified dispatch contract. Host vtable cells use native-width
//! pointers; `repr(C)` and target-only offset assertions preserve their ARM word
//! positions. Rust expresses the terminal `bx` as a typed call returning directly.

/// ARMv5TE word index of the component pointer in its owner.
const COMPONENT_WORD: usize = 0x430 / 4;
/// ARMv5TE vtable word index for byte offset `+0xb4`.
const COMPONENT_DISPATCH_SLOT: usize = 0xb4 / 4;

/// ABI of the unrecovered component method at vtable slot `+0xb4`.
pub type ComponentVtableSlot180Dispatch = unsafe extern "C" fn(*mut ComponentVtableSlot180) -> u32;

/// Prefix of the opaque component vtable consumed by the wrapper.
#[repr(C)]
pub struct ComponentVtableSlot180Vtable {
    /// `+0x00..+0xb0`: unresolved virtual entries.
    pub opaque_00_b0: [usize; COMPONENT_DISPATCH_SLOT],
    /// `+0xb4`: method invoked by the retail tail wrapper.
    pub dispatch: ComponentVtableSlot180Dispatch,
}

/// Component reached through the owner's `+0x430` field.
#[repr(C)]
pub struct ComponentVtableSlot180 {
    /// `+0x00`: virtual method table.
    pub vtable: *const ComponentVtableSlot180Vtable,
}

/// Owner prefix consumed by [`component_vtable_slot_180_tail_dispatch`].
#[repr(C)]
pub struct ComponentVtableSlot180Owner {
    /// `+0x00..+0x42c`: opaque owner state.
    pub opaque_00_42c: [u32; COMPONENT_WORD],
    /// `+0x430`: component selected as the virtual receiver.
    pub component: *mut ComponentVtableSlot180,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xb4] = [0; core::mem::offset_of!(ComponentVtableSlot180Vtable, dispatch)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x430] = [0; core::mem::offset_of!(ComponentVtableSlot180Owner, component)];

/// Tail-dispatches the owner's component through vtable slot `+0xb4`.
///
/// # Safety
///
/// `owner` must designate a readable [`ComponentVtableSlot180Owner`] with a
/// non-NULL component, vtable, and callable slot-`+0xb4` method. The retail
/// wrapper validates none of those pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.component_vtable_slot_180_tail_dispatch")]
pub unsafe extern "C" fn component_vtable_slot_180_tail_dispatch(
    owner: *mut ComponentVtableSlot180Owner,
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
    static mut FORWARDED_COMPONENT: *mut ComponentVtableSlot180 = ptr::null_mut();

    unsafe extern "C" fn wrong_slot(_component: *mut ComponentVtableSlot180) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(component: *mut ComponentVtableSlot180) -> u32 {
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
    fn dispatches_the_owner_component_through_only_slot_0xb4() {
        let _bench = bench();
        let mut vtable = ComponentVtableSlot180Vtable {
            opaque_00_b0: [wrong_slot as usize; COMPONENT_DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut component = ComponentVtableSlot180 { vtable: &mut vtable };
        let mut owner = ComponentVtableSlot180Owner {
            opaque_00_42c: [0; COMPONENT_WORD],
            component: &mut component,
        };

        let result = unsafe { component_vtable_slot_180_tail_dispatch(&mut owner) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0xb4 slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_COMPONENT, &mut component), "the component replaces owner in r0");
        }
    }
}
