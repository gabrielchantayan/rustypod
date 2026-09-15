//! Tail-dispatching an opaque component's vtable slot.
//!
//! `component_vtable_slot_208_tail_dispatch` — original: `FUN_081119c4` @
//! **0x081119c4** (16 bytes). Raw ARM establishes the exact body from
//! `0x081119c4` through the `bx r2` at `0x081119d0`; the independently linked
//! next function begins at `0x081119d4`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly four
//! inbound direct calls, all unconditional `bl` at `0x08112860`, `0x0819e2c0`,
//! `0x0819e31c`, and `0x08289b40`. There are no predicated forms or direct tail
//! branches. No aligned raw image word references this wrapper, so it is
//! statically called rather than virtual-dispatched.
//!
//! # Algorithm
//!
//! Loads the owner's opaque component pointer at `+0x430`, then tail-dispatches
//! that component through its vtable's `+0xd0` slot. The component replaces the
//! owner in `r0`; the selector already in `r1` is forwarded unchanged, and the
//! virtual method's `u32` result is returned unchanged. Neither the owner,
//! component, vtable, nor slot has a NULL guard.
//!
//! # Deliberate deviation
//!
//! The component and its virtual method are not identified, so this port models
//! only their verified dispatch contract. Host vtable cells use native-width
//! pointers; `repr(C)` and target-only offset assertions preserve their ARM word
//! positions. Rust expresses the terminal `bx` as a typed call returning directly.

/// ARMv5TE word index of the component pointer in its owner.
const COMPONENT_WORD: usize = 0x430 / 4;
/// ARMv5TE vtable word index for byte offset `+0xd0`.
const COMPONENT_DISPATCH_SLOT: usize = 0xd0 / 4;

/// ABI of the unrecovered component method at vtable slot `+0xd0`.
pub type ComponentVtableSlot208Dispatch = unsafe extern "C" fn(*mut ComponentVtableSlot208, u32) -> u32;

/// Prefix of the opaque component vtable consumed by the wrapper.
#[repr(C)]
pub struct ComponentVtableSlot208Vtable {
    /// `+0x00..+0xcc`: unresolved virtual entries.
    pub opaque_00_cc: [usize; COMPONENT_DISPATCH_SLOT],
    /// `+0xd0`: method invoked by the retail tail wrapper.
    pub dispatch: ComponentVtableSlot208Dispatch,
}

/// Component reached through the owner's `+0x430` field.
#[repr(C)]
pub struct ComponentVtableSlot208 {
    /// `+0x00`: virtual method table.
    pub vtable: *const ComponentVtableSlot208Vtable,
}

/// Owner prefix consumed by [`component_vtable_slot_208_tail_dispatch`].
#[repr(C)]
pub struct ComponentVtableSlot208Owner {
    /// `+0x00..+0x42c`: opaque owner state.
    pub opaque_00_42c: [u32; COMPONENT_WORD],
    /// `+0x430`: component selected as the virtual receiver.
    pub component: *mut ComponentVtableSlot208,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xd0] = [0; core::mem::offset_of!(ComponentVtableSlot208Vtable, dispatch)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x430] = [0; core::mem::offset_of!(ComponentVtableSlot208Owner, component)];

/// Tail-dispatches the owner's component through vtable slot `+0xd0`.
///
/// # Safety
///
/// `owner` must designate a readable [`ComponentVtableSlot208Owner`] with a
/// non-NULL component, vtable, and callable slot-`+0xd0` method. The retail
/// wrapper validates none of those pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.component_vtable_slot_208_tail_dispatch")]
pub unsafe extern "C" fn component_vtable_slot_208_tail_dispatch(
    owner: *mut ComponentVtableSlot208Owner,
    selector: u32,
) -> u32 {
    let component = unsafe { (*owner).component };
    let dispatch = unsafe { (*(*component).vtable).dispatch };
    unsafe { dispatch(component, selector) }
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
    static mut FORWARDED_COMPONENT: *mut ComponentVtableSlot208 = ptr::null_mut();
    static mut FORWARDED_SELECTOR: u32 = 0;

    unsafe extern "C" fn wrong_slot(_component: *mut ComponentVtableSlot208, _selector: u32) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(component: *mut ComponentVtableSlot208, selector: u32) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_COMPONENT = component;
            FORWARDED_SELECTOR = selector;
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
            FORWARDED_SELECTOR = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_owner_component_and_selector_through_only_slot_0xd0() {
        let _bench = bench();
        let mut vtable = ComponentVtableSlot208Vtable {
            opaque_00_cc: [wrong_slot as usize; COMPONENT_DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut component = ComponentVtableSlot208 { vtable: &mut vtable };
        let mut owner = ComponentVtableSlot208Owner {
            opaque_00_42c: [0; COMPONENT_WORD],
            component: &mut component,
        };

        let result = unsafe { component_vtable_slot_208_tail_dispatch(&mut owner, 0x1020_3040) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0xd0 slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_COMPONENT, &mut component), "the component replaces owner in r0");
            assert_eq!(FORWARDED_SELECTOR, 0x1020_3040, "r1 is forwarded to the virtual method");
        }
    }
}
