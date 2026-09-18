//! Tail-dispatching an owner's nested object through vtable slot `+0xec`.
//!
//! `owner_vtable_slot_ec_tail_dispatch` — original: `FUN_08116e34` @
//! **0x08116e34** (16 bytes). Raw ARM establishes the exact body from
//! `0x08116e34` through the `bx r1` at `0x08116e40`; the independently linked
//! next function begins at `0x08116e44`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly four
//! inbound direct calls: three unconditional `bl` at `0x08115204`,
//! `0x08116464`, and `0x0812f388`, plus one predicated `bleq` at `0x0812f344`.
//! There are no direct tail branches.
//!
//! # Algorithm
//!
//! Loads the nested dispatch object at owner `+0x888`, reads its vtable's
//! `+0xec` slot, and tail-dispatches it with that nested object in `r0`. The
//! virtual method's `u32` result remains in `r0`.
//!
//! # Deliberate deviation
//!
//! The owner, nested object, and virtual method are unrecovered, so this port
//! models only the verified dispatch contract. Host vtable cells use native-width
//! pointers; `repr(C)` and target-only offset assertions preserve their ARM word
//! positions. Rust expresses the terminal `bx` as a typed call.

/// ARMv5TE word index of the nested dispatch object in its owner.
const DISPATCH_OBJECT_WORD: usize = 0x888 / 4;
/// ARMv5TE vtable word index for byte offset `+0xec`.
const DISPATCH_SLOT: usize = 0xec / 4;

/// ABI of the unrecovered method at vtable slot `+0xec`.
pub type OwnerVtableSlotEcDispatch = unsafe extern "C" fn(*mut OwnerVtableSlotEcDispatchObject) -> u32;

/// Prefix of the opaque nested object's vtable consumed by the wrapper.
#[repr(C)]
pub struct OwnerVtableSlotEcDispatchVtable {
    /// `+0x00..+0xe8`: unresolved virtual entries.
    pub opaque_00_e8: [usize; DISPATCH_SLOT],
    /// `+0xec`: method invoked by the retail tail wrapper.
    pub dispatch: OwnerVtableSlotEcDispatch,
}

/// Nested object reached through the owner's `+0x888` field.
#[repr(C)]
pub struct OwnerVtableSlotEcDispatchObject {
    /// `+0x00`: virtual method table.
    pub vtable: *const OwnerVtableSlotEcDispatchVtable,
}

/// Owner prefix consumed by [`owner_vtable_slot_ec_tail_dispatch`].
#[repr(C)]
pub struct OwnerVtableSlotEcDispatchOwner {
    /// `+0x00..+0x884`: opaque owner state.
    pub opaque_00_884: [u32; DISPATCH_OBJECT_WORD],
    /// `+0x888`: nested object selected as the virtual receiver.
    pub dispatch_object: *mut OwnerVtableSlotEcDispatchObject,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xec] = [0; core::mem::offset_of!(OwnerVtableSlotEcDispatchVtable, dispatch)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x888] = [0; core::mem::offset_of!(OwnerVtableSlotEcDispatchOwner, dispatch_object)];

/// Tail-dispatches the owner's nested object through vtable slot `+0xec`.
///
/// # Safety
///
/// `owner` must designate a readable [`OwnerVtableSlotEcDispatchOwner`] with a
/// non-NULL nested object, vtable, and callable slot-`+0xec` method. The retail
/// wrapper validates none of those pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.owner_vtable_slot_ec_tail_dispatch")]
pub unsafe extern "C" fn owner_vtable_slot_ec_tail_dispatch(
    owner: *mut OwnerVtableSlotEcDispatchOwner,
) -> u32 {
    let dispatch_object = unsafe { (*owner).dispatch_object };
    let dispatch = unsafe { (*(*dispatch_object).vtable).dispatch };
    unsafe { dispatch(dispatch_object) }
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
    static mut FORWARDED_OBJECT: *mut OwnerVtableSlotEcDispatchObject = ptr::null_mut();

    unsafe extern "C" fn wrong_slot(_object: *mut OwnerVtableSlotEcDispatchObject) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(object: *mut OwnerVtableSlotEcDispatchObject) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_OBJECT = object;
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
            FORWARDED_OBJECT = ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_the_owner_object_through_only_slot_0xec() {
        let _bench = bench();
        let mut vtable = OwnerVtableSlotEcDispatchVtable {
            opaque_00_e8: [wrong_slot as usize; DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut dispatch_object = OwnerVtableSlotEcDispatchObject { vtable: &mut vtable };
        let mut owner = OwnerVtableSlotEcDispatchOwner {
            opaque_00_884: [0; DISPATCH_OBJECT_WORD],
            dispatch_object: &mut dispatch_object,
        };

        let result = unsafe { owner_vtable_slot_ec_tail_dispatch(&mut owner) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0xec slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(core::ptr::eq(FORWARDED_OBJECT, &mut dispatch_object), "the nested object replaces owner in r0");
        }
    }
}
