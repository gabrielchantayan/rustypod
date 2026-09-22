//! Tail-dispatching an opaque owner's prefix virtual method.
//!
//! `owner_prefix_vtable_slot_30_tail_dispatch` — original: `FUN_08214d34`
//! @ **0x08214d34** (12 bytes). Raw ARM establishes the exact three-word body
//! from `0x08214d34` through the terminal `bx r1` at `0x08214d3c`; the next
//! distinct function begins at `0x08214d40`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly three
//! inbound direct calls, all unconditional `bl` at `0x08214a94`, `0x08214d4c`,
//! and `0x08214da8`. There are no predicated `bl` forms or direct tail branches.
//!
//! # Algorithm
//!
//! Treats its argument as an address 0x2d8 bytes after an opaque owner prefix,
//! loads that prefix's vtable, then tail-dispatches its `+0x30` virtual slot.
//! The adjusted prefix pointer replaces the incoming argument in `r0`; the
//! virtual method's `u32` result remains in `r0`.
//!
//! # Deliberate deviation
//!
//! The virtual method has no recovered identity, so this port models only the
//! verified dispatch contract. Host vtable cells use native-width pointers;
//! target-only offset assertions preserve their ARM word positions. The target
//! build retains the exact three-instruction terminal dispatch in ARM assembly.

/// ARMv5TE word count between the incoming address and the owner prefix.
const OWNER_PREFIX_WORDS: usize = 0x2d8 / 4;
/// ARMv5TE vtable word index for byte offset `+0x30`.
const DISPATCH_SLOT: usize = 0x30 / 4;

/// ABI of the unrecovered owner-prefix method at vtable slot `+0x30`.
pub type OwnerPrefixVtableSlot30Dispatch = unsafe extern "C" fn(*mut OwnerPrefixVtableSlot30Receiver) -> u32;

/// Prefix of the opaque vtable consumed by the tail wrapper.
#[repr(C)]
pub struct OwnerPrefixVtableSlot30Vtable {
    /// `+0x00..+0x2c`: unresolved virtual entries.
    pub opaque_00_2c: [usize; DISPATCH_SLOT],
    /// `+0x30`: method invoked by the retail tail wrapper.
    pub dispatch: OwnerPrefixVtableSlot30Dispatch,
}

/// Owner prefix reached by subtracting `0x2d8` from the wrapper argument.
#[repr(C)]
pub struct OwnerPrefixVtableSlot30Receiver {
    /// `+0x00`: virtual method table.
    pub vtable: *const OwnerPrefixVtableSlot30Vtable,
    /// `+0x04..+0x2d7`: opaque owner-prefix state.
    pub opaque_04_2d7: [u32; OWNER_PREFIX_WORDS - 1],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x30] = [0; core::mem::offset_of!(OwnerPrefixVtableSlot30Vtable, dispatch)];

/// Tail-dispatches an opaque owner prefix through vtable slot `+0x30`.
///
/// # Safety
///
/// `address_after_owner_prefix` must be exactly `0x2d8` bytes after a readable
/// [`OwnerPrefixVtableSlot30Receiver`] with a non-NULL vtable and callable
/// slot-`+0x30` method. The retail wrapper validates none of those pointers.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owner_prefix_vtable_slot_30_tail_dispatch(
    address_after_owner_prefix: *mut u32,
) -> u32 {
    let receiver = unsafe { address_after_owner_prefix.sub(OWNER_PREFIX_WORDS) }
        .cast::<OwnerPrefixVtableSlot30Receiver>();
    let dispatch = unsafe { (*(*receiver).vtable).dispatch };
    unsafe { dispatch(receiver) }
}

// Keep the retail terminal virtual dispatch as assembly: Rust otherwise emits
// a prologue/epilogue around the typed call instead of the stock `bx r1`.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl owner_prefix_vtable_slot_30_tail_dispatch
    .type owner_prefix_vtable_slot_30_tail_dispatch, %function
owner_prefix_vtable_slot_30_tail_dispatch:
    ldr     r1, [r0, #-0x2d8]!
    ldr     r1, [r1, #0x30]
    bx      r1
    .size owner_prefix_vtable_slot_30_tail_dispatch, . - owner_prefix_vtable_slot_30_tail_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut FORWARDED_RECEIVER: *mut OwnerPrefixVtableSlot30Receiver = ptr::null_mut();

    unsafe extern "C" fn wrong_slot(_receiver: *mut OwnerPrefixVtableSlot30Receiver) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut OwnerPrefixVtableSlot30Receiver) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_RECEIVER = receiver;
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
            FORWARDED_RECEIVER = ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[test]
    fn subtracts_the_owner_prefix_and_dispatches_only_slot_0x30() {
        let _bench = bench();
        let mut vtable = OwnerPrefixVtableSlot30Vtable {
            opaque_00_2c: [wrong_slot as usize; DISPATCH_SLOT],
            dispatch: record_dispatch,
        };
        let mut receiver = OwnerPrefixVtableSlot30Receiver {
            vtable: &mut vtable,
            opaque_04_2d7: [0; OWNER_PREFIX_WORDS - 1],
        };
        let address_after_owner_prefix = unsafe {
            core::ptr::addr_of_mut!(receiver).cast::<u32>().add(OWNER_PREFIX_WORDS)
        };

        let result = unsafe { owner_prefix_vtable_slot_30_tail_dispatch(address_after_owner_prefix) };

        assert_eq!(result, 0xcafe_babe, "the virtual result remains in r0");
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1, "the +0x30 slot runs exactly once");
            assert_eq!(WRONG_SLOT_CALLS, 0, "no preceding vtable slot is called");
            assert!(ptr::eq(FORWARDED_RECEIVER, &mut receiver), "r0 becomes the owner prefix");
        }
    }
}
