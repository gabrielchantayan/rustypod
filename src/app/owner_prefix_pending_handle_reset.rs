//! Resets an opaque owner-prefix state and its pending shared-cell handle.
//!
//! `owner_prefix_pending_handle_reset` — original: `FUN_08214a84` @
//! **0x08214a84** (**72 bytes**, `0x08214a84..0x08214ac8`; the next distinct
//! function starts with `push {r4,r5,r6,r7,r8,lr}` at `0x08214acc`). Raw ARM
//! contains five unconditional direct `bl` instructions and no predicated
//! `bl`; whole-image decoding finds three inbound plain `bl` call sites
//! (`0x08214654`, `0x082147c4`, `0x08214dc4`) and zero predicated inbound calls.
//!
//! The routine invokes the unrecovered state reset at `0x0822bdc0`, dispatches
//! the owner-prefix vtable slot `+0x30`, replaces the shared-cell handle at
//! `+0x2f4` with an empty handle, then stores `{1, 0}` at `+0x2f0..+0x2f1`.
//!
//! # Deliberate deviation
//!
//! The `0x0822bdc0` callee has no established semantic identity, so target
//! builds call its verified retailOS address and host tests provide a recording
//! seam. Host pointers cannot occupy the target's four-byte handle slot, so the
//! host implementation writes only the observed empty u32 slot; target builds
//! invoke the ported shared-cell operations exactly as ARM does.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;
#[cfg(target_os = "none")]
use core::ptr::addr_of_mut;

#[cfg(not(target_arch = "arm"))]
use crate::cxx::owner_prefix_vtable_slot_30_tail_dispatch::owner_prefix_vtable_slot_30_tail_dispatch;
#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn owner_prefix_vtable_slot_30_tail_dispatch(address_after_owner_prefix: *mut u32) -> u32;
}
#[cfg(target_os = "none")]
use crate::cxx::shared_cell::{shared_cell_assign, shared_cell_construct, shared_cell_release, SharedCell};

const PENDING_HANDLE_OFFSET: usize = 0x2f4;
const RESET_FLAG_OFFSET: usize = 0x2f0;
const RETAIL_OWNER_PREFIX_STATE_RESET: usize = 0x0822_bdc0;

/// ABI of the unported state-reset callee at `0x0822bdc0`.
pub type OwnerPrefixStateReset = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn reset_owner_prefix_state(state: *mut u8) {
    let reset: OwnerPrefixStateReset = core::mem::transmute(RETAIL_OWNER_PREFIX_STATE_RESET);
    reset(state);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_prefix_state_reset(_state: *mut u8) {}

/// Host seam for the otherwise unported `0x0822bdc0` state reset.
#[cfg(not(target_os = "none"))]
pub static mut OWNER_PREFIX_STATE_RESET: OwnerPrefixStateReset = missing_owner_prefix_state_reset;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn reset_owner_prefix_state(state: *mut u8) {
    let reset = core::ptr::read_volatile(addr_of!(OWNER_PREFIX_STATE_RESET));
    reset(state);
}

/// Resets the owner-prefix state, dispatches its `+0x30` callback, and empties
/// the pending shared-cell handle.
///
/// # Safety
///
/// `state` must point 0x2d8 bytes after a valid owner prefix accepted by
/// [`owner_prefix_vtable_slot_30_tail_dispatch`], and must include writable
/// bytes through `+0x2f7`. The retail routine has no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_prefix_pending_handle_reset(state: *mut u8) {
    reset_owner_prefix_state(state);
    owner_prefix_vtable_slot_30_tail_dispatch(state.cast());
    empty_pending_handle(state);
    state.add(RESET_FLAG_OFFSET).write(1);
    state.add(RESET_FLAG_OFFSET + 1).write(0);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn empty_pending_handle(state: *mut u8) {
    let handle = state.add(PENDING_HANDLE_OFFSET).cast::<*mut SharedCell>();
    let mut empty = core::ptr::null_mut();
    shared_cell_construct(addr_of_mut!(empty), core::ptr::null_mut());
    shared_cell_assign(handle, addr_of_mut!(empty));
    shared_cell_release(addr_of_mut!(empty));
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn empty_pending_handle(state: *mut u8) {
    state.add(PENDING_HANDLE_OFFSET).cast::<u32>().write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::owner_prefix_vtable_slot_30_tail_dispatch::{OwnerPrefixVtableSlot30Receiver, OwnerPrefixVtableSlot30Vtable};
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RESET_CALLS: u32 = 0;
    static mut RESET_STATE: *mut u8 = ptr::null_mut();
    static mut DISPATCH_CALLS: u32 = 0;
    static mut DISPATCH_RECEIVER: *mut OwnerPrefixVtableSlot30Receiver = ptr::null_mut();

    unsafe extern "C" fn record_reset(state: *mut u8) {
        RESET_CALLS += 1;
        RESET_STATE = state;
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut OwnerPrefixVtableSlot30Receiver) -> u32 {
        DISPATCH_CALLS += 1;
        DISPATCH_RECEIVER = receiver;
        0
    }

    #[repr(C)]
    struct Fixture {
        receiver: OwnerPrefixVtableSlot30Receiver,
        tail: [u8; PENDING_HANDLE_OFFSET + 4],
    }

    #[test]
    fn resets_the_state_dispatches_owner_and_empties_pending_handle() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut vtable = OwnerPrefixVtableSlot30Vtable {
            opaque_00_2c: [0; 0x30 / 4],
            dispatch: record_dispatch,
        };
        let mut fixture = Fixture {
            receiver: OwnerPrefixVtableSlot30Receiver {
                vtable: &mut vtable,
                opaque_04_2d7: [0; 0x2d8 / 4 - 1],
            },
            tail: [0; PENDING_HANDLE_OFFSET + 4],
        };
        let state = unsafe { ptr::addr_of_mut!(fixture.receiver).cast::<u32>().add(0x2d8 / 4).cast::<u8>() };

        unsafe {
            state.add(PENDING_HANDLE_OFFSET).cast::<u32>().write(0xdead_beef);
            state.add(RESET_FLAG_OFFSET).write(0);
            state.add(RESET_FLAG_OFFSET + 1).write(0xff);
            RESET_CALLS = 0;
            RESET_STATE = ptr::null_mut();
            DISPATCH_CALLS = 0;
            DISPATCH_RECEIVER = ptr::null_mut();
            OWNER_PREFIX_STATE_RESET = record_reset;

            owner_prefix_pending_handle_reset(state);

            assert_eq!(RESET_CALLS, 1);
            assert_eq!(RESET_STATE, state);
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(DISPATCH_RECEIVER, ptr::addr_of_mut!(fixture.receiver));
            assert_eq!(state.add(PENDING_HANDLE_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(state.add(RESET_FLAG_OFFSET).read(), 1);
            assert_eq!(state.add(RESET_FLAG_OFFSET + 1).read(), 0);
            OWNER_PREFIX_STATE_RESET = missing_owner_prefix_state_reset;
        }
    }
}
