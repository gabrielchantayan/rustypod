//! Guarded virtual slot-`+0x40` dispatch.
//!
//! `guarded_vtable_slot_40_dispatch` — original: `FUN_083d6138` @
//! **0x083d6138** (32 bytes, including the fallback literal at
//! `0x083d6158`). Raw ARM establishes the extent through `bx lr` at
//! `0x083d6154`; the separately linked next function starts at `0x083d615c`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly five
//! inbound direct calls, all unconditional `bl`: `0x080f03e0`, `0x08147fec`,
//! `0x08148000`, `0x08148354`, and `0x08148364`. There are no predicated calls
//! or direct tail branches, and no aligned image word equals this entry.
//!
//! # Algorithm
//!
//! Reads the receiver's target word at `+4`. A zero word returns the literal
//! pointer `0x08a0fc64`. Otherwise it loads virtual-table word 16 (`+0x40`),
//! calls it as `method(receiver, 0)`, and returns the method's result. The
//! receiver, vtable, and method are not NULL-checked on the dispatch path.
//! The guarded word's meaning and the concrete virtual method identity remain
//! unrecovered and are deliberately not inferred.
//!
//! # Deliberate deviation
//!
//! The target fallback is a firmware absolute pointer. Host builds instead
//! return a stable private byte's address: its pointed-to data is not examined
//! by this wrapper, while dereferencing the firmware address would be invalid.

/// ARMv5TE vtable word index for byte offset `+0x40`.
const VTABLE_SLOT: usize = 0x40 / 4;

/// Receiver layout for the two words the wrapper observes.
///
/// `state` is at target offset `+4`. The named fields intentionally widen on
/// hosts so their host pointers remain valid and never overlap.
#[repr(C)]
pub struct GuardedVtableReceiver {
    vtable: *const usize,
    state: u32,
}

/// ABI of the unrecovered virtual method at vtable slot `+0x40`.
type GuardedVtableSlot40 = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
static HOST_FALLBACK: u8 = 0;

#[inline(always)]
fn fallback_pointer() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        0x08a0_fc64 as *mut u8
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(HOST_FALLBACK).cast_mut()
    }
}

/// Dispatches virtual slot `+0x40` only when the receiver's guard word is set.
///
/// # Safety
///
/// `receiver` must be readable. When `receiver.state` is nonzero, its vtable
/// pointer must name at least 17 readable entries and entry 16 must be a valid
/// [`GuardedVtableSlot40`] accepting `receiver` and a zero second argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn guarded_vtable_slot_40_dispatch(
    receiver: *mut GuardedVtableReceiver,
) -> *mut u8 {
    if unsafe { (*receiver).state } == 0 {
        return fallback_pointer();
    }

    let vtable = unsafe { (*receiver).vtable };
    let entry = unsafe { vtable.add(VTABLE_SLOT).read() };
    let method: GuardedVtableSlot40 = unsafe { core::mem::transmute(entry) };
    unsafe { method(receiver.cast(), 0) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_ARGUMENT: u32 = u32::MAX;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut DISPATCH_RESULT: u8 = 0;

    unsafe extern "C" fn slot_method(receiver: *mut u8, argument: u32) -> *mut u8 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_ARGUMENT = argument;
            core::ptr::addr_of_mut!(DISPATCH_RESULT)
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _argument: u32) -> *mut u8 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            core::ptr::addr_of_mut!(DISPATCH_RESULT)
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_ARGUMENT = u32::MAX;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn zero_guard_returns_stable_fallback_without_dereferencing_vtable() {
        let _bench = bench();
        let mut receiver = GuardedVtableReceiver {
            vtable: core::ptr::null(),
            state: 0,
        };

        let first = unsafe { guarded_vtable_slot_40_dispatch(&mut receiver) };
        let second = unsafe { guarded_vtable_slot_40_dispatch(&mut receiver) };

        assert!(!first.is_null());
        assert_eq!(first, second);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }

    #[test]
    fn nonzero_guard_dispatches_only_slot_40_with_zero_argument() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; VTABLE_SLOT + 1];
        vtable[VTABLE_SLOT] = slot_method as usize;
        let mut receiver = GuardedVtableReceiver {
            vtable: vtable.as_ptr(),
            state: u32::MAX,
        };
        let receiver_pointer = (&mut receiver as *mut GuardedVtableReceiver).cast::<u8>();

        let result = unsafe { guarded_vtable_slot_40_dispatch(&mut receiver) };

        assert_eq!(result, unsafe { core::ptr::addr_of_mut!(DISPATCH_RESULT) });
        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver_pointer as usize);
        assert_eq!(unsafe { FORWARDED_ARGUMENT }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }
}
