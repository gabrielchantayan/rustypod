//! `locked_vtable_slot_16_dispatch` — original: `FUN_0828083c` @
//! **0x0828083c** (80 bytes; seven unconditional direct `bl` call sites).
//!
//! Raw ARM establishes the exact 80-byte body from `0x0828083c` through its
//! `pop {r4,r5,r6,r7,r8,pc}` at `0x08280888`; the separately linked sibling
//! begins at `0x0828088c`. Decoding every ARM immediate `B`/`BL` word in
//! `osos.dec` finds calls at `0x0814a3a0`, `0x08162e58`, `0x08162e70`,
//! `0x08162e88`, `0x081631e0`, `0x081631f8`, and `0x0816331c`. All are plain
//! `bl`; there are no predicated or tail-branch callers, and no aligned image
//! word equals this entry, so it is statically called rather than virtual.
//!
//! # Algorithm
//!
//! Locks the receiver's counted mutex at `+0x78`, then loads vtable slot
//! `+0x10` and invokes it as `(receiver, selector, mode, receiver[+0x70] +
//! 0xc4)`. It releases the counted mutex after the virtual call and returns
//! the slot's 32-bit result unchanged. The receiver and the virtual slot have
//! no NULL guards. The actual receiver type and slot identity are unrecovered,
//! so the name states only the verified locking and dispatch behavior.
//!
//! # Deliberate deviation
//!
//! Rust models the ARM vtable as an array of host-sized function pointers.
//! The slot index, rather than a host byte offset, preserves the ARM `+0x10`
//! selection; the `repr(C)` receiver's named fields preserve its distinct
//! target fields without overlapping host pointers.

use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

/// ARMv5TE vtable word index for byte offset `+0x10`.
const LOCKED_DISPATCH_SLOT: usize = 0x10 / 4;
/// Byte displacement from the receiver's context field that reaches the
/// virtual slot's fourth argument.
const DISPATCH_CONTEXT_OFFSET: usize = 0xc4;

/// ABI of the unrecovered vtable slot at receiver vtable `+0x10`.
pub type LockedVtableSlot16 = unsafe extern "C" fn(
    *mut LockedVtableSlot16Receiver,
    u32,
    u32,
    *mut u8,
) -> u32;

/// Partial receiver layout used by [`locked_vtable_slot_16_dispatch`].
///
/// On ARM its fields land at vtable `+0x0`, context `+0x70`, and counted mutex
/// pointer `+0x78`. The host layout intentionally uses native-width pointers;
/// accesses are through named fields, never manually computed host offsets.
#[repr(C)]
pub struct LockedVtableSlot16Receiver {
    pub vtable: *const LockedVtableSlot16,
    _before_context: [u32; 27],
    pub dispatch_context: *mut u8,
    _before_lock: u32,
    pub lock: *mut CountedMutex,
}

/// Acquires the receiver's counted mutex, invokes virtual slot `+0x10`, then
/// releases the mutex and returns the slot result.
///
/// # Safety
///
/// `receiver` must be a non-NULL readable/writable
/// [`LockedVtableSlot16Receiver`] with a valid counted mutex, vtable, and
/// slot-16 callback. Its `dispatch_context` must support an offset of `0xc4`.
/// As in the firmware, the callback executes while the counted mutex is held.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_vtable_slot_16_dispatch(
    receiver: *mut LockedVtableSlot16Receiver,
    selector: u32,
    mode: u32,
) -> u32 {
    let lock = unsafe { (*receiver).lock };
    unsafe { mutex_lock_counted(lock) };

    let vtable = unsafe { (*receiver).vtable };
    let callback = unsafe { vtable.add(LOCKED_DISPATCH_SLOT).read() };
    let dispatch_context = unsafe { (*receiver).dispatch_context.add(DISPATCH_CONTEXT_OFFSET) };
    let result = unsafe { callback(receiver, selector, mode, dispatch_context) };

    unsafe { mutex_unlock_counted(lock) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    unsafe extern "C" fn assert_forwarded_arguments_while_locked(
        receiver: *mut LockedVtableSlot16Receiver,
        selector: u32,
        mode: u32,
        context: *mut u8,
    ) -> u32 {
        assert_eq!(selector, 0x1020_3040);
        assert_eq!(mode, 0x5060_7080);
        assert_eq!(unsafe { (*(*receiver).lock).hold_count }, 1);
        assert_eq!(context, unsafe { (*receiver).dispatch_context.add(DISPATCH_CONTEXT_OFFSET) });
        0xa5a5_5a5a
    }

    unsafe extern "C" fn return_wrapped_hold_count(
        receiver: *mut LockedVtableSlot16Receiver,
        _selector: u32,
        _mode: u32,
        _context: *mut u8,
    ) -> u32 {
        unsafe { (*(*receiver).lock).hold_count }
    }

    fn receiver(
        vtable: *const LockedVtableSlot16,
        dispatch_context: *mut u8,
        lock: *mut CountedMutex,
    ) -> LockedVtableSlot16Receiver {
        LockedVtableSlot16Receiver {
            vtable,
            _before_context: [0; 27],
            dispatch_context,
            _before_lock: 0,
            lock,
        }
    }

    fn counted_mutex(hold_count: u32) -> CountedMutex {
        CountedMutex {
            mutex: Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            },
            hold_count,
        }
    }

    #[test]
    fn dispatches_slot_16_with_context_while_lock_is_held() {
        let mut context = [0u8; DISPATCH_CONTEXT_OFFSET + 1];
        let mut lock = counted_mutex(0);
        let vtable: [LockedVtableSlot16; LOCKED_DISPATCH_SLOT + 1] = [
            assert_forwarded_arguments_while_locked,
            assert_forwarded_arguments_while_locked,
            assert_forwarded_arguments_while_locked,
            assert_forwarded_arguments_while_locked,
            assert_forwarded_arguments_while_locked,
        ];
        let mut receiver = receiver(vtable.as_ptr(), context.as_mut_ptr(), &mut lock);

        let result = unsafe {
            locked_vtable_slot_16_dispatch(&mut receiver, 0x1020_3040, 0x5060_7080)
        };

        assert_eq!(result, 0xa5a5_5a5a);
        assert_eq!(lock.hold_count, 0, "unlock follows the virtual call");
    }

    #[test]
    fn restores_wrapping_count_after_dispatch() {
        let mut context = [0u8; DISPATCH_CONTEXT_OFFSET + 1];
        let mut lock = counted_mutex(u32::MAX);
        let vtable: [LockedVtableSlot16; LOCKED_DISPATCH_SLOT + 1] = [
            return_wrapped_hold_count,
            return_wrapped_hold_count,
            return_wrapped_hold_count,
            return_wrapped_hold_count,
            return_wrapped_hold_count,
        ];
        let mut receiver = receiver(vtable.as_ptr(), context.as_mut_ptr(), &mut lock);

        let result = unsafe { locked_vtable_slot_16_dispatch(&mut receiver, 0, 0) };

        assert_eq!(result, 0, "the callback observes the wrapped held count");
        assert_eq!(lock.hold_count, u32::MAX, "unlock restores the prior count");
    }
}
