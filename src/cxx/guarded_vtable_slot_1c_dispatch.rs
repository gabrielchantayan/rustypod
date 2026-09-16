//! Guarded virtual slot-`+0x1c` dispatch through an object handle.
//!
//! `guarded_vtable_slot_1c_dispatch` — original: `FUN_083e72d4` @
//! **0x083e72d4** (36 bytes). Raw ARM establishes the extent: nine
//! instructions from `push {r4, lr}` at `0x083e72d4` through
//! `pop {r4, pc}` at `0x083e72f4`; the next function's `push {r4-r6, lr}`
//! starts at `0x083e72f8`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly
//! four inbound direct calls, all unconditional `bl`: `0x082267f0`,
//! `0x082268ec`, `0x08226aec`, and `0x08232bdc`. There are no predicated
//! call forms or direct tail branches.
//!
//! # Algorithm
//!
//! The argument is a handle: a pointer to an object pointer. When the
//! handle's object word is NULL the function returns the handle unchanged.
//! Otherwise it loads the object's vtable pointer, reads virtual-table
//! word 7 (`+0x1c`), and calls it as `method(object)` — the dispatch's
//! `r0` holds the inner object, not the handle, which Ghidra's argument
//! recovery misses. The method's result is discarded; the function always
//! returns the original handle in `r0`. The guarded object pointer's
//! meaning and the concrete virtual method identity remain unrecovered
//! and are deliberately not inferred.
//!
//! # Deliberate deviation
//!
//! Target vtable words are 32-bit while host callback pointers are
//! native-width, so the Rust port uses a host-sized typed vtable; this is
//! the only deliberate deviation.

/// ARMv5TE vtable word index for byte offset `+0x1c`.
const VTABLE_SLOT: usize = 0x1c / 4;

/// Handle layout for the one word the wrapper observes.
///
/// `object` is at target offset `+0`. The named field intentionally widens
/// on hosts so its host pointer remains valid.
#[repr(C)]
pub struct GuardedSlot1cHandle {
    object: *mut u8,
}

/// ABI of the unrecovered virtual method at vtable slot `+0x1c`.
type GuardedVtableSlot1c = unsafe extern "C" fn(*mut u8);

/// Dispatches the handled object's virtual slot `+0x1c` when present.
///
/// # Safety
///
/// `handle` must be readable. When `handle.object` is non-NULL, the object
/// must start with a vtable pointer naming at least 8 readable entries and
/// entry 7 must be a valid [`GuardedVtableSlot1c`] accepting the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn guarded_vtable_slot_1c_dispatch(
    handle: *mut GuardedSlot1cHandle,
) -> *mut GuardedSlot1cHandle {
    let object = unsafe { (*handle).object };
    if !object.is_null() {
        let vtable = unsafe { (object as *const usize).read() };
        let entry = unsafe { (vtable as *const usize).add(VTABLE_SLOT).read() };
        let method: GuardedVtableSlot1c = unsafe { core::mem::transmute(entry) };
        unsafe { method(object) };
    }
    handle
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_OBJECT: usize = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn slot_method(object: *mut u8) {
        unsafe {
            FORWARDED_OBJECT = object as usize;
        }
    }

    unsafe extern "C" fn wrong_slot(_object: *mut u8) {
        unsafe {
            WRONG_SLOT_CALLS += 1;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_OBJECT = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn null_object_returns_handle_without_dereferencing_vtable() {
        let _bench = bench();
        let mut handle = GuardedSlot1cHandle {
            object: core::ptr::null_mut(),
        };
        let handle_pointer = &mut handle as *mut GuardedSlot1cHandle;

        let result = unsafe { guarded_vtable_slot_1c_dispatch(handle_pointer) };

        assert_eq!(result, handle_pointer);
        assert_eq!(unsafe { FORWARDED_OBJECT }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }

    #[test]
    fn present_object_dispatches_only_slot_1c_and_returns_handle() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; VTABLE_SLOT + 1];
        vtable[VTABLE_SLOT] = slot_method as usize;
        let mut object_words = [vtable.as_ptr() as usize, 0];
        let object_pointer = object_words.as_mut_ptr().cast::<u8>();
        let mut handle = GuardedSlot1cHandle {
            object: object_pointer,
        };
        let handle_pointer = &mut handle as *mut GuardedSlot1cHandle;

        let result = unsafe { guarded_vtable_slot_1c_dispatch(handle_pointer) };

        assert_eq!(result, handle_pointer, "handle is returned, not the method result");
        assert_eq!(unsafe { FORWARDED_OBJECT }, object_pointer as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x1c dispatches");
    }
}
