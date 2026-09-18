//! Guarded virtual slot-`+0x04` dispatch through an object handle.
//!
//! `guarded_vtable_slot_04_dispatch_08157448` — original: `FUN_08157448` @
//! **0x08157448** (36 bytes). Raw `osos.dec` establishes the extent: nine
//! instructions from `push {r4, lr}` at `0x08157448` through `pop {r4, pc}`
//! at `0x08157468`; the next separately linked function starts at `0x0815746c`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly four
//! inbound direct calls, all plain unconditional `bl`: `0x08140730`,
//! `0x083d04ac`, `0x083d04fc`, and `0x083e73c0`. There are zero predicated
//! direct calls and no direct tail branches. The body makes no static calls;
//! its only call is a predicated `blxne` through vtable slot `+0x04`.
//!
//! # Algorithm
//!
//! The argument is a handle: a pointer to an object pointer. When the handle's
//! object word is NULL the function returns the handle unchanged. Otherwise it
//! reads the object's vtable word, dispatches vtable word 1 (`+0x04`) as
//! `method(object)`, discards that result, and returns the original handle.
//! The virtual method's concrete identity is unrecovered and deliberately not
//! inferred.
//!
//! # Deliberate deviation
//!
//! Target vtable words are 32-bit while host callback pointers are native-width,
//! so the Rust port uses a host-sized typed vtable. A dedicated text section
//! prevents LLVM from folding this separately hookable entry with the identical
//! `guarded_vtable_slot_04_dispatch` port at `0x083e72b0`.

/// ARMv5TE vtable word index for byte offset `+0x04`.
const VTABLE_SLOT: usize = 0x04 / 4;

/// Handle layout for the one word the wrapper observes.
#[repr(C)]
pub struct GuardedSlot04Handle08157448 {
    /// +0x00: object pointer, or NULL to suppress virtual dispatch.
    object: *mut u8,
}

/// ABI of the unrecovered virtual method at vtable slot `+0x04`.
type GuardedVtableSlot04 = unsafe extern "C" fn(*mut u8);

/// Dispatches the handled object's virtual slot `+0x04` when present.
///
/// # Safety
///
/// `handle` must be readable. When `handle.object` is non-NULL, the object
/// must start with a vtable pointer naming at least 2 readable entries and
/// entry 1 must be a valid [`GuardedVtableSlot04`] accepting the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.guarded_vtable_slot_04_dispatch_08157448")]
#[inline(never)]
pub unsafe extern "C" fn guarded_vtable_slot_04_dispatch_08157448(
    handle: *mut GuardedSlot04Handle08157448,
) -> *mut GuardedSlot04Handle08157448 {
    let object = unsafe { (*handle).object };
    if !object.is_null() {
        let vtable = unsafe { (object as *const usize).read() };
        let entry = unsafe { (vtable as *const usize).add(VTABLE_SLOT).read() };
        let method: GuardedVtableSlot04 = unsafe { core::mem::transmute(entry) };
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
        unsafe { FORWARDED_OBJECT = object as usize; }
    }

    unsafe extern "C" fn wrong_slot(_object: *mut u8) {
        unsafe { WRONG_SLOT_CALLS += 1; }
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
        let mut handle = GuardedSlot04Handle08157448 { object: core::ptr::null_mut() };
        let handle_pointer = &mut handle as *mut GuardedSlot04Handle08157448;

        let result = unsafe { guarded_vtable_slot_04_dispatch_08157448(handle_pointer) };

        assert_eq!(result, handle_pointer);
        assert_eq!(unsafe { FORWARDED_OBJECT }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }

    #[test]
    fn present_object_dispatches_only_slot_04_and_returns_handle() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; VTABLE_SLOT + 1];
        vtable[VTABLE_SLOT] = slot_method as usize;
        let mut object_words = [vtable.as_ptr() as usize, 0xdead_beef];
        let object_pointer = object_words.as_mut_ptr().cast::<u8>();
        let mut handle = GuardedSlot04Handle08157448 { object: object_pointer };
        let handle_pointer = &mut handle as *mut GuardedSlot04Handle08157448;

        let result = unsafe { guarded_vtable_slot_04_dispatch_08157448(handle_pointer) };

        assert_eq!(result, handle_pointer, "handle is returned, not the method result");
        assert_eq!(unsafe { FORWARDED_OBJECT }, object_pointer as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x04 dispatches");
        assert_eq!(handle.object, object_pointer, "handle word is never written");
        assert_eq!(object_words[1], 0xdead_beef, "object body is untouched");
    }
}
