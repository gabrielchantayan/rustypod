//! Guarded virtual slot-`+0x04` dispatch through an object handle.
//!
//! `guarded_vtable_slot_04_dispatch_083e7630` — original: `FUN_083e7630` @
//! **0x083e7630** (32 bytes). Raw ARM establishes the extent: eight
//! instructions from `push {r4, lr}` at `0x083e7630` through
//! `pop {r4, pc}` at `0x083e764c`; `push {r2,r3,r4,r5,r6,lr}` at
//! `0x083e7650` begins the next real function. Ghidra's 36-byte extent
//! includes that next function's first instruction.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly
//! three inbound direct calls, all unconditional `bl`: `0x08139698`,
//! `0x08139854`, and `0x08139908`. There are no predicated inbound direct
//! calls or direct tail branches. The body has no direct `bl` instructions;
//! its sole call is the predicated indirect `blxne r1` virtual dispatch.
//!
//! # Algorithm
//!
//! The argument is a handle: a pointer to an object pointer. When the
//! handle's object word is NULL the function returns the handle unchanged.
//! Otherwise it loads the object's vtable pointer, reads virtual-table word
//! 1 (`+0x04`), and calls it as `method(object)` — `r0` holds the inner
//! object, not the handle. The method's result is discarded; the function
//! always returns the original handle in `r0`. Recovered callers use it in
//! cleanup paths, but the concrete virtual method identity remains
//! unrecovered and is deliberately not inferred.
//!
//! # Deliberate deviation
//!
//! Target vtable words are 32-bit while host callback pointers are
//! native-width, so the Rust port uses a host-sized typed vtable; this is the
//! only deliberate deviation.

/// ARMv5TE vtable word index for byte offset `+0x04`.
const VTABLE_SLOT: usize = 0x04 / 4;

/// Handle layout for the one word the wrapper observes.
///
/// `object` is at target offset `+0`. The named field intentionally widens
/// on hosts so its host pointer remains valid.
#[repr(C)]
pub struct GuardedSlot04Handle {
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
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn guarded_vtable_slot_04_dispatch_083e7630(
    handle: *mut GuardedSlot04Handle,
) -> *mut GuardedSlot04Handle {
    let object = unsafe { (*handle).object };
    if !object.is_null() {
        let vtable = unsafe { (object as *const usize).read() };
        let entry = unsafe { (vtable as *const usize).add(VTABLE_SLOT).read() };
        let method: GuardedVtableSlot04 = unsafe { core::mem::transmute(entry) };
        unsafe { method(object) };
    }
    handle
}

// The device form preserves the original predicated virtual call and the
// caller-visible `{r4, lr}` frame exactly.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    ".syntax unified",
    ".arm",
    ".global guarded_vtable_slot_04_dispatch_083e7630",
    ".type guarded_vtable_slot_04_dispatch_083e7630,%function",
    "guarded_vtable_slot_04_dispatch_083e7630:",
    "push {{r4, lr}}",
    "mov r4, r0",
    "ldr r0, [r0]",
    "cmp r0, #0",
    "ldrne r1, [r0]",
    "ldrne r1, [r1, #4]",
    "blxne r1",
    "mov r0, r4",
    "pop {{r4, pc}}",
    ".size guarded_vtable_slot_04_dispatch_083e7630, . - guarded_vtable_slot_04_dispatch_083e7630",
);

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
        let mut handle = GuardedSlot04Handle {
            object: core::ptr::null_mut(),
        };
        let handle_pointer = &mut handle as *mut GuardedSlot04Handle;

        let result = unsafe { guarded_vtable_slot_04_dispatch_083e7630(handle_pointer) };

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
        let mut handle = GuardedSlot04Handle {
            object: object_pointer,
        };
        let handle_pointer = &mut handle as *mut GuardedSlot04Handle;

        let result = unsafe { guarded_vtable_slot_04_dispatch_083e7630(handle_pointer) };

        assert_eq!(result, handle_pointer, "handle is returned, not the method result");
        assert_eq!(unsafe { FORWARDED_OBJECT }, object_pointer as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x04 dispatches");
        assert_eq!(handle.object, object_pointer, "handle word is never written");
        assert_eq!(object_words[1], 0xdead_beef, "object body is untouched");
    }
}
