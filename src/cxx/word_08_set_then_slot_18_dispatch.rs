//! Virtual word-`+0x08` setter followed by slot-`+0x18` dispatch.
//!
//! `word_08_set_then_slot_18_dispatch` — original: `FUN_081534b8` @
//! **0x081534b8** (32 bytes). Raw ARM establishes the exact extent from
//! `push {r4,lr}` at `0x081534b8` through `pop {r4,pc}` at `0x081534d4`;
//! the next real function begins at `0x081534d8` with `push {r4,lr}`.
//! Decoding every immediate `B`/`BL` word in `osos.dec` finds four inbound
//! direct calls, all unconditional `bl` at `0x08170e4c`, `0x081a5430`,
//! `0x081bbe70`, and `0x081bbf18`; there are no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Stores `value` at object word `+0x08`, then calls the object's unrecovered
//! vtable slot `+0x18` with the object as its only argument and returns zero.
//! Neither object nor vtable is NULL-checked, matching retailOS.
//!
//! # Deliberate deviation
//!
//! The target vtable contains 32-bit entries while host function pointers are
//! wider. Rust models the host vtable with `usize` entries and selects entry
//! six; the concrete virtual method identity is not established and is
//! deliberately not invented.

/// ARMv5TE vtable word index for byte offset `+0x18`.
const DISPATCH_SLOT: usize = 0x18 / 4;

/// Object prefix consumed by the wrapper.
#[repr(C)]
pub struct Word08Slot18Object {
    pub vtable: *const usize,
    _word_04: u32,
    pub value: u32,
}

/// ABI of the unrecovered virtual method in vtable slot `+0x18`.
type VtableSlot18Dispatch = unsafe extern "C" fn(*mut Word08Slot18Object);

/// Stores `value` at object word `+0x08`, dispatches vtable slot `+0x18`, and returns zero.
///
/// # Safety
///
/// `object` must be writable through word `+0x08` and contain a readable vtable
/// whose word-six entry is a valid [`VtableSlot18Dispatch`]. No pointer is
/// NULL-checked, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_08_set_then_slot_18_dispatch(
    object: *mut Word08Slot18Object,
    value: u32,
) -> u32 {
    unsafe {
        (*object).value = value;
        let entry = (*object).vtable.add(DISPATCH_SLOT).read();
        let dispatch: VtableSlot18Dispatch = core::mem::transmute(entry);
        dispatch(object);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHED_OBJECT: usize = 0;
    static mut DISPATCHED_VALUE: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn dispatch(object: *mut Word08Slot18Object) {
        unsafe {
            DISPATCHED_OBJECT = object as usize;
            DISPATCHED_VALUE = (*object).value;
        }
    }

    unsafe extern "C" fn wrong_slot(_object: *mut Word08Slot18Object) {
        unsafe { WRONG_SLOT_CALLS += 1 }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCHED_OBJECT = 0;
            DISPATCHED_VALUE = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn stores_before_dispatching_only_vtable_slot_18_and_returns_zero() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; DISPATCH_SLOT + 1];
        vtable[DISPATCH_SLOT] = dispatch as usize;
        let mut object = Word08Slot18Object {
            vtable: vtable.as_ptr(),
            _word_04: 0x5a3c_91e7,
            value: 0,
        };

        let result = unsafe {
            word_08_set_then_slot_18_dispatch(&mut object, u32::MAX)
        };

        assert_eq!(result, 0);
        assert_eq!(object.value, u32::MAX);
        assert_eq!(unsafe { DISPATCHED_OBJECT }, (&mut object as *mut Word08Slot18Object) as usize);
        assert_eq!(unsafe { DISPATCHED_VALUE }, u32::MAX);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x18 dispatches");
    }
}
