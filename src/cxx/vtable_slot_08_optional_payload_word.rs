//! Guarded virtual slot-`+0x08` payload-word query.
//!
//! `vtable_slot_08_optional_payload_word` — original: `FUN_082a4460` @
//! **0x082a4460** (60 bytes). Raw `osos.dec` words establish the complete
//! extent: `e92d4070` at `0x082a4460` through `e8bd8070` at `0x082a4498`;
//! the next distinct function starts with `e92d4070` at `0x082a449c`.
//!
//! Decoding every ARM immediate branch in the raw image finds four inbound
//! direct calls, all unconditional `bl` (at `0x08179780`, `0x0817c2e0`,
//! `0x08231788`, and `0x082317e8`), and no predicated `bl` calls. The body
//! makes one indirect `blx` through vtable word 2 (`+0x08`).
//!
//! # Algorithm
//!
//! Calls `handle.vtable[2](handle)`. If it returns false, returns false
//! without writing `result`. Otherwise, if `handle.payload` is non-NULL,
//! copies `payload[4]` (target offset `+0x10`) to `*result` and returns true.
//! A successful query with a NULL payload also returns false and leaves the
//! output unchanged. The virtual method's concrete identity is unrecovered
//! and deliberately not invented.
//!
//! # Deliberate deviation
//!
//! The target's vtable and object pointer fields are 32-bit, while host
//! pointers are wider. Typed `repr(C)` fields preserve target offsets and
//! host tests use native-width function pointers; no algorithmic deviation.

/// ABI of the unrecovered virtual predicate at vtable byte offset `+0x08`.
pub type VtableSlot08Predicate = unsafe extern "C" fn(*mut OptionalPayloadHandle) -> bool;

/// The three vtable words observed by this wrapper.
#[repr(C)]
pub struct OptionalPayloadVtable {
    /// +0x00..+0x04: not decoded.
    pub slots_before: [Option<unsafe extern "C" fn()>; 2],
    /// +0x08: predicate dispatch.
    pub predicate: VtableSlot08Predicate,
}

/// The payload word read at target offset `+0x10`.
#[repr(C)]
pub struct OptionalPayload {
    /// +0x00..+0x0c: not decoded.
    pub words_before: [u32; 4],
    /// +0x10.
    pub result_word: u32,
}

/// Object layout observed by the wrapper.
#[repr(C)]
pub struct OptionalPayloadHandle {
    /// +0x00.
    pub vtable: *const OptionalPayloadVtable,
    /// +0x04 on ARM; widened on hosts to retain a valid pointer.
    pub payload: *mut OptionalPayload,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::offset_of!(OptionalPayloadVtable, predicate)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::offset_of!(OptionalPayload, result_word)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(OptionalPayloadHandle, payload)];

/// Queries the virtual predicate and, on success, publishes its payload word.
///
/// # Safety
///
/// `handle` and `result` must be valid pointers. `handle` must contain a
/// readable vtable whose slot `+0x08` accepts `handle`. A successful dispatch
/// requires a readable non-NULL `payload` to update `result`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_08_optional_payload_word(
    handle: *mut OptionalPayloadHandle,
    result: *mut u32,
) -> bool {
    let predicate = unsafe { (*(*handle).vtable).predicate };
    if !unsafe { predicate(handle) } {
        return false;
    }

    let payload = unsafe { (*handle).payload };
    if payload.is_null() {
        return false;
    }

    unsafe { result.write((*payload).result_word) };
    true
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: usize = 0;
    static mut FORWARDED_HANDLE: usize = 0;
    static mut PREDICATE_RESULT: bool = false;

    unsafe extern "C" fn predicate(handle: *mut OptionalPayloadHandle) -> bool {
        unsafe {
            DISPATCH_CALLS += 1;
            FORWARDED_HANDLE = handle as usize;
            PREDICATE_RESULT
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCH_CALLS = 0;
            FORWARDED_HANDLE = 0;
            PREDICATE_RESULT = false;
        }
        Bench { _lock: lock }
    }

    fn vtable() -> OptionalPayloadVtable {
        OptionalPayloadVtable { slots_before: [None; 2], predicate }
    }

    #[test]
    fn false_predicate_leaves_result_unchanged() {
        let _bench = bench();
        let vtable = vtable();
        let mut handle = OptionalPayloadHandle { vtable: &vtable, payload: core::ptr::null_mut() };
        let mut result = 0xdead_beef;

        assert!(!unsafe { vtable_slot_08_optional_payload_word(&mut handle, &mut result) });
        assert_eq!(result, 0xdead_beef);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { FORWARDED_HANDLE }, (&mut handle as *mut OptionalPayloadHandle) as usize);
    }

    #[test]
    fn true_predicate_with_null_payload_leaves_result_unchanged() {
        let _bench = bench();
        let vtable = vtable();
        let mut handle = OptionalPayloadHandle { vtable: &vtable, payload: core::ptr::null_mut() };
        let mut result = 0xdead_beef;
        unsafe { PREDICATE_RESULT = true };

        assert!(!unsafe { vtable_slot_08_optional_payload_word(&mut handle, &mut result) });
        assert_eq!(result, 0xdead_beef);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
    }

    #[test]
    fn true_predicate_publishes_payload_word() {
        let _bench = bench();
        let vtable = vtable();
        let mut payload = OptionalPayload { words_before: [0; 4], result_word: 0xa5a5_5a5a };
        let mut handle = OptionalPayloadHandle { vtable: &vtable, payload: &mut payload };
        let mut result = 0;
        unsafe { PREDICATE_RESULT = true };

        assert!(unsafe { vtable_slot_08_optional_payload_word(&mut handle, &mut result) });
        assert_eq!(result, 0xa5a5_5a5a);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
    }
}
