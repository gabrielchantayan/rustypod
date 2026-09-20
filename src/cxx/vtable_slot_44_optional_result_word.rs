//! Optional vtable slot-`+0x44` result-word wrapper.
//!
//! `vtable_slot_44_optional_result_word` — original: `FUN_083d6004` @
//! **0x083d6004** (40 bytes). Raw ARM establishes the exact extent from
//! `push {r0,r1,r4,lr}` at `0x083d6004` through `pop {r4,pc}` at
//! `0x083d6028`; the next independent function begins at `0x083d602c`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds exactly
//! three inbound direct calls, all unconditional plain `bl` at `0x0811b3e8`,
//! `0x0811b708`, and `0x0811bcc0`; there are no predicated `bl` forms. The
//! wrapper itself dispatches indirectly with `blx` through vtable word 17
//! (`+0x44`).
//!
//! # Algorithm
//!
//! Stores `key` on its stack, calls `receiver.vtable[17](receiver, &key, 4)`,
//! and returns zero for a NULL result or the first word of a non-NULL result.
//! The virtual method identity is not established and deliberately not
//! invented.
//!
//! # Deliberate deviation
//!
//! The target vtable has 32-bit entries while host function pointers are
//! wider. Rust selects word index 17 in a host-sized vtable; this preserves
//! the target slot on both host tests and ARM.

/// ARMv5TE vtable word index for byte offset `+0x44`.
const OPTIONAL_RESULT_WORD_SLOT: usize = 0x44 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x44`.
type VtableSlot44OptionalResult = unsafe extern "C" fn(*mut u8, *const u32, u32) -> *const u32;

/// Calls vtable slot `+0x44` with `key` and returns its optional first result word.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-17 entry is a valid [`VtableSlot44OptionalResult`]. A non-NULL result
/// must point to a readable `u32`. No input pointer is NULL-checked, matching
/// retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_44_optional_result_word(receiver: *mut u8, key: u32) -> u32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(OPTIONAL_RESULT_WORD_SLOT).read() };
    let method: VtableSlot44OptionalResult = unsafe { core::mem::transmute(entry) };
    let result = unsafe { method(receiver, &key, core::mem::size_of::<u32>() as u32) };
    if result.is_null() { 0 } else { unsafe { result.read() } }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_KEY: u32 = 0;
    static mut FORWARDED_LENGTH: u32 = 0;
    static mut RESULT_WORD: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn result_method(receiver: *mut u8, key: *const u32, length: u32) -> *const u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_KEY = key.read();
            FORWARDED_LENGTH = length;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    unsafe extern "C" fn null_method(_receiver: *mut u8, _key: *const u32, _length: u32) -> *const u32 {
        core::ptr::null()
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _key: *const u32, _length: u32) -> *const u32 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_KEY = 0;
            FORWARDED_LENGTH = 0;
            RESULT_WORD = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_key_and_returns_the_non_null_result_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; OPTIONAL_RESULT_WORD_SLOT + 1];
        vtable[OPTIONAL_RESULT_WORD_SLOT] = result_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();
        unsafe { RESULT_WORD = 0xa5a5_5a5a };

        let result = unsafe { vtable_slot_44_optional_result_word(receiver, u32::MAX) };

        assert_eq!(result, 0xa5a5_5a5a);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { FORWARDED_KEY }, u32::MAX);
        assert_eq!(unsafe { FORWARDED_LENGTH }, 4);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x44 dispatches");
    }

    #[test]
    fn returns_zero_when_the_virtual_method_returns_null() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; OPTIONAL_RESULT_WORD_SLOT + 1];
        vtable[OPTIONAL_RESULT_WORD_SLOT] = null_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };

        assert_eq!(unsafe { vtable_slot_44_optional_result_word((&mut object as *mut VtableObject).cast::<u8>(), 0) }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x44 dispatches");
    }
}
