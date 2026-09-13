//! Virtual slot-`+0x40` result-word wrapper.
//!
//! `vtable_slot_40_result_word` — original: `FUN_083d5fec` @ **0x083d5fec**
//! (24 bytes). Raw ARM establishes the exact extent from the `push {r4,lr}`
//! at `0x083d5fec` through `pop {r4,pc}` at `0x083d6000`; the independently
//! linked sibling begins at `0x083d6004`.
//!
//! Decoding every immediate `B`/`BL` word in `osos.dec` finds exactly six
//! inbound direct calls, all unconditional `bl` at `0x0811b910`, `0x0811b954`,
//! `0x0811bafc`, `0x0811bb40`, `0x0839c9b4`, and `0x0839c9f8`. There are no
//! predicated `bl` forms or direct tail branches. The wrapper itself invokes
//! an indirect `blx` through vtable word 16 (`+0x40`).
//!
//! # Algorithm
//!
//! Calls `receiver.vtable[16](receiver, index)`, then returns the first word
//! of the returned pointer. The raw body never writes `r1`, so the caller's
//! index is forwarded to the virtual method despite Ghidra omitting it from
//! the recovered prototype. Neither receiver, vtable, method result, nor its
//! first word is NULL-checked.
//!
//! # Deliberate deviation
//!
//! The target vtable contains 32-bit entries while host function pointers are
//! wider. Rust therefore selects word index 16 in a host-sized vtable, then
//! performs the equivalent call and result-word load. The concrete virtual
//! method identity is not established and deliberately not invented.

/// ARMv5TE vtable word index for byte offset `+0x40`.
const RESULT_WORD_SLOT: usize = 0x40 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x40`.
type VtableSlot40Result = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

/// Calls vtable slot `+0x40` and returns the first word of its result.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-16 entry is a valid [`VtableSlot40Result`]. That method must return a
/// non-NULL pointer to a readable `u32`. No input is NULL-checked, matching
/// retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_result_word(receiver: *mut u8, index: u32) -> u32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let method: VtableSlot40Result = unsafe { core::mem::transmute(entry) };
    let result = unsafe { method(receiver, index) };
    unsafe { result.read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_INDEX: u32 = 0;
    static mut RESULT_WORD: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn result_method(receiver: *mut u8, index: u32) -> *const u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_INDEX = index;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _index: u32) -> *const u32 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    /// An object with exactly the wrapper's required vtable field.
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
            FORWARDED_INDEX = 0;
            RESULT_WORD = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_receiver_and_index_then_loads_the_returned_first_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; RESULT_WORD_SLOT + 1];
        vtable[RESULT_WORD_SLOT] = result_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();
        let index = u32::MAX;
        unsafe { RESULT_WORD = 0x9a4e_71c3 };

        let result = unsafe { vtable_slot_40_result_word(receiver, index) };

        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, index);
        assert_eq!(result, 0x9a4e_71c3);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }
}
