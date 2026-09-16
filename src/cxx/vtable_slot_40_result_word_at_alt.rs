//! Alternate indexed virtual slot-`+0x40` result-word wrapper.
//!
//! `vtable_slot_40_result_word_at_alt` — original: `FUN_083d6ad4` @
//! **0x083d6ad4** (24 bytes). Raw ARM establishes the exact extent from
//! `push {r4,lr}` at `0x083d6ad4` through `pop {r4,pc}` at `0x083d6ae8`;
//! the next real function begins at `0x083d6aec`.
//!
//! Raw decoding finds four inbound direct calls, all unconditional `bl` at
//! `0x0829890c`, `0x08298efc`, `0x083d13e4`, and `0x083d1428`. There are no
//! predicated `bl` forms or direct tail branches. The wrapper itself makes one
//! indirect `blx` through vtable word 16 (`+0x40`).
//!
//! # Algorithm
//!
//! Calls `receiver.vtable[16](receiver, index)`, then returns the first word
//! of the returned pointer. The raw body never writes `r1`, so `index` is
//! forwarded despite Ghidra omitting it from the recovered prototype. Neither
//! receiver, vtable, method result, nor its first word is NULL-checked.
//!
//! # Deliberate deviation
//!
//! The target vtable contains 32-bit entries while host function pointers are
//! wider. Rust therefore selects word index 16 in a host-sized vtable, then
//! performs the equivalent call and result-word load. The concrete virtual
//! method identity is not established and deliberately not invented. An empty
//! inline-assembly compiler barrier keeps this separately linked wrapper a
//! distinct exported BL target; it emits no ARM instruction.

/// ARMv5TE vtable word index for byte offset `+0x40`.
const RESULT_WORD_SLOT: usize = 0x40 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x40`.
type VtableSlot40ResultAtAlt = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

/// Calls vtable slot `+0x40` with `index` and returns the first word of its result.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-16 entry is a valid [`VtableSlot40ResultAtAlt`]. That method must return
/// a non-NULL pointer to a readable `u32`. No input is NULL-checked, matching
/// retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_result_word_at_alt(receiver: *mut u8, index: u32) -> u32 {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    let vtable = unsafe { (receiver as *const *const VtableSlot40ResultAtAlt).read() };
    let callback = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let result = unsafe { callback(receiver, index) };
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
    static mut DISPATCH_CALLS: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _index: u32) -> *const u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        core::ptr::null()
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut u8, index: u32) -> *const u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_INDEX = index;
            DISPATCH_CALLS += 1;
            core::ptr::addr_of!(RESULT)
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_INDEX = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            RESULT = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_only_slot_40_forwards_index_and_loads_returned_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as VtableSlot40ResultAtAlt; RESULT_WORD_SLOT + 1];
        vtable[RESULT_WORD_SLOT] = record_dispatch;
        let mut receiver = vtable.as_ptr() as *mut u8;
        unsafe { RESULT = 0xa5a5_5a5a };

        assert_eq!(unsafe { vtable_slot_40_result_word_at_alt(&mut receiver as *mut _ as *mut u8, 0x7fff_ffff) }, 0xa5a5_5a5a);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut receiver as *mut *mut u8) as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, 0x7fff_ffff);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }
}
