//! Virtual slot-`+0x1b4` decrement-if-nonzero wrapper.
//!
//! `vtable_slot_1b4_decrement_nonzero` — original: `FUN_0813c4c0` @
//! **0x0813c4c0** (28 bytes). Raw ARM establishes the exact extent from
//! `push {r4,lr}` at `0x0813c4c0` through `pop {r4,pc}` at `0x0813c4d8`; the
//! next separately linked function begins at `0x0813c4dc`.
//!
//! Decoding every immediate `B`/`BL` word in `osos.dec` finds exactly four
//! inbound direct calls, all unconditional `bl` at `0x0810c80c`,
//! `0x0810c81c`, `0x0810c8b0`, and `0x0810c914`. There are no predicated
//! direct calls or direct tail branches. The wrapper itself invokes one
//! indirect `blx` through vtable word 109 (`+0x1b4`).
//!
//! # Algorithm
//!
//! Calls `receiver.vtable[109](receiver)`. It returns zero unchanged; every
//! nonzero callback result is decremented by one with ARM wrapping arithmetic.
//! The concrete virtual method identity is unrecovered and deliberately not
//! invented.
//!
//! # Deliberate deviation
//!
//! The target vtable contains 32-bit entries while host function pointers are
//! wider. Rust selects the same word index from a native-width typed vtable.

/// ARMv5TE vtable word index for byte offset `+0x1b4`.
const DECREMENT_NONZERO_SLOT: usize = 0x1b4 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x1b4`.
type VtableSlot1b4Result = unsafe extern "C" fn(*mut u8) -> u32;

/// Calls vtable slot `+0x1b4` and decrements a nonzero result.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-109 entry is a valid [`VtableSlot1b4Result`]. No input is NULL-checked,
/// matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_1b4_decrement_nonzero(receiver: *mut u8) -> u32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(DECREMENT_NONZERO_SLOT).read() };
    let method: VtableSlot1b4Result = unsafe { core::mem::transmute(entry) };
    let result = unsafe { method(receiver) };
    if result == 0 { 0 } else { result.wrapping_sub(1) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut CALLBACK_RESULT: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn result_method(receiver: *mut u8) -> u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            CALLBACK_RESULT
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8) -> u32 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            CALLBACK_RESULT
        }
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench(result: u32) -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            CALLBACK_RESULT = result;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn returns_zero_unchanged_and_dispatches_only_slot_1b4() {
        let _bench = bench(0);
        let mut vtable = [wrong_slot as usize; DECREMENT_NONZERO_SLOT + 1];
        vtable[DECREMENT_NONZERO_SLOT] = result_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        assert_eq!(unsafe { vtable_slot_1b4_decrement_nonzero(receiver) }, 0);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x1b4 dispatches");
    }

    #[test]
    fn decrements_all_nonzero_results_including_u32_max() {
        let _bench = bench(u32::MAX);
        let mut vtable = [wrong_slot as usize; DECREMENT_NONZERO_SLOT + 1];
        vtable[DECREMENT_NONZERO_SLOT] = result_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        assert_eq!(unsafe { vtable_slot_1b4_decrement_nonzero(receiver) }, u32::MAX - 1);
    }
}
