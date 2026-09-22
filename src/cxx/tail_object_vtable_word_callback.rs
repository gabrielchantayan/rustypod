//! Vtable word callback through an object's +8 subobject.
//!
//! `tail_object_vtable_word_callback` — original: `FUN_08291e58` @
//! **0x08291e58** (28 bytes). Raw `osos.dec` words establish the exact
//! seven-instruction body from `push {r3,lr}` through `pop {r4,pc}` at
//! `0x08291e70`; the next independently entered function begins at
//! `0x08291e74` with `push {r4,lr}`. There are three inbound direct calls
//! (`0x08186f14` is predicated `blne`; `0x08291f18` and `0x08291f98` are
//! plain unconditional `bl`); no other direct calls target it. The body
//! contains no direct `bl`, only its one unconditional indirect `blx` through
//! vtable slot +0x1c.
//! # Algorithm
//!
//! Treats `object_prefix + 8` as the receiver, spills `word` to a private
//! stack word, loads the receiver vtable's +0x1c entry, and invokes it as
//! `callback(receiver, &spilled_word, callback, forwarded_r3)`. The callback
//! return value is propagated. The original deliberately provides a writable
//! ephemeral word address; any callback mutation dies with the wrapper frame.
//!
//! # Deliberate deviation
//!
//! Rust represents the ARM stack spill with a local `u32`, and expresses the
//! indirect branch as a normal call. Target vtables are 32-bit words whereas
//! host callback pointers are native-width; host fixtures use native-width
//! entries. These preserve the callback ABI and observable result.

/// ARMv5TE vtable word index for byte offset +0x1c.
const WORD_CALLBACK_VTABLE_INDEX: usize = 0x1c / 4;

/// ABI of the unrecovered vtable callback.
type TailObjectWordCallback = unsafe extern "C" fn(*mut u8, *mut u32, usize, usize) -> usize;

/// Dispatches the +8 receiver's vtable `+0x1c` callback with a private word spill.
///
/// # Safety
///
/// `object_prefix.add(8)` must designate a receiver whose first word is a
/// vtable with at least eight readable native-width entries. Entry 7 must be
/// a valid [`TailObjectWordCallback`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_object_vtable_word_callback(
    object_prefix: *mut u8,
    word: u32,
    _discarded_r2: usize,
    forwarded_r3: usize,
) -> usize {
    let receiver = unsafe { object_prefix.add(8) };
    let vtable = unsafe { (receiver as *const *const TailObjectWordCallback).read() };
    let callback = unsafe { vtable.add(WORD_CALLBACK_VTABLE_INDEX).read() };
    let mut spilled_word = word;

    unsafe { callback(receiver, &mut spilled_word, callback as usize, forwarded_r3) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVER: usize = 0;
    static mut SPILLED_WORD: u32 = 0;
    static mut CALLBACK_ADDRESS: usize = 0;
    static mut FORWARDED_R3: usize = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn callback(
        receiver: *mut u8,
        spilled_word: *mut u32,
        callback_address: usize,
        forwarded_r3: usize,
    ) -> usize {
        unsafe {
            RECEIVER = receiver as usize;
            SPILLED_WORD = spilled_word.read();
            CALLBACK_ADDRESS = callback_address;
            FORWARDED_R3 = forwarded_r3;
            spilled_word.write(0);
        }
        0x8f31_c2d4
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _word: *mut u32, _callback: usize, _r3: usize) -> usize {
        unsafe {
            WRONG_SLOT_CALLS += 1;
        }
        0
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            RECEIVER = 0;
            SPILLED_WORD = 0;
            CALLBACK_ADDRESS = 0;
            FORWARDED_R3 = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_tail_receiver_to_only_slot_1c_with_private_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; WORD_CALLBACK_VTABLE_INDEX + 1];
        vtable[WORD_CALLBACK_VTABLE_INDEX] = callback as usize;
        let mut object_words = [0usize; 3];
        object_words[1] = vtable.as_ptr() as usize;
        let object_prefix = object_words.as_mut_ptr().cast::<u8>();
        let expected_receiver = unsafe { object_prefix.add(8) };

        let result = unsafe {
            tail_object_vtable_word_callback(object_prefix, 0x57a1_0c3e, 0xdead_beef, 0x4f19_7ab2)
        };

        assert_eq!(result, 0x8f31_c2d4);
        assert_eq!(unsafe { RECEIVER }, expected_receiver as usize);
        assert_eq!(unsafe { SPILLED_WORD }, 0x57a1_0c3e);
        assert_eq!(unsafe { CALLBACK_ADDRESS }, callback as usize);
        assert_eq!(unsafe { FORWARDED_R3 }, 0x4f19_7ab2);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x1c dispatches");
        assert_eq!(object_words[0], 0);
    }
}
