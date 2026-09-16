//! `vtable_word_callback_repeat` — original: `FUN_0839eb54` @ `0x0839eb54`
//! (56 bytes; 4 direct call sites, all unconditional `bl` at `0x080f0358`,
//! `0x080f036c`, `0x080f0384`, and `0x080f03a0`; no predicated calls or tail
//! `b` sites).
//!
//! Raw ARM covers exactly 14 instruction words from the
//! `push {r0,r1,r2,r4,r5,r6,r7,lr}` at `0x0839eb54` through the
//! `pop {r1,r2,r3,r4,r5,r6,r7,pc}` at `0x0839eb88`; the separately linked
//! sibling `vtable_word_callback` begins at `0x0839eb8c`. Ghidra's reported
//! 56 bytes match this extent. The loop performs no direct `bl`; its single
//! dispatch is a register-indirect `blx r2` through vtable word 7 (`+0x1c`),
//! the same slot invoked once by the sibling wrapper.
//!
//! # Algorithm
//!
//! The incoming `r2` is spilled to the stack once before the loop. Each
//! iteration reloads `receiver->vtable`, loads slot `+0x1c`, and invokes
//! `method(receiver, &spilled_word, method, forwarded_r3)`. Because the spill
//! lives at the same stack address across iterations, a callback that mutates
//! it hands the mutated word to the next call. The loop counter (`r4`) runs
//! `0..count` with a signed `blt` against `count` (`r1`), so a zero or
//! negative count performs no dispatch at all. The last callback's `r0`
//! return survives the final pop; with zero iterations `r0` still holds
//! `receiver`.
//!
//! Recovered direct callers (all in the escape-sequence parser around
//! `0x080f0300`) pass `count = 1` and pre-load `r2` with a character value
//! that becomes the spill seed. The concrete virtual method identity is
//! unrecovered and deliberately not invented.
//!
//! Deviation: Rust represents the ARM stack spill with a local `u32`, and the
//! register-indirect `blx` as a typed callback call. Both retain the
//! observable virtual-call ABI, the shared spill across iterations, and the
//! return-value propagation.

/// ARMv5TE vtable word index for byte offset `+0x1c`.
const WORD_CALLBACK_VTABLE_INDEX: usize = 0x1c / 4;

/// ABI of the unrecovered callback slot. The third argument is the slot's own
/// address because `blx r2` leaves `r2` live; the fourth is forwarded verbatim.
type WordCallback = unsafe extern "C" fn(*mut u8, *mut u32, usize, usize) -> usize;

/// Calls a receiver's vtable `+0x1c` callback `count` times over one spill.
///
/// `spilled_seed_r2` seeds the private word spill; callback mutations of the
/// spill are visible to later iterations. `receiver`, its vtable, and the
/// selected slot are deliberately unchecked, matching the original. The last
/// callback's return is propagated; for `count <= 0` the receiver itself is
/// returned, matching the ARM register residue.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_word_callback_repeat(
    receiver: *mut u8,
    count: i32,
    spilled_seed_r2: u32,
    forwarded_r3: usize,
) -> usize {
    let mut spilled_word = spilled_seed_r2;
    let mut index = 0i32;
    let mut result = receiver as usize;
    while index < count {
        let vtable = unsafe { (receiver as *const *const WordCallback).read() };
        let callback = unsafe { vtable.add(WORD_CALLBACK_VTABLE_INDEX).read() };
        result = unsafe {
            callback(receiver, &mut spilled_word, callback as usize, forwarded_r3)
        };
        index += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;
    static mut RECEIVED_RECEIVER: *mut u8 = ptr::null_mut();
    static mut SPILL_HISTORY: [u32; 8] = [0; 8];
    static mut RECEIVED_CALLBACK: usize = 0;
    static mut RECEIVED_R3: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot(
        _receiver: *mut u8,
        _word: *mut u32,
        _callback: usize,
        _r3: usize,
    ) -> usize {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn accumulating_callback(
        receiver: *mut u8,
        word: *mut u32,
        callback: usize,
        r3: usize,
    ) -> usize {
        unsafe {
            let call = CALLS;
            CALLS += 1;
            RECEIVED_RECEIVER = receiver;
            if call < SPILL_HISTORY.len() {
                SPILL_HISTORY[call] = word.read();
            }
            word.write(word.read().wrapping_add(0x10));
            RECEIVED_CALLBACK = callback;
            RECEIVED_R3 = r3;
            0x1000 + call
        }
    }

    fn reset_recording() {
        unsafe {
            CALLS = 0;
            RECEIVED_RECEIVER = ptr::null_mut();
            SPILL_HISTORY = [0; 8];
            RECEIVED_CALLBACK = 0;
            RECEIVED_R3 = 0;
            WRONG_SLOT_CALLS = 0;
        }
    }

    #[repr(C)]
    struct CallbackReceiver {
        vtable: *const WordCallback,
        payload: u32,
    }

    fn with_fixture(body: impl Fn(*mut u8)) {
        let mut vtable = [wrong_slot as WordCallback; WORD_CALLBACK_VTABLE_INDEX + 1];
        vtable[WORD_CALLBACK_VTABLE_INDEX] = accumulating_callback;
        let mut receiver = CallbackReceiver {
            vtable: vtable.as_ptr(),
            payload: 0x1234_5678,
        };
        body((&mut receiver as *mut CallbackReceiver).cast());
        assert_eq!(receiver.payload, 0x1234_5678, "the callback writes only the private spill");
    }

    #[test]
    fn repeats_slot_1c_over_one_shared_spill() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording();

        with_fixture(|receiver_ptr| {
            let result = unsafe {
                vtable_word_callback_repeat(receiver_ptr, 3, 0x0000_00a0, 0x3333_4444)
            };

            assert_eq!(result, 0x1002, "the last callback return remains in r0");
            unsafe {
                assert_eq!(CALLS, 3, "slot +0x1c is called once per iteration");
                assert_eq!(WRONG_SLOT_CALLS, 0, "adjacent vtable entries are not called");
                assert_eq!(RECEIVED_RECEIVER, receiver_ptr);
                assert_eq!(
                    SPILL_HISTORY[0..3],
                    [0xa0, 0xb0, 0xc0],
                    "spill is seeded from r2 and mutations persist across iterations"
                );
                assert_eq!(RECEIVED_CALLBACK, accumulating_callback as usize, "r2 becomes the slot address");
                assert_eq!(RECEIVED_R3, 0x3333_4444, "r3 is forwarded unchanged");
            }
        });
    }

    #[test]
    fn zero_or_negative_count_never_dispatches() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording();

        with_fixture(|receiver_ptr| {
            let zero = unsafe { vtable_word_callback_repeat(receiver_ptr, 0, 0xdead_beef, 0x9999) };
            assert_eq!(zero, receiver_ptr as usize, "zero count returns the receiver residue");
            assert_eq!(unsafe { CALLS }, 0, "zero count performs no dispatch");

            let negative = unsafe { vtable_word_callback_repeat(receiver_ptr, -2, 0xdead_beef, 0x9999) };
            assert_eq!(negative, receiver_ptr as usize, "signed blt skips negative counts");
            assert_eq!(unsafe { CALLS }, 0, "negative count performs no dispatch");
            assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "no vtable entry is touched");
        });
    }
}
