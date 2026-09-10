//! `vtable_word_callback` — original: `FUN_0839eb8c` @ `0x0839eb8c` (24
//! bytes; 11 direct call sites: 10 unconditional `bl`, one `blcc`, and no
//! tail `b` sites).
//!
//! Raw ARM covers exactly six instruction words from `0x0839eb8c` through the
//! `pop {r2,r3,r4,pc}` at `0x0839eba0`; the separately linked sibling begins
//! at `0x0839eba4`. It spills the incoming word (`r1`), loads the receiver's
//! vtable and its slot `+0x1c`, then invokes the slot as
//! `method(receiver, &spilled_word, method, forwarded_r3)`. The virtual
//! method's `r0` return survives the pop unchanged. The word is deliberately
//! handed through a writable stack address: any mutation is discarded when
//! this wrapper returns.
//!
//! Binary-scanning every ARM immediate B/BL word found calls at
//! `0x080dc9d0`, `0x080dc9e4`, `0x080dc9fc`, `0x08147fc8` (`blcc`),
//! `0x08148088`, `0x08178824`, `0x08178844`, `0x08178850`, `0x08178878`,
//! `0x081a77f0`, and `0x081a7804`. The conditional call confirms the wrapper
//! has no NULL guard; its callers may gate dispatch themselves.
//!
//! Deviation: Rust represents the ARM stack spill with a local `u32`, and its
//! final indirect branch as a regular call returning directly. Both retain the
//! observable virtual-call ABI and return value.

/// ARMv5TE vtable word index for byte offset `+0x1c`.
const WORD_CALLBACK_VTABLE_INDEX: usize = 0x1c / 4;

/// ABI of the unrecovered callback slot. The third argument is the slot's own
/// address because `blx r2` leaves `r2` live; the fourth is forwarded verbatim.
type WordCallback = unsafe extern "C" fn(*mut u8, *mut u32, usize, usize) -> usize;

/// Calls a receiver's vtable `+0x1c` callback with a private spill of `word`.
///
/// `receiver`, its vtable, and the selected slot are deliberately unchecked,
/// matching the original three dereferences/indirect branch. The virtual
/// return value is propagated even though recovered direct callers discard it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_word_callback(
    receiver: *mut u8,
    word: u32,
    _discarded_r2: usize,
    forwarded_r3: usize,
) -> usize {
    let vtable = unsafe { (receiver as *const *const WordCallback).read() };
    let callback = unsafe { vtable.add(WORD_CALLBACK_VTABLE_INDEX).read() };
    let mut spilled_word = word;

    unsafe { callback(receiver, &mut spilled_word, callback as usize, forwarded_r3) }
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
    static mut RECEIVED_WORD: u32 = 0;
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

    unsafe extern "C" fn recording_callback(
        receiver: *mut u8,
        word: *mut u32,
        callback: usize,
        r3: usize,
    ) -> usize {
        unsafe {
            CALLS += 1;
            RECEIVED_RECEIVER = receiver;
            RECEIVED_WORD = word.read();
            word.write(0xffff_ffff);
            RECEIVED_CALLBACK = callback;
            RECEIVED_R3 = r3;
        }
        0xcafe_babe
    }

    fn reset_recording() {
        unsafe {
            CALLS = 0;
            RECEIVED_RECEIVER = ptr::null_mut();
            RECEIVED_WORD = 0;
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

    #[test]
    fn dispatches_only_slot_1c_with_a_private_word_spill() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording();

        let mut vtable = [wrong_slot as WordCallback; WORD_CALLBACK_VTABLE_INDEX + 1];
        vtable[WORD_CALLBACK_VTABLE_INDEX] = recording_callback;
        let mut receiver = CallbackReceiver {
            vtable: vtable.as_ptr(),
            payload: 0x1234_5678,
        };

        let result = unsafe {
            vtable_word_callback(
                (&mut receiver as *mut CallbackReceiver).cast(),
                0x00ab_cdef,
                0x1111_2222,
                0x3333_4444,
            )
        };

        assert_eq!(result, 0xcafe_babe, "the callback return remains in r0");
        unsafe {
            assert_eq!(CALLS, 1, "only vtable slot +0x1c is called");
            assert_eq!(WRONG_SLOT_CALLS, 0, "adjacent vtable entries are not called");
            assert_eq!(RECEIVED_RECEIVER, (&mut receiver as *mut CallbackReceiver).cast());
            assert_eq!(RECEIVED_WORD, 0x00ab_cdef, "r1 is spilled before dispatch");
            assert_eq!(RECEIVED_CALLBACK, recording_callback as usize, "r2 becomes the slot address");
            assert_eq!(RECEIVED_R3, 0x3333_4444, "r3 is forwarded unchanged");
        }
        assert_eq!(receiver.payload, 0x1234_5678, "the callback writes only the private spill");
    }
}
