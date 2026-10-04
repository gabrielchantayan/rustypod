//! Reset the shared iAP session state and poll its registered worker slots.

use super::iap_incoming_process_thread::{
    iap_incoming_process_thread_instance_veneer,
    iap_incoming_process_thread_slot_poll,
};
use core::ptr::{read_volatile, write_volatile};

#[cfg(not(target_os = "none"))]
pub static mut IAP_SESSION_STATE: *mut u32 = core::ptr::null_mut();

/// Original `FUN_081f21a0` at 0x081f21a0: 124 bytes through 0x081f221c,
/// including literals at 0x081f2214/18 (Ghidra's 116 counts only code).
/// Verified whole-image inbound calls: two plain BLs, zero predicated BLs.
/// Body: three plain BLs, zero predicated BLs, one tail B to slot_poll.
/// Set the shared state's +0x14 word to 44100, clear the selected counters,
/// flags and words, preserving +2..3, +0x0c and both registration indices.
/// Poll +0x2c if not -1, discard its result, then poll +0x30 if not -1.
/// Return the second poll's status, or -1 when its index is absent.
/// The incoming r0 is ignored; this is not an object-field reset.
/// Deviations: the literal-selected state at 0x089cca2c is host-rebindable;
/// volatile accesses retain the original store order and post-instance index
/// reloads. Existing Rust instance/poll ports replace the firmware calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_session_state_reset() -> u32 {
    #[cfg(target_os = "none")]
    let state = 0x089cca2c as *mut u32;
    #[cfg(not(target_os = "none"))]
    let state = read_volatile(core::ptr::addr_of!(IAP_SESSION_STATE));
    reset_state(state, |slot| {
        let instance = iap_incoming_process_thread_instance_veneer();
        iap_incoming_process_thread_slot_poll(instance, read_volatile(slot))
    })
}

#[inline(always)]
unsafe fn reset_state(mut_state: *mut u32, mut poll: impl FnMut(*mut u32) -> u32) -> u32 {
    write_volatile(mut_state.add(5), 44100);
    for index in 6..=10 {
        write_volatile(mut_state.add(index), 0);
    }
    write_volatile((mut_state as *mut u8).add(1), 0);
    write_volatile(mut_state.add(4), 0);
    write_volatile(mut_state as *mut u8, 0);
    write_volatile(mut_state.add(2), 0);
    write_volatile(mut_state.add(1), 0);
    write_volatile(mut_state.add(13), 0);
    let first = mut_state.add(11);
    if read_volatile(first) != u32::MAX {
        poll(first);
    }
    let second = mut_state.add(12);
    if read_volatile(second) == u32::MAX {
        u32::MAX
    } else {
        poll(second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    #[test]
    fn reset_preserves_unrelated_bytes_and_registration_indices() {
        let mut state = [0xa5a5a5a5; 16];
        state[11] = u32::MAX;
        state[12] = u32::MAX;
        let result = unsafe { reset_state(state.as_mut_ptr(), |_| panic!("absent slot polled")) };
        let mut expected = [0xa5a5a5a5; 16];
        expected[0] = 0xa5a50000;
        for i in [1, 2, 4, 6, 7, 8, 9, 10, 13] { expected[i] = 0; }
        expected[5] = 44100;
        expected[11] = u32::MAX;
        expected[12] = u32::MAX;
        assert_eq!(state, expected);
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn slot_presence_and_return_precedence() {
        for first in [u32::MAX, 0, 28] {
            for second in [u32::MAX, 0, 28] {
                let mut state = [0x55555555; 14];
                state[11] = first;
                state[12] = second;
                let ptr = state.as_mut_ptr();
                let mut seen = std::vec::Vec::new();
                let result = unsafe { reset_state(ptr, |slot| {
                    assert_eq!(read_volatile(ptr.add(5)), 44100);
                    assert_eq!(read_volatile(ptr.add(13)), 0);
                    seen.push(read_volatile(slot));
                    if slot == ptr.add(11) { 17 } else { 5 }
                }) };
                let expected: std::vec::Vec<_> = [first, second].into_iter()
                    .filter(|&index| index != u32::MAX).collect();
                assert_eq!(seen, expected);
                assert_eq!(result, if second == u32::MAX { u32::MAX } else { 5 });
            }
        }
    }

    #[test]
    fn second_slot_is_checked_after_first_poll() {
        for replacement in [u32::MAX, 7] {
            let mut state = [0; 14];
            state[11] = 3;
            state[12] = 9;
            let ptr = state.as_mut_ptr();
            let mut calls = 0;
            let result = unsafe { reset_state(ptr, |slot| {
                calls += 1;
                if slot == ptr.add(11) {
                    write_volatile(ptr.add(12), replacement);
                    19
                } else {
                    assert_eq!(read_volatile(slot), 7);
                    23
                }
            }) };
            assert_eq!(calls, if replacement == u32::MAX { 1 } else { 2 });
            assert_eq!(result, if replacement == u32::MAX { u32::MAX } else { 23 });
        }
    }
}
