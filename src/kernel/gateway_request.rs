//! Port of the timed kernel-gateway request helper @ 0x08047f40 (104 bytes,
//! 69 `bl` call sites in osos 2.0.4) — the tag-2 member of the four-helper
//! request family @ 0x08047edc..0x0804805c (tags 3/2/4/0), all of which post
//! a 5-word request frame to the ROM kernel gateway's service-4 stub
//! (`rom_svc_2200418c`, thunk 0x08037e18 -> ROM 0x2200418c) serialized by
//! kernel semaphore 9 (`rom_sem_wait`/`rom_sem_signal`, thunks 0x08037e08 /
//! 0x08037e10 -> ROM 0x22003fd0 / 0x220042b4 — the ported veneer family in
//! kernel/task_lock.rs).
//!
//! Algorithm (verified against osos.asm @ 0x08047f40..0x08047fa4): build a
//! 9-word stack frame — words 0..4 are the declared 5-word request frame
//! {0, 0, 0, 0, tag}, with the tag byte 2 stored at word 4 (frame layout
//! matches Ghidra's {local_2c..local_1c}); word 5 = the payload argument,
//! word 6 = timeout + 1, word 7 is untouched padding, word 8 = 0. Then,
//! holding kernel semaphore 9, call the service-4 gateway stub with
//! (kind = 1, &frame, FRAME_WORDS = 5) and release the semaphore. The
//! payload/timeout words sit immediately past the declared frame — the ROM
//! service reads them through the same pointer beyond the announced count.
//! Call-site survey: r1 (timeout) is 0x3e8 (1000) at 53 of 69 sites, else
//! 0xfa/0x1f4/0x1f40/0 or a computed value; r0 (payload) is an object
//! pointer or a small id (0x1, 0x3, 0x9, 0xd, 0xe, 0x10, 0x21 observed).
//!
//! Deviations from the original (the task_lock.rs ROM-dispatch design):
//! - The three ROM calls dispatch indirectly through task_lock::ROM_KERNEL
//!   instead of `bl` to the 8-byte thunk veneers; match.py diffs are
//!   structural, as with the rest of the family.
//! - The original loads r3 = 6 (the service-4 sub-op) before the gateway
//!   call; the ported veneer `rom_svc_2200418c` forwards only r0-r2, so
//!   the sub-op cannot ride along — visible to match.py as a missing
//!   `mov r3, #6`. Same caveat as every client of that veneer.
//! - The padding word 7 (sp+0x20 in the original) is zeroed rather than
//!   left uninitialized; nothing declared reads it.
//! - The original leaves the semaphore-signal result in r0; no caller
//!   consumes it, so the port returns nothing.

use crate::kernel::task_lock;

/// Kernel semaphore serializing the whole request family (r0 = 9 at all
/// four helpers' wait/signal call sites).
const REQUEST_LOCK: usize = 9;

/// Tag byte identifying this helper's request flavor (frame word 4).
const REQUEST_TAG: usize = 2;

/// First argument to the service-4 gateway stub (`mov r0, #1`).
const SERVICE4_KIND: usize = 1;

/// Declared frame length in words, the stub's third argument (`mov r2, #5`).
const FRAME_WORDS: usize = 5;

/// Total stack words the original writes/addresses: the declared frame,
/// the payload and timeout+1 words past it, one padding word, and the
/// trailing zero.
const FRAME_SLOTS: usize = 9;

/// gateway_request_timed — original: FUN_08047f40 @ 0x08047f40 (104 bytes).
/// Posts a tag-2 request frame carrying `payload` and `timeout + 1` to the
/// ROM kernel gateway's service-4 stub, serialized by kernel semaphore 9.
/// See the module header for the frame layout and deviations.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gateway_request_timed(payload: usize, timeout: usize) {
    let frame: [usize; FRAME_SLOTS] = [
        0,
        0,
        0,
        0,
        REQUEST_TAG,
        payload,
        timeout.wrapping_add(1), // the original's `add r0, r4, #1`
        0,                       // padding (uninitialized in the original)
        0,
    ];
    task_lock::rom_sem_wait(REQUEST_LOCK);
    task_lock::rom_svc_2200418c(SERVICE4_KIND, frame.as_ptr() as usize, FRAME_WORDS);
    task_lock::rom_sem_signal(REQUEST_LOCK);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::task_lock::tests::OPS_LOCK;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;
    use std::vec::Vec;
    use task_lock::RomThunkOps;

    /// Ordered log of the ROM calls the helper makes, plus the frame
    /// contents the service-4 mock reads back through the frame pointer.
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut WAIT_ARG: usize = 0;
    static mut SIGNAL_ARG: usize = 0;
    static mut SVC_ARGS: [usize; 3] = [0; 3];
    static mut FRAME_READ: [usize; FRAME_SLOTS] = [0; FRAME_SLOTS];

    unsafe extern "C" fn mock_sem_wait(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("wait");
        *addr_of_mut!(WAIT_ARG) = sem;
        0
    }

    unsafe extern "C" fn mock_svc4(a0: usize, a1: usize, a2: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("svc4");
        *addr_of_mut!(SVC_ARGS) = [a0, a1, a2];
        // The ROM service reads the request through the frame pointer;
        // capture everything the original wrote around it.
        for (i, slot) in (*addr_of_mut!(FRAME_READ)).iter_mut().enumerate() {
            *slot = (a1 as *const usize).add(i).read_volatile();
        }
        0
    }

    unsafe extern "C" fn mock_sem_signal(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("signal");
        *addr_of_mut!(SIGNAL_ARG) = sem;
        0
    }

    /// Installs the mocks in task_lock's ROM_KERNEL (OPS_LOCK serializes
    /// the swap against task_lock's and csem's tests), returns the guard
    /// and the saved table.
    fn install() -> (MutexGuard<'static, ()>, RomThunkOps) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(CALL_LOG)).clear();
            *addr_of_mut!(WAIT_ARG) = 0;
            *addr_of_mut!(SIGNAL_ARG) = 0;
            *addr_of_mut!(SVC_ARGS) = [0; 3];
            *addr_of_mut!(FRAME_READ) = [0; FRAME_SLOTS];
            let saved = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut patched = saved;
            patched.rom_sem_wait = mock_sem_wait;
            patched.rom_svc_2200418c = mock_svc4;
            patched.rom_sem_signal = mock_sem_signal;
            addr_of_mut!(task_lock::ROM_KERNEL).write(patched);
            (guard, saved)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, RomThunkOps)) {
        unsafe {
            addr_of_mut!(task_lock::ROM_KERNEL).write(state.1);
        }
        drop(state);
    }

    /// The full contract: semaphore 9 brackets the service-4 call, the
    /// stub gets (1, &frame, 5), and the stack frame carries
    /// {0,0,0,0, tag 2, payload, timeout+1, pad, 0}.
    #[test]
    fn posts_tag2_frame_under_semaphore_9() {
        let state = install();
        unsafe {
            gateway_request_timed(0x080c_1234, 0x3e8);
            assert_eq!(*addr_of!(CALL_LOG), ["wait", "svc4", "signal"]);
            assert_eq!(*addr_of!(WAIT_ARG), 9);
            assert_eq!(*addr_of!(SIGNAL_ARG), 9);
            let svc = *addr_of!(SVC_ARGS);
            assert_eq!(svc[0], 1, "service-4 kind");
            assert_ne!(svc[1], 0, "frame pointer");
            assert_eq!(svc[2], 5, "declared frame words");
            assert_eq!(
                *addr_of!(FRAME_READ),
                [0, 0, 0, 0, 2, 0x080c_1234, 0x3e9, 0, 0],
                "frame layout"
            );
        }
        restore(state);
    }

    /// The timeout is stored plus one with the original's wrapping add
    /// (ARM `add r0, r4, #1` wraps; 0 -> 1, usize::MAX -> 0).
    #[test]
    fn timeout_is_stored_plus_one_wrapping() {
        let state = install();
        unsafe {
            gateway_request_timed(0, 0);
            assert_eq!((*addr_of!(FRAME_READ))[6], 1);
            gateway_request_timed(0, usize::MAX);
            assert_eq!((*addr_of!(FRAME_READ))[6], 0);
            gateway_request_timed(0xdead_beef, 0x1f40);
            assert_eq!((*addr_of!(FRAME_READ))[5], 0xdead_beef);
            assert_eq!((*addr_of!(FRAME_READ))[6], 0x1f41);
            // Each call re-brackets the semaphore.
            assert_eq!(
                *addr_of!(CALL_LOG),
                ["wait", "svc4", "signal", "wait", "svc4", "signal", "wait", "svc4", "signal"]
            );
        }
        restore(state);
    }
}
