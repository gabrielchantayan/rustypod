//! Port of the timed kernel-gateway request helper @ 0x08047f40 (104 bytes,
//! 69 `bl` call sites in osos 2.0.4) — the tag-2 member of the four-helper
//! request family @ 0x08047edc..0x0804805c (tags 3/2/4/0), all of which post
//! a 5-word request frame through the ported mode-1 mailbox-send gateway
//! body (`mailbox_send_gateway_mode1`, thunk 0x08037e18 -> ROM 0x2200418c)
//! serialized by kernel semaphore 9 (`rom_sem_wait`/`rom_sem_signal`, thunks
//! 0x08037e08 / 0x08037e10 -> ROM 0x22003fd0 / 0x220042b4 — the ported veneer
//! family in kernel/task_lock.rs).
//!
//! Algorithm (verified against osos.asm @ 0x08047f40..0x08047fa4): build a
//! 9-word stack frame — words 0..4 are the declared 5-word request frame
//! {0, 0, 0, 0, tag}, with the tag byte 2 stored at word 4 (frame layout
//! matches Ghidra's {local_2c..local_1c}); word 5 = the payload argument,
//! word 6 = timeout + 1, word 7 is untouched padding, word 8 = 0. Then,
//! holding kernel semaphore 9, call the mode-1 mailbox-send gateway body with
//! (mailbox = 1, message = &frame, priority = 5, semaphore = 6) and release
//! the semaphore. The body preserves the fourth argument as the RTXC request's
//! semaphore word. The payload/timeout words sit immediately past the declared
//! frame — the ROM service reads them through the same pointer beyond the
//! announced count.
//! Call-site survey: r1 (timeout) is 0x3e8 (1000) at 53 of 69 sites, else
//! 0xfa/0x1f4/0x1f40/0 or a computed value; r0 (payload) is an object
//! pointer or a small id (0x1, 0x3, 0x9, 0xd, 0xe, 0x10, 0x21 observed).
//!
//! Deviations from the original:
//! - The semaphore calls dispatch indirectly through task_lock::ROM_KERNEL
//!   instead of `bl` to the 8-byte thunk veneers; match.py diffs are
//!   structural, as with the rest of the family.
//! - The ported mode-1 mailbox-send body calls the existing
//!   message_dispatch_veneer seam rather than the original direct PC-relative
//!   `bl`; unlike the stale task_lock veneer, it preserves the raw `r3 = 6`
//!   as its fourth argument.
//! - The padding word 7 (sp+0x20 in the original) is zeroed rather than
//!   left uninitialized; nothing declared reads it.
//! - The original leaves the semaphore-signal result in r0; no caller
//!   consumes it, so the port returns nothing.

use crate::kernel::mailbox_send_gateway_mode1::mailbox_send_gateway_mode1;
use crate::kernel::task_lock;

/// Kernel semaphore serializing the whole request family (r0 = 9 at all
/// four helpers' wait/signal call sites).
const REQUEST_LOCK: usize = 9;

/// Tag byte identifying this helper's request flavor (frame word 4).
const REQUEST_TAG: usize = 2;

/// Mailbox passed to the mode-1 mailbox-send gateway body (`mov r0, #1`).
const GATEWAY_MAILBOX: u32 = 1;

/// Priority passed to the mode-1 mailbox-send gateway body (`mov r2, #5`).
const GATEWAY_PRIORITY: u32 = 5;

/// Semaphore passed to the mode-1 mailbox-send gateway body (`mov r3, #6`).
const GATEWAY_SEMAPHORE: u32 = 6;

/// Total stack words the original writes/addresses: the declared frame,
/// the payload and timeout+1 words past it, one padding word, and the
/// trailing zero.
const FRAME_SLOTS: usize = 9;

/// gateway_request_timed — original: FUN_08047f40 @ 0x08047f40 (104 bytes).
/// ROM kernel's mode-1 mailbox-send gateway body, serialized by kernel
/// semaphore 9.
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
    mailbox_send_gateway_mode1(
        GATEWAY_MAILBOX,
        frame.as_ptr() as usize as u32,
        GATEWAY_PRIORITY,
        GATEWAY_SEMAPHORE,
    );
    task_lock::rom_sem_signal(REQUEST_LOCK);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::tests::OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::MutexGuard as ParkingLotMutexGuard;
    use std::sync::MutexGuard as StdMutexGuard;
    use std::vec::Vec;
    use task_lock::RomThunkOps;

    /// Ordered log of the semaphore and actual dispatch calls. The RTXC
    /// request's deliberately uninitialized words are never read by tests.
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut WAIT_ARG: usize = 0;
    static mut SIGNAL_ARG: usize = 0;
    static mut DISPATCH_COUNT: usize = 0;
    static mut DISPATCH_REQUEST: [u32; 9] = [0; 9];

    unsafe extern "C" fn mock_sem_wait(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("wait");
        *addr_of_mut!(WAIT_ARG) = sem;
        0
    }

    unsafe extern "C" fn mock_dispatch(request: *mut u32) {
        (*addr_of_mut!(CALL_LOG)).push("dispatch");
        *addr_of_mut!(DISPATCH_COUNT) += 1;
        for word in [0, 2, 3, 5, 6, 7, 8] {
            (*addr_of_mut!(DISPATCH_REQUEST))[word] = request.add(word).read();
        }
    }

    unsafe extern "C" fn mock_sem_signal(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("signal");
        *addr_of_mut!(SIGNAL_ARG) = sem;
        0
    }

    /// Restores the semaphore and dispatch seams and releases their shared
    /// test locks.
    struct Installed {
        _dispatch_lock: ParkingLotMutexGuard<'static, ()>,
        _kernel_lock: StdMutexGuard<'static, ()>,
        saved_kernel: RomThunkOps,
        saved_dispatch: MessageDispatchVeneerOps,
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(task_lock::ROM_KERNEL).write(self.saved_kernel);
                MESSAGE_DISPATCH_VENEER_OPS = self.saved_dispatch;
            }
        }
    }

    /// Installs semaphore mocks in task_lock::ROM_KERNEL and a recorder at the
    /// established message-dispatch veneer seam.
    fn install() -> Installed {
        let dispatch_lock = DISPATCH_OPS_LOCK.lock();
        let kernel_lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(CALL_LOG)).clear();
            *addr_of_mut!(WAIT_ARG) = 0;
            *addr_of_mut!(SIGNAL_ARG) = 0;
            *addr_of_mut!(DISPATCH_COUNT) = 0;
            *addr_of_mut!(DISPATCH_REQUEST) = [0; 9];

            let saved_kernel = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut patched_kernel = saved_kernel;
            patched_kernel.rom_sem_wait = mock_sem_wait;
            patched_kernel.rom_sem_signal = mock_sem_signal;
            addr_of_mut!(task_lock::ROM_KERNEL).write(patched_kernel);

            let saved_dispatch = MESSAGE_DISPATCH_VENEER_OPS;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: mock_dispatch,
            };
            Installed {
                _dispatch_lock: dispatch_lock,
                _kernel_lock: kernel_lock,
                saved_kernel,
                saved_dispatch,
            }
        }
    }

    /// Semaphore 9 brackets exactly one mode-1 mailbox-send dispatch. Its
    /// sparse RTXC request preserves the raw fourth argument as word 2:
    /// `{4, _, 6, 1, _, 5, frame, 1, 0}`.
    #[test]
    fn posts_tag2_frame_through_mode1_gateway_under_semaphore_9() {
        let _installed = install();
        unsafe {
            gateway_request_timed(0x080c_1234, 0x3e8);
            assert_eq!(*addr_of!(CALL_LOG), ["wait", "dispatch", "signal"]);
            assert_eq!(*addr_of!(WAIT_ARG), 9);
            assert_eq!(*addr_of!(SIGNAL_ARG), 9);
            assert_eq!(*addr_of!(DISPATCH_COUNT), 1, "exactly one dispatch");
            let request = *addr_of!(DISPATCH_REQUEST);
            assert_eq!(request[0], 4, "mailbox-send selector");
            assert_eq!(request[2], 6, "preserved r3 semaphore");
            assert_eq!(request[3], 1, "mailbox");
            assert_eq!(request[5], 5, "priority");
            assert_ne!(request[6], 0, "frame pointer");
            assert_eq!(request[7], 1, "mode");
            assert_eq!(request[8], 0, "trailing mode word");
        }
    }

    /// Each request independently brackets one actual dispatcher call.
    #[test]
    fn every_timed_request_rebrackets_the_dispatcher() {
        let _installed = install();
        unsafe {
            gateway_request_timed(0, 0);
            gateway_request_timed(0, usize::MAX);
            gateway_request_timed(0xdead_beef, 0x1f40);
            assert_eq!(*addr_of!(DISPATCH_COUNT), 3);
            assert_eq!(
                *addr_of!(CALL_LOG),
                [
                    "wait", "dispatch", "signal", "wait", "dispatch", "signal", "wait",
                    "dispatch", "signal"
                ]
            );
        }
    }
}
