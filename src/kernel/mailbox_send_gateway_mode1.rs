//! RTXC mailbox-send gateway, mode-1 request form.
//!
//! The literal veneer `thunk_EXT_FUN_2200418c` at load address `0x08037e18`
//! is **8 bytes**: `ldr pc, [pc, #-4]` plus its literal target
//! `0x2200418c`; Ghidra reports only the first 4-byte instruction. The boot
//! relocator mirrors that body at `0x0800418c`; raw ARM proves its complete
//! extent is 64 bytes, ending immediately before its sibling at `0x080041cc`.
//! A direct survey of every ARM B/BL encoding finds exactly 11 callers, all
//! unconditional, and no data pointer refers to this entry.
//!
//! Raw algorithm: reserve nine request words, then write
//! `{4, uninitialized, semaphore, mailbox, uninitialized, priority, message,
//! 1, 0}` and dispatch the writable record. Selector 4 is RTXC mailbox send.
//! The meanings of the trailing mode words `{1, 0}` are not established; this
//! port preserves both initialized values rather than naming unsupported
//! semantics.
//!
//! ## Intentional dispatch-seam deviation
//!
//! The original body performs a direct PC-relative `bl` to the foreign
//! dispatcher at `0x08003660`. This port deliberately calls the existing
//! installable [`message_dispatch_veneer`] seam instead, so target integration
//! can bind that seam to the foreign dispatcher and host tests can observe the
//! real writable request ABI. It does not recreate the stale foreign
//! `task_lock::rom_svc_2200418c` seam.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// Load address of `thunk_EXT_FUN_2200418c`.
pub const MAILBOX_SEND_GATEWAY_MODE1_THUNK: u32 = 0x0803_7e18;
/// ROM address reached by [`MAILBOX_SEND_GATEWAY_MODE1_THUNK`].
pub const MAILBOX_SEND_GATEWAY_MODE1_ROM_ENTRY: u32 = 0x2200_418c;
/// RetailOS mirror of [`MAILBOX_SEND_GATEWAY_MODE1_ROM_ENTRY`].
pub const MAILBOX_SEND_GATEWAY_MODE1_MIRROR_ENTRY: u32 = 0x0800_418c;
/// RTXC request selector for mailbox send.
pub const GATEWAY_SERVICE_MAILBOX_SEND: u32 = 4;

const REQUEST_WORDS: usize = 9;
const SERVICE_WORD: usize = 0;
const SEMAPHORE_WORD: usize = 2;
const MAILBOX_WORD: usize = 3;
const PRIORITY_WORD: usize = 5;
const MESSAGE_WORD: usize = 6;
const MODE_WORD: usize = 7;
const TRAILING_ZERO_WORD: usize = 8;
const MODE_ONE: u32 = 1;

/// mailbox_send_gateway_mode1 — original body @ `0x0800418c` (64 bytes).
///
/// Writes RTXC selector 4's mode-1 request form
/// `{4, _, semaphore, mailbox, _, priority, message, 1, 0}` and dispatches
/// it exactly once. Words 1 and 4 remain uninitialized, as in the ARM body;
/// callers discard the dispatcher's return register, so this wrapper returns
/// no artificial status value. `u32` preserves all four ARM argument words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mailbox_send_gateway_mode1(
    mailbox: u32,
    message: u32,
    priority: u32,
    semaphore: u32,
) {
    let mut request = MaybeUninit::<[u32; REQUEST_WORDS]>::uninit();
    let words = request.as_mut_ptr().cast::<u32>();

    words.add(SERVICE_WORD).write(GATEWAY_SERVICE_MAILBOX_SEND);
    words.add(SEMAPHORE_WORD).write(semaphore);
    words.add(MAILBOX_WORD).write(mailbox);
    words.add(PRIORITY_WORD).write(priority);
    words.add(MESSAGE_WORD).write(message);
    words.add(MODE_WORD).write(MODE_ONE);
    words.add(TRAILING_ZERO_WORD).write(0);
    message_dispatch_veneer(words);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use parking_lot::MutexGuard;
    use std::vec::Vec;

    /// Initialized request words only: 0, 2, 3, 5, 6, 7, and 8.
    static mut OBSERVED: Vec<[u32; 7]> = Vec::new();

    struct Recorder {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn recording_dispatch(request: *mut u32) {
        OBSERVED.push([
            request.add(SERVICE_WORD).read(),
            request.add(SEMAPHORE_WORD).read(),
            request.add(MAILBOX_WORD).read(),
            request.add(PRIORITY_WORD).read(),
            request.add(MESSAGE_WORD).read(),
            request.add(MODE_WORD).read(),
            request.add(TRAILING_ZERO_WORD).read(),
        ]);
    }

    fn install() -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED = Vec::new();
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn dispatches_the_complete_mode_one_record_once() {
        let _recorder = install();
        unsafe {
            mailbox_send_gateway_mode1(0x0000_0003, 0x080c_1234, 7, 0x0000_0013);
            assert_eq!(OBSERVED.len(), 1, "delegates exactly once");
            assert_eq!(
                OBSERVED.as_slice(),
                &[[GATEWAY_SERVICE_MAILBOX_SEND, 0x13, 3, 7, 0x080c_1234, MODE_ONE, 0]],
                "preserves selector, all four inputs, and trailing words 7/8"
            );
        }
    }

    #[test]
    fn successive_calls_build_distinct_records() {
        let _recorder = install();
        unsafe {
            mailbox_send_gateway_mode1(1, 2, 3, 4);
            mailbox_send_gateway_mode1(0x8000_0000, 0xffff_ffff, 0, 0x7fff_ffff);
            assert_eq!(OBSERVED.len(), 2, "one dispatch per distinct call");
            assert_eq!(
                OBSERVED.as_slice(),
                &[
                    [GATEWAY_SERVICE_MAILBOX_SEND, 4, 1, 3, 2, MODE_ONE, 0],
                    [GATEWAY_SERVICE_MAILBOX_SEND, 0x7fff_ffff, 0x8000_0000, 0, 0xffff_ffff, MODE_ONE, 0],
                ]
            );
            assert_ne!(OBSERVED[0], OBSERVED[1]);
        }
    }

    #[test]
    fn records_verified_gateway_addresses() {
        assert_eq!(MAILBOX_SEND_GATEWAY_MODE1_THUNK, 0x0803_7e18);
        assert_eq!(MAILBOX_SEND_GATEWAY_MODE1_ROM_ENTRY, 0x2200_418c);
        assert_eq!(MAILBOX_SEND_GATEWAY_MODE1_MIRROR_ENTRY, 0x0800_418c);
    }
}
