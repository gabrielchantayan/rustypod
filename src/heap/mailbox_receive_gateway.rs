//! RTXC mailbox-receive gateway wrapper.
//!
//! `FUN_080040fc` is the retailOS mirror of RTXC service 5,
//! [`KS_receive(MBOX, TASK)`](https://freemyipod.org/wiki/RetailOS). It
//! submits the caller's mailbox and task identifiers to the foreign mask-ROM
//! dispatcher at `0x08003660`; the dispatcher stores the returned `RTXCMSG *`
//! in the request frame.

use core::mem::MaybeUninit;

use crate::heap::rom_task_start::gateway_dispatch;

/// Words from the selector passed to the gateway through the final explicit
/// zero word. The original initializes only words 0, 3, 4, 6, 7, and 8.
const RECEIVE_REQUEST_WORDS: usize = 9;

/// mailbox_receive_gateway — original: `FUN_080040fc` @ `0x080040fc` (60 bytes).
///
/// Reference: `decomp/c/000/080040fc_FUN_080040fc.c`; raw assembly at
/// `0x080040fc`; and the RTXC service catalogue identifying selector 5 as
/// `KS_receive(MBOX mailbox, TASK task)`. The original reserves 44 stack
/// bytes, passes `sp + 4` to `FUN_08003660`, and writes its nine-word request
/// span as `{ 5, uninitialized, uninitialized, mailbox, task, uninitialized,
/// output = 0, 1, 0 }`. After dispatch it returns the mutable output word at
/// request word 6. The leading stack word outside the dispatched span is also
/// unwritten and has no observable gateway role.
///
/// The shared volatile heap gateway hook is the required foreign-ROM/host-test
/// seam; target integration must bind it to the actual dispatcher rather than
/// synthesize a mailbox message result. `u32` preserves the ARM EABI's two
/// input registers and one-word pointer result on host and target builds.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mailbox_receive_gateway(mailbox: u32, task: u32) -> u32 {
    let mut request = [MaybeUninit::<u32>::uninit(); RECEIVE_REQUEST_WORDS];
    let words = request.as_mut_ptr().cast::<u32>();

    // These are the exact initialized request words in the original; words
    // 1, 2, and 5 deliberately retain their stack contents.
    words.write(5);
    words.add(3).write(mailbox);
    words.add(4).write(task);
    words.add(6).write(0);
    words.add(7).write(1);
    words.add(8).write(0);

    gateway_dispatch()(words);
    words.add(6).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_INITIALIZED_WORDS: [u32; 6] = [0; 6];

    unsafe extern "C" fn record_receive_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        // Do not read request words 1, 2, or 5: the firmware deliberately
        // leaves those stack words uninitialized.
        addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([
            request.read(),
            request.add(3).read(),
            request.add(4).read(),
            request.add(6).read(),
            request.add(7).read(),
            request.add(8).read(),
        ]);
        request.add(6).write(0x8f00_1234);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([0; 6]);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_receive_and_reply,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn builds_receive_request_delegates_and_returns_gateway_output() {
        let guard = install_recorder();
        unsafe {
            let output = mailbox_receive_gateway(0x0000_0003, 0x080c_1234);
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            assert_eq!(
                addr_of!(RECORDED_INITIALIZED_WORDS).read(),
                [5, 0x0000_0003, 0x080c_1234, 0, 1, 0],
                "preserves every initialized service-5 request word"
            );
            assert_eq!(
                output, 0x8f00_1234,
                "returns the output word written by the gateway"
            );
        }
        restore(guard);
    }
}
