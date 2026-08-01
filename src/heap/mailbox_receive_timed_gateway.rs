//! RTXC timed-mailbox-receive gateway wrapper.
//!
//! `FUN_080040ac` is the retailOS internal gateway ABI for RTXC service 5's
//! timed receive operation, [`KS_receivet(MBOX, TASK, TICKS)`](https://freemyipod.org/wiki/RetailOS).
//! Unlike the public RTXC pointer-returning veneer, this raw wrapper returns a
//! service status and writes the received `RTXCMSG *` through its final
//! pointer argument.

use core::mem::MaybeUninit;

use crate::heap::rom_task_start::gateway_dispatch;

/// Number of request words passed to the gateway after the 32-byte scratch
/// prefix. The ROM receives this full sparse frame starting at word 0.
const TIMED_RECEIVE_REQUEST_WORDS: usize = 10;

/// Complete 72-byte local allocation below the saved `{r4, lr}` pair.
///
/// The original reserves 32 scratch bytes followed by the 10 request words.
/// It passes `request`, but request word 9 points back to `scratch`.
#[repr(C)]
struct TimedMailboxReceiveFrame {
    scratch: [u8; 32],
    request: [MaybeUninit<u32>; TIMED_RECEIVE_REQUEST_WORDS],
}

/// mailbox_receive_timed_gateway — original: `FUN_080040ac` @ `0x080040ac` (80 bytes).
///
/// Reference: `decomp/c/000/080040ac_FUN_080040ac.c`; raw assembly at
/// `0x080040ac`; and the RTXC service catalogue identifying selector 5's
/// three-input form as `KS_receivet(MBOX mailbox, TASK task, TICKS timeout)`.
/// The original reserves a 72-byte local frame (plus saved `{r4, lr}`): an
/// uninitialized 32-byte scratch prefix and the sparse ten-word request
/// `{5, output = 0, uninitialized, mailbox, task, uninitialized, status = 0,
/// 1, timeout, scratch_pointer}`. It passes request word 0 to `FUN_08003660`,
/// then writes the gateway-mutated output word 1 to `message_out` and returns
/// the gateway-mutated status word 6. The shared volatile heap gateway hook is
/// the required foreign-ROM/host-test seam; no result is synthesized here.
///
/// # Safety
/// `message_out` must be valid and writable for one `u32`. As in the original,
/// it is dereferenced after dispatch without a null check. The three scalar
/// arguments are the RTXC mailbox, task filter, and timeout tick count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mailbox_receive_timed_gateway(
    mailbox: u32,
    task: u32,
    timeout_ticks: u32,
    message_out: *mut u32,
) -> u32 {
    let mut frame = MaybeUninit::<TimedMailboxReceiveFrame>::uninit();
    let frame_ptr = frame.as_mut_ptr();
    let scratch = core::ptr::addr_of_mut!((*frame_ptr).scratch) as *mut u8;
    let request = core::ptr::addr_of_mut!((*frame_ptr).request).cast::<u32>();

    // These are exactly the seven initialized request words in the original.
    // Words 2 and 5, and the 32-byte scratch prefix, remain uninitialized.
    request.write(5);
    request.add(1).write(0);
    request.add(3).write(mailbox);
    request.add(4).write(task);
    request.add(6).write(0);
    request.add(7).write(1);
    request.add(8).write(timeout_ticks);
    request.add(9).write(scratch as usize as u32);

    gateway_dispatch()(request);
    message_out.write(request.add(1).read());
    request.add(6).read()
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
    static mut RECORDED_INITIALIZED_WORDS: [u32; 8] = [0; 8];
    static mut RECORDED_SCRATCH_POINTER: u32 = 0;
    static mut RECORDED_REQUEST_POINTER: u32 = 0;

    unsafe extern "C" fn record_timed_receive_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        // Do not read words 2 or 5: the firmware deliberately leaves those
        // stack words uninitialized.
        addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([
            request.read(),
            request.add(1).read(),
            request.add(3).read(),
            request.add(4).read(),
            request.add(6).read(),
            request.add(7).read(),
            request.add(8).read(),
            request.add(9).read(),
        ]);
        addr_of_mut!(RECORDED_REQUEST_POINTER).write(request as usize as u32);
        addr_of_mut!(RECORDED_SCRATCH_POINTER).write(request.add(9).read());
        request.add(1).write(0x8f00_1234);
        request.add(6).write(0x0000_0007);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([0; 8]);
            addr_of_mut!(RECORDED_SCRATCH_POINTER).write(0);
            addr_of_mut!(RECORDED_REQUEST_POINTER).write(0);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_timed_receive_and_reply,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn builds_timed_receive_frame_delegates_writes_output_and_returns_status() {
        let guard = install_recorder();
        unsafe {
            let mut message = 0xdead_beef;
            let status = mailbox_receive_timed_gateway(
                0x0000_0003,
                0x080c_1234,
                0x0000_03e8,
                &mut message,
            );
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            let recorded = addr_of!(RECORDED_INITIALIZED_WORDS).read();
            assert_eq!(
                recorded[..7],
                [5, 0, 0x0000_0003, 0x080c_1234, 0, 1, 0x0000_03e8],
                "preserves every initialized service-5 request word",
            );
            assert_eq!(
                recorded[7],
                addr_of!(RECORDED_REQUEST_POINTER)
                    .read()
                    .wrapping_sub(32),
                "request word 9 points at the preceding 32-byte scratch area",
            );
            assert_eq!(
                addr_of!(RECORDED_SCRATCH_POINTER).read(),
                recorded[7],
                "gateway observes the initialized scratch pointer",
            );
            assert_eq!(message, 0x8f00_1234, "writes gateway output through message_out");
            assert_eq!(status, 7, "returns the gateway-mutated status word");
        }
        restore(guard);
    }
}
