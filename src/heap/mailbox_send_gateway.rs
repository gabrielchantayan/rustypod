//! RTXC mailbox-send gateway wrapper.
//!
//! `FUN_08004154` is retailOS's mirror of RTXC service 4,
//! [`KS_send(MBOX, RTXCMSG *, PRIORITY, SEMA)`](https://freemyipod.org/wiki/RetailOS).
//! It submits every register-passed API argument in the mask-ROM dispatcher's
//! sparse request-frame layout.

use core::mem::MaybeUninit;

use crate::heap::rom_task_start::gateway_dispatch;

/// Request words beginning at the selector passed to the gateway.
///
/// The original writes words 0, 2, 3, 5, 6, and 7 only; words 1 and 4 retain
/// their stack contents and are not part of this wrapper's initialized ABI.
const SEND_REQUEST_WORDS: usize = 8;

/// mailbox_send_gateway — original: `FUN_08004154` @ `0x08004154` (56 bytes).
///
/// Reference: `decomp/c/000/08004154_FUN_08004154.c`; raw assembly at
/// `0x08004154`; and the RTXC service catalogue identifying selector 4 as
/// `KS_send(MBOX mailbox, RTXCMSG *message, PRIORITY priority, SEMA semaphore)`.
/// The original reserves eleven stack words and dispatches the eight-word span
/// at `sp + 4`: `{ 4, uninitialized, semaphore, mailbox, uninitialized,
/// priority, message, output = 0 }`. It returns void after exactly one call to
/// `FUN_08003660`; the service's output slot is initialized but not read by
/// this asynchronous-send wrapper. `u32` preserves the ARM EABI's four
/// one-word register arguments, including the message pointer representation.
///
/// The shared volatile heap gateway hook is the required foreign-ROM/host-test
/// seam; target integration must bind it to the actual dispatcher rather than
/// synthesize the service result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mailbox_send_gateway(
    mailbox: u32,
    message: u32,
    priority: u32,
    semaphore: u32,
) {
    let mut request = [MaybeUninit::<u32>::uninit(); SEND_REQUEST_WORDS];
    let words = request.as_mut_ptr().cast::<u32>();

    // These are exactly the six stores in the original; words 1 and 4 are
    // deliberately left uninitialized stack contents.
    words.write(4);
    words.add(2).write(semaphore);
    words.add(3).write(mailbox);
    words.add(5).write(priority);
    words.add(6).write(message);
    words.add(7).write(0);

    gateway_dispatch()(words);
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

    unsafe extern "C" fn record_send(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        // Do not read words 1 or 4: the firmware deliberately leaves them
        // uninitialized.
        addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([
            request.read(),
            request.add(2).read(),
            request.add(3).read(),
            request.add(5).read(),
            request.add(6).read(),
            request.add(7).read(),
        ]);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_INITIALIZED_WORDS).write([0; 6]);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_send,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn builds_full_send_request_and_delegates_once() {
        let guard = install_recorder();
        unsafe {
            mailbox_send_gateway(0x0000_0003, 0x080c_1234, 7, 0x0000_0013);
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            assert_eq!(
                addr_of!(RECORDED_INITIALIZED_WORDS).read(),
                [4, 0x0000_0013, 0x0000_0003, 7, 0x080c_1234, 0],
                "preserves every initialized service-4 request word"
            );
        }
        restore(guard);
    }
}
