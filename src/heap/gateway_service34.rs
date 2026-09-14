//! Raw mask-ROM service-34 gateway wrapper.
//!
//! The retailOS veneer at `0x08037fb0` tail-branches through literal
//! `0x2200439c`, the IRAM mirror of this 36-byte body at `0x0800439c`.
//! Selector `0x22` is established by raw assembly, but its higher-level RTXC
//! operation is not recovered, so this module names the verified wire protocol
//! rather than guessing an operation.

use crate::heap::rom_task_start::gateway_dispatch;

/// Four-word request received by the ROM gateway for selector 34.
///
/// The physical ARM save area has six words: the dispatched prefix below,
/// followed by preserved `r4` and `lr`. The mirror overwrites saved `r0` with
/// the selector and saved `r3` with input `r0`, so incoming `r3` is discarded.
pub type GatewayService34Request = [u32; 4];

/// gateway_service34_request — original: `thunk_EXT_FUN_2200439c` @
/// `0x08037fb0` (8-byte literal veneer; IRAM target body `0x0800439c`, 36 bytes;
/// 6 unconditional `bl` call sites).
///
/// Raw words prove the full veneer is `ldr pc, [pc, #-4]` at `0x08037fb0` plus
/// target literal `0x2200439c` at `0x08037fb4`; Ghidra reports only four bytes.
/// The IRAM relocator mirrors that target from `0x0800439c`. Its body saves
/// `{r0-r4, lr}`, turns the first four saved words into `{0x22, input_r1,
/// input_r2, input_r0}`, passes them to `FUN_08003660`, then returns the
/// dispatcher-mutated third word while restoring `r4`. Decoding every aligned
/// ARM B/BL word in `osos.dec` finds exactly six direct callers, all plain,
/// unconditional `bl` at `0x080c9c80`, `0x080cb788`, `0x08392ea0`,
/// `0x08393030`, `0x0839356c`, and `0x08393830`; no predicated forms or plain
/// branches target the veneer.
///
/// Deliberate deviation: the foreign dispatcher is represented by the shared
/// volatile ROM-gateway seam. Rust's call has a return edge where both retail
/// veneer and IRAM dispatcher path tail-branch; the writable four-word request
/// and observable returned word are preserved exactly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service34_request(
    input_r0: u32,
    input_r1: u32,
    input_r2: u32,
    _input_r3: u32,
) -> u32 {
    let mut request: GatewayService34Request = [0x22, input_r1, input_r2, input_r0];
    gateway_dispatch()(request.as_mut_ptr());
    request[2]
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
    static mut RECORDED_REQUEST: GatewayService34Request = [0; 4];

    unsafe extern "C" fn record_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        let words = core::slice::from_raw_parts_mut(request, 4);
        addr_of_mut!(RECORDED_REQUEST).write(words.try_into().unwrap());
        words[2] = 0x5a5a_a5a5;
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_REQUEST).write([0; 4]);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_and_reply,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn builds_service34_frame_and_returns_mutated_third_word() {
        let guard = install_recorder();
        unsafe {
            let result = gateway_service34_request(
                0xa1b2_c3d4,
                0x1122_3344,
                0x5566_7788,
                0x99aa_bbcc,
            );
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            assert_eq!(
                addr_of!(RECORDED_REQUEST).read(),
                [0x22, 0x1122_3344, 0x5566_7788, 0xa1b2_c3d4],
                "selector overwrites r0, r1/r2 pass through, and r0 replaces r3",
            );
            assert_eq!(result, 0x5a5a_a5a5, "returns the post-dispatch third word");
        }
        restore(guard);
    }
}
