//! RTXC task-yield gateway wrapper.
//!
//! The retailOS mirror at `0x080043f4` invokes RTXC service `0x1c`,
//! [`KS_yield`](https://freemyipod.org/wiki/RetailOS), through the foreign
//! mask-ROM dispatcher at `0x08003660`. It has no direct caller or veneer in
//! this retailOS image, so its externally visible ABI is retained exactly.

use crate::heap::rom_task_start::gateway_dispatch;

/// Four-word request received by the ROM gateway for RTXC `KS_yield`.
///
/// The physical ARM save area has six words: the dispatched prefix below,
/// followed by preserved `r4` and `lr`. The dispatcher receives the prefix at
/// `sp`; the epilogue discards its four words and restores only those trailing
/// saved registers. Although `KS_yield` has no semantic parameters, this
/// mirror deliberately forwards the incoming live `r2` and `r3` in words 2/3.
/// Incoming `r0` and `r1` are overwritten before dispatch.
pub type TaskYieldRequest = [u32; 4];

/// task_yield_gateway — original: `FUN_080043f4` @ `0x080043f4` (40 bytes).
///
/// Reference: `decomp/c/000/080043f4_FUN_080043f4.c`; raw assembly at
/// `0x080043f4`; the retailOS RTXC service catalogue identifies selector
/// `0x1c` as `KS_yield`. The original saves `{r0-r4, lr}`, overwrites the
/// saved `r0`/`r1` words with `{ 0x1c, 0x0d }`, and passes the resulting
/// `{ selector, status, input_r2, input_r3 }` prefix to `FUN_08003660`.
/// Afterwards it returns the dispatch-mutated status word, while `r4` is
/// restored and incoming `r0`/`r1` remain ignored. The shared volatile hook
/// is the necessary foreign-ROM/host-test seam; target integration must bind
/// it to the actual ROM gateway rather than synthesize a result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_yield_gateway(
    _ignored_r0: u32,
    _ignored_r1: u32,
    input_r2: u32,
    input_r3: u32,
) -> u32 {
    let mut request: TaskYieldRequest = [0x1c, 0x0d, input_r2, input_r3];
    gateway_dispatch()(request.as_mut_ptr());
    request[1]
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
    static mut RECORDED_REQUEST: TaskYieldRequest = [0; 4];

    unsafe extern "C" fn record_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        let words = core::slice::from_raw_parts_mut(request, 4);
        addr_of_mut!(RECORDED_REQUEST).write(words.try_into().unwrap());
        assert_eq!(words[1], 0x0d, "status is initialized before dispatch");
        words[1] = 0x5a5a_a5a5;
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
    fn builds_yield_frame_delegates_and_returns_mutated_status() {
        let guard = install_recorder();
        unsafe {
            let status = task_yield_gateway(0x1111_2222, 0x3333_4444, 0x5566_7788, 0x99aa_bbcc);
            assert_eq!(addr_of!(CALLS).read(), 1, "delegates exactly once");
            assert_eq!(
                addr_of!(RECORDED_REQUEST).read(),
                [0x1c, 0x0d, 0x5566_7788, 0x99aa_bbcc],
                "selector/status overwrite r0/r1 while r2/r3 are forwarded",
            );
            assert_eq!(status, 0x5a5a_a5a5, "returns the post-dispatch status word");
        }
        restore(guard);
    }
}
