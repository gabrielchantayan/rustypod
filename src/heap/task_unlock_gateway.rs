//! Raw mask-ROM task-unlock gateway wrapper.
//!
//! This is the osos mirror of ROM `0x2200408c`, reached through the
//! `0x08037e50` RTXC thunk. The established kernel thunk catalogue names this
//! selector-3 operation `task_unlock`: call sites use it immediately after the
//! kernel-id lookup around semaphore and mutex critical sections. The generic
//! gateway itself remains foreign, so this wrapper uses the shared volatile
//! dispatch binding from `rom_task_start`.

use crate::heap::rom_task_start::gateway_dispatch;
use core::mem::MaybeUninit;

/// Three-word request frame for RTXC gateway service 3.
///
/// The assembly writes word 0 (selector 3) and word 2 (the task/kernel id),
/// deliberately leaving word 1 uninitialized for the gateway to fill as the
/// high return word. It must not be read before dispatch.
#[repr(C)]
pub struct TaskUnlockRequest {
    pub selector_or_result_low: u32,
    pub result_high: MaybeUninit<u32>,
    pub task_id: u32,
}

/// task_unlock_gateway — original: `FUN_0800408c` @ `0x0800408c` (32 bytes).
///
/// Reference: `decomp/c/000/0800408c_FUN_0800408c.c`; raw assembly at
/// `0x0800408c`; ROM thunk/caller evidence in
/// `kernel/task_lock.rs` (`0x08037e50 -> 0x2200408c`). Builds the writable
/// three-word service-3 frame `{ 3, uninitialized_output, task_id }`,
/// delegates it to `FUN_08003660`, then returns its first two post-dispatch
/// words as the ARM EABI `u64` result (`r0` low, `r1` high). The dispatcher is
/// the shared volatile foreign-ROM hook; host tests install a recorder, while
/// target integration must bind the real gateway rather than synthesize a
/// result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_unlock_gateway(task_id: u32) -> u64 {
    let mut request = MaybeUninit::<TaskUnlockRequest>::uninit();
    let request_ptr = request.as_mut_ptr();
    core::ptr::addr_of_mut!((*request_ptr).selector_or_result_low).write(3);
    core::ptr::addr_of_mut!((*request_ptr).task_id).write(task_id);
    gateway_dispatch()(request_ptr.cast());
    let request = request.assume_init();
    (request.selector_or_result_low as u64) | ((request.result_high.assume_init() as u64) << 32)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{
        RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_SELECTOR: u32 = 0;
    static mut RECORDED_TASK_ID: u32 = 0;

    unsafe extern "C" fn record_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        addr_of_mut!(RECORDED_SELECTOR).write(request.read());
        addr_of_mut!(RECORDED_TASK_ID).write(request.add(2).read());
        request.write(0xfeed_cafe);
        request.add(1).write(0x1234_5678);
    }

    #[test]
    fn builds_service_3_request_delegates_and_returns_gateway_pair() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_SELECTOR).write(0);
            addr_of_mut!(RECORDED_TASK_ID).write(0);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_and_reply,
            });

            let result = task_unlock_gateway(0xa1b2_c3d4);

            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(addr_of!(RECORDED_SELECTOR).read(), 3);
            assert_eq!(addr_of!(RECORDED_TASK_ID).read(), 0xa1b2_c3d4);
            assert_eq!(result, 0x1234_5678_feed_cafe);
            addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS);
        }
        drop(guard);
    }
}
