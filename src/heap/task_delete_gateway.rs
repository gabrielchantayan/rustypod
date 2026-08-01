//! Raw mask-ROM task-delete gateway wrapper.
//!
//! The wrapper mirrors ROM `0x2200427c`, reached through the `0x08037f80`
//! RTXC thunk from `task_destroy`. That caller supplies the kernel task id in
//! `r0`; the ROM service selector is `0x18`. The mask-ROM gateway entry
//! (`FUN_08003660`) is foreign, so this wrapper reuses the shared volatile
//! dispatch seam from [`super::rom_task_start`].

use crate::heap::rom_task_start::gateway_dispatch;

/// Four-word service request used by the ROM task-delete entry.
///
/// The assembly initializes every word: selector 24, raw input `r1`, the task
/// id from `r0`, and raw input `r3`. Input `r2` is saved and restored only by
/// the prologue/epilogue and is not part of the service frame.
pub type TaskDeleteRequest = [u32; 4];

/// task_delete_gateway — original: `FUN_0800427c` @ `0x0800427c` (28 bytes).
///
/// Reference: `decomp/c/000/0800427c_FUN_0800427c.c`; raw assembly at
/// `0x0800427c`; thunk/caller evidence: `0x08037f80 -> 0x2200427c` from
/// `task_destroy`. Builds `{ 0x18, input_r1, task_id, input_r3 }`, delegates
/// the writable frame to `FUN_08003660`, then returns the first two
/// post-dispatch words as an ARM EABI `u64` (`r0` low, `r1` high). `input_r2`
/// is not a service input. The shared volatile hook is the necessary
/// foreign-ROM/host-test seam; on target it must bind the real gateway rather
/// than synthesize a result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_delete_gateway(
    task_id: u32,
    input_r1: u32,
    _input_r2: u32,
    input_r3: u32,
) -> u64 {
    let mut request: TaskDeleteRequest = [0x18, input_r1, task_id, input_r3];
    gateway_dispatch()(request.as_mut_ptr());
    (request[0] as u64) | ((request[1] as u64) << 32)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{
        RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_REQUEST: TaskDeleteRequest = [0; 4];

    unsafe extern "C" fn record_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        let request = core::slice::from_raw_parts_mut(request, 4);
        addr_of_mut!(RECORDED_REQUEST).write(request.try_into().unwrap());
        request[0] = 0xfeed_cafe;
        request[1] = 0x1234_5678;
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
    fn builds_service_24_request_delegates_and_returns_gateway_pair() {
        let guard = install_recorder();
        unsafe {
            let result = task_delete_gateway(
                0xa1b2_c3d4,
                0x1122_3344,
                0xdead_beef,
                0x5566_7788,
            );
            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(
                addr_of!(RECORDED_REQUEST).read(),
                [0x18, 0x1122_3344, 0xa1b2_c3d4, 0x5566_7788],
                "r2 is not part of the initialized request frame"
            );
            assert_eq!(result, 0x1234_5678_feed_cafe);
        }
        restore(guard);
    }
}
