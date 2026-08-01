//! Raw mask-ROM task-start gateway wrapper.
//!
//! The wrapper is the osos mirror of ROM `0x22003e00`.  The public RTXC
//! task-start veneer at `0x08037f78` jumps there with the task id in `r0`.
//! Its direct boot callers also establish that selector `0x15` starts the
//! supplied kernel task id.  The remaining live registers are not decoded by
//! any caller, but this mirror faithfully carries `r1` and `r3` into the
//! request and returns the two words the gateway leaves in their slots.
//!
//! The mask-ROM gateway entry (`0x08003660`) is outside the Rust port.  As in
//! the other heap foreign-service boundaries, it is an indirect, volatile
//! hook so target integration can install the real service and host tests can
//! observe the exact request.  Its unwired default spins rather than inventing
//! a task-start result.

/// Four-word service request used by the ROM task-start entry.
///
/// Word 0 is selector 21, word 1 preserves input `r1`, word 2 is the task id
/// from input `r0`, and word 3 preserves input `r3`.  Input `r2` is saved and
/// restored by the assembly prologue but is deliberately absent from this
/// frame.
pub type TaskStartRequest = [u32; 4];

/// Foreign gateway entry `FUN_08003660` @ `0x08003660`.
///
/// It receives a writable request-frame pointer. Each selector defines its
/// own frame length, but the gateway may replace the first two words; wrappers
/// that return `u64` expose those words as the ARM EABI result (`r0` low,
/// `r1` high).
#[derive(Clone, Copy)]
pub struct RomGatewayOps {
    pub dispatch: unsafe extern "C" fn(request: *mut u32),
}

unsafe extern "C" fn missing_dispatch(_request: *mut u32) {
    loop {}
}

/// Default foreign-service binding until the mask-ROM gateway is installed.
pub const DEFAULT_ROM_GATEWAY_OPS: RomGatewayOps = RomGatewayOps {
    dispatch: missing_dispatch,
};

/// Active mask-ROM gateway binding. Target integration installs the real
/// service once; focused host tests replace it with a request recorder.
pub static mut ROM_GATEWAY_OPS: RomGatewayOps = DEFAULT_ROM_GATEWAY_OPS;

/// Reads the shared mask-ROM gateway hook without allowing LLVM to fold the
/// table back to its unwired default.
#[inline(always)]
pub(crate) fn gateway_dispatch() -> unsafe extern "C" fn(request: *mut u32) {
    unsafe { core::ptr::addr_of!(ROM_GATEWAY_OPS.dispatch).read_volatile() }
}

/// rom_task_start — original: `FUN_08003e00` @ `0x08003e00` (28 bytes).
///
/// Reference: `decomp/c/000/08003e00_FUN_08003e00.c` and the raw assembly at
/// `0x08003e00`.  Builds `{ 0x15, input_r1, task_id, input_r3 }`, delegates
/// the writable frame to `FUN_08003660`, then restores the frame's first two
/// words as its 64-bit ARM return (`r0` low, `r1` high).  `input_r2` is not a
/// service input: the original saves/restores it only because its push/pop
/// covers `r0-r4`.
///
/// `task_id` is the semantic input used by the service-15 task-start callers;
/// `input_r1` and `input_r3` preserve the raw mirror ABI for the ROM gateway.
/// The hook indirection is the necessary host-test/foreign-service deviation;
/// on target it must be bound to the real gateway, never synthesized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rom_task_start(
    task_id: u32,
    input_r1: u32,
    _input_r2: u32,
    input_r3: u32,
) -> u64 {
    let mut request = [0x15, input_r1, task_id, input_r3];
    gateway_dispatch()(request.as_mut_ptr());
    (request[0] as u64) | ((request[1] as u64) << 32)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_REQUEST: TaskStartRequest = [0; 4];

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
    fn builds_service_15_request_and_delegates_it_once() {
        let guard = install_recorder();
        unsafe {
            let result = rom_task_start(0xa1b2_c3d4, 0x1122_3344, 0xdead_beef, 0x5566_7788);
            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(
                addr_of!(RECORDED_REQUEST).read(),
                [0x15, 0x1122_3344, 0xa1b2_c3d4, 0x5566_7788],
                "r2 is not part of the request frame"
            );
            assert_eq!(result, 0x1234_5678_feed_cafe);
        }
        restore(guard);
    }
}
