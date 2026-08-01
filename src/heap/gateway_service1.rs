//! Raw mask-ROM service-1 gateway request wrapper.
//!
//! `FUN_080043c0` packages two raw service inputs and a 32-byte scratch area
//! for the foreign gateway dispatcher at `0x08003660`. The service selector
//! is known to be 1; its higher-level RTXC operation has no recovered caller
//! or thunk evidence, so this module deliberately names the established wire
//! protocol rather than guessing an operation.

use crate::heap::rom_task_start::gateway_dispatch;

/// Complete 52-byte ARM stack allocation for the service-1 request.
///
/// The dispatcher receives `&mut selector`, not the start of this object.
/// `scratch` therefore lives at request-word offset -8, and `scratch_pointer`
/// points back to it. The original writes only the five request words; its
/// 32-byte scratch region is intentionally left uninitialized.
#[repr(C)]
struct GatewayService1Frame {
    scratch: [u8; 32],
    selector: u32,
    output: u32,
    input0: u32,
    input1: u32,
    scratch_pointer: u32,
}

/// gateway_service1_request — original: `FUN_080043c0` @ `0x080043c0` (52 bytes).
///
/// Reference: `decomp/c/000/080043c0_FUN_080043c0.c`; raw assembly at
/// `0x080043c0`. Reserves the original 52-byte frame: uninitialized scratch
/// `[sp..sp+0x20)`, then `{ service = 1, output = 0, input0, input1,
/// scratch_pointer = sp }`. It passes `&service` (`sp + 0x20`) to the foreign
/// `FUN_08003660` gateway dispatcher and returns the post-dispatch `output`
/// word. ARM EABI inputs and result are `u32`; the service communicates its
/// result through the writable request word, not the dispatcher's return
/// register.
///
/// The shared volatile hook is the required ROM/host-test seam. The service's
/// higher-level operation is not identified by recovered callers, so this
/// wrapper preserves only the established service-1 protocol.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service1_request(input0: u32, input1: u32) -> u32 {
    let mut frame = core::mem::MaybeUninit::<GatewayService1Frame>::uninit();
    let frame_ptr = frame.as_mut_ptr();
    let scratch = core::ptr::addr_of_mut!((*frame_ptr).scratch) as *mut u8;

    // These are exactly the five stores in the original; `scratch` remains
    // deliberately uninitialized.
    core::ptr::addr_of_mut!((*frame_ptr).selector).write(1);
    core::ptr::addr_of_mut!((*frame_ptr).output).write(0);
    core::ptr::addr_of_mut!((*frame_ptr).input0).write(input0);
    core::ptr::addr_of_mut!((*frame_ptr).input1).write(input1);
    core::ptr::addr_of_mut!((*frame_ptr).scratch_pointer).write(scratch as u32);

    let request = core::ptr::addr_of_mut!((*frame_ptr).selector);
    gateway_dispatch()(request);
    core::ptr::addr_of!((*frame_ptr).output).read()
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
    static mut RECORDED_REQUEST: [u32; 5] = [0; 5];
    static mut RECORDED_SCRATCH_OFFSET: isize = 0;

    unsafe extern "C" fn record_and_reply(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        let words = core::slice::from_raw_parts_mut(request, 5);
        addr_of_mut!(RECORDED_REQUEST).write(words.try_into().unwrap());
        let scratch = (request as *mut u8).sub(32);
        addr_of_mut!(RECORDED_SCRATCH_OFFSET).write(request as isize - scratch as isize);
        assert_eq!(words[4], scratch as u32, "scratch pointer is the frame base");
        assert_eq!(words[1], 0, "output word is explicitly cleared before dispatch");
        words[1] = 0x89ab_cdef;
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_REQUEST).write([0; 5]);
            addr_of_mut!(RECORDED_SCRATCH_OFFSET).write(0);
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
    fn builds_service1_frame_delegates_and_returns_output_word() {
        let guard = install_recorder();
        unsafe {
            let output = gateway_service1_request(0x1122_3344, 0x5566_7788);
            assert_eq!(addr_of!(CALLS).read(), 1);
            let request = addr_of!(RECORDED_REQUEST).read();
            assert_eq!(
                &request[..4],
                &[1, 0, 0x1122_3344, 0x5566_7788],
                "service, zero output, and inputs were dispatched"
            );
            assert_eq!(addr_of!(RECORDED_SCRATCH_OFFSET).read(), 32);
            assert_eq!(output, 0x89ab_cdef, "return reads the post-dispatch output word");
        }
        restore(guard);
    }
}
