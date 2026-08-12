//! Port of the RTXC task-delay gateway stub @ 0x08003d44 (44 bytes) — the
//! osos link-order mirror of mask ROM 0x22003d44 (aliased by thunk
//! 0x08037e88, whose 15 osos callers pass r0 = 0 — the current task — and
//! r1 = a small tick count like 1 or 0x64; see kernel/task_lock.rs). This is
//! gateway service 0x14 (20), the timed task delay behind
//! kernel/task.rs `task_sleep`'s nonzero-ticks path and behind the
//! `task_delay(0, 1)` polls in the i2c0 wait routines
//! (runtime/i2c0_idle.rs, runtime/i2c0_transfer.rs — currently reached
//! through their target-default seams; rewiring those to this port is a
//! follow-up, deliberately not done here because src/runtime is another
//! porter's territory). The mirror's only direct osos caller is the ROM
//! tick-housekeeping path @ 0x08002dc4, which delays the current task by
//! 100 (0x64) ticks.
//!
//! Algorithm (verified against osos.asm @ 0x08003d44..0x08003d70 and the
//! reference C decomp/c/000/08003d44_FUN_08003d44.c): reserve a 0x34-byte
//! frame — word at sp+0 holds the pushed lr, a 32-byte scratch area at
//! sp+4..sp+0x24 is left uninitialized, and the four-word request at
//! sp+0x24 is `{ selector = 0x14, task (r0), ticks (r1),
//! scratch_pointer = sp+4 }`. The request pointer is handed to the kernel
//! gateway dispatcher @ 0x08003660 and nothing is read back: the original
//! returns void after the call.
//!
//! Deviations (the heap/gateway_service1.rs precedent):
//! - The gateway call dispatches indirectly through the shared volatile
//!   heap::rom_task_start::ROM_GATEWAY_OPS hook instead of `bl 0x08003660`;
//!   the foreign ROM dispatcher is outside the port, and the unwired
//!   default spins rather than inventing a delay result. match.py diffs
//!   are structural, as with the rest of the gateway family.
//! - The 32-byte scratch and the pushed-lr slot are modeled with
//!   MaybeUninit and never written — exactly the original's store set.

use crate::heap::rom_task_start::gateway_dispatch;

/// Complete 0x34-byte ARM stack allocation for the service-0x14 request.
///
/// The dispatcher receives `&mut selector` (sp+0x24), not the start of
/// this object: `scratch` therefore lives at request-word offset -8, and
/// `scratch_pointer` points back to it. The original writes only the four
/// request words; the pushed-lr slot and the scratch region are
/// intentionally left uninitialized.
#[repr(C)]
struct TaskDelayFrame {
    /// sp+0: the original's pushed-lr slot; unwritten by the port.
    saved_lr: u32,
    /// sp+4..sp+0x24: scratch for the ROM service, never initialized.
    scratch: [u8; 32],
    /// sp+0x24: gateway service selector 0x14 (timed task delay).
    selector: u32,
    /// sp+0x28: kernel task to delay (r0; 0 = current task at call sites).
    task: u32,
    /// sp+0x2c: delay length in kernel ticks (r1).
    ticks: u32,
    /// sp+0x30: pointer back to `scratch` (sp+4).
    scratch_pointer: u32,
}

/// task_delay — original: FUN_08003d44 @ 0x08003d44 (44 bytes).
///
/// Reference: decomp/c/000/08003d44_FUN_08003d44.c; raw assembly at
/// 0x08003d44. Reserves the original 0x34-byte frame: untouched pushed-lr
/// slot, uninitialized 32-byte scratch, then `{ selector = 0x14, task,
/// ticks, scratch_pointer = &scratch }`. It passes `&selector` to the
/// foreign 0x08003660 gateway dispatcher and returns void, exactly like
/// the original — the service's effect is the side effect of the dispatch,
/// not any word read back.
///
/// `task` is the kernel task to suspend (0 = the current task, the only
/// observed call-site value); `ticks` is the delay in kernel ticks. The
/// shared volatile hook is the required ROM/host-test seam; on target it
/// must be bound to the real gateway, never synthesized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_delay(task: u32, ticks: u32) {
    let mut frame = core::mem::MaybeUninit::<TaskDelayFrame>::uninit();
    let frame_ptr = frame.as_mut_ptr();
    let scratch = core::ptr::addr_of_mut!((*frame_ptr).scratch) as *mut u8;

    // These are exactly the four stores in the original; `saved_lr` and
    // `scratch` remain deliberately uninitialized.
    core::ptr::addr_of_mut!((*frame_ptr).selector).write(0x14);
    core::ptr::addr_of_mut!((*frame_ptr).task).write(task);
    core::ptr::addr_of_mut!((*frame_ptr).ticks).write(ticks);
    core::ptr::addr_of_mut!((*frame_ptr).scratch_pointer).write(scratch as u32);

    let request = core::ptr::addr_of_mut!((*frame_ptr).selector);
    gateway_dispatch()(request);
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
    static mut RECORDED_REQUEST: [u32; 4] = [0; 4];
    /// Request pointer the recorder observed, for scratch-geometry checks.
    static mut RECORDED_REQUEST_PTR: usize = 0;

    /// Records the four request words, then clobbers them the way the ROM
    /// service may (the gateway owns the frame once dispatched).
    unsafe extern "C" fn record_and_clobber(request: *mut u32) {
        addr_of_mut!(CALLS).write(addr_of!(CALLS).read() + 1);
        addr_of_mut!(RECORDED_REQUEST_PTR).write(request as usize);
        let words = core::slice::from_raw_parts(request, 4);
        addr_of_mut!(RECORDED_REQUEST).write(words.try_into().unwrap());
        for i in 0..4 {
            request.add(i).write(0xdead_0000 + i as u32);
        }
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_REQUEST).write([0; 4]);
            addr_of_mut!(RECORDED_REQUEST_PTR).write(0);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_and_clobber,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    #[test]
    fn builds_service_20_request_and_delegates_it_once() {
        let guard = install_recorder();
        unsafe {
            // The i2c0 wait routines' call shape: current task, one tick.
            task_delay(0, 1);
            assert_eq!(addr_of!(CALLS).read(), 1, "exactly one gateway dispatch");
            let request = addr_of!(RECORDED_REQUEST).read();
            assert_eq!(request[0], 0x14, "selector is service 20");
            assert_eq!(request[1], 0, "task argument forwarded");
            assert_eq!(request[2], 1, "ticks argument forwarded");
        }
        restore(guard);
    }

    #[test]
    fn scratch_pointer_addresses_the_frame_scratch() {
        let guard = install_recorder();
        unsafe {
            task_delay(0, 0x64);
            let request = addr_of!(RECORDED_REQUEST).read();
            let request_ptr = addr_of!(RECORDED_REQUEST_PTR).read();
            // scratch is 32 bytes immediately before the request (sp+4 vs
            // sp+0x24), and word 3 points at it. The field is a u32, so on
            // 64-bit hosts compare the truncated pointer (exact on target).
            assert_eq!(
                request[3] as usize,
                (request_ptr - 0x20) as u32 as usize,
                "scratch_pointer = &request - 0x20 (sp+4 in the original)"
            );
        }
        restore(guard);
    }

    #[test]
    fn forwards_edge_arguments_and_survives_frame_clobber() {
        let guard = install_recorder();
        unsafe {
            // Nonzero task id (never observed, but the ABI carries it) and
            // the tick-count extremes. The recorder clobbers every request
            // word; the void wrapper reads nothing back and must simply
            // return.
            task_delay(0x2e, u32::MAX);
            assert_eq!(addr_of!(CALLS).read(), 1);
            let request = addr_of!(RECORDED_REQUEST).read();
            assert_eq!(request[0], 0x14);
            assert_eq!(request[1], 0x2e);
            assert_eq!(request[2], u32::MAX);

            task_delay(u32::MAX, 0);
            assert_eq!(addr_of!(CALLS).read(), 2);
            let request = addr_of!(RECORDED_REQUEST).read();
            assert_eq!(request[1], u32::MAX);
            assert_eq!(request[2], 0, "zero ticks forwards verbatim");
        }
        restore(guard);
    }
}
