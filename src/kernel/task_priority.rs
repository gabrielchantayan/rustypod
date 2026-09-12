//! RTXC task-priority gateway wrapper.
//!
//! `thunk_EXT_FUN_22003bcc` is the eight-byte literal veneer at load address
//! `0x08037ed0`: `e51ff004` (`ldr pc, [pc, #-4]`) followed by the target
//! `0x22003bcc`. The boot relocator at `0x080046e0` mirrors that target from
//! osos `0x08003bcc`, whose 28-byte body prepares RTXC service `0x1b`.

use crate::heap::rom_task_start::gateway_dispatch;

/// Four-word request received by RTXC `KS_defpriority` (service `0x1b`).
///
/// The ARM save area is six words wide. Its dispatch prefix overwrites saved
/// `r0..r3` with `{ selector, priority, task, priority }`; saved `r4` and
/// `lr` remain outside this request and are restored by the epilogue.
pub type TaskPriorityRequest = [u32; 4];

/// RTXC selector for `KS_defpriority(TASK task, PRIORITY priority)`.
pub const TASK_PRIORITY_SERVICE: u32 = 0x1b;

/// task_priority_set — original: `thunk_EXT_FUN_22003bcc` @ `0x08037ed0`
/// (8-byte veneer), targeting the 28-byte IRAM mirror body @ `0x08003bcc`.
///
/// Raw ARM builds `{ 0x1b, priority, task, priority }`, dispatches it through
/// `FUN_08003660`, and restores the incoming `r0` as its return word. The RTXC
/// catalogue identifies selector `0x1b` as `KS_defpriority`; callers use
/// `(0, 2)` to set the current task's priority and later restore a saved
/// priority. Decoding every ARM B/BL word in osos.dec finds eight direct
/// callers: seven plain `bl` (0x08067fa8, 0x0806802c, 0x08104fec,
/// 0x0810500c, 0x081e1d1c, 0x082e85c8, 0x08393f04) and one caller-gated
/// `blne` (0x081e1d5c). The veneer has no guard and no data-word reference.
///
/// Deliberate deviation: the literal tail branch and its foreign dispatcher
/// are represented by the existing volatile gateway seam. Rust cannot expose
/// the original's incidental restoration of caller-saved `r2`/`r3`; neither is
/// a C ABI result, and both are absent from the dispatched record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_priority_set(task: u32, priority: u32) -> u32 {
    let mut request: TaskPriorityRequest = [TASK_PRIORITY_SERVICE, priority, task, priority];
    gateway_dispatch()(request.as_mut_ptr());
    task
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

    unsafe extern "C" fn record_and_clobber(request: *mut u32) {
        let call = addr_of!(CALLS).read();
        let words = core::slice::from_raw_parts_mut(request, 4);
        match call {
            0 => assert_eq!(words, &[0x1b, 2, 0, 2]),
            1 => assert_eq!(words, &[0x1b, u32::MAX, u32::MAX, u32::MAX]),
            _ => panic!("unexpected gateway dispatch"),
        }
        words.copy_from_slice(&[0xa5a5_a5a5; 4]);
        addr_of_mut!(CALLS).write(call + 1);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
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
    fn forwards_priority_record_and_preserves_task_return_word() {
        let guard = install_recorder();
        unsafe {
            assert_eq!(task_priority_set(0, 2), 0);
            assert_eq!(task_priority_set(u32::MAX, u32::MAX), u32::MAX);
            assert_eq!(addr_of!(CALLS).read(), 2);
        }
        restore(guard);
    }
}
