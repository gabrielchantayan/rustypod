//! Startup status-wait wrapper @ 0x080004ec.
//!
//! The stock wrapper delegates to the unported status wait routine at
//! 0x080003b8 with a fixed 100,000-tick timeout, discards that routine's
//! status result, and returns zero. The status word and its bit meanings are
//! not established yet, so the direct ROM callee remains behind a replaceable
//! dispatch slot. On target the default reaches the original routine; host
//! tests install a recorder.

/// Load address of the unported status-wait callee.
const ROM_WAIT_FOR_STATUS_CLEAR: usize = 0x0800_03b8;

/// The fixed timeout literal loaded by the original wrapper.
pub const STARTUP_STATUS_WAIT_TICKS: u32 = 100_000;

/// The unported wait routine's direct-call ABI.
pub type StatusWaitFn = unsafe extern "C" fn(timeout_ticks: u32) -> u32;

/// Runtime integration seam for the original call at 0x080003b8.
#[derive(Clone, Copy)]
pub struct StartupWaitOps {
    pub wait_for_status_clear: StatusWaitFn,
}

unsafe extern "C" fn rom_wait_for_status_clear(timeout_ticks: u32) -> u32 {
    let callee: StatusWaitFn = core::mem::transmute(ROM_WAIT_FOR_STATUS_CLEAR);
    callee(timeout_ticks)
}

/// Direct-ROM default used on device; host tests replace this slot before use.
pub static mut STARTUP_WAIT_OPS: StartupWaitOps = StartupWaitOps {
    wait_for_status_clear: rom_wait_for_status_clear,
};

#[inline(always)]
unsafe fn startup_wait_ops() -> StartupWaitOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STARTUP_WAIT_OPS))
}

/// startup_wait_for_status_clear — original: `FUN_080004ec` @ 0x080004ec
/// (20 bytes). Reference: `decomp/c/000/080004ec_FUN_080004ec.c`.
///
/// Calls the status-clear wait at 0x080003b8 with 100,000 ticks, discards its
/// return value, then returns zero. The callee's status-word contract is not
/// ported; its exact device behavior is retained through [`STARTUP_WAIT_OPS`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn startup_wait_for_status_clear() -> i32 {
    (startup_wait_ops().wait_for_status_clear)(STARTUP_STATUS_WAIT_TICKS);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;
    static mut LAST_TIMEOUT: u32 = 0;

    unsafe extern "C" fn recording_wait(timeout_ticks: u32) -> u32 {
        CALLS += 1;
        LAST_TIMEOUT = timeout_ticks;
        0x15
    }

    #[test]
    fn delegates_fixed_timeout_and_discards_callee_status() {
        let _lock = match OPS_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(STARTUP_WAIT_OPS));
            STARTUP_WAIT_OPS = StartupWaitOps {
                wait_for_status_clear: recording_wait,
            };
            CALLS = 0;
            LAST_TIMEOUT = 0;

            let result = startup_wait_for_status_clear();
            let calls = CALLS;
            let timeout = LAST_TIMEOUT;
            STARTUP_WAIT_OPS = saved;

            assert_eq!(calls, 1);
            assert_eq!(timeout, STARTUP_STATUS_WAIT_TICKS);
            assert_eq!(result, 0);
        }
    }
}
