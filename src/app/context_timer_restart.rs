//! Restart the timer embedded in an unidentified context object.
//!
//! `context_restart_timer` — original: `FUN_08116a24` @ 0x08116a24 (12
//! bytes exactly, 0x08116a24..0x08116a30; `ldr r0,[r0,#0x30]` at 0x08116a30
//! starts the next function). A raw A32 branch-word scan finds three incoming
//! unconditional `bl` instructions (0x08202e54, 0x08202ec0, 0x08202fe4) and
//! no predicated `bl` instructions.
//!
//! # Algorithm
//!
//! Adds 0x77c to `context` and tail-branches to `timer_restart` @ 0x0812bf4c.
//! The embedded timer is passed directly; stock has no NULL guard.
//!
//! # Deliberate deviations
//!
//! Rust represents the tail branch as a normal call. LLVM expands the existing
//! `timer_restart` body into this wrapper, so match.py reports that body after
//! the context+0x77c address calculation; the stock tail-call return value is
//! unobservable because the retail signature is `void`.

use crate::drivers::timer::timer_restart;

/// Target-width layout of the sole field this wrapper addresses.
#[repr(C)]
struct ContextTimerField {
    _before_timer: [u8; 0x77c],
    timer: [u8; 0x2c],
}

/// context_restart_timer — original: `FUN_08116a24` @ 0x08116a24 (12 bytes;
/// 3 unconditional incoming `bl`, 0 predicated incoming `bl`).
///
/// Restarts the timer embedded at `context + 0x77c`.
///
/// # Safety
///
/// `context` must point to an object containing a valid timer through
/// `context + 0x7a7`; stock dereferences that object without a NULL check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_restart_timer(context: *mut u8) {
    unsafe { timer_restart(core::ptr::addr_of_mut!((*context.cast::<ContextTimerField>()).timer).cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr::addr_of_mut;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTEXT_TIMER_RESTART, SLAB_LEN).map(|pointer| pointer as usize)
    });


    struct OpsRestore(TimerOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    unsafe extern "C" fn trace_assert(_timer: *mut u8) {}
    unsafe extern "C" fn arm_timer(_timer: *mut u8) {}

    unsafe fn install_ops() -> OpsRestore {
        let saved = unsafe { core::ptr::addr_of!(TIMER_OPS).read_volatile() };
        let mut ops = saved;
        ops.trace_assert = trace_assert;
        ops.arm_timer = arm_timer;
        unsafe { core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(ops) };
        OpsRestore(saved)
    }

    #[test]
    fn restarts_embedded_timer() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(base) = *SLAB else {
            note_missing_u32_fixture("context_restart_timer");
            return;
        };
        let context = base as *mut ContextTimerField;
        let _restore = unsafe { install_ops() };
        unsafe {
            addr_of_mut!((*context).timer)
                .cast::<u32>()
                .add(8)
                .write(crate::drivers::timer::TIMER_STATE_STOPPED)
        };

        unsafe { context_restart_timer(context.cast()) };

        assert_eq!(
            unsafe { addr_of_mut!((*context).timer).cast::<u32>().add(8).read() },
            TIMER_STATE_RUNNING
        );
    }
}
