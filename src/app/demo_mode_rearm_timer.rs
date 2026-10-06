//! Demo-mode timer rearm — FUN_08187d00 @ 0x08187d00.
//! True extent: 32 bytes, [0x08187d00, 0x08187d20); the next function
//! loads +0x28, stores +0x30, and returns. Whole-image raw A32 decoding
//! finds 2 plain incoming BLs (0x08187fd0, 0x08188938), 0 predicated BLs.
//! Body: 1 plain BL to timer_start_after, 0 predicated BLs, 1 tail B to
//! timer_restart. Ghidra incorrectly incorporates the timer callees.
//!
//! Read the delay word at +0x148, stop/reprogram the embedded timer at
//! +0x11c, then restart it. No NULL guard, delay clamping, or armed check
//! is added. Deliberate deviation: the tail branch is a return-position
//! Rust call. LLVM inlines timer_restart: BL timer_stop, store 'run ',
//! then dispatch through the existing TimerOps arm slot. match.py reports
//! 21 Rust instructions versus 8 stock; relocations confirm timer_start_after
//! remains a real BL target and both object offsets are unchanged.

use crate::drivers::timer::{timer_restart, timer_start_after};

/// # Safety
/// `demo` must be aligned and readable/writable through +0x14b, with a
/// valid embedded timer at +0x11c and initialized timer dependencies.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_rearm_timer(demo: *mut u8) {
    let delay = demo.add(0x148).cast::<u32>().read();
    let timer = demo.add(0x11c);
    timer_start_after(timer, delay);
    timer_restart(timer);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::{self, TimerOps, TIMER_OPS, TIMER_PENDING_HEAD,
        TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DEMO_MODE_REARM_TIMER, 0x1000).map(|p| p as usize)
    });

    struct Restore { ops: TimerOps, head: u32 }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(TIMER_OPS).write_volatile(self.ops);
                addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(self.head);
            }
        }
    }
    unsafe extern "C" fn validate(_: *mut u8) {}
    unsafe extern "C" fn notify(_: *const u32) {}
    unsafe extern "C" fn tick() -> u32 { 0xffff_ff00 }

    #[test]
    fn zero_delay_does_not_queue_and_full_width_delay_wraps_deadline() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *SLAB else {
            note_missing_u32_fixture("demo_mode_rearm_timer");
            return;
        };
        unsafe {
            let saved = addr_of!(TIMER_OPS).read_volatile();
            let _restore = Restore { ops: saved, head: addr_of!(TIMER_PENDING_HEAD).read_volatile() };
            let mut ops = saved;
            ops.trace_assert = validate;
            ops.trace_validate = validate;
            ops.notify_pending = notify;
            ops.tick = tick;
            ops.arm_timer = timer::timer_arm;
            ops.compare_deadlines = timer::timer_deadline_is_after;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            let demo = base as *mut u8;
            let timer = demo.add(0x11c).cast::<u32>();
            for delay in [0u32, 1, 0x8000_0000, u32::MAX] {
                core::ptr::write_bytes(demo, 0xa5, 0x14c);
                core::ptr::write_bytes(timer, 0, 11);
                timer.add(1).write(77);
                timer.add(2).write(0x1234_5678);
                timer.add(8).write(TIMER_STATE_STOPPED);
                demo.add(0x148).cast::<u32>().write(delay);
                addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(0);
                demo_mode_rearm_timer(demo);
                assert_eq!(timer.add(1).read(), delay);
                assert_eq!(timer.add(8).read(), TIMER_STATE_RUNNING);
                assert_eq!(timer.add(7).read(), u32::from(delay != 0));
                assert_eq!(addr_of!(TIMER_PENDING_HEAD).read_volatile(),
                    if delay == 0 { 0 } else { timer as usize as u32 });
                assert_eq!(timer.add(2).read(), if delay == 0 { 0x1234_5678 }
                    else { 0xffff_ff00u32.wrapping_add(delay.wrapping_mul(1000)) });
                assert_eq!(demo.add(0x148).cast::<u32>().read(), delay);
                assert!((0..0x11c).all(|i| demo.add(i).read() == 0xa5));
            }
        }
    }
}
