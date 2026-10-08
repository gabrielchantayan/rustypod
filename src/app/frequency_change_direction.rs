//! Start frequency-change timing with the requested direction.
//!
//! FUN_0811a938 @ 0x0811a938: true extent [0x0811a938, 0x0811a96c),
//! 52 bytes (48 code + 4-byte 3000-ms literal). Next function starts PUSH.
//! Raw aligned branch-word scan: two plain incoming BLs, zero predicated;
//! body has two plain BLs, zero predicated, and one tail B to timer_restart.
//! Stop the +0xb8 timer, reload it to program 3000 ms, store the direction
//! byte at +0xb4, then reload the timer again and restart it. Seek-up and
//! seek-down callers pass 1 and 2 respectively and discard the return.
//! Deviations: final tail branch is a Rust return-position call; no algorithm
//! changes. Pointer fields remain target-width u32 on hosts; no null guard.

use crate::drivers::timer::{timer_restart, timer_start_after, timer_stop};

#[inline(always)]
unsafe fn timer(controller: *mut u8) -> *mut u8 {
    controller.add(0xb8).cast::<u32>().read_volatile() as usize as *mut u8
}

/// # Safety
/// `controller` must be aligned and writable through +0xbb. Each timer
/// pointer loaded from +0xb8 must satisfy the timer helpers' contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn start_frequency_change_direction(controller: *mut u8, direction: u8) {
    timer_stop(timer(controller));
    timer_start_after(timer(controller), 3000);
    controller.add(0xb4).write(direction);
    timer_restart(timer(controller));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};

    static mut OWNER: *mut u8 = core::ptr::null_mut();
    static mut TRACES: usize = 0;
    static mut DIRECTION: u8 = 0;
    static mut ARMED: bool = false;

    unsafe extern "C" fn trace(timer: *mut u8) {
        TRACES += 1;
        let offset = match TRACES { 1 => 0x200, 2 | 3 => 0x300, 4 => 0x400, _ => panic!("extra trace") };
        assert_eq!(timer, OWNER.add(offset));
        assert_eq!(OWNER.add(0xb4).read(), if TRACES == 4 { DIRECTION } else { 0x55 });
        if TRACES == 1 || TRACES == 3 {
            // Retail callbacks can replace the owner's timer between calls.
            OWNER.add(0xb8).cast::<u32>().write(OWNER.add(offset + 0x100) as usize as u32);
        }
    }

    unsafe extern "C" fn arm(timer: *mut u8) {
        assert_eq!(timer, OWNER.add(0x400));
        assert_eq!(OWNER.add(0xb4).read(), DIRECTION);
        assert_eq!(timer.add(0x20).cast::<u32>().read(), TIMER_STATE_RUNNING);
        ARMED = true;
    }

    struct Restore(TimerOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0); }
        }
    }

    #[test]
    fn direction_boundaries_reload_timers_and_publish_before_restart() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = try_map_u32_slab(hints::FREQUENCY_CHANGE_DIRECTION, 0x1000) else {
            assert!(note_missing_u32_fixture("app/frequency_change_direction"));
            return;
        };
        unsafe {
            let saved = core::ptr::addr_of!(TIMER_OPS).read_volatile();
            let _restore = Restore(saved);
            let mut ops = saved;
            ops.trace_assert = trace;
            ops.arm_timer = arm;
            core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(ops);
            for direction in [0, 1, 2, 0x80, 0xff] {
                base.write_bytes(0, 0x1000);
                OWNER = base;
                TRACES = 0;
                ARMED = false;
                DIRECTION = direction;
                base.add(0xb4).write(0x55);
                base.add(0xb5).write_bytes(0xa5, 3);
                base.add(0xb8).cast::<u32>().write(base.add(0x200) as usize as u32);
                start_frequency_change_direction(base, direction);
                assert_eq!(base.add(0x204).cast::<u32>().read(), 0);
                assert_eq!(base.add(0x304).cast::<u32>().read(), 3000);
                assert_eq!(base.add(0x404).cast::<u32>().read(), 0);
                assert_eq!(base.add(0x220).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(base.add(0x320).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(base.add(0xb4).read(), direction);
                assert_eq!(core::slice::from_raw_parts(base.add(0xb5), 3), &[0xa5; 3]);
                assert!(ARMED);
            }
        }
    }
}
