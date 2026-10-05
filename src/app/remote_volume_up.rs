//! Remote volume-up press handling.
//!
//! Original: `FUN_081d0054` @ 0x081d0054, exactly 48 bytes
//! (0x081d0054..0x081d0084; next function starts with push {r4,r5,r6,lr}).
//! Raw ARM scan: two inbound calls, plain BL at 0x081cfd5c and BLNE at
//! 0x081ce110. Body: three BL calls and one tail B. Stops both controller
//! timers, applies the increment with the step word at +0xb8, then reloads
//! +0xb0 to program delay 500 and reloads it again to restart. No NULL guards.
//! Deliberate deviations: final tail B is a Rust call; unported increment
//! helper @ 0x081cf9fc is a fixed-address seam on device and an explicitly
//! installed operation on host. Its raw code doubles the step, clamps against
//! the volume object's maximum, and invokes its setter. Ghidra incorrectly
//! absorbs timer implementation code beyond this function's true boundary.

use super::controller_timer_pair::stop_controller_timer_pair;
use crate::drivers::timer::{timer_start_after, timer_restart};

type IncrementVolume = unsafe extern "C" fn(*mut u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_increment(_controller: *mut u8, _step: u32) {
    panic!("install remote volume increment operation before host use")
}

#[cfg(not(target_os = "none"))]
pub static mut REMOTE_VOLUME_INCREMENT: IncrementVolume = missing_increment;

/// Handles a remote volume-up press and arms its repeat timer.
///
/// # Safety
/// Controller must contain aligned target-width timer pointers at +0xb0
/// and +0xb4 and a readable step word at +0xb8. Timers and controller must
/// satisfy the timer and retail increment helper contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remote_volume_up(controller: *mut u8) {
    stop_controller_timer_pair(controller);
    #[cfg(target_os = "none")]
    let increment: IncrementVolume = core::mem::transmute(0x081c_f9fcusize);
    #[cfg(not(target_os = "none"))]
    let increment = core::ptr::addr_of!(REMOTE_VOLUME_INCREMENT).read_volatile();
    increment(controller, controller.add(0xb8).cast::<u32>().read());
    timer_start_after(controller.add(0xb0).cast::<u32>().read() as usize as *mut u8, 500);
    timer_restart(controller.add(0xb0).cast::<u32>().read() as usize as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::timer::{TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, TIMER_OPS_TEST_LOCK};
    use core::ptr;

    unsafe extern "C" fn arm(_timer: *mut u8) {}
    unsafe extern "C" fn increment(controller: *mut u8, step: u32) {
        assert_eq!(controller.add(0x220).cast::<u32>().read(), TIMER_STATE_STOPPED);
        assert_eq!(controller.add(0x320).cast::<u32>().read(), TIMER_STATE_STOPPED);
        assert_eq!(step, controller.add(0xbc).cast::<u32>().read());
        controller.add(0xb0).cast::<u32>().write(controller.add(0x400) as usize as u32);
    }
    unsafe extern "C" fn replace_during_delay_stop(timer: *mut u8) {
        if timer.add(4).cast::<u32>().read() == 23 {
            let base = timer.sub(0x400);
            base.add(0xb0).cast::<u32>().write(base.add(0x500) as usize as u32);
        }
    }

    #[test]
    fn stops_both_timers_and_reloads_replacements_for_zero_and_max_step() {
        let _guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = try_map_u32_slab(hints::REMOTE_VOLUME_UP, 0x1000) else {
            assert!(note_missing_u32_fixture("app/remote_volume_up"));
            return;
        };
        unsafe {
            let saved_ops = ptr::addr_of!(TIMER_OPS).read();
            let saved_increment = ptr::addr_of!(REMOTE_VOLUME_INCREMENT).read();
            let mut ops = saved_ops;
            ops.trace_assert = replace_during_delay_stop;
            ops.arm_timer = arm;
            ptr::addr_of_mut!(TIMER_OPS).write(ops);
            ptr::addr_of_mut!(REMOTE_VOLUME_INCREMENT).write(increment);
            for step in [0, u32::MAX] {
                ptr::write_bytes(base, 0, 0x1000);
                base.add(0xb0).cast::<u32>().write(base.add(0x200) as usize as u32);
                base.add(0xb4).cast::<u32>().write(base.add(0x300) as usize as u32);
                base.add(0xb8).cast::<u32>().write(step);
                base.add(0xbc).cast::<u32>().write(step);
                for offset in [0x200, 0x300, 0x400, 0x500] {
                    base.add(offset + 0x20).cast::<u32>().write(TIMER_STATE_RUNNING);
                    base.add(offset + 4).cast::<u32>().write(17);
                }
                base.add(0x404).cast::<u32>().write(23);
                remote_volume_up(base);
                assert_eq!(base.add(0x404).cast::<u32>().read(), 500);
                assert_eq!(base.add(0x420).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(base.add(0x520).cast::<u32>().read(), TIMER_STATE_RUNNING);
                assert_eq!(base.add(0x504).cast::<u32>().read(), 17);
                assert_eq!(base.add(0x320).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(base.add(0xb4).cast::<u32>().read(), base.add(0x300) as usize as u32);
                assert_eq!(base.add(0xb8).cast::<u32>().read(), step);
            }
            ptr::addr_of_mut!(TIMER_OPS).write(saved_ops);
            ptr::addr_of_mut!(REMOTE_VOLUME_INCREMENT).write(saved_increment);
        }
    }
}
