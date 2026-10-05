//! Remote volume-down press handling.
//!
//! Original: `FUN_081d04b8` @ 0x081d04b8, exactly 48 bytes
//! (0x081d04b8..0x081d04e8; next function starts with push {r4,lr}).
//! Raw ARM branch scan: two incoming BL sites, one plain at 0x081d021c
//! and one BLNE at 0x081ce238. Body: three BL calls and one tail B.
//! Stops both controller timers, applies the volume decrement using +0xb8,
//! then reloads +0xb4 to program delay 500 and reloads it again to restart.
//! No NULL guards. Deliberate deviation: final tail B is a Rust call.
//! The decrement uses the ported remote_position_decrement; its singleton
//! constructor remains a hook-readiness prerequisite. Ghidra's body
//! incorrectly includes timer implementation code beyond the true boundary.

use super::controller_timer_pair::stop_controller_timer_pair;
use crate::drivers::timer::{timer_start_after, timer_restart};

use super::remote_position_decrement::remote_position_decrement;

/// Handles a remote volume-down press and arms its repeat timer.
///
/// # Safety
/// Controller must contain aligned target-width timer pointers at +0xb0
/// and +0xb4 and a readable step word at +0xb8. Timers and controller must
/// satisfy the timer and retail decrement helper contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remote_volume_down(controller: *mut u8) {
    stop_controller_timer_pair(controller);
    remote_position_decrement(controller, controller.add(0xb8).cast::<u32>().read());
    timer_start_after(controller.add(0xb4).cast::<u32>().read() as usize as *mut u8, 500);
    timer_restart(controller.add(0xb4).cast::<u32>().read() as usize as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::timer::{TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, TIMER_OPS_TEST_LOCK};
    use core::ptr;
    use super::super::remote_position_decrement::{REMOTE_POSITION_GETTER, TEST_LOCK};
    use super::super::volume_controller_adjust_position::{PositionInterface, PositionVtable};
    static mut CONTROLLER: *mut u8 = core::ptr::null_mut();
    static mut INTERFACE: *mut PositionInterface = core::ptr::null_mut();
    unsafe extern "C" fn get_interface() -> *mut PositionInterface { INTERFACE }

    unsafe extern "C" fn trace(_timer: *mut u8) {}
    unsafe extern "C" fn arm(_timer: *mut u8) {}
    unsafe extern "C" fn query(_interface: *mut PositionInterface) -> u32 {
        let base = CONTROLLER;
        assert_eq!(base.add(0x220).cast::<u32>().read(), TIMER_STATE_STOPPED);
        assert_eq!(base.add(0x320).cast::<u32>().read(), TIMER_STATE_STOPPED);
        base.add(0xb4).cast::<u32>().write(base.add(0x400) as usize as u32);
        u32::MAX
    }
    unsafe extern "C" fn set(_interface: *mut PositionInterface, position: u32, flag: u32) -> u32 {
        assert_eq!(position, 1);
        assert_eq!(flag, 1);
        0
    }
    unsafe extern "C" fn replace_during_delay_stop(timer: *mut u8) {
        if timer.add(4).cast::<u32>().read() == 23 {
            let base = timer.sub(0x400);
            base.add(0xb4).cast::<u32>().write(base.add(0x500) as usize as u32);
        }
    }

    #[test]
    fn stops_both_timers_and_reloads_replacements_between_operations() {
        let _guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _position_guard = TEST_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::REMOTE_VOLUME_DOWN, 0x1000) else {
            assert!(note_missing_u32_fixture("app/remote_volume_down"));
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, 0x1000);
            base.add(0xb0).cast::<u32>().write(base.add(0x200) as usize as u32);
            base.add(0xb4).cast::<u32>().write(base.add(0x300) as usize as u32);
            base.add(0xb8).cast::<u32>().write(u32::MAX);
            // Stopped state with stale periods must not accidentally re-arm.
            for offset in [0x200, 0x300, 0x400, 0x500] {
                base.add(offset + 0x20).cast::<u32>().write(TIMER_STATE_STOPPED);
                base.add(offset + 4).cast::<u32>().write(17);
            }
            base.add(0x404).cast::<u32>().write(23);
            let saved_ops = ptr::addr_of!(TIMER_OPS).read();
            let saved_getter = ptr::addr_of!(REMOTE_POSITION_GETTER).read();
            let vtable = PositionVtable { unresolved_00_50: [0; 21], set_position: set,
                unresolved_58: 0, query_position: query, unresolved_60: 0, query_limit: query };
            let mut interface = PositionInterface { vtable: &vtable };
            CONTROLLER = base; INTERFACE = &mut interface;
            let mut ops = saved_ops;
            ops.trace_assert = trace;
            ops.arm_timer = arm;
            ptr::addr_of_mut!(TIMER_OPS).write(ops);
            ptr::addr_of_mut!(REMOTE_POSITION_GETTER).write(get_interface);
            // Delay programming stops the loaded timer; that stop replaces
            // +0xb4. Restart must reload rather than reusing that timer.
            ops.trace_assert = replace_during_delay_stop;
            ptr::addr_of_mut!(TIMER_OPS).write(ops);
            remote_volume_down(base);
            ptr::addr_of_mut!(TIMER_OPS).write(saved_ops);
            ptr::addr_of_mut!(REMOTE_POSITION_GETTER).write(saved_getter);
            assert_eq!(base.add(0x404).cast::<u32>().read(), 500);
            assert_eq!(base.add(0x420).cast::<u32>().read(), TIMER_STATE_STOPPED);
            assert_eq!(base.add(0x520).cast::<u32>().read(), TIMER_STATE_RUNNING);
            assert_eq!(base.add(0x504).cast::<u32>().read(), 17);
            assert_eq!(base.add(0xb8).cast::<u32>().read(), u32::MAX);
        }
    }
}
