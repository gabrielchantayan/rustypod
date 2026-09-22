//! Controller timer-pair destructor.
//!
//! `destruct_controller_timer_pair` — original: `FUN_082178a4` @
//! 0x082178a4 (**80 bytes**, 0x082178a4..0x082178f4: 76 bytes of code plus
//! its vtable literal; the next function begins at 0x082178f4). Raw ARM has
//! **4 plain `bl` instructions and 1 predicated `blxne`**: the plain calls
//! stop and trace each of the timers at +0xb8 and +0xc4; the predicated
//! dispatch invokes slot +4 of the optional object at +0xc8. It then tail
//! branches to the verified base destructor at 0x08134e98.
//!
//! The destructor installs vtable 0x08993760, tears down both timers, invokes
//! the optional owned object's second virtual slot, and hands the object to
//! the base destructor. The base destructor's identity is not yet known;
//! target builds call its verified address, while host tests use the explicit
//! seam below. The tail branch is deliberately an ordinary Rust call.

use crate::drivers::timer::{timer_stop, timer_stop_then_trace};

const VTABLE: u32 = 0x0899_3760;
const FIRST_TIMER_OFFSET: usize = 0xb8;
const SECOND_TIMER_OFFSET: usize = 0xc4;
const OPTIONAL_OBJECT_OFFSET: usize = 0xc8;
const BASE_DESTRUCTOR_ADDRESS: usize = 0x0813_4e98;

type DestructorFn = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ControllerTimerPairDestructorOps {
    pub optional_object_destruct: DestructorFn,
    pub base_destruct: DestructorFn,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_destructor(_object: *mut u8) {}

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS: ControllerTimerPairDestructorOps =
    ControllerTimerPairDestructorOps {
        optional_object_destruct: no_op_destructor,
        base_destruct: no_op_destructor,
    };

#[inline(always)]
unsafe fn pointer_at(object: *const u8, offset: usize) -> *mut u8 {
    unsafe { object.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

#[cfg(target_os = "none")]
unsafe fn destruct_optional_object(object: *mut u8) {
    let optional = unsafe { pointer_at(object, OPTIONAL_OBJECT_OFFSET) };
    if !optional.is_null() {
        let vtable = unsafe { pointer_at(optional, 0) };
        let destruct: DestructorFn = unsafe { core::mem::transmute(pointer_at(vtable, 4)) };
        unsafe { destruct(optional) };
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn destruct_optional_object(object: *mut u8) {
    if !unsafe { pointer_at(object, OPTIONAL_OBJECT_OFFSET) }.is_null() {
        unsafe { (CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS.optional_object_destruct)(object) };
    }
}

#[cfg(target_os = "none")]
unsafe fn destruct_base(object: *mut u8) {
    let destruct: DestructorFn = unsafe { core::mem::transmute(BASE_DESTRUCTOR_ADDRESS) };
    unsafe { destruct(object) };
}

#[cfg(not(target_os = "none"))]
unsafe fn destruct_base(object: *mut u8) {
    unsafe { (CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS.base_destruct)(object) };
}

/// destruct_controller_timer_pair — original: `FUN_082178a4` @ 0x082178a4
/// (80 bytes; four plain `bl` and one predicated `blxne` in its body).
///
/// Installs the derived vtable; stops then traces the timer words at +0xb8 and
/// +0xc4; destroys the optional +0xc8 object when non-NULL; then destructs the
/// shared base. Pointer fields remain 32-bit words, matching retailOS on both
/// the ARM target and u32-addressable host fixtures.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destruct_controller_timer_pair(controller: *mut u8) {
    unsafe {
        controller.cast::<u32>().write(VTABLE);
        timer_stop(pointer_at(controller, FIRST_TIMER_OFFSET));
        timer_stop_then_trace(pointer_at(controller, FIRST_TIMER_OFFSET));
        timer_stop(pointer_at(controller, SECOND_TIMER_OFFSET));
        timer_stop_then_trace(pointer_at(controller, SECOND_TIMER_OFFSET));
        destruct_optional_object(controller);
        destruct_base(controller);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, CONTROLLER_TIMER_PAIR_DESTRUCTOR_TEST_LOCK, TIMER_OPS_TEST_LOCK};
    use core::ptr;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const FIRST_TIMER_IN_SLAB: usize = 0x400;
    const SECOND_TIMER_IN_SLAB: usize = 0x500;
    const OPTIONAL_OBJECT_IN_SLAB: usize = 0x600;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTROLLER_TIMER_PAIR_DESTRUCTOR, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut TRACE_ORDER: [u8; 6] = [0; 6];
    static mut TRACE_COUNT: usize = 0;
    static mut OPTIONAL_CALLED: bool = false;
    static mut BASE_CALLED: bool = false;

    unsafe extern "C" fn record_trace(timer: *mut u8) {
        unsafe {
            TRACE_ORDER[TRACE_COUNT] = if timer == FIRST_TIMER { 1 } else { 2 };
            TRACE_COUNT += 1;
        }
    }
    static mut FIRST_TIMER: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn no_op_cancel(_handle: usize, _callback: usize, _timer: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn no_op_timer(_timer: *mut u8) {}
    unsafe extern "C" fn no_op_notify(_cell: *const u32) {}
    unsafe extern "C" fn no_op_construct(_timer: *mut u8, _arg: u32, _config: u32, _handle: usize) {}
    unsafe extern "C" fn zero_tick() -> u32 { 0 }
    unsafe extern "C" fn no_deadline_order(_a: *const u32, _b: *const u32) -> u32 { 0 }
    unsafe extern "C" fn optional_destruct(_object: *mut u8) { unsafe { OPTIONAL_CALLED = true } }
    unsafe extern "C" fn base_destruct(_object: *mut u8) { unsafe { BASE_CALLED = true } }

    const RECORDING_TIMER_OPS: TimerOps = TimerOps {
        trace_assert: record_trace, cancel_callback: no_op_cancel, arm_timer: no_op_timer,
        construct_timer: no_op_construct, trace_validate: no_op_timer, tick: zero_tick,
        compare_deadlines: no_deadline_order, notify_pending: no_op_notify,
    };
    const RECORDING_DESTRUCTOR_OPS: ControllerTimerPairDestructorOps = ControllerTimerPairDestructorOps {
        optional_object_destruct: optional_destruct, base_destruct,
    };

    #[test]
    fn stops_and_traces_each_timer_before_optional_and_base_destruction() {
        let _destructor_guard = CONTROLLER_TIMER_PAIR_DESTRUCTOR_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _timer_guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/controller_timer_pair_destruct"));
            return;
        };
        unsafe {
            let controller = base as *mut u8;
            let first_timer = controller.add(FIRST_TIMER_IN_SLAB);
            let second_timer = controller.add(SECOND_TIMER_IN_SLAB);
            ptr::write_bytes(controller, 0, SLAB_LEN);
            controller.add(FIRST_TIMER_OFFSET).cast::<u32>().write(first_timer as usize as u32);
            controller.add(SECOND_TIMER_OFFSET).cast::<u32>().write(second_timer as usize as u32);
            controller.add(OPTIONAL_OBJECT_OFFSET).cast::<u32>().write(controller.add(OPTIONAL_OBJECT_IN_SLAB) as usize as u32);
            FIRST_TIMER = first_timer;
            TRACE_ORDER = [0; 6]; TRACE_COUNT = 0; OPTIONAL_CALLED = false; BASE_CALLED = false;
            let saved_timer_ops = ptr::addr_of!(TIMER_OPS).read_volatile();
            let saved_destructor_ops = ptr::addr_of!(CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS).read_volatile();
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(RECORDING_TIMER_OPS);
            ptr::addr_of_mut!(CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS).write_volatile(RECORDING_DESTRUCTOR_OPS);
            destruct_controller_timer_pair(controller);
            ptr::addr_of_mut!(CONTROLLER_TIMER_PAIR_DESTRUCTOR_OPS).write_volatile(saved_destructor_ops);
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(saved_timer_ops);
            assert_eq!(controller.cast::<u32>().read(), VTABLE);
            assert_eq!(TRACE_ORDER, [1, 1, 1, 2, 2, 2]);
            assert!(OPTIONAL_CALLED);
            assert!(BASE_CALLED);
        }
    }
}
