//! Construction of the controller carrying two timer objects.

use crate::drivers::timer::timer_schedule_shim;
use crate::heap::veneers::operator_new;

const VTABLE: u32 = 0x0899_3760;
const FIRST_TIMER_OFFSET: usize = 0xb8;
const SECOND_TIMER_OFFSET: usize = 0xc4;
const OPTIONAL_OBJECT_OFFSET: usize = 0xc8;
const TIMER_SIZE: usize = 0x2c;

type ConstructBase = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type Allocate = unsafe extern "C" fn(usize) -> *mut u8;
type ScheduleTimer = unsafe extern "C" fn(u32, *mut u8, u32, usize);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ControllerTimerPairConstructOps {
    pub construct_base: ConstructBase,
    pub allocate: Allocate,
    pub schedule_timer: ScheduleTimer,
}

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS: ControllerTimerPairConstructOps =
    ControllerTimerPairConstructOps {
        construct_base: super::silver_controller::silver_controller_construct,
        allocate: operator_new,
        schedule_timer: timer_schedule_shim,
    };

#[inline(always)]
unsafe fn construct_base(this: *mut u8, name: *const u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { super::silver_controller::silver_controller_construct(this, name) }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS.construct_base)))(this, name)
    }
}

#[inline(always)]
unsafe fn allocate(size: usize) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { operator_new(size) }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS.allocate)))(size)
    }
}

#[inline(always)]
unsafe fn schedule_timer(config_word: u32, timer: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { timer_schedule_shim(config_word, timer, 0, 0) }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS.schedule_timer)))(config_word, timer, 0, 0)
    }
}

/// construct_controller_timer_pair — original: `FUN_082177fc` @ 0x082177fc
/// (140 bytes, exact extent 0x082177fc..0x08217887: 136 bytes of code plus
/// the vtable literal; 0x0821788c begins the next real function).
///
/// Raw A32 decoding verifies five plain `bl` instructions and no predicated
/// `bl`: one base construction, two 44-byte allocations, and two timer
/// schedules (three callee targets). It constructs the Silver base, installs
/// vtable 0x08993760, clears derived fields +0xb0..+0xc8 except for
/// the two timer pointers, allocates each 44-byte timer, schedules both with
/// the controller address as config word, and returns the base result. The
/// host-only seam is deliberate; target builds call the three verified ports
/// directly, with no behavioral deviation.
///
/// # Safety
///
/// `this` and `name` must satisfy the base constructor and its returned object
/// must be writable through +0xc8. Both allocations must be writable timer objects.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn construct_controller_timer_pair(
    this: *mut u8,
    name: *const u8,
) -> *mut u8 {
    unsafe {
        let controller = construct_base(this, name);
        core::ptr::write_volatile(controller.cast::<u32>(), VTABLE);
        core::ptr::write_volatile(controller.add(0xb0).cast::<u32>(), 0);
        core::ptr::write_volatile(controller.add(0xb4), 0);
        core::ptr::write_volatile(controller.add(FIRST_TIMER_OFFSET).cast::<u32>(), 0);
        core::ptr::write_volatile(controller.add(0xbc), 0);
        core::ptr::write_volatile(controller.add(0xbd), 0);
        core::ptr::write_volatile(controller.add(0xbe), 0);
        core::ptr::write_volatile(controller.add(0xbf), 0);
        core::ptr::write_volatile(controller.add(0xc0), 0);
        core::ptr::write_volatile(controller.add(0xc1), 0);
        core::ptr::write_volatile(controller.add(SECOND_TIMER_OFFSET).cast::<u32>(), 0);
        core::ptr::write_volatile(controller.add(OPTIONAL_OBJECT_OFFSET).cast::<u32>(), 0);

        let first_timer = allocate(TIMER_SIZE);
        core::ptr::write_volatile(controller.add(FIRST_TIMER_OFFSET).cast::<u32>(), first_timer as usize as u32);
        schedule_timer(controller as usize as u32, first_timer);

        let second_timer = allocate(TIMER_SIZE);
        core::ptr::write_volatile(controller.add(SECOND_TIMER_OFFSET).cast::<u32>(), second_timer as usize as u32);
        schedule_timer(controller as usize as u32, second_timer);
        controller
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x400;
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTROLLER_TIMER_PAIR_CONSTRUCT, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut ALLOCATION_COUNT: usize = 0;
    static mut SCHEDULED: [(u32, usize, u32, usize); 2] = [(0, 0, 0, 0); 2];
    static mut SCHEDULE_COUNT: usize = 0;

    unsafe extern "C" fn construct(this: *mut u8, _name: *const u8) -> *mut u8 { this }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, TIMER_SIZE);
        let base = (*SLAB).unwrap();
        let index = ALLOCATION_COUNT;
        ALLOCATION_COUNT += 1;
        (base + 0x200 + index * TIMER_SIZE) as *mut u8
    }
    unsafe extern "C" fn schedule(config: u32, timer: *mut u8, init: u32, callback: usize) {
        SCHEDULED[SCHEDULE_COUNT] = (config, timer as usize, init, callback);
        SCHEDULE_COUNT += 1;
    }

    #[test]
    fn constructs_two_timers_and_clears_only_derived_fields() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/controller_timer_pair_construct"));
            return;
        };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS)) };
        unsafe {
            CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS = ControllerTimerPairConstructOps { construct_base: construct, allocate, schedule_timer: schedule };
            ALLOCATION_COUNT = 0;
            SCHEDULE_COUNT = 0;
            core::ptr::write_bytes(base as *mut u8, 0xa5, SLAB_LEN);
            let controller = base as *mut u8;
            let name = b"TimerPair\0";
            let result = construct_controller_timer_pair(controller, name.as_ptr());
            CONTROLLER_TIMER_PAIR_CONSTRUCT_OPS = previous;
            assert_eq!(result, controller);
            assert_eq!(controller.cast::<u32>().read(), VTABLE);
            assert_eq!(controller.add(0xb0).cast::<u32>().read(), 0);
            assert_eq!(controller.add(0xb4).read(), 0);
            assert_eq!(controller.add(0xb8).cast::<u32>().read(), (base + 0x200) as u32);
            assert_eq!(controller.add(0xbc).read(), 0);
            assert_eq!(controller.add(0xc1).read(), 0);
            assert_eq!(controller.add(0xc4).cast::<u32>().read(), (base + 0x200 + TIMER_SIZE) as u32);
            assert_eq!(controller.add(0xc8).cast::<u32>().read(), 0);
            assert_eq!(controller.add(0xb5).read(), 0xa5);
            assert_eq!(ALLOCATION_COUNT, 2);
            assert_eq!(SCHEDULE_COUNT, 2);
            assert_eq!(SCHEDULED, [(base as u32, base + 0x200, 0, 0), (base as u32, base + 0x200 + TIMER_SIZE, 0, 0)]);
        }
    }
}
