//! `seek_down_with_timer` — FUN_0811ab94 @ 0x0811ab94, 92 bytes.
//! Raw extent [0x0811ab94, 0x0811abf0), ending in pop {r4,pc}; the next
//! function starts with push {r2,r3,r4,lr}. Six plain and two EQ-predicated
//! outbound BLs; inbound calls are one BLNE and one BLEQ, zero plain BLs.
//! The SeekDownWithTimer event initializes the retail subsystem when the
//! pending-direction byte is zero, stops the tuning timer, resets frequency
//! change timing, displays the tuning region, clears a nonzero class flag,
//! dispatches the class target's virtual slot +0x50, then starts frequency
//! change timing with direction 2. Always returns handled (1).
//! Deviations: none in the algorithm. Unported subsystem initialization keeps
//! its exact retail-address seam; direction timing calls the Rust port and
//! the class clear seam is reused. Target-width pointer fields stay u32 on hosts.

use super::tuning_timer::stop_frequency_change_and_start_tuning_timer;
use super::tuning_status::show_tuning_region;
use super::object_dispatch_entry::{object_dispatch_entry_dispatch_vtable_slot_50, ObjectDispatchSource};
use crate::drivers::timer::timer_stop;
use crate::ui::flag_2c::flag_2c_is_clear;
use super::frequency_change_direction::start_frequency_change_direction;

#[cfg(target_os = "none")]
unsafe fn initialize_seek_subsystem() {
    // Identity beyond its use by both seek handlers remains unresolved.
    let call: unsafe extern "C" fn() = core::mem::transmute(0x0803_c264usize);
    call();
}
#[cfg(not(target_os = "none"))]
unsafe fn initialize_seek_subsystem() { panic!("retail seek subsystem unavailable on host"); }


#[inline(always)]
unsafe fn pointer_at(controller: *const u8, offset: usize) -> *mut u8 {
    controller.add(offset).cast::<u32>().read() as usize as *mut u8
}

#[inline(always)]
unsafe fn seek_with_timer(
    controller: *mut u8,
    direction: u8,
    mut initialize: impl FnMut(),
    mut stop: impl FnMut(*mut u8),
    mut prepare: impl FnMut(*mut u8),
    mut display: impl FnMut(*mut u8),
    mut clear: impl FnMut(*mut u8),
    mut dispatch: impl FnMut(*mut u8),
    mut start: impl FnMut(*mut u8, u8),
) -> u32 {
    if controller.add(0xb4).read() == 0 { initialize(); }
    stop(pointer_at(controller, 0xb0));
    prepare(controller);
    display(controller);
    if flag_2c_is_clear(pointer_at(controller, 0xbc)) == 0 {
        clear(pointer_at(controller, 0xbc));
    }
    dispatch(pointer_at(controller, 0xbc));
    start(controller, direction);
    1
}

/// # Safety
/// Controller must contain aligned, live target pointers at +0xb0, +0xb8,
/// and +0xbc, and satisfy each timer, display, and class operation's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn seek_down_with_timer(controller: *mut u8) -> u32 {
    seek_with_timer(controller, 2,
        || initialize_seek_subsystem(),
        |timer| timer_stop(timer),
        |owner| stop_frequency_change_and_start_tuning_timer(owner),
        |owner| show_tuning_region(owner),
        |class| {
            let clear = core::ptr::read_volatile(core::ptr::addr_of!(
                super::class_6280_flag_dispatch::CLASS_6280_FLAG_DISPATCH_OPS.clear));
            clear(class);
        },
        |class| object_dispatch_entry_dispatch_vtable_slot_50(class.cast::<ObjectDispatchSource>()),
        |owner, direction| start_frequency_change_direction(owner, direction))
}

/// `seek_up_with_timer` — FUN_0811a96c @ 0x0811a96c, 92 bytes.
/// Raw extent [0x0811a96c, 0x0811a9c8): six plain and two EQ-predicated
/// outbound BLs; inbound calls are one BLNE and one plain BL. The next
/// function begins with push {r4,lr}. Initialize the seek subsystem only
/// when +0xb4 is zero, stop the +0xb0 timer, reset frequency-change timing,
/// show the region, clear a nonzero class flag, dispatch virtual slot +0x4c,
/// then start frequency-change timing with direction 1. Return handled (1).
/// Deviations: no algorithm changes. Reuse the exact-address seam for
/// unported initialization and the class-clear seam; direction timing calls
/// the Rust port. Target pointer fields remain four-byte words on hosts.
///
/// # Safety
/// Same controller/timer/display contracts as `seek_down_with_timer`;
/// the class must also satisfy `object_dispatch_entry_dispatch`'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn seek_up_with_timer(controller: *mut u8) -> u32 {
    seek_with_timer(controller, 1,
        || initialize_seek_subsystem(),
        |timer| timer_stop(timer),
        |owner| stop_frequency_change_and_start_tuning_timer(owner),
        |owner| show_tuning_region(owner),
        |class| {
            let clear = core::ptr::read_volatile(core::ptr::addr_of!(
                super::class_6280_flag_dispatch::CLASS_6280_FLAG_DISPATCH_OPS.clear));
            clear(class);
        },
        |class| {
            super::object_dispatch_entry::object_dispatch_entry_dispatch(class.cast::<ObjectDispatchSource>());
        },
        |owner, direction| start_frequency_change_direction(owner, direction))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn direction_and_class_flag_boundaries_preserve_order_and_reload_class() {
        let Some(base) = try_map_u32_slab(hints::SEEK_DOWN_WITH_TIMER, 0x1000) else {
            assert!(note_missing_u32_fixture("app/seek_down_with_timer"));
            return;
        };
        unsafe {
            let owner = base;
            let class = base.add(0x200);
            let replacement = base.add(0x300);
            for pending in [0u8, 1, 2, 255] {
              for direction in [1u8, 2] {
                for flag in 0u8..=255 {
                    core::ptr::write_bytes(base, 0, 0x1000);
                    owner.add(0xb0).cast::<u32>().write(base.add(0x400) as usize as u32);
                    owner.add(0xbc).cast::<u32>().write(class as usize as u32);
                    owner.add(0xb4).write(pending);
                    class.add(0x2c).write(flag);
                    let stage = Cell::new(0);
                    let initialized = Cell::new(false);
                    let cleared = Cell::new(false);
                    let result = seek_with_timer(owner, direction,
                        || {
                            assert_eq!(stage.get(), 0);
                            initialized.set(true);
                            // Initialization can replace the tuning timer: reload after it.
                            owner.add(0xb0).cast::<u32>().write(base.add(0x500) as usize as u32);
                        },
                        |timer| {
                            assert_eq!(stage.replace(1), 0);
                            assert_eq!(timer, base.add(if pending == 0 { 0x500 } else { 0x400 }));
                            timer.cast::<u32>().write(0);
                        },
                        |p| {
                            assert_eq!(stage.replace(2), 1);
                            p.add(0xb4).write(0);
                        },
                        |_| {
                            assert_eq!(stage.replace(3), 2);
                        },
                        |p| {
                            assert_eq!(stage.get(), 3);
                            assert_eq!(p, class);
                            p.add(0x2c).write(0);
                            cleared.set(true);
                            // The following dispatch must reload +0xbc after this callback.
                            owner.add(0xbc).cast::<u32>().write(replacement as usize as u32);
                        },
                        |p| {
                            assert_eq!(stage.replace(4), 3);
                            assert_eq!(p, if flag == 0 { class } else { replacement });
                            p.add(0x30).cast::<u32>().write(0x50);
                        },
                        |p, direction| {
                            assert_eq!(stage.replace(5), 4);
                            p.add(0xb4).write(direction);
                        });
                    assert_eq!(result, 1);
                    assert_eq!(initialized.get(), pending == 0);
                    assert_eq!(cleared.get(), flag != 0);
                    assert_eq!(class.add(0x2c).read(), 0);
                    assert_eq!(owner.add(0xb4).read(), direction);
                    assert_eq!(stage.get(), 5);
                    let selected = if flag == 0 { class } else { replacement };
                    assert_eq!(selected.add(0x30).cast::<u32>().read(), 0x50);
                }
              }
            }
        }
    }
}
