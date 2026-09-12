//! `controller_transition_volume_post` — original: `FUN_081a4044` @
//! **0x081a4044** (160 bytes exactly, 0x081a4044..0x081a40e4).
//!
//! The next sibling starts with `push {r4,lr}` at 0x081a40e4. Decoding every
//! ARM B/BL immediate in `osos.dec` finds eight direct incoming branches: all
//! are unconditional `bl` (0x08126294, 0x081263d0, 0x081264dc, 0x0819b130,
//! 0x0819b1d4, 0x0819b41c, 0x081a2fac, and 0x081a39a0); there are no
//! predicated calls or direct tail branches.
//!
//! ## Algorithm
//!
//! First call the availability virtual at slot +0x38 of the object returned by
//! `lazy_singleton_0xbc`. If it returns zero, skip every controller mutation
//! and timer operation. Otherwise, an unset controller +0x8a starts the first
//! state: set +0x8a, clear +0x8b and +0x8c, obtain one byte from the singleton
//! virtual at +0x40 into +0x76, then call the controller's +0xac virtual on
//! its +0x20 receiver. A set +0x8a instead toggles +0x8c from zero to one (or
//! clears any nonzero value) and calls the +0xb0 virtual on that receiver.
//! The final +0x8c selects `timer_restart` (zero) or `timer_stop` (nonzero)
//! for the embedded timer at +0xa4. Both availability paths then fetch the
//! volume controller and tail into 0x081f9354, whose verified body invokes
//! its +0x58 virtual three times with the stock command words.
//!
//! ## Deliberate deviation
//!
//! The stock virtual calls and the unported 0x081f9354 continuation are
//! represented by a volatile, swappable ops table. ARM defaults perform the
//! verified vtable calls and fixed-address tail continuation; host defaults
//! panic until tests install recorders, including a host-only substitute for
//! the already-ported volume getter so tests do not mutate its shared cache.
//! Rust spells the final tail branch as a normal call. Names describe observed
//! state transitions and dispatch slots, not unrecovered controller or command
//! identities.

use core::ptr::{addr_of, addr_of_mut};

#[cfg(target_os = "none")]
use crate::app::singletons::{lazy_singleton_0xbc, volume_controller_get};
use crate::drivers::timer::{timer_restart, timer_stop};

const CONTROLLER_DISPATCH_TARGET_OFFSET: usize = 0x20;
const SINGLETON_AVAILABILITY_SLOT: usize = 0x38;
const SINGLETON_SELECTION_SLOT: usize = 0x40;
const INITIAL_STATE_DISPATCH_SLOT: usize = 0xac;
const TOGGLED_STATE_DISPATCH_SLOT: usize = 0xb0;
const TRANSITION_TIMER_OFFSET: usize = 0xa4;
const VOLUME_POST_OPERATION_ADDRESS: usize = 0x081f_9354;

/// The controller bytes and receiver word this routine observes. Pointer
/// fields deliberately remain u32: that is the retail ARM object layout.
#[repr(C)]
struct ControllerTransitionFields {
    _prefix_0_to_1f: [u8; CONTROLLER_DISPATCH_TARGET_OFFSET],
    dispatch_target: u32,
    _opaque_24_to_75: [u8; 0x52],
    singleton_selection: u8,
    _opaque_77_to_89: [u8; 0x13],
    transition_started: u8,
    transition_auxiliary: u8,
    timer_stop_select: u8,
}

const _: () = assert!(core::mem::offset_of!(ControllerTransitionFields, dispatch_target) == 0x20);
const _: () = assert!(core::mem::offset_of!(ControllerTransitionFields, singleton_selection) == 0x76);
const _: () = assert!(core::mem::offset_of!(ControllerTransitionFields, transition_started) == 0x8a);
const _: () = assert!(core::mem::offset_of!(ControllerTransitionFields, transition_auxiliary) == 0x8b);
const _: () = assert!(core::mem::offset_of!(ControllerTransitionFields, timer_stop_select) == 0x8c);

/// Replaceable unknown virtual/external operations reached by this wrapper.
#[derive(Clone, Copy)]
pub struct ControllerTransitionVolumePostOps {
    pub singleton_availability: unsafe extern "C" fn() -> u32,
    pub singleton_selection: unsafe extern "C" fn() -> u32,
    pub dispatch_initial_state: unsafe extern "C" fn(*mut u8),
    pub dispatch_toggled_state: unsafe extern "C" fn(*mut u8),
    pub post_volume_operation: unsafe extern "C" fn(*mut u8),
    #[cfg(not(target_os = "none"))]
    pub host_volume_controller_get: unsafe extern "C" fn() -> *mut u8,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn vtable_slot(receiver: *mut u8, byte_offset: usize) -> usize {
    let vtable = unsafe { receiver.cast::<u32>().read_volatile() } as usize;
    unsafe { (vtable as *const u32).add(byte_offset / 4).read_volatile() as usize }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_singleton_availability() -> u32 {
    let singleton = unsafe { lazy_singleton_0xbc() };
    let method: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { core::mem::transmute(vtable_slot(singleton, SINGLETON_AVAILABILITY_SLOT)) };
    unsafe { method(singleton) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_singleton_selection() -> u32 {
    let singleton = unsafe { lazy_singleton_0xbc() };
    let method: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { core::mem::transmute(vtable_slot(singleton, SINGLETON_SELECTION_SLOT)) };
    unsafe { method(singleton) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_dispatch_initial_state(receiver: *mut u8) {
    let method: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(vtable_slot(receiver, INITIAL_STATE_DISPATCH_SLOT)) };
    unsafe { method(receiver) };
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_dispatch_toggled_state(receiver: *mut u8) {
    let method: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(vtable_slot(receiver, TOGGLED_STATE_DISPATCH_SLOT)) };
    unsafe { method(receiver) };
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_post_volume_operation(volume_controller: *mut u8) {
    let post: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(VOLUME_POST_OPERATION_ADDRESS) };
    unsafe { post(volume_controller) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_availability() -> u32 {
    panic!("controller_transition_volume_post requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection() -> u32 {
    panic!("controller_transition_volume_post requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_receiver: *mut u8) {
    panic!("controller_transition_volume_post requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_volume_post(_volume_controller: *mut u8) {
    panic!("controller_transition_volume_post requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_volume_controller_get() -> *mut u8 {
    panic!("controller_transition_volume_post requires installed firmware ops")
}

#[cfg(target_os = "none")]
pub static mut CONTROLLER_TRANSITION_VOLUME_POST_OPS: ControllerTransitionVolumePostOps =
    ControllerTransitionVolumePostOps {
        singleton_availability: firmware_singleton_availability,
        singleton_selection: firmware_singleton_selection,
        dispatch_initial_state: firmware_dispatch_initial_state,
        dispatch_toggled_state: firmware_dispatch_toggled_state,
        post_volume_operation: firmware_post_volume_operation,
    };

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_TRANSITION_VOLUME_POST_OPS: ControllerTransitionVolumePostOps =
    ControllerTransitionVolumePostOps {
        singleton_availability: missing_availability,
        singleton_selection: missing_selection,
        dispatch_initial_state: missing_dispatch,
        dispatch_toggled_state: missing_dispatch,
        post_volume_operation: missing_volume_post,
        host_volume_controller_get: missing_volume_controller_get,
    };

#[inline(always)]
fn transition_ops() -> ControllerTransitionVolumePostOps {
    unsafe { addr_of!(CONTROLLER_TRANSITION_VOLUME_POST_OPS).read_volatile() }
}

#[inline(always)]
unsafe fn dispatch_target(fields: *mut ControllerTransitionFields) -> *mut u8 {
    unsafe { addr_of!((*fields).dispatch_target).read_volatile() as usize as *mut u8 }
}

/// Runs the controller's availability-gated transition and always posts the
/// resulting volume operation.
///
/// # Safety
///
/// `this` must be writable through the embedded timer at +0xa4 and have valid
/// retail controller receivers at +0x20. The stock routine performs no NULL
/// checks after availability succeeds.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_transition_volume_post(this: *mut u8) {
    let fields = this.cast::<ControllerTransitionFields>();
    let ops = transition_ops();

    if unsafe { (ops.singleton_availability)() } != 0 {
        if unsafe { addr_of!((*fields).transition_started).read_volatile() } == 0 {
            unsafe { addr_of_mut!((*fields).transition_started).write_volatile(1) };
            unsafe { addr_of_mut!((*fields).transition_auxiliary).write_volatile(0) };
            unsafe { addr_of_mut!((*fields).timer_stop_select).write_volatile(0) };
            let selection = unsafe { (ops.singleton_selection)() } as u8;
            unsafe { addr_of_mut!((*fields).singleton_selection).write_volatile(selection) };
            unsafe { (ops.dispatch_initial_state)(dispatch_target(fields)) };
        } else {
            let old = unsafe { addr_of!((*fields).timer_stop_select).read_volatile() };
            unsafe { addr_of_mut!((*fields).timer_stop_select).write_volatile((old == 0) as u8) };
            unsafe { (ops.dispatch_toggled_state)(dispatch_target(fields)) };
        }

        let timer = unsafe { this.add(TRANSITION_TIMER_OFFSET) };
        if unsafe { addr_of!((*fields).timer_stop_select).read_volatile() } == 0 {
            unsafe { timer_restart(timer) };
        } else {
            unsafe { timer_stop(timer) };
        }
    }

    #[cfg(target_os = "none")]
    let volume_controller = unsafe { volume_controller_get() };
    #[cfg(not(target_os = "none"))]
    let volume_controller = unsafe { (ops.host_volume_controller_get)() };
    unsafe { (ops.post_volume_operation)(volume_controller) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_STOPPED};
    use crate::testing::TIMER_OPS_TEST_LOCK;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    const CONTROLLER_LEN: usize = TRANSITION_TIMER_OFFSET + 0x30;
    const TIMER_STATE_OFFSET: usize = TRANSITION_TIMER_OFFSET + 0x20;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Availability,
        Selection,
        InitialDispatch,
        ToggledDispatch,
        TimerTrace(usize),
        TimerArm(usize),
        VolumePost,
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn record(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }

    unsafe extern "C" fn available() -> u32 {
        record(Event::Availability);
        1
    }

    unsafe extern "C" fn unavailable() -> u32 {
        record(Event::Availability);
        0
    }

    unsafe extern "C" fn selected() -> u32 {
        record(Event::Selection);
        0xab
    }

    unsafe extern "C" fn initial_dispatch(_receiver: *mut u8) {
        record(Event::InitialDispatch);
    }

    unsafe extern "C" fn toggled_dispatch(_receiver: *mut u8) {
        record(Event::ToggledDispatch);
    }

    unsafe extern "C" fn volume_post(_volume_controller: *mut u8) {
        record(Event::VolumePost);
    }

    unsafe extern "C" fn host_volume_controller_get() -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn timer_trace(timer: *mut u8) {
        record(Event::TimerTrace(timer as usize));
    }

    unsafe extern "C" fn timer_cancel(_handle: usize, _id: usize, _timer: *mut u8) -> u32 {
        0
    }

    unsafe extern "C" fn timer_arm(timer: *mut u8) {
        record(Event::TimerArm(timer as usize));
    }

    unsafe extern "C" fn timer_validate(_timer: *mut u8) {}
    unsafe extern "C" fn timer_tick() -> u32 { 0 }
    unsafe extern "C" fn timer_compare(_left: *const u32, _right: *const u32) -> u32 { 0 }
    unsafe extern "C" fn timer_notify(_callback: *const u32) {}
    unsafe extern "C" fn timer_construct(_timer: *mut u8, _a: u32, _b: u32, _handle: usize) {}

    struct TestGuard {
        saved_ops: ControllerTransitionVolumePostOps,
        saved_timer_ops: TimerOps,
        _timer: MutexGuard<'static, ()>,
        _ops: MutexGuard<'static, ()>,
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CONTROLLER_TRANSITION_VOLUME_POST_OPS).write_volatile(self.saved_ops);
                ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.saved_timer_ops);
            }
            EVENTS
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
        }
    }

    fn install(availability: unsafe extern "C" fn() -> u32) -> TestGuard {
        let timer = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let ops = OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let saved_ops = unsafe { ptr::addr_of!(CONTROLLER_TRANSITION_VOLUME_POST_OPS).read_volatile() };
        let saved_timer_ops = unsafe { ptr::addr_of!(TIMER_OPS).read_volatile() };
        unsafe {
            ptr::addr_of_mut!(CONTROLLER_TRANSITION_VOLUME_POST_OPS).write_volatile(
                ControllerTransitionVolumePostOps {
                    singleton_availability: availability,
                    singleton_selection: selected,
                    dispatch_initial_state: initial_dispatch,
                    dispatch_toggled_state: toggled_dispatch,
                    post_volume_operation: volume_post,
                    host_volume_controller_get,
                },
            );
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(TimerOps {
                trace_assert: timer_trace,
                cancel_callback: timer_cancel,
                arm_timer: timer_arm,
                trace_validate: timer_validate,
                tick: timer_tick,
                compare_deadlines: timer_compare,
                notify_pending: timer_notify,
                construct_timer: timer_construct,
            });
            EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
        }
        TestGuard { saved_ops, saved_timer_ops, _timer: timer, _ops: ops }
    }

    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn set_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn unavailable_only_posts_the_volume_operation() {
        let _guard = install(unavailable);
        let mut controller = [0u8; CONTROLLER_LEN];
        controller[0x76] = 0x44;
        controller[0x8a] = 0;
        controller[0x8b] = 0x55;
        controller[0x8c] = 1;
        set_word(&mut controller, TIMER_STATE_OFFSET, TIMER_STATE_STOPPED);

        unsafe { controller_transition_volume_post(controller.as_mut_ptr()) };

        assert_eq!(controller[0x76], 0x44);
        assert_eq!(controller[0x8a], 0);
        assert_eq!(controller[0x8b], 0x55);
        assert_eq!(controller[0x8c], 1);
        assert_eq!(*EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()), [Event::Availability, Event::VolumePost]);
    }

    #[test]
    fn initial_state_dispatches_and_restarts_the_embedded_timer() {
        let _guard = install(available);
        let mut controller = [0u8; CONTROLLER_LEN];
        controller[0x8b] = 0xff;
        controller[0x8c] = 0xff;
        set_word(&mut controller, TIMER_STATE_OFFSET, TIMER_STATE_STOPPED);
        let timer = unsafe { controller.as_mut_ptr().add(TRANSITION_TIMER_OFFSET) } as usize;

        unsafe { controller_transition_volume_post(controller.as_mut_ptr()) };

        assert_eq!(controller[0x76], 0xab);
        assert_eq!(&controller[0x8a..=0x8c], &[1, 0, 0]);
        assert_eq!(word(&controller, TIMER_STATE_OFFSET), crate::drivers::timer::TIMER_STATE_RUNNING);
        assert_eq!(
            *EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()),
            [Event::Availability, Event::Selection, Event::InitialDispatch, Event::TimerTrace(timer), Event::TimerArm(timer), Event::VolumePost],
        );
    }

    #[test]
    fn toggled_state_dispatches_and_stops_the_embedded_timer() {
        let _guard = install(available);
        let mut controller = [0u8; CONTROLLER_LEN];
        controller[0x76] = 0x99;
        controller[0x8a] = 1;
        controller[0x8b] = 0x77;
        controller[0x8c] = 0;
        set_word(&mut controller, TIMER_STATE_OFFSET, TIMER_STATE_STOPPED);
        let timer = unsafe { controller.as_mut_ptr().add(TRANSITION_TIMER_OFFSET) } as usize;

        unsafe { controller_transition_volume_post(controller.as_mut_ptr()) };

        assert_eq!(controller[0x76], 0x99);
        assert_eq!(&controller[0x8a..=0x8c], &[1, 0x77, 1]);
        assert_eq!(
            *EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()),
            [Event::Availability, Event::ToggledDispatch, Event::TimerTrace(timer), Event::VolumePost],
        );
    }
}
