//! `event_listener_controller_available` — original: `FUN_081a4210` @
//! **0x081a4210** (**24 bytes**; the next separately linked function begins
//! at 0x081a4228; **7 direct `bl` call sites, all unconditional — 0
//! predicated and 0 plain `b`**, verified by decoding every ARM B/BL immediate
//! in `work/firmware/osos.dec`).
//!
//! # Algorithm
//!
//! Fetches the event-listener controller through
//! [`crate::app::singletons::lazy_singleton_0xbc`], loads its first-word
//! vtable, then tail-dispatches the unknown virtual slot `+0x38` with that
//! controller as `this`. Callers use the returned word as an availability
//! predicate. Raw ARM has no NULL checks: a failed singleton construction, a
//! missing vtable, or a missing slot faults before the virtual call.
//!
//! On ARM this is the original `push; bl; ldr; ldr; pop; bx` sequence, kept as
//! assembly so the final dispatch remains a tail branch. Host builds model the
//! target's 32-bit vtable word positions with pointer-width fields so tests can
//! invoke a real function pointer; that layout widening is the only deliberate
//! deviation. The virtual target has no recovered identity.

#[cfg(not(target_arch = "arm"))]
use crate::app::singletons::lazy_singleton_0xbc;

/// Vtable-bearing event-listener controller, as observed by this wrapper.
#[repr(C)]
pub struct EventListenerController {
    /// +0x00: points to the controller's virtual dispatch table.
    pub vtable: *const EventListenerControllerVtable,
}

/// Recovered portion of the event-listener controller vtable.
#[repr(C)]
pub struct EventListenerControllerVtable {
    /// Slots +0x00..+0x34, not decoded by this wrapper.
    pub unresolved_00: [usize; 14],
    /// +0x38: returns the controller's availability state.
    pub availability: unsafe extern "C" fn(this: *mut EventListenerController) -> u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x38] = [0; core::mem::offset_of!(EventListenerControllerVtable, availability)];

/// event_listener_controller_available — original: `FUN_081a4210` @
/// **0x081a4210** (**24 bytes**; **7 direct `bl` call sites, all
/// unconditional — 0 predicated and 0 plain `b`**, binary-verified from
/// `osos.dec`).
///
/// Returns vtable slot `+0x38` from the lazily constructed 0xbc-byte
/// event-listener controller. The virtual target's identity is unrecovered;
/// callers establish only that its result gates controller transitions.
///
/// # Safety
///
/// The singleton must return a non-NULL controller whose first word names a
/// readable vtable containing a callable `+0x38` slot. The retail function
/// performs no NULL validation.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_listener_controller_available() -> u32 {
    let controller = lazy_singleton_0xbc().cast::<EventListenerController>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*controller).vtable));
    ((*vtable).availability)(controller)
}

// Keep the original lazy getter call and virtual tail dispatch as one ARM
// fragment. A Rust call would introduce a local return edge after the slot.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl event_listener_controller_available
    .type event_listener_controller_available, %function
event_listener_controller_available:
    push    {{r4, lr}}
    bl      lazy_singleton_0xbc
    ldr     r1, [r0]
    ldr     r1, [r1, #0x38]
    pop     {{r4, lr}}
    bx      r1
    .size event_listener_controller_available, . - event_listener_controller_available
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::singletons::{SINGLETON_0XBC, SINGLETON_LOCK};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;

    static mut AVAILABILITY_CALLS: u32 = 0;
    static mut AVAILABILITY_ANSWER: u32 = 0;
    static mut SEEN_CONTROLLER: *mut EventListenerController = core::ptr::null_mut();

    unsafe extern "C" fn record_availability(controller: *mut EventListenerController) -> u32 {
        AVAILABILITY_CALLS += 1;
        SEEN_CONTROLLER = controller;
        AVAILABILITY_ANSWER
    }

    static VTABLE: EventListenerControllerVtable = EventListenerControllerVtable {
        unresolved_00: [0; 14],
        availability: record_availability,
    };
    static mut CONTROLLER: EventListenerController = EventListenerController { vtable: &VTABLE };

    struct InstalledController {
        _singleton_guard: MutexGuard<'static, ()>,
    }

    impl Drop for InstalledController {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(SINGLETON_0XBC).write(core::ptr::null_mut()) };
        }
    }

    fn install(answer: u32) -> InstalledController {
        let singleton_guard = SINGLETON_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(AVAILABILITY_CALLS).write(0);
            addr_of_mut!(AVAILABILITY_ANSWER).write(answer);
            addr_of_mut!(SEEN_CONTROLLER).write(core::ptr::null_mut());
            addr_of_mut!(CONTROLLER).write(EventListenerController { vtable: &VTABLE });
            addr_of_mut!(SINGLETON_0XBC).write(addr_of_mut!(CONTROLLER).cast());
        }
        InstalledController { _singleton_guard: singleton_guard }
    }

    #[test]
    fn returns_the_virtual_availability_answer() {
        let _installed = install(1);

        assert_eq!(unsafe { event_listener_controller_available() }, 1);
        unsafe {
            assert_eq!(addr_of!(AVAILABILITY_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_CONTROLLER).read(), addr_of_mut!(CONTROLLER));
        }
    }

    #[test]
    fn preserves_a_zero_availability_answer() {
        let _installed = install(0);

        assert_eq!(unsafe { event_listener_controller_available() }, 0);
        unsafe {
            assert_eq!(addr_of!(AVAILABILITY_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_CONTROLLER).read(), addr_of_mut!(CONTROLLER));
        }
    }
}
