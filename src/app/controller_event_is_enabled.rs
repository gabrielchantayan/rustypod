//! `controller_event_is_enabled` — original: `FUN_08172550` @ 0x08172550
//! (88 bytes; four unconditional `bl` instructions and no predicated `bl`).
//!
//! Raw `osos.dec` establishes the exact extent `0x08172550..0x081725a8`; the
//! next separately linked function starts at 0x081725a8. The routine maps an
//! event code to a bit, classifies that event, then ANDs the bit with one of two
//! masks obtained from the controller's +0xa8 input state: class zero uses the
//! +0xb30 accessor and class one uses +0xb8c. Other classes use a zero mask.
//!
//! # Deliberate deviations
//!
//! Device builds invoke the four verified retail addresses. Host builds use a
//! volatile operation seam so tests can observe their call order and inputs;
//! this is the only deliberate deviation.

use core::ptr;

/// Direct callees used by `controller_event_is_enabled`.
#[repr(C)]
pub struct ControllerEventEnablementOps {
    pub event_mask: unsafe extern "C" fn(u32) -> u32,
    pub event_class: unsafe extern "C" fn(u32) -> u32,
    pub class_zero_mask: unsafe extern "C" fn(u32) -> u32,
    pub class_one_mask: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_mask(event: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(0x080d_21f8usize) };
    unsafe { function(event) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_class(event: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(0x080e_2054usize) };
    unsafe { function(event) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_class_zero_mask(input_state: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(0x0805_38a4usize) };
    unsafe { function(input_state) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_class_one_mask(input_state: u32) -> u32 {
    let function: unsafe extern "C" fn(u32) -> u32 = unsafe { core::mem::transmute(0x0805_38b0usize) };
    unsafe { function(input_state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_operation(_value: u32) -> u32 {
    panic!("controller_event_is_enabled requires retail event operations")
}

#[cfg(target_os = "none")]
pub const DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS: ControllerEventEnablementOps = ControllerEventEnablementOps {
    event_mask: firmware_event_mask,
    event_class: firmware_event_class,
    class_zero_mask: firmware_class_zero_mask,
    class_one_mask: firmware_class_one_mask,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS: ControllerEventEnablementOps = ControllerEventEnablementOps {
    event_mask: missing_event_operation,
    event_class: missing_event_operation,
    class_zero_mask: missing_event_operation,
    class_one_mask: missing_event_operation,
};

/// Active direct-call operations. Host tests replace this with a recorder.
pub static mut CONTROLLER_EVENT_ENABLEMENT_OPS: ControllerEventEnablementOps =
    DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS;

#[inline(always)]
unsafe fn event_enablement_ops() -> ControllerEventEnablementOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(CONTROLLER_EVENT_ENABLEMENT_OPS)) }
}

/// Returns whether `event` is enabled by the mask selected from `controller`.
///
/// `controller` must point to a retail-layout object with a valid 32-bit input
/// state pointer at byte offset +0xa8.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.controller_event_is_enabled")]
#[inline(never)]
pub unsafe extern "C" fn controller_event_is_enabled(controller: *const u8, event: u32) -> u32 {
    let ops = unsafe { event_enablement_ops() };
    let event_mask = unsafe { (ops.event_mask)(event) };
    let event_class = unsafe { (ops.event_class)(event) };
    let selected_mask = match event_class {
        0 => unsafe { (ops.class_zero_mask)(ptr::read_unaligned(controller.add(0xa8).cast::<u32>())) },
        1 => unsafe { (ops.class_one_mask)(ptr::read_unaligned(controller.add(0xa8).cast::<u32>())) },
        _ => 0,
    };
    u32::from(selected_mask & event_mask != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of_mut, write_unaligned};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 4] = [0; 4];
    static mut EVENT_MASK: u32 = 0;
    static mut EVENT_CLASS: u32 = 0;
    static mut CLASS_ZERO_MASK: u32 = 0;
    static mut CLASS_ONE_MASK: u32 = 0;

    unsafe extern "C" fn event_mask(event: u32) -> u32 { unsafe { CALLS[0] = event; EVENT_MASK } }
    unsafe extern "C" fn event_class(event: u32) -> u32 { unsafe { CALLS[1] = event; EVENT_CLASS } }
    unsafe extern "C" fn class_zero_mask(input: u32) -> u32 { unsafe { CALLS[2] = input; CLASS_ZERO_MASK } }
    unsafe extern "C" fn class_one_mask(input: u32) -> u32 { unsafe { CALLS[3] = input; CLASS_ONE_MASK } }

    fn install_ops() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 4];
            addr_of_mut!(CONTROLLER_EVENT_ENABLEMENT_OPS).write(ControllerEventEnablementOps {
                event_mask, event_class, class_zero_mask, class_one_mask,
            });
        }
        guard
    }

    fn restore_ops(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(CONTROLLER_EVENT_ENABLEMENT_OPS).write(DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS) };
        drop(guard);
    }

    fn controller(input_state: u32) -> [u32; 43] {
        let mut words = [0; 43];
        words[42] = input_state;
        words
    }

    #[test]
    fn class_zero_uses_its_mask_and_returns_the_and_result() {
        let guard = install_ops();
        unsafe { EVENT_MASK = 0x20; EVENT_CLASS = 0; CLASS_ZERO_MASK = 0x24; CLASS_ONE_MASK = 0; }
        let mut controller = controller(0x1234_5678);
        assert_eq!(unsafe { controller_event_is_enabled(controller.as_mut_ptr().cast(), 0x821a) }, 1);
        assert_eq!(unsafe { CALLS }, [0x821a, 0x821a, 0x1234_5678, 0]);
        restore_ops(guard);
    }

    #[test]
    fn class_one_uses_its_distinct_mask_and_can_reject_an_event() {
        let guard = install_ops();
        unsafe { EVENT_MASK = 0x20; EVENT_CLASS = 1; CLASS_ZERO_MASK = u32::MAX; CLASS_ONE_MASK = 0x10; }
        let mut controller = controller(0x8765_4321);
        assert_eq!(unsafe { controller_event_is_enabled(controller.as_mut_ptr().cast(), 0x821a) }, 0);
        assert_eq!(unsafe { CALLS }, [0x821a, 0x821a, 0, 0x8765_4321]);
        restore_ops(guard);
    }

    #[test]
    fn unsupported_class_skips_both_mask_accessors() {
        let guard = install_ops();
        unsafe { EVENT_MASK = u32::MAX; EVENT_CLASS = 2; CLASS_ZERO_MASK = u32::MAX; CLASS_ONE_MASK = u32::MAX; }
        let mut controller = controller(0);
        assert_eq!(unsafe { controller_event_is_enabled(controller.as_mut_ptr().cast(), 0x824c) }, 0);
        assert_eq!(unsafe { CALLS }, [0x824c, 0x824c, 0, 0]);
        restore_ops(guard);
    }
}
