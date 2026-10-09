//! `controller_event_set_enabled` — FUN_08172610 @ 0x08172610.
//! True extent: 128 bytes, ending at the next prologue at 0x08172690.
//! Four plain unconditional BLs; zero predicated BLs. Two conditional tail
//! branches invoke the class-zero/one setters at 0x08067124/0x08067140.
//!
//! Map the event to a mask, classify it, read the selected input-state mask,
//! then clear its bits for zero `enabled`, or set them for any nonzero value.
//! Unsupported classes do not access the controller. Retail setters update
//! only changed masks and mark their backing state dirty.
//!
//! Deliberate deviation: host builds inject operations rather than executing
//! retail addresses. Device builds use five verified retail targets and the
//! shared Rust classifier. Ghidra includes tail callees and reports 184 bytes.

use core::ptr;
use super::controller_event_is_enabled::{ControllerEventEnablementOps, DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS};

#[repr(C)]
pub struct ControllerEventUpdateOps {
    pub query: ControllerEventEnablementOps,
    pub set_class_zero_mask: unsafe extern "C" fn(u32, u32),
    pub set_class_one_mask: unsafe extern "C" fn(u32, u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn set_class_zero_mask(input: u32, mask: u32) {
    let function: unsafe extern "C" fn(u32, u32) = unsafe { core::mem::transmute(0x0806_7124usize) };
    unsafe { function(input, mask) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn set_class_one_mask(input: u32, mask: u32) {
    let function: unsafe extern "C" fn(u32, u32) = unsafe { core::mem::transmute(0x0806_7140usize) };
    unsafe { function(input, mask) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_mask(_input: u32, _mask: u32) {
    panic!("controller_event_set_enabled requires retail mask setters")
}

pub static mut CONTROLLER_EVENT_UPDATE_OPS: ControllerEventUpdateOps = ControllerEventUpdateOps {
    query: DEFAULT_CONTROLLER_EVENT_ENABLEMENT_OPS,
    #[cfg(target_os = "none")]
    set_class_zero_mask,
    #[cfg(target_os = "none")]
    set_class_one_mask,
    #[cfg(not(target_os = "none"))]
    set_class_zero_mask: missing_set_mask,
    #[cfg(not(target_os = "none"))]
    set_class_one_mask: missing_set_mask,
};

/// Updates the selected event bits. For supported classes, `controller` must
/// be aligned and contain a valid retail input-state pointer at word 42.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.controller_event_set_enabled")]
#[inline(never)]
pub unsafe extern "C" fn controller_event_set_enabled(controller: *const u32, event: u32, enabled: u32) {
    let ops = unsafe { ptr::read_volatile(ptr::addr_of!(CONTROLLER_EVENT_UPDATE_OPS)) };
    let bits = unsafe { (ops.query.event_mask)(event) };
    let class = unsafe { (ops.query.event_class)(event) };
    let mask = match class {
        0 => unsafe { (ops.query.class_zero_mask)(ptr::read(controller.add(42))) },
        1 => unsafe { (ops.query.class_one_mask)(ptr::read(controller.add(42))) },
        _ => return,
    };
    let updated = if enabled == 0 { mask & !bits } else { mask | bits };
    let input = unsafe { ptr::read(controller.add(42)) };
    match class {
        0 => unsafe { (ops.set_class_zero_mask)(input, updated) },
        1 => unsafe { (ops.set_class_one_mask)(input, updated) },
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut MASKS: [u32; 2] = [0; 2];
    static mut DIRTY: bool = false;
    unsafe extern "C" fn bits(event: u32) -> u32 { event & 0xffff }
    unsafe extern "C" fn class(event: u32) -> u32 { event >> 16 }
    unsafe extern "C" fn zero(_input: u32) -> u32 { unsafe { MASKS[0] } }
    unsafe extern "C" fn one(_input: u32) -> u32 { unsafe { MASKS[1] } }
    unsafe fn set(index: usize, value: u32) {
        unsafe {
            if MASKS[index] != value { MASKS[index] = value; DIRTY = true; }
        }
    }
    extern crate std;
    unsafe extern "C" fn set_zero(_input: u32, value: u32) { unsafe { set(0, value) } }
    unsafe extern "C" fn set_one(_input: u32, value: u32) { unsafe { set(1, value) } }

    #[test]
    fn mask_transitions_preserve_other_bits_and_only_dirty_on_changes() {
        let _guard = LOCK.lock();
        unsafe {
            let old = ptr::read(ptr::addr_of!(CONTROLLER_EVENT_UPDATE_OPS));
            ptr::write(ptr::addr_of_mut!(CONTROLLER_EVENT_UPDATE_OPS), ControllerEventUpdateOps {
                query: ControllerEventEnablementOps { event_mask: bits, event_class: class, class_zero_mask: zero, class_one_mask: one },
                set_class_zero_mask: set_zero, set_class_one_mask: set_one,
            });
            let controller = [0u32; 43];
            for selected in 0..2 {
                for initial in [0, 0xaaaa_5555, u32::MAX] {
                    for bits in [0, 1, 0x55, 0xffff] {
                        for enabled in [0, 1, 2, u32::MAX] {
                            MASKS = [initial; 2];
                            DIRTY = false;
                            controller_event_set_enabled(controller.as_ptr(), (selected << 16) | bits, enabled);
                            let expected = if enabled == 0 { initial & !bits } else { initial | bits };
                            let actual = MASKS;
                            assert_eq!(actual[selected as usize], expected);
                            assert_eq!(actual[1 - selected as usize], initial);
                            assert_eq!(DIRTY, expected != initial);
                        }
                    }
                }
            }
            MASKS = [0x1234, 0x5678];
            DIRTY = false;
            controller_event_set_enabled(ptr::null(), 0x20001, 1);
            let actual = MASKS;
            assert_eq!(actual, [0x1234, 0x5678]);
            assert!(!DIRTY);
            ptr::write(ptr::addr_of_mut!(CONTROLLER_EVENT_UPDATE_OPS), old);
        }
    }
}
