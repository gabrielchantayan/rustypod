//! Remote position increment — `FUN_081cf9fc` at **0x081cf9fc**.
//! True extent **104 bytes**, ending at the next prologue at 0x081cfa64.
//! Raw-word scan: **two incoming plain BLs, zero predicated BLs**;
//! body: one plain BL, zero predicated BLs, two virtual BLXs, one tail BX.
//!
//! Query the 0x8c singleton's position (+0x5c), double the step modulo
//! 2^32, then query its limit (+0x64). If wrapping limit-minus-step is
//! greater than current, select wrapping current-plus-step; otherwise select
//! limit. Clamp the selected unsigned value to limit and dispatch +0x54
//! with flag 1. Reload the vtable after each query. Controller is unused.
//!
//! Deviations: native-width typed host vtables and a host getter seam.
//! Target uses the existing singleton port, whose unported constructor
//! remains a hook-readiness prerequisite. Preserve the tail call's r0.

use super::volume_controller_adjust_position::PositionInterface;

#[cfg(not(target_os = "none"))]
pub static mut REMOTE_POSITION_INCREMENT_GETTER: unsafe extern "C" fn() -> *mut PositionInterface = missing_getter;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_getter() -> *mut PositionInterface { panic!("install remote position increment getter") }

/// # Safety
/// Singleton and each reloaded vtable must be valid, with callbacks obeying
/// the position-interface ABI. RetailOS does not check for NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remote_position_increment(_controller: *mut u8, step: u32) -> u32 {
    #[cfg(target_os = "none")]
    let interface: *mut PositionInterface = super::singletons::lazy_singleton_0x8c().cast();
    #[cfg(not(target_os = "none"))]
    let interface = core::ptr::addr_of!(REMOTE_POSITION_INCREMENT_GETTER).read_volatile()();
    let current = ((*(*interface).vtable).query_position)(interface);
    let delta = step.wrapping_mul(2);
    let limit = ((*(*interface).vtable).query_limit)(interface);
    let selected = if limit.wrapping_sub(delta) > current {
        current.wrapping_add(delta)
    } else { limit };
    ((*(*interface).vtable).set_position)(interface, selected.min(limit), 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::volume_controller_adjust_position::PositionVtable;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut INTERFACE: *mut PositionInterface = core::ptr::null_mut();
    static mut CURRENT: u32 = 0;
    static mut LIMIT: u32 = 0;
    static mut SELECTED: u32 = 0;
    static mut PHASE: u32 = 0;
    static mut LIMIT_TABLE: *const PositionVtable = core::ptr::null();
    static mut SET_TABLE: *const PositionVtable = core::ptr::null();
    unsafe extern "C" fn get() -> *mut PositionInterface { PHASE = 0; INTERFACE }
    unsafe extern "C" fn current(interface: *mut PositionInterface) -> u32 {
        assert_eq!(interface, INTERFACE); assert_eq!(PHASE, 0);
        PHASE = 1; (*interface).vtable = LIMIT_TABLE; CURRENT
    }
    unsafe extern "C" fn limit(interface: *mut PositionInterface) -> u32 {
        assert_eq!(interface, INTERFACE); assert_eq!(PHASE, 1);
        PHASE = 2; (*interface).vtable = SET_TABLE; LIMIT
    }
    unsafe extern "C" fn stale_query(_: *mut PositionInterface) -> u32 { panic!("stale query") }
    unsafe extern "C" fn stale_set(_: *mut PositionInterface, _: u32, _: u32) -> u32 { panic!("stale setter") }
    unsafe extern "C" fn set(interface: *mut PositionInterface, position: u32, flag: u32) -> u32 {
        assert_eq!(interface, INTERFACE); assert_eq!(PHASE, 2); assert_eq!(flag, 1);
        PHASE = 3; SELECTED = position; 0x12345678
    }
    #[test]
    fn unsigned_boundaries_wrapping_and_both_vtable_reloads() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = REMOTE_POSITION_INCREMENT_GETTER;
            REMOTE_POSITION_INCREMENT_GETTER = get;
            let initial = PositionVtable { unresolved_00_50: [0; 21], set_position: stale_set,
                unresolved_58: 0, query_position: current, unresolved_60: 0, query_limit: stale_query };
            let middle = PositionVtable { query_limit: limit, ..initial };
            let final_table = PositionVtable { set_position: set, ..initial };
            LIMIT_TABLE = &middle; SET_TABLE = &final_table;
            let mut interface = PositionInterface { vtable: &initial };
            INTERFACE = &mut interface;
            for (cur, cap, step, expected) in [
                (9, 100, 2, 13), (96, 100, 2, 100), (99, 100, 2, 100),
                (101, 100, 0, 100), (0, 0, 0, 0), (9, 100, 0, 9),
                (1, 3, 2, 3), // subtraction underflow, final clamp
                (0xfffffffe, 3, 2, 2), // unsigned subtraction and addition wrap
                (0xfffffff0, 3, 16, 3), // both subtraction and addition wrap
                (9, 100, 0x80000000, 9), // doubled step wraps to zero
                (1, 100, 0x7fffffff, 100), (2, 100, 0x7fffffff, 0),
                (0x80000000, u32::MAX, 1, 0x80000002),
            ] {
                CURRENT = cur; LIMIT = cap; interface.vtable = &initial;
                assert_eq!(remote_position_increment(core::ptr::null_mut(), step), 0x12345678);
                assert_eq!(SELECTED, expected); assert_eq!(PHASE, 3);
            }
            REMOTE_POSITION_INCREMENT_GETTER = saved;
        }
    }
}
