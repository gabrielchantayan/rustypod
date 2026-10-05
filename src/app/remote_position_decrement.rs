//! Remote position decrement — `FUN_081cfc9c` at **0x081cfc9c**.
//! True extent **72 bytes**, ending at the next prologue at 0x081cfce4.
//! Raw ARM scan: **two incoming plain BLs, zero predicated BLs**; body:
//! one plain BL, zero predicated BLs, one virtual BLX, one tail virtual BX.
//!
//! Obtain the 0x8c singleton, query vtable slot +0x5c, double the step
//! modulo 2^32, and subtract with an unsigned clamp to zero. Reload the
//! vtable after the query and invoke slot +0x54 with the new position and
//! flag 1. The controller argument is unused. Slot names describe observed
//! roles, not an inferred concrete class or volume unit.
//!
//! Deviations: typed native-width host vtables and a host getter seam;
//! ARM uses the existing singleton port, whose unported constructor remains
//! a hook-readiness prerequisite. Return the tail call's r0 unchanged.

use super::volume_controller_adjust_position::PositionInterface;

#[cfg(not(target_os = "none"))]
pub static mut REMOTE_POSITION_GETTER: unsafe extern "C" fn() -> *mut PositionInterface = missing_getter;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_getter() -> *mut PositionInterface { panic!("install remote position getter") }
#[cfg(test)]
pub(crate) static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// # Safety
/// The singleton and its reloaded vtable must be valid; callbacks must
/// satisfy the position-interface ABI. No NULL checks exist in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remote_position_decrement(_controller: *mut u8, step: u32) -> u32 {
    #[cfg(target_os = "none")]
    let interface: *mut PositionInterface = super::singletons::lazy_singleton_0x8c().cast();
    #[cfg(not(target_os = "none"))]
    let interface = core::ptr::addr_of!(REMOTE_POSITION_GETTER).read_volatile()();
    let current = ((*(*interface).vtable).query_position)(interface);
    let position = current.saturating_sub(step.wrapping_mul(2));
    ((*(*interface).vtable).set_position)(interface, position, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::volume_controller_adjust_position::PositionVtable;
    static mut INTERFACE: *mut PositionInterface = core::ptr::null_mut();
    static mut CURRENT: u32 = 0;
    static mut SELECTED: u32 = 0;
    static mut REPLACEMENT: *const PositionVtable = core::ptr::null();
    unsafe extern "C" fn get() -> *mut PositionInterface { INTERFACE }
    unsafe extern "C" fn query(interface: *mut PositionInterface) -> u32 {
        (*interface).vtable = REPLACEMENT;
        CURRENT
    }
    unsafe extern "C" fn stale(_: *mut PositionInterface, _: u32, _: u32) -> u32 { panic!("stale vtable") }
    unsafe extern "C" fn set(interface: *mut PositionInterface, position: u32, flag: u32) -> u32 {
        assert_eq!(interface, INTERFACE); assert_eq!(flag, 1);
        SELECTED = position; 0x12345678
    }
    #[test]
    fn unsigned_clamp_wrapping_and_vtable_reload() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = REMOTE_POSITION_GETTER;
            REMOTE_POSITION_GETTER = get;
            let old = PositionVtable { unresolved_00_50: [0; 21], set_position: stale,
                unresolved_58: 0, query_position: query, unresolved_60: 0, query_limit: get_limit };
            let new = PositionVtable { set_position: set, ..old };
            REPLACEMENT = &new;
            let mut interface = PositionInterface { vtable: &old };
            INTERFACE = &mut interface;
            for (current, step, expected) in [
                (9, 2, 5), (4, 2, 0), (3, 2, 0), (0, 0, 0), (9, 0, 9),
                (9, 0x80000000, 9), (u32::MAX, u32::MAX, 1),
                (0x80000001, 0x40000000, 1), (9, 0x7fffffff, 0),
            ] {
                CURRENT = current; interface.vtable = &old;
                assert_eq!(remote_position_decrement(core::ptr::null_mut(), step), 0x12345678);
                assert_eq!(SELECTED, expected);
            }
            REMOTE_POSITION_GETTER = saved;
        }
    }
    unsafe extern "C" fn get_limit(_: *mut PositionInterface) -> u32 { panic!("unexpected limit query") }
}
