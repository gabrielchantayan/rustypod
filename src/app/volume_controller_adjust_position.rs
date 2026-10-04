//! Adjust the volume controller's cached media position — `FUN_081f77fc`
//! at **0x081f77fc**, **168 bytes**, ending at the next prologue 0x081f78a4.
//! Raw-word decoding verifies two inbound plain BL calls and zero predicated
//! BL calls; the body has three plain BLs, two BLXs, and a final virtual BX.
//!
//! Double the wheel delta with wrapping arithmetic. Lazily cache the 0x8c
//! singleton, query slot +0x5c, and clamp backwards to zero or forwards to
//! slot +0x64's limit. Only an interior adjustment calls the unresolved
//! controller helper at 0x081f9770 with the doubled magnitude. Finally invoke
//! slot +0x54 with the selected position and flag 1. Slot identities beyond
//! these observed roles remain unresolved. Unsigned subtraction before the
//! forward comparison is intentional, including underflow.
//!
//! Deviations: host fixtures use native-width typed pointers and host-only
//! getter/helper seams. ARM layouts are asserted and the target uses the
//! existing singleton port (whose unported constructor remains a prerequisite)
//! and the original helper address. Rust returns the final slot's r0 result
//! rather than discarding the tail dispatch result.

#[repr(C)]
pub struct PositionInterface {
    pub vtable: *const PositionVtable,
}

#[repr(C)]
pub struct PositionVtable {
    pub unresolved_00_50: [usize; 21],
    pub set_position: unsafe extern "C" fn(*mut PositionInterface, u32, u32) -> u32,
    pub unresolved_58: usize,
    pub query_position: unsafe extern "C" fn(*mut PositionInterface) -> u32,
    pub unresolved_60: usize,
    pub query_limit: unsafe extern "C" fn(*mut PositionInterface) -> u32,
}

#[repr(C)]
pub struct PositionController {
    pub unresolved_00_80: [u32; 33],
    pub interface: *mut PositionInterface,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(PositionController, interface) == 0x84);
    assert!(core::mem::offset_of!(PositionVtable, set_position) == 0x54);
    assert!(core::mem::offset_of!(PositionVtable, query_position) == 0x5c);
    assert!(core::mem::offset_of!(PositionVtable, query_limit) == 0x64);
};

#[cfg(not(target_os = "none"))]
pub static mut POSITION_GETTER: unsafe extern "C" fn() -> *mut PositionInterface = missing_getter;
#[cfg(not(target_os = "none"))]
pub static mut POSITION_ADJUSTMENT_HELPER: unsafe extern "C" fn(*mut PositionController, u32) = missing_helper;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_getter() -> *mut PositionInterface { panic!("install position getter") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_helper(_: *mut PositionController, _: u32) { panic!("install position helper") }

unsafe fn get_interface() -> *mut PositionInterface {
    #[cfg(target_os = "none")]
    { super::singletons::lazy_singleton_0x8c().cast() }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(POSITION_GETTER))() }
}

unsafe fn notify_adjustment(controller: *mut PositionController, magnitude: u32) {
    #[cfg(target_os = "none")]
    {
        let helper: unsafe extern "C" fn(*mut PositionController, u32) =
            core::mem::transmute(0x081f9770usize);
        helper(controller, magnitude);
    }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(POSITION_ADJUSTMENT_HELPER))(controller, magnitude); }
}

/// # Safety
/// Controller, cached singleton, and vtable must be valid retail objects.
/// Callbacks must preserve their ABI and all reloaded interface pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_controller_adjust_position(controller: *mut PositionController, wheel_delta: i32) -> u32 {
    let delta = wheel_delta.wrapping_mul(2);
    if core::ptr::read_volatile(core::ptr::addr_of!((*controller).interface)).is_null() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*controller).interface), get_interface());
    }
    let interface = core::ptr::read_volatile(core::ptr::addr_of!((*controller).interface));
    let current = ((*(*interface).vtable).query_position)(interface);
    let position = if delta < 0 {
        let magnitude = delta.wrapping_neg() as u32;
        if current > magnitude {
            notify_adjustment(controller, magnitude);
            current.wrapping_sub(magnitude)
        } else { 0 }
    } else {
        let interface = core::ptr::read_volatile(core::ptr::addr_of!((*controller).interface));
        let limit = ((*(*interface).vtable).query_limit)(interface);
        if limit.wrapping_sub(delta as u32) > current {
            notify_adjustment(controller, delta as u32);
            current.wrapping_add(delta as u32)
        } else { limit }
    };
    let interface = core::ptr::read_volatile(core::ptr::addr_of!((*controller).interface));
    ((*(*interface).vtable).set_position)(interface, position, 1)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CURRENT: u32 = 0;
    static mut LIMIT: u32 = 0;
    static mut SELECTED: u32 = 0;
    static mut NOTIFIED: Option<u32> = None;
    static mut GETS: u32 = 0;
    static mut LIMIT_QUERIES: u32 = 0;
    static mut INTERFACE: *mut PositionInterface = core::ptr::null_mut();
    unsafe extern "C" fn get() -> *mut PositionInterface { GETS += 1; INTERFACE }
    unsafe extern "C" fn current(_: *mut PositionInterface) -> u32 { CURRENT }
    unsafe extern "C" fn limit(_: *mut PositionInterface) -> u32 { LIMIT_QUERIES += 1; LIMIT }
    unsafe extern "C" fn set(_: *mut PositionInterface, position: u32, flag: u32) -> u32 {
        assert_eq!(flag, 1); SELECTED = position; 0x12345678
    }
    unsafe extern "C" fn notify(_: *mut PositionController, magnitude: u32) { NOTIFIED = Some(magnitude); }

    #[test]
    fn boundaries_wrapping_and_lazy_cache() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = (POSITION_GETTER, POSITION_ADJUSTMENT_HELPER);
            POSITION_GETTER = get; POSITION_ADJUSTMENT_HELPER = notify;
            let vtable = PositionVtable { unresolved_00_50: [0; 21], set_position: set,
                unresolved_58: 0, query_position: current, unresolved_60: 0, query_limit: limit };
            let mut interface = PositionInterface { vtable: &vtable };
            INTERFACE = &mut interface;
            let mut controller = PositionController { unresolved_00_80: [0; 33], interface: core::ptr::null_mut() };
            GETS = 0;
            for (cur, cap, delta, expected, notification) in [
                (9, 100, -2, 5, Some(4)), (4, 100, -2, 0, None),
                (3, 100, -2, 0, None), (90, 100, 2, 94, Some(4)),
                (96, 100, 2, 100, None), (99, 100, 2, 100, None),
                (0, 0, 0, 0, None), (5, 10, 0, 5, Some(0)),
                (1, 3, 2, 5, Some(4)), // unsigned limit subtraction underflows
                (0x80000001, 0, 0x40000000, 1, Some(0x80000000)),
                (5, 10, i32::MIN, 5, Some(0)), // doubled delta wraps to zero
            ] {
                CURRENT = cur; LIMIT = cap; NOTIFIED = None; LIMIT_QUERIES = 0;
                assert_eq!(volume_controller_adjust_position(&mut controller, delta), 0x12345678);
                assert_eq!(SELECTED, expected);
                assert_eq!(NOTIFIED, notification);
                assert_eq!(LIMIT_QUERIES, u32::from(delta.wrapping_mul(2) >= 0));
            }
            assert_eq!(GETS, 1);
            assert_eq!(controller.interface, &mut interface as *mut _);
            POSITION_GETTER = saved.0; POSITION_ADJUSTMENT_HELPER = saved.1;
        }
    }
}
