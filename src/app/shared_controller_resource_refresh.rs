//! Refresh the shared controller and publish its two resource updates.
//!
//! Original: FUN_081caac0 @ 0x081caac0. Raw extent is 24 bytes through
//! 0x081caad8 (including the singleton literal); the BNE reaches a separate
//! 80-byte shared body at 0x081cadd4..0x081cae24, including three literals.
//! Ghidra's 88-byte size is not a contiguous extent. Whole-image word decoding
//! finds two inbound plain BLs (0x081caae0, 0x081cac40), zero predicated BLs.
//! Entry has no BLs; shared body has one plain BL to 0x081cad34, no predicated
//! BLs, one virtual BLX and one virtual tail BX through slot +0x58.
//!
//! Capture the singleton at 0x089d00a0. If non-NULL, refresh its selection/state
//! via the unported helper, then dispatch ("****", 0x8d01) and ("****", 0x8d02).
//! Reload the captured object's vtable between dispatches, not the singleton.
//! Deliberate deviations: the discontiguous body is inlined into this port;
//! native repr(C) pointers widen on hosts; the final tail BX is a Rust call.
//! Preserve the final r0 result (zero on the NULL path), though callers ignore it.

use core::ptr;

pub type ResourceDispatch = unsafe extern "C" fn(*mut SharedController, u32, u32) -> u32;
type RefreshSelection = unsafe extern "C" fn(*mut SharedController);

#[repr(C)]
pub struct SharedControllerVtable {
    pub preceding_slots: [usize; 0x58 / 4],
    pub dispatch: ResourceDispatch,
}

#[repr(C)]
pub struct SharedController {
    pub vtable: *const SharedControllerVtable,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_controller: *mut SharedController) {
    panic!("install shared-controller selection refresh host seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SHARED_CONTROLLER: *mut SharedController = ptr::null_mut();
#[cfg(not(target_os = "none"))]
pub static mut SHARED_CONTROLLER_REFRESH_SELECTION: RefreshSelection = missing_refresh;

/// # Safety
/// The singleton must be NULL or a live controller satisfying the original
/// 0x081cad34 helper's contract, with callable vtable slot +0x58. Callbacks may
/// change the vtable or singleton, but must keep the captured controller live.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_controller_resource_refresh() -> u32 {
    #[cfg(target_os = "none")]
    let controller = ptr::read_volatile(0x089d_00a0 as *const *mut SharedController);
    #[cfg(not(target_os = "none"))]
    let controller = ptr::read_volatile(ptr::addr_of!(SHARED_CONTROLLER));
    if controller.is_null() {
        return 0;
    }
    #[cfg(target_os = "none")]
    let refresh: RefreshSelection = core::mem::transmute(0x081c_ad34usize);
    #[cfg(not(target_os = "none"))]
    let refresh = ptr::read_volatile(ptr::addr_of!(SHARED_CONTROLLER_REFRESH_SELECTION));
    refresh(controller);
    let vtable = ptr::read_volatile(ptr::addr_of!((*controller).vtable));
    let dispatch = ptr::read_volatile(ptr::addr_of!((*vtable).dispatch));
    dispatch(controller, 0x2a2a_2a2a, 0x8d01);
    let vtable = ptr::read_volatile(ptr::addr_of!((*controller).vtable));
    let dispatch = ptr::read_volatile(ptr::addr_of!((*vtable).dispatch));
    dispatch(controller, 0x2a2a_2a2a, 0x8d02)
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(SharedControllerVtable, dispatch) == 0x58);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<Vec<(usize, u32, u32)>> = Mutex::new(Vec::new());
    static SECOND: SharedControllerVtable = SharedControllerVtable { preceding_slots: [0; 22], dispatch: second };
    static FIRST: SharedControllerVtable = SharedControllerVtable { preceding_slots: [0; 22], dispatch: first };

    unsafe extern "C" fn refresh(controller: *mut SharedController) {
        EVENTS.lock().push((controller as usize, 0, 0));
        (*controller).vtable = &FIRST;
        // The original retains r4 even when the singleton changes.
        SHARED_CONTROLLER = ptr::null_mut();
    }
    unsafe extern "C" fn first(controller: *mut SharedController, group: u32, resource: u32) -> u32 {
        EVENTS.lock().push((controller as usize, group, resource));
        (*controller).vtable = &SECOND;
        0x1111
    }
    unsafe extern "C" fn second(controller: *mut SharedController, group: u32, resource: u32) -> u32 {
        EVENTS.lock().push((controller as usize, group, resource));
        0xfeed_9876
    }

    #[test]
    fn null_singleton_skips_refresh_and_dispatch() {
        let _guard = LOCK.lock();
        EVENTS.lock().clear();
        unsafe {
            SHARED_CONTROLLER = ptr::null_mut();
            SHARED_CONTROLLER_REFRESH_SELECTION = refresh;
            assert_eq!(shared_controller_resource_refresh(), 0);
            SHARED_CONTROLLER_REFRESH_SELECTION = missing_refresh;
        }
        assert_eq!(*EVENTS.lock(), Vec::new());
    }

    #[test]
    fn captured_object_survives_singleton_change_and_reloads_each_vtable() {
        let _guard = LOCK.lock();
        EVENTS.lock().clear();
        let mut controller = SharedController { vtable: ptr::null() };
        let address = ptr::addr_of_mut!(controller) as usize;
        unsafe {
            SHARED_CONTROLLER = &mut controller;
            SHARED_CONTROLLER_REFRESH_SELECTION = refresh;
            assert_eq!(shared_controller_resource_refresh(), 0xfeed_9876);
            SHARED_CONTROLLER = ptr::null_mut();
            SHARED_CONTROLLER_REFRESH_SELECTION = missing_refresh;
        }
        assert_eq!(*EVENTS.lock(), std::vec![
            (address, 0, 0),
            (address, 0x2a2a_2a2a, 0x8d01),
            (address, 0x2a2a_2a2a, 0x8d02),
        ]);
        assert_eq!(controller.vtable, &SECOND as *const _);
    }
}
