//! `controller_extra_info_layout_dispatch` — original: `FUN_0821e0c4` @
//! `0x0821e0c4` (128 bytes, `0x0821e0c4..0x0821e144`; the following bytes
//! are the two NUL-terminated layout names).
//!
//! Raw ARM has four direct, unconditional plain-`bl` callers (0x0821dcec,
//! 0x0821e080, 0x0821e8f4, and 0x0821f038), with no predicated `bl` forms.
//! It clears controller byte `+0xe2`, fetches the volume controller, then
//! dispatches `GotoExtraInfoLayout` when its predicate is nonzero or
//! `GotoExtraInfoLoadingLayout` otherwise. The loading path arms and restarts
//! the controller's timer pointer at `+0xdc` after releasing the temporary COW
//! string.
//!
//! # Deliberate deviations
//!
//! `volume_controller_get` and its predicate at `0x081f78ec` are not ported:
//! target builds call their fixed retailOS addresses and host tests install
//! explicit operations. The established COW-string, layout-dispatch, and timer
//! seams are retained directly.

use crate::app::controller_layout_dispatch::app_controller_dispatch_layout;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use crate::drivers::timer::{timer_restart, timer_start_after};
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_VOLUME_CONTROLLER_GET: usize = 0x081f_77a4;
const RETAIL_VOLUME_CONTROLLER_HAS_EXTRA_INFO: usize = 0x081f_78ec;
const TIMER_POINTER_OFFSET: usize = 0xdc;
const EXTRA_INFO_PENDING_OFFSET: usize = 0xe2;
const EXTRA_INFO_DELAY_MS: u32 = 1000;
const EXTRA_INFO_LAYOUT: &[u8] = b"GotoExtraInfoLayout\0";
const EXTRA_INFO_LOADING_LAYOUT: &[u8] = b"GotoExtraInfoLoadingLayout\0";

type VolumeControllerGet = unsafe extern "C" fn() -> *mut u8;
type VolumeControllerHasExtraInfo = unsafe extern "C" fn(*mut u8) -> u32;
type LayoutDispatch = unsafe extern "C" fn(*mut u8, *mut u8);
type StringFromCstr = unsafe extern "C" fn(*mut *mut u8, *const u8) -> *mut *mut u8;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);
type TimerStartAfter = unsafe extern "C" fn(*mut u8, u32);
type TimerRestart = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_volume_controller_get() -> *mut u8 {
    let get: VolumeControllerGet = core::mem::transmute(RETAIL_VOLUME_CONTROLLER_GET);
    get()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_volume_controller_has_extra_info(volume_controller: *mut u8) -> u32 {
    let has_extra_info: VolumeControllerHasExtraInfo =
        core::mem::transmute(RETAIL_VOLUME_CONTROLLER_HAS_EXTRA_INFO);
    has_extra_info(volume_controller)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_volume_controller_get() -> *mut u8 {
    panic!("install controller extra-info layout operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_volume_controller_has_extra_info(_volume_controller: *mut u8) -> u32 {
    panic!("install controller extra-info layout operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub struct ControllerExtraInfoLayoutOps {
    pub volume_controller_get: VolumeControllerGet,
    pub volume_controller_has_extra_info: VolumeControllerHasExtraInfo,
}

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_EXTRA_INFO_LAYOUT_OPS: ControllerExtraInfoLayoutOps =
    ControllerExtraInfoLayoutOps {
        volume_controller_get: missing_volume_controller_get,
        volume_controller_has_extra_info: missing_volume_controller_has_extra_info,
    };

unsafe extern "C" fn controller_layout_dispatch(controller: *mut u8, layout: *mut u8) {
    app_controller_dispatch_layout(controller.cast(), layout);
}


unsafe fn controller_extra_info_layout_dispatch_with(
    controller: *mut u8,
    timer: *mut u8,
    volume_controller_get: VolumeControllerGet,
    volume_controller_has_extra_info: VolumeControllerHasExtraInfo,
    string_from_cstr: StringFromCstr,
    layout_dispatch: LayoutDispatch,
    string_release: StringRelease,
    timer_start_after: TimerStartAfter,
    timer_restart: TimerRestart,
) {
    controller.add(EXTRA_INFO_PENDING_OFFSET).write_volatile(0);
    let volume_controller = volume_controller_get();
    let has_extra_info = volume_controller_has_extra_info(volume_controller) != 0;
    let layout_name = if has_extra_info {
        EXTRA_INFO_LAYOUT
    } else {
        EXTRA_INFO_LOADING_LAYOUT
    };
    let mut layout = core::ptr::null_mut();
    string_from_cstr(core::ptr::addr_of_mut!(layout), layout_name.as_ptr());
    layout_dispatch(controller, layout);
    string_release(core::ptr::addr_of_mut!(layout));
    if !has_extra_info {
        timer_start_after(timer, EXTRA_INFO_DELAY_MS);
        timer_restart(timer);
    }
}

/// Dispatches the extra-information or loading layout for `controller`.
///
/// # Safety
/// `controller` must have writable byte `+0xe2`, a valid timer pointer word at
/// `+0xdc`, and satisfy every selected retailOS callee's pointer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_extra_info_layout_dispatch(controller: *mut u8) {
    #[cfg(target_os = "none")]
    controller_extra_info_layout_dispatch_with(
        controller,
        (controller.add(TIMER_POINTER_OFFSET).cast::<u32>().read_volatile() as usize) as *mut u8,
        retail_volume_controller_get,
        retail_volume_controller_has_extra_info,
        cxx_string_from_cstr,
        controller_layout_dispatch,
        cxx_string_release,
        timer_start_after,
        timer_restart,
    );
    #[cfg(not(target_os = "none"))]
    controller_extra_info_layout_dispatch_with(
        controller,
        (controller.add(TIMER_POINTER_OFFSET).cast::<u32>().read_volatile() as usize) as *mut u8,
        core::ptr::read_volatile(addr_of!(CONTROLLER_EXTRA_INFO_LAYOUT_OPS.volume_controller_get)),
        core::ptr::read_volatile(addr_of!(CONTROLLER_EXTRA_INFO_LAYOUT_OPS.volume_controller_has_extra_info)),
        cxx_string_from_cstr,
        controller_layout_dispatch,
        cxx_string_release,
        timer_start_after,
        timer_restart,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;
    use parking_lot::Mutex;

    use super::*;

    static mut VOLUME_CONTROLLER: *mut u8 = core::ptr::null_mut();
    static mut HAS_EXTRA_INFO: u32 = 0;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHED_LAYOUT: *const u8 = core::ptr::null();
    static mut RELEASED: bool = false;
    static mut TIMER_START: Option<(*mut u8, u32)> = None;
    static mut TIMER_RESTART: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn get_volume_controller() -> *mut u8 { VOLUME_CONTROLLER }
    unsafe extern "C" fn has_extra_info(_volume_controller: *mut u8) -> u32 { HAS_EXTRA_INFO }
    unsafe extern "C" fn record_string_from_cstr(string: *mut *mut u8, source: *const u8) -> *mut *mut u8 {
        *string = source as *mut u8;
        string
    }
    unsafe extern "C" fn record_layout_dispatch(_controller: *mut u8, layout: *mut u8) {
        DISPATCHED_LAYOUT = layout;
    }
    unsafe extern "C" fn record_string_release(_string: *mut *mut u8) { RELEASED = true; }
    unsafe extern "C" fn record_timer_start(timer: *mut u8, delay: u32) { TIMER_START = Some((timer, delay)); }
    unsafe extern "C" fn record_timer_restart(timer: *mut u8) { TIMER_RESTART = timer; }

    unsafe fn dispatch(controller: *mut u8, timer: *mut u8) {
        controller_extra_info_layout_dispatch_with(
            controller, timer, get_volume_controller, has_extra_info,
            record_string_from_cstr, record_layout_dispatch, record_string_release,
            record_timer_start, record_timer_restart,
        );
    }

    #[test]
    fn extra_info_dispatches_without_rearming_timer() {
        let mut controller = [0xa5_u8; 0xe3];
        let _lock = LOCK.lock();
        let mut volume_controller = 0_u8;
        let mut timer = 0_u8;
        unsafe {
            VOLUME_CONTROLLER = core::ptr::addr_of_mut!(volume_controller);
            HAS_EXTRA_INFO = 1;
            RELEASED = false;
            TIMER_START = None;
            TIMER_RESTART = core::ptr::null_mut();
            dispatch(controller.as_mut_ptr(), core::ptr::addr_of_mut!(timer));
            assert_eq!(DISPATCHED_LAYOUT, EXTRA_INFO_LAYOUT.as_ptr());
            assert!(RELEASED);
            assert_eq!(controller[EXTRA_INFO_PENDING_OFFSET], 0);
            assert_eq!(TIMER_START, None);
            assert!(TIMER_RESTART.is_null());
        }
    }

    #[test]
    fn loading_dispatch_rearms_embedded_timer_after_release() {
        let mut controller = [0xa5_u8; 0xe3];
        let _lock = LOCK.lock();
        let mut timer = 0_u8;
        unsafe {
            HAS_EXTRA_INFO = 0;
            RELEASED = false;
            dispatch(controller.as_mut_ptr(), core::ptr::addr_of_mut!(timer));
            assert_eq!(DISPATCHED_LAYOUT, EXTRA_INFO_LOADING_LAYOUT.as_ptr());
            assert!(RELEASED);
            assert_eq!(TIMER_START, Some((core::ptr::addr_of_mut!(timer), EXTRA_INFO_DELAY_MS)));
            assert_eq!(TIMER_RESTART, core::ptr::addr_of_mut!(timer));
        }
    }
}
