//! Requesting the navigation dispatcher's default destination.

use core::ptr;

/// ABI of the unported navigation dispatcher at 0x08218e0c.
///
/// The wrapper's only contribution is the three default selector arguments;
/// the dispatcher owns all object access and result handling.
type NavigationRequest = unsafe extern "C" fn(*mut u8, i32, u32, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_navigation_request(
    controller: *mut u8,
    selection: i32,
    flags: u32,
    item: i32,
) {
    let navigation_request: NavigationRequest = core::mem::transmute(0x0821_8e0cusize);
    navigation_request(controller, selection, flags, item);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_navigation_request(
    _controller: *mut u8,
    _selection: i32,
    _flags: u32,
    _item: i32,
) {
    panic!("ui_request_default_navigation requires dispatcher 0x08218e0c")
}

#[cfg(target_os = "none")]
static mut NAVIGATION_REQUEST: NavigationRequest = firmware_navigation_request;
#[cfg(not(target_os = "none"))]
static mut NAVIGATION_REQUEST: NavigationRequest = missing_navigation_request;

#[inline(always)]
unsafe fn navigation_request() -> NavigationRequest {
    ptr::read_volatile(ptr::addr_of!(NAVIGATION_REQUEST))
}

/// `ui_request_default_navigation` — original: `FUN_08219ed4` @ 0x08219ed4
/// (16 bytes, exactly 0x08219ed4..0x08219ee4; the separate sibling function
/// starts at 0x08219ee4). Verified by decoding the raw ARM words:
///
/// ```text
/// 08219ed4  mvn r3, #0
/// 08219ed8  mov r2, #0
/// 08219edc  mvn r1, #0
/// 08219ee0  b   0x08218e0c
/// ```
///
/// There are exactly 12 direct call sites, all `blne` (at 0x08131474,
/// 0x08225a18, 0x0822719c, 0x082296dc, 0x0822a2dc, 0x0822a8c4, 0x082311bc,
/// 0x082321ec, 0x08232c68, 0x0823305c, 0x082370b0, and 0x082393c4), and no
/// data-word references, verified by decoding every direct B/BL word and
/// scanning every aligned word of `osos.dec`. Thus callers, rather than this
/// wrapper, gate navigation requests; it deliberately has no NULL guard.
///
/// The function passes its controller through to the unported navigation
/// dispatcher 0x08218e0c with the default selector tuple `(-1, 0, -1)`.
/// The branch is a tail call in retailOS, so the dispatcher returns directly
/// to the caller.
///
/// # Deliberate deviations
///
/// Rust performs an ordinary indirect call through a volatile seam rather
/// than a tail branch. Its observable arguments and return behaviour are
/// identical; the seam calls 0x08218e0c on firmware and lets host tests record
/// the otherwise unported dispatcher.
///
/// # Safety
///
/// `controller` is passed unguarded to the retail dispatcher, exactly as the
/// original does. It must satisfy that dispatcher's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_request_default_navigation(controller: *mut u8) {
    navigation_request()(controller, -1, 0, -1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_CONTROLLER: *mut u8 = ptr::null_mut();
    static mut SEEN_SELECTION: i32 = 0;
    static mut SEEN_FLAGS: u32 = 0;
    static mut SEEN_ITEM: i32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_request(
        controller: *mut u8,
        selection: i32,
        flags: u32,
        item: i32,
    ) {
        SEEN_CONTROLLER = controller;
        SEEN_SELECTION = selection;
        SEEN_FLAGS = flags;
        SEEN_ITEM = item;
        CALLS += 1;
    }

    unsafe fn prepare() {
        NAVIGATION_REQUEST = recording_request;
        SEEN_CONTROLLER = ptr::null_mut();
        SEEN_SELECTION = 0;
        SEEN_FLAGS = u32::MAX;
        SEEN_ITEM = 0;
        CALLS = 0;
    }

    #[test]
    fn passes_default_selector_tuple_to_dispatcher() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut controller = [0u8; 1];
        unsafe {
            prepare();
            ui_request_default_navigation(controller.as_mut_ptr());

            assert_eq!(SEEN_CONTROLLER, controller.as_mut_ptr());
            assert_eq!(SEEN_SELECTION, -1);
            assert_eq!(SEEN_FLAGS, 0);
            assert_eq!(SEEN_ITEM, -1);
            assert_eq!(CALLS, 1);
        }
    }

    #[test]
    fn passes_null_controller_without_guarding() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            prepare();
            ui_request_default_navigation(ptr::null_mut());

            assert_eq!(SEEN_CONTROLLER, ptr::null_mut());
            assert_eq!(SEEN_SELECTION, -1);
            assert_eq!(SEEN_FLAGS, 0);
            assert_eq!(SEEN_ITEM, -1);
            assert_eq!(CALLS, 1);
        }
    }
}
