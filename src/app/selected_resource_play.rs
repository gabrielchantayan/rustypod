//! Requests playback of the selected resource and refreshes the application root.
//!
//! `selected_resource_play` — `FUN_081a2fd0` @ `0x081a2fd0`.
//! True extent: 60 bytes, `0x081a2fd0..0x081a300c`: 56 instruction bytes
//! plus the root-slot literal; the next real function starts with a push.
//! Whole-image A32 decoding finds two inbound plain BLs (0x081e7f10,
//! 0x0820aa44), zero predicated inbound BLs. Outbound: one plain BL to
//! 0x08060fcc and one BLNE to 0x08113a68.
//!
//! Set byte +0x1c to 1, request playback using the resource object at +0x44
//! and selection at +0x60, then refresh the non-null app root regardless of
//! the request status. Return 1 exactly when the unsigned status is zero:
//! ARM RSBS/MOVCC maps both 1 and larger errors to zero.
//! Deliberate deviations: reuse the crate's shared APP_ROOT_OBJECT model of
//! 0x089ca674. Unported callees retain verified retail addresses on ARM and
//! require host seams. repr(C) pointer fields widen naturally on hosts.

#[repr(C)]
pub struct SelectedResourcePlayback {
    pub reserved_00_1b: [u8; 0x1c],
    pub playback_requested: u8,
    pub reserved_1d_43: [u8; 0x27],
    pub resource_object: *mut u8,
    pub reserved_48_5f: [u8; 0x18],
    pub selection: u32,
}

type StartSelectedResource = unsafe extern "C" fn(*mut u8, u32) -> u32;
type RefreshPlaybackRoot = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_start(_object: *mut u8, _selection: u32) -> u32 {
    panic!("install selected-resource playback host start seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_root: *mut u8) {
    panic!("install selected-resource playback host refresh seam")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_RESOURCE_PLAY_START: StartSelectedResource = missing_start;
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_RESOURCE_PLAY_REFRESH: RefreshPlaybackRoot = missing_refresh;

/// # Safety
/// `state` must be writable and its resource object and selection must satisfy
/// retail 0x08060fcc's contract. A non-null shared root must satisfy
/// retail 0x08113a68's contract. Host callers must install both seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_resource_play(state: *mut SelectedResourcePlayback) -> u32 {
    unsafe {
        (*state).playback_requested = 1;
        #[cfg(target_os = "none")]
        let start: StartSelectedResource = core::mem::transmute(0x0806_0fccusize);
        #[cfg(not(target_os = "none"))]
        let start = core::ptr::read_volatile(core::ptr::addr_of!(SELECTED_RESOURCE_PLAY_START));
        let status = start((*state).resource_object, (*state).selection);
        let root = crate::app::context_scope::app_root_object();
        if !root.is_null() {
            #[cfg(target_os = "none")]
            let refresh: RefreshPlaybackRoot = core::mem::transmute(0x0811_3a68usize);
            #[cfg(not(target_os = "none"))]
            let refresh = core::ptr::read_volatile(core::ptr::addr_of!(SELECTED_RESOURCE_PLAY_REFRESH));
            refresh(root);
        }
        u32::from(status == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;

    static mut STATUS: u32 = 0;
    static mut STATE: *mut SelectedResourcePlayback = core::ptr::null_mut();
    static mut NEXT_ROOT: *mut u8 = core::ptr::null_mut();
    static mut REFRESHES: u32 = 0;

    unsafe extern "C" fn start(object: *mut u8, selection: u32) -> u32 {
        assert_eq!((*STATE).playback_requested, 1);
        assert_eq!(object, (*STATE).resource_object);
        assert_eq!(selection, 0x1234_5678);
        APP_ROOT_OBJECT = NEXT_ROOT;
        STATUS
    }
    unsafe extern "C" fn refresh(root: *mut u8) {
        assert_eq!(root, NEXT_ROOT);
        REFRESHES += 1;
        // Refresh must not replace the saved start status.
        STATUS = !STATUS;
    }

    #[test]
    fn status_boundaries_and_post_request_root_transition() {
        let _guard = crate::testing::APP_ROOT_TEST_LOCK.lock().unwrap();
        let mut object = [0u8; 4];
        let mut old_root = [0u8; 4];
        let mut new_root = [0u8; 4];
        let mut state = SelectedResourcePlayback {
            reserved_00_1b: [0xa5; 0x1c], playback_requested: 0,
            reserved_1d_43: [0xa5; 0x27], resource_object: object.as_mut_ptr(),
            reserved_48_5f: [0xa5; 0x18], selection: 0x1234_5678,
        };
        unsafe {
            let saved_root = APP_ROOT_OBJECT;
            SELECTED_RESOURCE_PLAY_START = start;
            SELECTED_RESOURCE_PLAY_REFRESH = refresh;
            STATE = &mut state;
            for status in [0, 1, 2, 0xfffe_ffff, u32::MAX] {
                for live in [false, true] {
                    STATUS = status;
                    REFRESHES = 0;
                    state.playback_requested = 0;
                    APP_ROOT_OBJECT = old_root.as_mut_ptr();
                    NEXT_ROOT = if live { new_root.as_mut_ptr() } else { core::ptr::null_mut() };
                    assert_eq!(selected_resource_play(&mut state), u32::from(status == 0));
                    assert_eq!(REFRESHES, u32::from(live));
                    assert_eq!(state.playback_requested, 1);
                    assert_eq!(state.reserved_00_1b, [0xa5; 0x1c]);
                    assert_eq!(state.reserved_1d_43, [0xa5; 0x27]);
                    assert_eq!(state.reserved_48_5f, [0xa5; 0x18]);
                }
            }
            APP_ROOT_OBJECT = saved_root;
            STATE = core::ptr::null_mut();
            NEXT_ROOT = core::ptr::null_mut();
            SELECTED_RESOURCE_PLAY_START = missing_start;
            SELECTED_RESOURCE_PLAY_REFRESH = missing_refresh;
        }
    }
}
