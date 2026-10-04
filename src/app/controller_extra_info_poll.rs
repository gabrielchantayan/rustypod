//! Extra-info readiness poll — retailOS `FUN_081f78ec` @ `0x081f78ec`.
//! True extent: 128 bytes through `0x081f796c` (120 code, 8 literal pool).
//! Verified outgoing calls: one plain BL, zero predicated BL, two BLX,
//! one BLXNE. Inbound: two plain BL, zero predicated BL.
//!
//! Return 1 if the controller's source is NULL or source slot +0xec returns
//! zero. Otherwise return cached byte +0xc5, querying media-player slot +0xdc
//! with embedded payload +0xac when that byte is zero. Store the low byte of
//! the query result; if the full result is nonzero, notify controller slot
//! +0x58 with (controller, 0x53747220, 0x7f1b), then reload the cached byte.
//! Callers select the extra-info loading/ready layout from this result.
//!
//! Deliberate deviations: repr(C) pointer fields and native-width vtable
//! entries expand on hosts, retaining target offsets on ARM. Tests substitute
//! only singleton lookup. Virtual method identities remain unresolved; their
//! slots and observed arguments define the ABI. The existing media-player
//! singleton constructor's not-hook-ready prerequisite is inherited.

use core::mem::transmute;

#[repr(C)]
pub struct ExtraInfoController {
    pub vtable: *const usize,
    pub opaque_words: [u32; 6],
    pub source: *mut u8,
    pub opaque_bytes: [u8; 0xac - 0x20],
    pub payload: [u8; 0xc5 - 0xac],
    pub ready: u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(ExtraInfoController, source) == 0x1c);
    assert!(core::mem::offset_of!(ExtraInfoController, payload) == 0xac);
    assert!(core::mem::offset_of!(ExtraInfoController, ready) == 0xc5);
};

unsafe fn slot(object: *mut u8, index: usize) -> usize {
    let vtable = unsafe { *object.cast::<*const usize>() };
    unsafe { *vtable.add(index) }
}

#[inline(always)]
unsafe fn poll(controller: *mut ExtraInfoController, get_player: impl FnOnce() -> *mut u8) -> u8 {
    let source = unsafe { (*controller).source };
    if source.is_null() { return 1; }
    let source_query: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { transmute(slot(source, 0xec / 4)) };
    if unsafe { source_query(source) } == 0 { return 1; }
    if unsafe { (*controller).ready } == 0 {
        let player = get_player();
        let query: unsafe extern "C" fn(*mut u8, *mut u8) -> u32 =
            unsafe { transmute(slot(player, 0xdc / 4)) };
        let result = unsafe { query(player, core::ptr::addr_of_mut!((*controller).payload).cast()) };
        unsafe { (*controller).ready = result as u8; }
        if result != 0 {
            let notify: unsafe extern "C" fn(*mut ExtraInfoController, u32, u32) =
                unsafe { transmute(slot(controller.cast(), 0x58 / 4)) };
            unsafe { notify(controller, 0x5374_7220, 0x7f1b); }
        }
    }
    unsafe { (*controller).ready }
}

/// # Safety
/// The controller, source and media-player interface must have valid recovered
/// fields and callable virtual slots. No NULL-player check exists in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_extra_info_poll(controller: *mut ExtraInfoController) -> u8 {
    unsafe { poll(controller, || super::singletons::media_player_interface_get()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Source { vtable: *const usize, active: u32 }
    #[repr(C)]
    struct Player { vtable: *const usize, result: u32, calls: u32, payload: *mut u8 }
    #[repr(C)]
    struct Controller { base: ExtraInfoController, notifications: u32, replace: u8 }

    unsafe extern "C" fn active(source: *mut u8) -> u32 {
        unsafe { (*source.cast::<Source>()).active }
    }
    unsafe extern "C" fn query(player: *mut u8, payload: *mut u8) -> u32 {
        let player = unsafe { &mut *player.cast::<Player>() };
        assert_eq!(payload, player.payload);
        player.calls += 1;
        player.result
    }
    unsafe extern "C" fn notify(controller: *mut ExtraInfoController, kind: u32, key: u32) {
        assert_eq!((kind, key), (0x5374_7220, 0x7f1b));
        let controller = unsafe { &mut *controller.cast::<Controller>() };
        controller.notifications += 1;
        if controller.replace != 0 { controller.base.ready = controller.replace; }
    }

    #[test]
    fn bypass_cache_retry_truncation_and_notification_mutation() {
        let mut source_table = [0usize; 0xec / 4 + 1];
        source_table[0xec / 4] = active as *const () as usize;
        let mut player_table = [0usize; 0xdc / 4 + 1];
        player_table[0xdc / 4] = query as *const () as usize;
        let mut controller_table = [0usize; 0x58 / 4 + 1];
        controller_table[0x58 / 4] = notify as *const () as usize;
        let mut source = Source { vtable: source_table.as_ptr(), active: 1 };
        let mut controller = Controller {
            base: ExtraInfoController { vtable: controller_table.as_ptr(), opaque_words: [0; 6],
                source: core::ptr::addr_of_mut!(source).cast(), opaque_bytes: [0; 0xac - 0x20],
                payload: [0; 0xc5 - 0xac], ready: 0 },
            notifications: 0, replace: 0,
        };
        let mut player = Player { vtable: player_table.as_ptr(), result: 0, calls: 0,
            payload: controller.base.payload.as_mut_ptr() };
        let c = core::ptr::addr_of_mut!(controller.base);
        controller.base.source = core::ptr::null_mut();
        assert_eq!(unsafe { poll(c, || panic!("NULL source must bypass player")) }, 1);
        controller.base.source = core::ptr::addr_of_mut!(source).cast();
        source.active = 0;
        controller.base.ready = 77;
        assert_eq!(unsafe { poll(c, || panic!("inactive source must bypass cache")) }, 1);
        assert_eq!(controller.base.ready, 77);
        source.active = 1;
        assert_eq!(unsafe { poll(c, || panic!("warm cache must bypass player")) }, 77);
        controller.base.ready = 0;
        for result in [0, 0, 0x100, 0xffff_ffff] {
            player.result = result;
            let got = unsafe { poll(c, || core::ptr::addr_of_mut!(player).cast()) };
            assert_eq!(got, result as u8);
            assert_eq!(controller.base.ready, result as u8);
        }
        assert_eq!(player.calls, 4);
        assert_eq!(controller.notifications, 2);
        controller.base.ready = 0;
        controller.replace = 19;
        player.result = 1;
        assert_eq!(unsafe { poll(c, || core::ptr::addr_of_mut!(player).cast()) }, 19);
        assert_eq!(controller.notifications, 3);
        assert_eq!(unsafe { poll(c, || panic!("mutated cache must be retained")) }, 19);
    }
}
