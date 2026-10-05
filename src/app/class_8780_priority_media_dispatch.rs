//! `class_8780_priority_media_dispatch` — `FUN_081a4f34` @ **0x081a4f34**.
//! True size 48 bytes, ending at the independent constructor at 0x081a4f64.
//! Raw A32 decoding: incoming 2 plain BLs, 0 predicated BLs; outgoing 2
//! plain BLs, 0 predicated BLs, 1 register BLX, and 1 direct tail branch.
//!
//! Only dispatch state 3 obtains the media-player interface and invokes its
//! unresolved vtable slot +0xb8. After that action, pass the original object
//! to the draw-event update at 0x081a38c0 (queries media slot +0x120, optionally
//! clears +0x1c, then emits Draw events 0x7f0c/0x7f0d through object slot +0x58).
//! Ghidra incorrectly incorporates that tail target into this function.
//!
//! Deviations: discard unspecified return-register values; the unported
//! draw-event update remains a firmware-address seam. Reuse the existing
//! singleton getter with its documented not-hook-ready caveat. Host vtable
//! fixtures use native-width words; target slots are four bytes apart.

use super::class_8780_dispatch_state::class_8780_dispatch_state;

const MEDIA_SLOT: usize = 0xb8 / 4;
type MediaAction = unsafe extern "C" fn(*mut u8);

unsafe fn dispatch(
    object: *mut u8,
    get_interface: impl FnOnce() -> *mut u8,
    update_draw_events: impl FnOnce(*mut u8),
) {
    if class_8780_dispatch_state(object) != 3 {
        return;
    }
    let interface = get_interface();
    let vtable = interface.cast::<*const usize>().read_volatile();
    let action: MediaAction = core::mem::transmute(vtable.add(MEDIA_SLOT).read_volatile());
    action(interface);
    update_draw_events(object);
}

unsafe fn update_draw_events(object: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let update: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x081a_38c0usize);
        update(object);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = object; panic!("firmware draw-event update unavailable on host"); }
}

/// Dispatches media slot +0xb8, then draw-event updates, only in state 3.
///
/// # Safety
/// `object` must be readable through +0x8c and valid for the firmware update.
/// In state 3 the singleton must exist, with a callable media slot +0xb8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_8780_priority_media_dispatch(object: *mut u8) {
    dispatch(object, || super::singletons::media_player_interface_get(),
        |object| update_draw_events(object));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Interface {
        vtable: *const usize,
        object: *mut u8,
    }

    unsafe extern "C" fn media_action(interface: *mut u8) {
        let interface = &*interface.cast::<Interface>();
        // The action changes the gate: the continuation must not recheck it.
        *interface.object.add(0x1c) = 0;
        *interface.object.add(0x40) = 0xa5;
    }

    #[test]
    fn inactive_states_never_acquire_or_dispatch() {
        for (gate, value) in [(0, 0), (0, 255), (1, 0), (1, 1), (255, 255)] {
            let mut object = [0u8; 0x8d];
            object[0x8a] = gate;
            object[0x8c] = value;
            let before = object;
            unsafe { dispatch(object.as_mut_ptr(),
                || panic!("inactive state acquired singleton"),
                |_| panic!("inactive state updated draw events")); }
            assert_eq!(object, before);
        }
    }

    #[test]
    fn every_nonzero_priority_runs_media_before_update_without_rechecking() {
        let mut vtable = [0usize; MEDIA_SLOT + 1];
        vtable[MEDIA_SLOT] = media_action as *const () as usize;
        for priority in 1..=255u8 {
            let mut object = [0u8; 0x8d];
            object[0x1c] = priority;
            object[0x8a] = 255;
            object[0x8c] = 255;
            let base = object.as_mut_ptr();
            let mut interface = Interface { vtable: vtable.as_ptr(), object: base };
            unsafe { dispatch(base, || (&mut interface as *mut Interface).cast(), |received| {
                assert_eq!(received, base);
                assert_eq!(*received.add(0x1c), 0);
                assert_eq!(*received.add(0x40), 0xa5);
                *received.add(0x40) = 0x5a;
            }); }
            assert_eq!(object[0x40], 0x5a);
            assert_eq!((object[0x8a], object[0x8c]), (255, 255));
        }
    }
}
