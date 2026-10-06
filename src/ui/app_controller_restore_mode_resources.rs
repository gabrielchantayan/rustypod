//! Restores queued app-controller resources after refreshing the secondary display.
//!
//! Original: `FUN_08182200` at `0x08182200`, 68 bytes through `0x08182244`
//! (exclusive), where the next independent push begins. Raw A32 decoding finds
//! two inbound plain BLs at 0x0817ed8c and 0x0817ff28, no predicated inbound
//! BLs; outbound calls are three plain BLs and one BLNE. Refresh display 1,
//! then take slots 0..3 in order and activate each non-NULL resource. Taking
//! clears the controller's word at +0xd8 + 4*slot before activation.
//!
//! Deliberate deviations: reuse the existing refresh seam. Target display_get
//! remains retail 0x081d8870 because the Rust getter's constructor is not
//! hook-ready. Unported take (0x0817f710) and activation (0x0817f4f4) retain
//! their firmware implementations; host tests substitute those operations.

use crate::drivers::display::{display_get, Display};
use crate::app::restore_display_layout::firmware_display_refresh;

type TakeResource = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;
type ActivateResource = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    get: unsafe extern "C" fn(u32) -> *mut Display,
    refresh: unsafe extern "C" fn(*mut Display),
    take: TakeResource,
    activate: ActivateResource,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_take(_controller: *mut u8, _slot: i32) -> *mut u8 {
    panic!("resource take requires firmware 0x0817f710");
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_activate(_controller: *mut u8, _resource: *mut u8) {
    panic!("resource activation requires firmware 0x0817f4f4");
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    get: display_get, refresh: firmware_display_refresh,
    take: firmware_take, activate: firmware_activate,
};

/// # Safety
/// `controller` must have the retailOS app-controller layout and remain valid
/// across display refresh and resource activation. Queued resources must satisfy
/// the firmware activation routine's object/vtable contract; display services
/// must be initialized. Callbacks may change later slots, which are read lazily.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_controller_restore_mode_resources(controller: *mut u8) {
    #[cfg(target_os = "none")]
    let (get, refresh, take, activate) = unsafe {
        (core::mem::transmute::<usize, unsafe extern "C" fn(u32) -> *mut Display>(0x081d8870), firmware_display_refresh,
         core::mem::transmute::<usize, TakeResource>(0x0817f710),
         core::mem::transmute::<usize, ActivateResource>(0x0817f4f4))
    };
    #[cfg(not(target_os = "none"))]
    let HostOps { get, refresh, take, activate } = unsafe { HOST_OPS };
    unsafe {
        refresh(get(1));
        for slot in 0..4 {
            let resource = take(controller, slot);
            if !resource.is_null() { activate(controller, resource); }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    #[repr(C)]
    struct Fixture {
        slots: [*mut u8; 4],
        restored: [usize; 4],
        count: usize,
        next_slot: i32,
        refreshed: bool,
        replace_later: bool,
    }
    unsafe extern "C" fn get(id: u32) -> *mut Display {
        assert_eq!(id, 1);
        core::ptr::null_mut()
    }
    static mut CURRENT: *mut Fixture = core::ptr::null_mut();
    unsafe extern "C" fn refresh(display: *mut Display) {
        assert!(display.is_null());
        unsafe { (*CURRENT).refreshed = true; }
    }
    unsafe extern "C" fn take(controller: *mut u8, slot: i32) -> *mut u8 {
        let state = unsafe { &mut *controller.cast::<Fixture>() };
        assert!(state.refreshed);
        assert_eq!(slot, state.next_slot);
        state.next_slot += 1;
        core::mem::replace(&mut state.slots[slot as usize], core::ptr::null_mut())
    }
    unsafe extern "C" fn activate(controller: *mut u8, resource: *mut u8) {
        let state = unsafe { &mut *controller.cast::<Fixture>() };
        assert!(state.slots[(state.next_slot - 1) as usize].is_null());
        state.restored[state.count] = resource as usize;
        state.count += 1;
        if state.replace_later && state.next_slot == 1 {
            state.slots[2] = state.slots[3];
            state.slots[3] = core::ptr::null_mut();
        }
    }
    fn exercise(slots: [*mut u8; 4], replace_later: bool) -> Fixture {
        let mut state = Fixture { slots, restored: [0; 4], count: 0,
            next_slot: 0, refreshed: false, replace_later };
        unsafe {
            let saved = HOST_OPS;
            CURRENT = &mut state;
            HOST_OPS = HostOps { get, refresh, take, activate };
            app_controller_restore_mode_resources((&mut state as *mut Fixture).cast());
            HOST_OPS = saved;
            CURRENT = core::ptr::null_mut();
        }
        assert_eq!(state.next_slot, 4);
        assert!(state.refreshed);
        assert!(state.slots.iter().all(|slot| slot.is_null()));
        state
    }
    #[test]
    fn clears_sparse_slots_before_activation_and_refreshes_empty_queue() {
        let _lock = LOCK.lock();
        let mut resources = [0u8; 2];
        let first = resources.as_mut_ptr();
        let last = unsafe { first.add(1) };
        let state = exercise([first, core::ptr::null_mut(), core::ptr::null_mut(), last], false);
        assert_eq!(state.count, 2);
        assert_eq!(state.restored, [first as usize, last as usize, 0, 0]);
        let empty = exercise([core::ptr::null_mut(); 4], false);
        assert_eq!(empty.count, 0);
        assert_eq!(empty.restored, [0; 4]);
    }
    #[test]
    fn activation_can_replace_and_remove_later_resources() {
        let _lock = LOCK.lock();
        let mut resources = [0u8; 4];
        let slots = core::array::from_fn(|i| unsafe { resources.as_mut_ptr().add(i) });
        let state = exercise(slots, true);
        assert_eq!(state.count, 3);
        assert_eq!(state.restored, [slots[0] as usize, slots[1] as usize, slots[3] as usize, 0]);
    }
}
