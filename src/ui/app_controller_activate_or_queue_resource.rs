//! Activate a resource when its category slot is free; otherwise queue it.
//!
//! Original `FUN_08180a28` at **0x08180a28**, **44 bytes** through
//! `0x08180a54` (exclusive), the next independent push. Raw A32 has one
//! plain BL and zero predicated BLs; inbound calls are two plain BLs at
//! `0x0817ed34` and `0x08181f8c`, with zero predicated BLs.
//!
//! Query the existing category-slot availability helper, then tail-dispatch
//! to retail queue `0x0817f6c8` on zero or activation `0x0817f4f4` otherwise.
//! Invalid categories therefore take the queue path (whose category lookup
//! suppresses the store). Ghidra incorrectly follows the next function and
//! inlines both branch targets. No semantic deviations: Rust preserves the
//! controller through the normal ABI instead of relying on r3 preservation.
//! Unported actions remain firmware seams; host execution requires actions
//! supplied to the internal dispatcher, rather than fake firmware services.

use super::app_controller_resource_slot_available::app_controller_resource_slot_available;

type ResourceAction = unsafe extern "C" fn(*mut u8, *mut u8);

unsafe fn dispatch_resource(
    controller: *mut u8,
    resource: *mut u8,
    queue: ResourceAction,
    activate: ResourceAction,
) {
    if unsafe { app_controller_resource_slot_available(controller, resource) } == 0 {
        unsafe { queue(controller, resource) };
    } else {
        unsafe { activate(controller, resource) };
    }
}

/// # Safety
/// Both objects must satisfy retailOS controller/resource layouts and the
/// queue/activation routines' contracts, including initialized display services
/// and a valid resource vtable for activation. Only callable on firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_controller_activate_or_queue_resource(
    controller: *mut u8,
    resource: *mut u8,
) {
    #[cfg(target_os = "none")]
    unsafe {
        dispatch_resource(controller, resource,
            core::mem::transmute::<usize, ResourceAction>(0x0817f6c8),
            core::mem::transmute::<usize, ResourceAction>(0x0817f4f4));
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, resource);
        panic!("resource dispatch requires retailOS queue/activation services");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Controller {
        bytes: [u8; 0xd8],
        queued: [*mut u8; 4],
        activated: [*mut u8; 4],
    }

    unsafe extern "C" fn queue(controller: *mut u8, resource: *mut u8) {
        let category = unsafe { resource.add(0x11d).read() };
        if (1..=4).contains(&category) {
            unsafe { (*controller.cast::<Controller>()).queued[category as usize - 1] = resource };
        }
    }

    unsafe extern "C" fn activate(controller: *mut u8, resource: *mut u8) {
        let slot = unsafe { resource.add(0x11d).read() } as usize - 1;
        let state = unsafe { &mut *controller.cast::<Controller>() };
        assert_eq!(state.bytes[0xd4 + slot], 0);
        state.bytes[0xd4 + slot] = 1;
        state.activated[slot] = resource;
    }

    #[test]
    fn free_slot_activates_then_subsequent_resource_replaces_queue_only() {
        for category in 1..=4 {
            let mut state = Controller { bytes: [0xff; 0xd8],
                queued: [core::ptr::null_mut(); 4], activated: [core::ptr::null_mut(); 4] };
            let slot = category as usize - 1;
            state.bytes[0xd4 + slot] = 0;
            let controller = (&mut state as *mut Controller).cast();
            let mut first = [0u8; 0x11e];
            let mut second = first;
            first[0x11d] = category;
            second[0x11d] = category;
            unsafe { dispatch_resource(controller, first.as_mut_ptr(), queue, activate) };
            assert_eq!(state.activated[slot], first.as_mut_ptr());
            assert_eq!(state.bytes[0xd4 + slot], 1);
            assert!(state.queued.iter().all(|p| p.is_null()));
            for active in [1, 0x7f, 0x80, 0xff] {
                state.bytes[0xd4 + slot] = active;
                unsafe { dispatch_resource(controller, second.as_mut_ptr(), queue, activate) };
                assert_eq!(state.queued[slot], second.as_mut_ptr());
                assert_eq!(state.activated[slot], first.as_mut_ptr());
                assert_eq!(state.bytes[0xd4 + slot], active);
            }
            for other in 0..4 {
                if other != slot {
                    assert!(state.queued[other].is_null());
                    assert!(state.activated[other].is_null());
                    assert_eq!(state.bytes[0xd4 + other], 0xff);
                }
            }
        }
    }

    #[test]
    fn invalid_categories_queue_without_accessing_controller() {
        let mut resource = [0u8; 0x11e];
        for category in 0..=255u8 {
            if (1..=4).contains(&category) { continue; }
            resource[0x11d] = category;
            unsafe { dispatch_resource(core::ptr::null_mut(), resource.as_mut_ptr(), queue, activate) };
        }
    }
}
